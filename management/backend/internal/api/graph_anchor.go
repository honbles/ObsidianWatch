package api

// graph_anchor.go — Alert Graph phase 2. Every alert resolves to one or more
// anchors (spec §3.1). deriveAnchors is pure: event in, anchors out. The
// anchor linker persists them in alert_entities for every engine via
// store.AlertCreatedHook, so no engine call site needs to change.

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// Anchor is one entity an alert is about. Kind is an Entity* constant.
type Anchor struct {
	Kind string `json:"kind"`
	Key  string `json:"key"`
}

const maxProcessAnchorsPerAlert = 25

func gs(p *string) string {
	if p == nil {
		return ""
	}
	return strings.TrimSpace(*p)
}

func isProcessEvent(t string) bool {
	switch t {
	case "process", "network", "dns", "file", "fim", "registry", "sysmon":
		return true
	}
	return false
}

func isAuthEvent(t string) bool {
	return t == "logon" || t == "kerberos" || strings.HasPrefix(t, "cloud.")
}

// processAnchorKey is "agent|guid", or "agent|pid:N|name" when the event has
// no GUID (Windows without Sysmon, rows older than migration 009).
func processAnchorKey(ev store.Event) string {
	if ev.AgentID == "" {
		return ""
	}
	if ev.ProcessGUID != "" {
		return ev.AgentID + "|" + ev.ProcessGUID
	}
	if ev.PID != nil && *ev.PID > 0 && isProcessEvent(ev.EventType) {
		return ev.AgentID + "|pid:" + strconv.Itoa(*ev.PID) + "|" + strings.ToLower(gs(ev.ProcessName))
	}
	return ""
}

// deriveAnchors returns the anchors for an event in priority order: the first
// is the primary anchor the graph opens on.
func deriveAnchors(ev store.Event) []Anchor {
	var out []Anchor
	seen := map[string]bool{}
	add := func(kind, key string) {
		if key == "" || strings.HasSuffix(key, "|") || seen[kind+"\x00"+key] {
			return
		}
		seen[kind+"\x00"+key] = true
		out = append(out, Anchor{kind, key})
	}
	auth := isAuthEvent(ev.EventType)

	// Identity events lead with the actor; everything else leads with the process.
	userAnchor := func() {
		if u := strings.ToLower(gs(ev.UserName)); u != "" && auth {
			add(EntityUser, u)
		}
		if ip := gs(ev.SrcIP); ip != "" && auth {
			add(EntityIP, ip)
		}
	}
	if auth {
		userAnchor()
	}
	add(EntityProcess, processAnchorKey(ev))
	if l := strings.ToLower(gs(ev.LogonID)); l != "" && ev.AgentID != "" && l != "0x0" {
		add(EntityLogon, ev.AgentID+"|"+l)
	}
	if !auth {
		userAnchor()
	}
	switch ev.EventType {
	case "network", "dns":
		if d := strings.ToLower(gs(ev.DstIP)); d != "" {
			if net.ParseIP(d) != nil {
				add(EntityIP, d)
			} else {
				add(EntityDomain, d)
			}
		}
	case "file", "fim":
		if p := gs(ev.FilePath); p != "" && ev.Host != "" {
			add(EntityFile, ev.Host+"|"+strings.ToLower(p))
		}
	case "registry":
		if k := gs(ev.RegKey); k != "" && ev.Host != "" {
			add(EntityRegistry, ev.Host+"|"+strings.ToLower(k))
		}
	}
	return out
}

// linkAnchors persists the anchors for an alert. Process anchors are capped
// so a signature that keeps tripping on new processes cannot grow one alert's
// link set without bound.
func linkAnchors(ctx context.Context, db *store.DB, alertID int64, ev store.Event) {
	for _, a := range deriveAnchors(ev) {
		if a.Kind == EntityProcess {
			_ = db.LinkAlertEntityCapped(ctx, alertID, a.Kind, a.Key, maxProcessAnchorsPerAlert)
			continue
		}
		_ = db.LinkAlertEntity(ctx, alertID, a.Kind, a.Key)
	}
}

// installAlertAnchorLinker chains store.AlertCreatedHook so every newly
// inserted alert, from any engine, is linked to the entities of its source
// event. Work is queued and done off the insert path; a full queue drops the
// link (resolve-on-read in the graph builder still works for that alert).
func installAlertAnchorLinker(db *store.DB) {
	type job struct{ a store.Alert }
	ch := make(chan job, 2048)
	go func() {
		for j := range ch {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if j.a.Host != "" {
				_ = db.LinkAlertEntity(ctx, j.a.ID, EntityHost, j.a.Host)
			}
			if j.a.SourceEventID != "" {
				if ev, err := db.GetEventByID(ctx, j.a.SourceEventID); err == nil && ev != nil {
					linkAnchors(ctx, db, j.a.ID, *ev)
				}
			}
			cancel()
		}
	}()
	prev := store.AlertCreatedHook
	store.AlertCreatedHook = func(a store.Alert) {
		if prev != nil {
			prev(a)
		}
		select {
		case ch <- job{a}:
		default:
		}
	}
}
