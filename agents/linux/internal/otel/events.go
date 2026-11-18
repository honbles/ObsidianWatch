package otel

// events.go - helper log events become app.security events. They are emitted into
// the agent's NORMAL event channel (the one that runs enrichment, normalisation, the
// agent-own-activity filter and the rate limiter), never straight to the forwarder, so
// every event carries the sender's process and parent ids.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"

	"obsidianwatch/linux-agent/pkg/schema"
)

// SecurityEventSource labels app-originated events.
const SecurityEventSource = "app"

func newEventID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// EventContext carries what the agent knows that the application cannot say.
type EventContext struct {
	AgentID  string
	Host     string
	Hasher   *Hasher
	IPMode   func(service, env string) string // client address storage mode
	ClearTxt func(service, env string) bool   // service opted into cleartext user ids
}

// BuildSecurityEvent turns a helper log into an app.security event. ok is false for
// records that are not helper events.
func BuildSecurityEvent(l Log, peer Peer, identity string, ec EventContext, now time.Time) (ev schema.Event, ok bool) {
	if !helperEvents[l.EventName] {
		return ev, false
	}
	svc, env := l.Res.Service, envOf(l.Res.Environment)
	if svc == "" {
		return ev, false
	}
	mode := ClientIPFull
	if ec.IPMode != nil {
		mode = ec.IPMode(svc, env)
	}
	clear := ec.ClearTxt != nil && ec.ClearTxt(svc, env)

	id := func(v string) string {
		if v == "" {
			return ""
		}
		if clear {
			return v
		}
		return ec.Hasher.Hash(v) // "" when no key is configured: never send a raw identifier by default
	}
	user := l.Attrs["user"]
	if user == "" {
		user = l.Attrs["enduser.id"]
	}
	clientIP := ApplyClientIP(l.Attrs["client.address"], mode)
	peerIP := ApplyClientIP(l.Attrs["network.peer.address"], mode)

	app := map[string]any{
		"service": svc, "environment": env, "event.name": l.EventName,
		"identity": identity, "tier": 2,
	}
	if l.Res.InstanceRef != "" {
		app["instance_ref"] = l.Res.InstanceRef
	}
	if l.Res.Version != "" {
		app["version"] = l.Res.Version
	}
	if peer.ContainerID != "" {
		app["container_id"] = peer.ContainerID
	}
	if l.TraceID != "" {
		app["trace_id"] = l.TraceID
	}
	if l.SpanID != "" {
		app["span_id"] = l.SpanID
	}
	if clientIP != "" {
		app["client_ip"] = clientIP
	}
	if peerIP != "" {
		app["peer_ip"] = peerIP
	}
	if v := l.Attrs["route"]; v != "" {
		app["route"] = appRouteOnly(v)
	}
	for _, k := range []string{"outcome", "method", "reason", "mfa", "resource_type", "action", "policy", "kind",
		"parameter", "target_host", "type_name", "limit_name", "target_type", "target_id", "rows", "bytes",
		"format", "object_type", "helper_version"} {
		if v := l.Attrs[k]; v != "" {
			app[k] = v
		}
	}
	if v := id(l.Attrs["object_id"]); v != "" {
		app["object_id"] = v
	}
	if v := id(l.Attrs["session"]); v != "" {
		app["session"] = v
	}

	raw, err := json.Marshal(map[string]any{"app": app})
	if err != nil {
		return ev, false
	}
	t := now
	if l.TimeNano > 0 {
		if lt := time.Unix(0, int64(l.TimeNano)); lt.After(now.Add(-maxSkew)) && lt.Before(now.Add(maxSkew)) {
			t = lt // trust the app's clock only inside the skew window
		}
	}
	ev = schema.Event{
		ID: newEventID(), Time: t.UTC(), AgentID: ec.AgentID, Host: ec.Host, OS: eventOS,
		EventType: "app.security", Severity: schema.SeverityInfo, Source: SecurityEventSource, Raw: raw,
		PID: peer.PID, PPID: peer.PPID, ProcessName: ExeBase(peer.Exe), ImagePath: peer.Exe,
		UserName: id(user),
	}
	return ev, true
}

// appRouteOnly keeps a route template: no query string, no fragment.
func appRouteOnly(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '?' || s[i] == '#' {
			return s[:i]
		}
	}
	return s
}
