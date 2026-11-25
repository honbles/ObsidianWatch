package api

// code_reachability.go - Code step 4: is a vulnerable dependency actually
// running?
//
// The Linux agent's host sensor reports runtime_inventory events for every
// service process (discovered by its listening ports, or instrumented with
// OpenTelemetry): the packages compiled into it or memory-mapped by it
// ("loaded") and the ones installed where it loads code from ("deployed").
// RuntimeIndexer folds those events into runtime_packages. Dependency findings
// (SCA-*) are then labelled when they are read:
//
//	loaded      - that exact package version is loaded by a running process
//	deployed    - it is installed for a running process, not proven loaded
//	not_running - hosts report inventories, and none has this version
//	unknown     - no host reports an inventory, so nothing can be said
//
// A critical or high dependency vulnerability that is loaded also raises an
// alert (CODE-RT-001) on the host running it.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// findingReach is attached to a dependency finding when it is read.
type findingReach struct {
	Level    string     `json:"level"` // loaded | deployed | not_running | unknown
	Hosts    []string   `json:"hosts,omitempty"`
	Services []string   `json:"services,omitempty"`
	LastSeen *time.Time `json:"last_seen,omitempty"`
}

// runtimeFresh: a package counts as running if reported within this window.
const runtimeFresh = 24 * time.Hour

const runtimeInventoryType = "runtime_inventory"

// ── Indexer ───────────────────────────────────────────────────────────────────

type RuntimeIndexer struct {
	db, eventDB *store.DB
	logger      *slog.Logger
}

func NewRuntimeIndexer(db, eventDB *store.DB, logger *slog.Logger) *RuntimeIndexer {
	return &RuntimeIndexer{db: db, eventDB: eventDB, logger: logger}
}

func (x *RuntimeIndexer) Run(ctx context.Context) {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	// Scan results change without new inventories (a new SAST scan), so the
	// running-vulnerability check also runs on its own clock.
	check := time.NewTicker(10 * time.Minute)
	defer check.Stop()
	prune := time.NewTicker(6 * time.Hour)
	defer prune.Stop()
	x.indexOnce(ctx)
	x.raiseRunningVulnAlerts(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-prune.C:
			x.db.PruneRuntimePackages(ctx, 14*24*time.Hour)
		case <-check.C:
			x.raiseRunningVulnAlerts(ctx)
		case <-t.C:
			x.indexOnce(ctx)
		}
	}
}

type inventoryRaw struct {
	Inventory struct {
		Service   string `json:"service"`
		Container string `json:"container"`
		Exe       string `json:"exe"`
		Packages  []struct {
			E  string `json:"e"`
			N  string `json:"n"`
			V  string `json:"v"`
			Ev string `json:"ev"`
		} `json:"packages"`
	} `json:"inventory"`
}

// inventoryRows converts one runtime_inventory event into rows.
func inventoryRows(ev store.Event) []store.RuntimePackage {
	var raw inventoryRaw
	if json.Unmarshal(ev.Raw, &raw) != nil {
		return nil
	}
	inv := raw.Inventory
	out := make([]store.RuntimePackage, 0, len(inv.Packages))
	for _, p := range inv.Packages {
		if p.E == "" || p.N == "" || p.V == "" {
			continue
		}
		evd := p.Ev
		if evd != "loaded" {
			evd = "deployed"
		}
		out = append(out, store.RuntimePackage{Ecosystem: p.E, Name: p.N, Version: normVersion(p.E, p.V),
			AgentID: ev.AgentID, Host: ev.Host, Service: inv.Service, Container: inv.Container, Exe: inv.Exe,
			Evidence: evd, LastSeen: ev.Time})
	}
	return out
}

func (x *RuntimeIndexer) indexOnce(ctx context.Context) {
	for i := 0; i < 20; i++ { // drain a backlog in pages
		events, err := pageEventCursor(ctx, x.eventDB, "runtime-inventory", store.EventFilter{EventType: runtimeInventoryType}, 24*time.Hour, 2000)
		if err != nil {
			x.logger.Warn("runtime inventory: read failed", "err", err)
			return
		}
		var rows []store.RuntimePackage
		for _, ev := range events {
			rows = append(rows, inventoryRows(ev)...)
		}
		if err := x.db.UpsertRuntimePackages(ctx, rows); err != nil {
			x.logger.Warn("runtime inventory: store failed", "err", err)
			return
		}
		if len(rows) > 0 {
			x.raiseRunningVulnAlerts(ctx)
		}
		if len(events) < 2000 {
			return
		}
	}
}

// normVersion makes scanner and runtime versions comparable (Go modules are
// reported with and without the leading "v").
func normVersion(eco, v string) string {
	v = strings.TrimSpace(v)
	if eco == "Go" {
		v = strings.TrimPrefix(v, "v")
	}
	return v
}

// ── Labelling findings ────────────────────────────────────────────────────────

// reachLabeller answers reachability questions with a per-request cache.
type reachLabeller struct {
	db       *store.DB
	since    time.Time
	coverage int
	cache    map[string]*findingReach
}

func newReachLabeller(ctx context.Context, db *store.DB) *reachLabeller {
	since := time.Now().Add(-runtimeFresh)
	return &reachLabeller{db: db, since: since, coverage: db.RuntimeInventoryCoverage(ctx, since), cache: map[string]*findingReach{}}
}

func (l *reachLabeller) label(ctx context.Context, f SASTFinding) *findingReach {
	if f.Package == "" || f.Version == "" || !strings.HasPrefix(f.RuleID, "SCA-") {
		return nil
	}
	if l.coverage == 0 {
		return &findingReach{Level: "unknown"}
	}
	key := f.Ecosystem + "\x00" + store.PackageNameKey(f.Ecosystem, f.Package) + "\x00" + normVersion(f.Ecosystem, f.Version)
	if r, ok := l.cache[key]; ok {
		return r
	}
	rows, err := l.db.FindRuntimePackage(ctx, f.Ecosystem, f.Package, normVersion(f.Ecosystem, f.Version), l.since, 50)
	r := &findingReach{Level: "not_running"}
	if err == nil && len(rows) > 0 {
		r.Level = "deployed"
		hosts, svcs := map[string]bool{}, map[string]bool{}
		for _, p := range rows {
			if p.Evidence == "loaded" {
				r.Level = "loaded"
			}
			hosts[p.Host] = true
			if p.Service != "" {
				svcs[p.Service] = true
			}
			if r.LastSeen == nil || p.LastSeen.After(*r.LastSeen) {
				t := p.LastSeen
				r.LastSeen = &t
			}
		}
		r.Hosts, r.Services = reachKeys(hosts, 10), reachKeys(svcs, 10)
	} else if err != nil {
		r.Level = "unknown"
	}
	l.cache[key] = r
	return r
}

func reachKeys(m map[string]bool, max int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	if len(out) > max {
		out = out[:max]
	}
	return out
}

// labelFindings sets Reachability on every dependency finding.
func labelFindings(ctx context.Context, db *store.DB, findings []SASTFinding) []SASTFinding {
	var l *reachLabeller
	for i := range findings {
		if findings[i].Package == "" {
			continue
		}
		if l == nil {
			l = newReachLabeller(ctx, db)
		}
		findings[i].Reachability = l.label(ctx, findings[i])
	}
	return findings
}

// ── Alert: a vulnerable dependency is running ─────────────────────────────────

// raiseRunningVulnAlerts checks the latest stored dependency findings (critical
// and high) against what is loaded now, and raises one alert per vulnerability,
// package and host per day.
func (x *RuntimeIndexer) raiseRunningVulnAlerts(ctx context.Context) {
	rows, err := x.db.QueryContext(ctx, `
		SELECT DISTINCT ON (connector_id, repo) connector_id, repo, findings
		FROM sast_results WHERE scanned_at > NOW() - INTERVAL '30 days'
		ORDER BY connector_id, repo, scanned_at DESC`)
	if err != nil {
		return
	}
	type hit struct {
		f    SASTFinding
		repo string
	}
	var hits []hit
	for rows.Next() {
		var conn int64
		var repo string
		var raw []byte
		if rows.Scan(&conn, &repo, &raw) != nil {
			continue
		}
		var fs []SASTFinding
		if json.Unmarshal(raw, &fs) != nil {
			continue
		}
		// Accepted risks and false positives raise no alert.
		ix := loadTriageIndex(ctx, x.db, conn)
		for i := range fs {
			ix.apply(&fs[i])
		}
		fs, _ = withoutDismissed(fs)
		for _, f := range fs {
			if f.Package != "" && (f.Severity == "critical" || f.Severity == "high") {
				hits = append(hits, hit{f, repo})
			}
		}
	}
	rows.Close()
	since := time.Now().Add(-runtimeFresh)
	seen := map[string]bool{}
	for _, h := range hits {
		running, err := x.db.FindRuntimePackage(ctx, h.f.Ecosystem, h.f.Package, normVersion(h.f.Ecosystem, h.f.Version), since, 50)
		if err != nil {
			continue
		}
		for _, p := range running {
			if p.Evidence != "loaded" {
				continue
			}
			vuln := strings.TrimPrefix(h.f.RuleID, "SCA-")
			k := vuln + "|" + p.Ecosystem + "|" + p.Name + "|" + p.Version + "|" + p.Host
			if seen[k] {
				continue
			}
			seen[k] = true
			where := p.Host
			if p.Service != "" {
				where = p.Service + " on " + p.Host
			}
			sev := 4
			if h.f.Severity == "critical" {
				sev = 5
			}
			desc := fmt.Sprintf("%s (%s) affects %s %s, which is loaded by a running process: %s (%s).\n\nFound by the dependency scan of %s in %s.\n\nFix: %s",
				vuln, h.f.Severity, p.Name, p.Version, where, p.Exe, h.repo, h.f.File, h.f.Fix)
			_, _, _ = x.db.CreateAlertDeduped(ctx, store.Alert{
				Title:       fmt.Sprintf("[T1190] Vulnerable dependency running: %s in %s %s", vuln, p.Name, p.Version),
				Description: desc, Severity: sev, Host: p.Host, AgentID: p.AgentID, EventType: runtimeInventoryType,
				EventID: fmt.Sprintf("CODE-RT-001:%s:%s:%s:%s:%s", vuln, p.Ecosystem, store.PackageNameKey(p.Ecosystem, p.Name), p.Version, time.Now().UTC().Format("20060102")),
			})
		}
	}
}

// ── API ───────────────────────────────────────────────────────────────────────

// handleRuntimePackages: GET /api/v1/runtime-packages?name=&ecosystem=&version=
// answers "is this package (version) running anywhere?".
func handleRuntimePackages(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		name := strings.TrimSpace(q.Get("name"))
		if name == "" {
			writeJSON(w, 400, map[string]string{"error": "name is required"})
			return
		}
		hours, _ := strconv.Atoi(q.Get("hours"))
		if hours <= 0 || hours > 24*14 {
			hours = 24
		}
		rows, err := db.FindRuntimePackage(r.Context(), q.Get("ecosystem"), name, normVersion(q.Get("ecosystem"), q.Get("version")),
			time.Now().Add(-time.Duration(hours)*time.Hour), 500)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if rows == nil {
			rows = []store.RuntimePackage{}
		}
		writeJSON(w, 200, map[string]interface{}{"packages": rows,
			"hosts_reporting": db.RuntimeInventoryCoverage(r.Context(), time.Now().Add(-runtimeFresh))})
	}
}
