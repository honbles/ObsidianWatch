package api

// app_code.go - Application ↔ host ↔ code correlation.
//
//   - Service code links: an analyst links a repository branch to a monitored
//     service (manual only). The service's Code tab reads that branch's latest
//     scan and labels each dependency finding against what the service's own
//     processes run (agent + pid, container, or discovered name), not the fleet.
//   - Hosts: the hosts that run monitored services, each with its services,
//     host alerts, service alerts, host vulnerability scan, and the dependency
//     findings whose package version is loaded by a service on that host.
//
// Ingest tables (services, service_instances) are read through idb; alerts,
// links, scans and runtime packages through db. There is no cross-database
// join; matching is done here.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lib/pq"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

// ── Instances and attribution ────────────────────────────────────────────────

type appLiveInst struct {
	ServiceID   int64
	Name, Env   string
	Source      string
	AgentID     string
	Host        string
	PID         int
	ContainerID string
	Exe         string
	Ports       []int
	VCSRevision string // commit the instance was built from, when reported
	VCSRepo     string
	VCSBranch   string
	VCSSource   string
}

// appLiveInstances lists live instances seen since, for the given services
// (ids) or on the given agent. Both empty: every live instance.
func appLiveInstances(ctx context.Context, idb *store.DB, ids []int64, agent string, since time.Time) []appLiveInst {
	q := `SELECT i.service_id, s.name, s.environment, s.source, i.agent_id, i.host, i.pid, i.container_id,
		  COALESCE(i.attrs->>'exe',''), i.listen,
		  COALESCE(i.attrs->>'vcs_revision',''), COALESCE(i.attrs->>'vcs_repo',''), COALESCE(i.attrs->>'vcs_branch',''), COALESCE(i.attrs->>'vcs_source','')
		FROM service_instances i JOIN services s ON s.id = i.service_id
		WHERE i.stopped_at IS NULL AND i.last_seen >= $1`
	args := []interface{}{since}
	if ids != nil {
		args = append(args, pq.Array(ids))
		q += ` AND i.service_id = ANY($2)`
	}
	if agent != "" {
		args = append(args, agent)
		q += ` AND i.agent_id = $` + strconv.Itoa(len(args))
	}
	q += ` ORDER BY i.last_seen DESC LIMIT 5000`
	rows, err := idb.QueryContext(ctx, q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []appLiveInst
	for rows.Next() {
		var x appLiveInst
		var listen []byte
		if rows.Scan(&x.ServiceID, &x.Name, &x.Env, &x.Source, &x.AgentID, &x.Host, &x.PID, &x.ContainerID, &x.Exe, &listen,
			&x.VCSRevision, &x.VCSRepo, &x.VCSBranch, &x.VCSSource) == nil {
			x.Ports = appListenPorts(listen)
			out = append(out, x)
		}
	}
	return out
}

// appAttributor maps a runtime package row to the service whose process it
// was seen in: same agent and pid first, then the container, then the
// discovered service name. Exe alone is not used: every Java service on a
// host shares /usr/bin/java.
type appAttributor struct {
	byPID       map[string]int64
	byContainer map[string]int64
	byName      map[string]int64
}

func newAppAttributor(insts []appLiveInst) *appAttributor {
	a := &appAttributor{byPID: map[string]int64{}, byContainer: map[string]int64{}, byName: map[string]int64{}}
	for _, i := range insts {
		if i.PID > 0 {
			a.byPID[i.AgentID+"\x00"+strconv.Itoa(i.PID)] = i.ServiceID
		}
		if i.ContainerID != "" {
			a.byContainer[i.AgentID+"\x00"+i.ContainerID] = i.ServiceID
		}
		if i.Source != "otel" {
			a.byName[i.AgentID+"\x00"+i.Name] = i.ServiceID
		}
	}
	return a
}

func (a *appAttributor) service(p store.RuntimePackage) (int64, bool) {
	if p.PID > 0 {
		if id, ok := a.byPID[p.AgentID+"\x00"+strconv.Itoa(p.PID)]; ok {
			return id, true
		}
	}
	if p.Container != "" {
		for k, id := range a.byContainer {
			// container ids are reported full or shortened; match on prefix
			if strings.HasPrefix(k, p.AgentID+"\x00") {
				c := k[len(p.AgentID)+1:]
				if strings.HasPrefix(c, p.Container) || strings.HasPrefix(p.Container, c) {
					return id, true
				}
			}
		}
	}
	if p.Service != "" {
		if id, ok := a.byName[p.AgentID+"\x00"+p.Service]; ok {
			return id, true
		}
	}
	return 0, false
}

func pkgKey(eco, name, ver string) string {
	return eco + "\x00" + store.PackageNameKey(eco, name) + "\x00" + normVersion(eco, ver)
}

// ── Code findings index (latest scan of every repository) ────────────────────

type codeHit struct {
	ConnID    int64
	Repo      string
	Branch    string
	ScannedAt time.Time
	F         SASTFinding
}

var codeIndexCache struct {
	mu  sync.Mutex
	at  time.Time
	idx map[string][]codeHit
}

// appCodeIndex returns not-dismissed dependency findings of every repository's
// latest scan (last 30 days), keyed by package version. Cached for 2 minutes.
func appCodeIndex(ctx context.Context, db *store.DB) map[string][]codeHit {
	c := &codeIndexCache
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.idx != nil && time.Since(c.at) < 2*time.Minute {
		return c.idx
	}
	idx := map[string][]codeHit{}
	rows, err := db.QueryContext(ctx, `
		SELECT DISTINCT ON (connector_id, repo) connector_id, repo, COALESCE(branch,''), scanned_at, findings
		FROM sast_results WHERE scanned_at > NOW() - INTERVAL '30 days'
		ORDER BY connector_id, repo, scanned_at DESC`)
	if err == nil {
		type scan struct {
			conn     int64
			repo, br string
			at       time.Time
			raw      []byte
		}
		var scans []scan
		for rows.Next() {
			var s scan
			if rows.Scan(&s.conn, &s.repo, &s.br, &s.at, &s.raw) == nil {
				scans = append(scans, s)
			}
		}
		rows.Close()
		triage := map[int64]*triageIndex{}
		for _, s := range scans {
			var fs []SASTFinding
			if json.Unmarshal(s.raw, &fs) != nil {
				continue
			}
			ix, ok := triage[s.conn]
			if !ok {
				ix = loadTriageIndex(ctx, db, s.conn)
				triage[s.conn] = ix
			}
			for i := range fs {
				f := fs[i]
				if f.Package == "" || f.Version == "" {
					continue
				}
				ix.apply(&f)
				if findingDismissed(f) {
					continue
				}
				k := pkgKey(f.Ecosystem, f.Package, f.Version)
				idx[k] = append(idx[k], codeHit{s.conn, s.repo, s.br, s.at, f})
			}
		}
	}
	c.idx, c.at = idx, time.Now()
	return idx
}

// appInvalidateCodeIndex drops the cache (after a link or scan change).
func appInvalidateCodeIndex() {
	codeIndexCache.mu.Lock()
	codeIndexCache.idx = nil
	codeIndexCache.mu.Unlock()
}

// appLinkedScan reads the latest scan of a linked repository branch.
func appLinkedScan(ctx context.Context, db *store.DB, l store.ServiceCodeLink) (findings []SASTFinding, branch string, at time.Time, engines json.RawMessage, ok bool) {
	var raw []byte
	err := db.QueryRowContext(ctx, `
		SELECT findings, COALESCE(branch,''), scanned_at, COALESCE(engines,'{}')
		FROM sast_results WHERE connector_id = $1 AND repo = $2
		  AND (branch = $3 OR ($4 AND COALESCE(branch,'') IN ('', 'HEAD')))
		ORDER BY scanned_at DESC LIMIT 1`, l.ConnectorID, l.Repo, l.Branch, l.IsDefault).Scan(&raw, &branch, &at, &engines)
	if err != nil {
		return nil, "", time.Time{}, nil, false
	}
	_ = json.Unmarshal(raw, &findings)
	return enrichFindings(ctx, db, l.ConnectorID, findings), branch, at, engines, true
}

// ── Risk weighting ───────────────────────────────────────────────────────────

// appRiskWeigh applies the service-alert weighting (internet-facing +1, high
// or critical criticality +1, capped at Critical) to a 1-5 severity.
func appRiskWeigh(sev int, st appServiceSettings) int {
	w, _ := appWeigh(sev, st, "verified", false, false)
	if w > 5 {
		w = 5
	}
	return w
}

func sevName(n int) string {
	switch {
	case n >= 5:
		return "critical"
	case n == 4:
		return "high"
	case n == 3:
		return "medium"
	case n == 2:
		return "low"
	}
	return "info"
}

// ── Host vulnerability scan ──────────────────────────────────────────────────

type appHostScan struct {
	ScannedAt *time.Time       `json:"scanned_at,omitempty"`
	Critical  int              `json:"critical"`
	High      int              `json:"high"`
	Medium    int              `json:"medium"`
	CVEs      int              `json:"cves"`
	OpenPorts int              `json:"open_ports"`
	portRisks []appPortRisk    // port findings, to attach to services by port
	findings  []appScanFinding // host configuration findings
	cveList   []HostCVE
	packages  map[string]string // OS package name -> version
}

type appPortRisk struct {
	Port     int    `json:"port"`
	Product  string `json:"product"`
	Version  string `json:"version"`
	Label    string `json:"risk_label"`
	Detail   string `json:"risk_detail"`
	Severity int    `json:"severity"`
}

type appScanFinding struct {
	Category string `json:"category"`
	Severity int    `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Fix      string `json:"fix"`
}

// appHostVuln reads the host's latest vulnerability scan and the cached NVD
// CVE result (never starts a CVE lookup).
func appHostVuln(ctx context.Context, db, backendDB *store.DB, host string) appHostScan {
	out := appHostScan{packages: map[string]string{}}
	if host == "" {
		return out
	}
	f := store.EventFilter{HostExact: host, EventType: "vulnerability.scan", Limit: 1}
	evs, _, err := db.QueryEvents(ctx, f)
	if (err != nil || len(evs) == 0) && backendDB != nil {
		evs, _, _ = backendDB.QueryEvents(ctx, f)
	}
	if len(evs) > 0 {
		var raw struct {
			OpenPorts     []appPortRisk                    `json:"open_ports"`
			Findings      []appScanFinding                 `json:"findings"`
			Packages      []struct{ Name, Version string } `json:"packages"`
			CriticalCount int                              `json:"critical_count"`
			HighCount     int                              `json:"high_count"`
			MediumCount   int                              `json:"medium_count"`
		}
		if json.Unmarshal(evs[0].Raw, &raw) == nil {
			t := evs[0].Time
			out.ScannedAt = &t
			out.Critical, out.High, out.Medium, out.OpenPorts = raw.CriticalCount, raw.HighCount, raw.MediumCount, len(raw.OpenPorts)
			for _, p := range raw.OpenPorts {
				if p.Severity >= 3 {
					out.portRisks = append(out.portRisks, p)
				}
			}
			for _, x := range raw.Findings {
				if x.Severity >= 3 {
					out.findings = append(out.findings, x)
				}
			}
			for _, p := range raw.Packages {
				out.packages[strings.ToLower(p.Name)] = p.Version
			}
		}
	}
	if b, _, _, ok := db.HostCVEGet(ctx, host); ok {
		var r HostCVEResult
		if json.Unmarshal(b, &r) == nil {
			out.cveList = r.Findings
			out.CVEs = len(r.Findings)
		}
	}
	return out
}

// appPackageForService finds the OS package a platform service comes from
// (nginx -> nginx / nginx-core, postgres -> postgresql-16, redis -> redis-server).
func appPackageForService(name string, role appRole, pkgs map[string]string) (string, string) {
	cands := appNameVariants(name)
	if role.Label != "" {
		cands = append(cands, strings.ToLower(strings.Fields(role.Label)[0]))
	}
	for _, c := range cands {
		if v, ok := pkgs[c]; ok {
			return c, v
		}
		for _, suf := range []string{"-server", "-core", "-common", "d"} {
			if v, ok := pkgs[c+suf]; ok {
				return c + suf, v
			}
		}
	}
	for _, c := range cands { // postgresql-16, php8.2-fpm
		if len(c) < 3 {
			continue
		}
		best := ""
		for p := range pkgs {
			if strings.HasPrefix(p, c) && (best == "" || len(p) < len(best)) && !strings.Contains(p, "-doc") && !strings.Contains(p, "-client") && !strings.HasPrefix(p, c+"-dev") {
				best = p
			}
		}
		if best != "" {
			return best, pkgs[best]
		}
	}
	return "", ""
}

// ── Risk items ───────────────────────────────────────────────────────────────

type appRisk struct {
	Kind       string     `json:"kind"`     // host_alert | service_alert | code_vuln | host_port | host_finding | host_cve
	Severity   string     `json:"severity"` // after weighting by the service's exposure and criticality
	Base       string     `json:"base_severity"`
	Title      string     `json:"title"`
	Detail     string     `json:"detail,omitempty"`
	ServiceID  int64      `json:"service_id,omitempty"`
	Service    string     `json:"service,omitempty"`
	ServiceKey string     `json:"service_key,omitempty"`
	AlertID    int64      `json:"alert_id,omitempty"`
	Repo       string     `json:"repo,omitempty"`
	ConnID     int64      `json:"connector_id,omitempty"`
	Linked     bool       `json:"linked,omitempty"` // the repository is linked to this service
	Evidence   string     `json:"evidence,omitempty"`
	Fix        string     `json:"fix,omitempty"`
	Time       *time.Time `json:"time,omitempty"`
}

func sortRisks(r []appRisk) {
	kindOrder := map[string]int{"service_alert": 0, "host_alert": 1, "code_vuln": 2, "host_port": 3, "host_cve": 4, "host_finding": 5}
	sort.SliceStable(r, func(i, j int) bool {
		a, b := sevRankStr(r[i].Severity), sevRankStr(r[j].Severity)
		if a != b {
			return a > b
		}
		return kindOrder[r[i].Kind] < kindOrder[r[j].Kind]
	})
}

type appAlertRow struct {
	ID         int64
	At         time.Time
	Title      string
	Severity   int
	ServiceKey string
}

// appOpenAlerts returns open alerts for an agent/host, with the service key
// when the alert is linked to a service.
func appOpenAlerts(ctx context.Context, db *store.DB, agent, host string, limit int) []appAlertRow {
	rows, err := db.QueryContext(ctx, `
		SELECT a.id, a.created_at, a.title, a.severity,
		  COALESCE((SELECT e.key FROM alert_entities e WHERE e.alert_id = a.id AND e.kind = 'service' LIMIT 1), '')
		FROM alerts a
		WHERE a.status <> 'closed' AND (a.agent_id = $1 OR ($2 <> '' AND a.host = $2))
		ORDER BY a.severity DESC, a.id DESC LIMIT $3`, agent, host, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []appAlertRow
	for rows.Next() {
		var a appAlertRow
		if rows.Scan(&a.ID, &a.At, &a.Title, &a.Severity, &a.ServiceKey) == nil {
			out = append(out, a)
		}
	}
	return out
}

// ── Host model ───────────────────────────────────────────────────────────────

type appHostService struct {
	ID        int64    `json:"id"`
	Name      string   `json:"name"`
	Env       string   `json:"environment"`
	Key       string   `json:"key"`
	Tier      int      `json:"tier"`
	Role      string   `json:"role"`
	RoleLabel string   `json:"role_label,omitempty"`
	RoleRank  int      `json:"role_rank"`
	Ports     []int    `json:"ports"`
	Instances int      `json:"instances"`
	Exposure  string   `json:"exposure"`
	Critical  string   `json:"criticality"`
	Alerts    int      `json:"open_alerts"`
	CodeVulns int      `json:"code_vulns"` // dependency findings loaded by this service
	CodeLinks []string `json:"code_links"` // linked repositories
	OSPackage string   `json:"os_package,omitempty"`
	OSVersion string   `json:"os_package_version,omitempty"`
	HostRisks int      `json:"host_risks"` // port findings and CVEs attributed to it
	TopSev    string   `json:"top_severity,omitempty"`
}

type appHostSummary struct {
	AgentID      string           `json:"agent_id"`
	Host         string           `json:"host"`
	OS           string           `json:"os"`
	IP           string           `json:"ip"`
	Online       bool             `json:"online"`
	LastSeen     *time.Time       `json:"last_seen,omitempty"`
	Services     int              `json:"services"`
	ByTier       [3]int           `json:"by_tier"`
	HostAlerts   int              `json:"host_alerts"`
	SvcAlerts    int              `json:"service_alerts"`
	TopAlertSev  int              `json:"top_alert_severity"`
	Vuln         appHostScan      `json:"vuln"`
	CodeVulns    int              `json:"code_vulns"`
	CodeCritical int              `json:"code_critical"`
	TopSev       string           `json:"top_severity,omitempty"`
	ServiceList  []appHostService `json:"service_list,omitempty"`
	Risks        []appRisk        `json:"risks,omitempty"`
	Inventory    bool             `json:"runtime_inventory"` // the host reported a runtime package inventory
}

// appBuildHost assembles one host. detail adds the service list and risks.
func appBuildHost(ctx context.Context, db, idb, backendDB *store.DB, agent string, insts []appLiveInst, agents map[string]store.Agent, helpers map[string]bool, detail bool) appHostSummary {
	h := appHostSummary{AgentID: agent}
	if a, ok := agents[agent]; ok {
		h.Host, h.OS, h.IP, h.Online = a.Hostname, a.OS, a.LastIP, a.Online
		t := a.LastSeen
		h.LastSeen = &t
	}
	// services on the host
	svcs := map[int64]*appHostService{}
	var order []int64
	sources := map[int64]string{}
	for _, i := range insts {
		if h.Host == "" {
			h.Host = i.Host
		}
		s, ok := svcs[i.ServiceID]
		if !ok {
			s = &appHostService{ID: i.ServiceID, Name: i.Name, Env: i.Env, Key: appServiceKey(i.Name, i.Env), Ports: []int{}, CodeLinks: []string{}}
			s.Tier = appTierWithHelper(i.Source, s.Key, helpers)
			svcs[i.ServiceID] = s
			order = append(order, i.ServiceID)
			sources[i.ServiceID] = i.Source
		}
		s.Instances++
		for _, p := range i.Ports {
			dup := false
			for _, q := range s.Ports {
				dup = dup || q == p
			}
			if !dup {
				s.Ports = append(s.Ports, p)
			}
		}
	}
	h.Services = len(svcs)
	ids := make([]int64, 0, len(order))
	for _, id := range order {
		ids = append(ids, id)
		h.ByTier[svcs[id].Tier]++
	}
	settings := appSettingsByID(ctx, db, ids)
	appApplyExposure(ctx, idb, ids, settings)
	st := func(id int64) appServiceSettings {
		if s, ok := settings[id]; ok {
			return s
		}
		return appDefaultSettings()
	}
	imgs := appLocators(ctx, idb, ids, time.Now().Add(-24*time.Hour))
	byKey := map[string]*appHostService{}
	for _, id := range ids {
		s := svcs[id]
		role := appServiceRole(s.Name, nil, imgs[id].images, s.Tier)
		s.Role, s.RoleLabel, s.RoleRank = role.Role, role.Label, role.Rank
		ss := st(id)
		s.Exposure, s.Critical = ss.EffectiveExposure(), ss.Criticality
		byKey[s.Key] = s
	}
	links, _ := db.ServiceCodeLinks(ctx, ids)
	linked := map[string]bool{} // service id + conn + repo
	for _, l := range links {
		if s := svcs[l.ServiceID]; s != nil {
			s.CodeLinks = append(s.CodeLinks, l.Repo)
		}
		linked[fmt.Sprintf("%d\x00%d\x00%s", l.ServiceID, l.ConnectorID, l.Repo)] = true
	}
	var risks []appRisk
	add := func(r appRisk) {
		if detail {
			risks = append(risks, r)
		}
		if sevRankStr(r.Severity) > sevRankStr(h.TopSev) {
			h.TopSev = r.Severity
		}
		if s := svcs[r.ServiceID]; s != nil && r.ServiceID != 0 && sevRankStr(r.Severity) > sevRankStr(s.TopSev) {
			s.TopSev = r.Severity
		}
	}

	// alerts
	for _, a := range appOpenAlerts(ctx, db, agent, h.Host, 300) {
		if a.Severity > h.TopAlertSev {
			h.TopAlertSev = a.Severity
		}
		t := a.At
		r := appRisk{Severity: sevName(a.Severity), Base: sevName(a.Severity), Title: a.Title, AlertID: a.ID, Time: &t}
		if s := byKey[a.ServiceKey]; s != nil {
			h.SvcAlerts++
			s.Alerts++
			r.Kind, r.ServiceID, r.Service, r.ServiceKey = "service_alert", s.ID, s.Name, s.Key
		} else {
			h.HostAlerts++
			r.Kind = "host_alert"
		}
		add(r)
	}

	// host scan: ports and CVEs attributed to services, the rest to the host
	h.Vuln = appHostVuln(ctx, db, backendDB, h.Host)
	byPort := map[int]*appHostService{}
	for _, id := range ids {
		for _, p := range svcs[id].Ports {
			byPort[p] = svcs[id]
		}
	}
	for _, p := range h.Vuln.portRisks {
		r := appRisk{Kind: "host_port", Base: sevName(p.Severity), Severity: sevName(p.Severity),
			Title: fmt.Sprintf("Port %d: %s", p.Port, strings.TrimSpace(p.Label+" "+p.Product+" "+p.Version)), Detail: p.Detail, Evidence: "host vulnerability scan"}
		if s := byPort[p.Port]; s != nil {
			r.ServiceID, r.Service, r.ServiceKey = s.ID, s.Name, s.Key
			r.Severity = sevName(appRiskWeigh(p.Severity, st(s.ID)))
			s.HostRisks++
		}
		add(r)
	}
	for _, id := range ids {
		s := svcs[id]
		if s.Role == "app" || s.Role == "other" {
			continue
		}
		s.OSPackage, s.OSVersion = appPackageForService(s.Name, appRole{s.Role, s.RoleLabel, s.RoleRank}, h.Vuln.packages)
	}
	for _, c := range h.Vuln.cveList {
		base := 3
		switch strings.ToLower(c.Severity) {
		case "critical":
			base = 5
		case "high":
			base = 4
		case "low":
			base = 2
		}
		r := appRisk{Kind: "host_cve", Base: sevName(base), Severity: sevName(base), Title: c.CVEID + " in " + c.Package + " " + c.Version,
			Detail: c.Description, Evidence: "NVD by installed version"}
		for _, id := range ids {
			s := svcs[id]
			if s.OSPackage != "" && strings.EqualFold(s.OSPackage, c.Package) || appNameMatches(s.Name, c.Package) {
				r.ServiceID, r.Service, r.ServiceKey = s.ID, s.Name, s.Key
				r.Severity = sevName(appRiskWeigh(base, st(s.ID)))
				s.HostRisks++
				break
			}
		}
		add(r)
	}
	for _, f := range h.Vuln.findings {
		add(appRisk{Kind: "host_finding", Base: sevName(f.Severity), Severity: sevName(f.Severity), Title: f.Title, Detail: f.Detail, Fix: f.Fix, Evidence: "host vulnerability scan"})
	}

	// code: dependency findings whose package version a service here loads
	pkgs, _ := db.RuntimePackagesOnAgents(ctx, []string{agent}, time.Now().Add(-runtimeFresh), 20000)
	h.Inventory = len(pkgs) > 0
	if len(pkgs) > 0 {
		attr := newAppAttributor(insts)
		idx := appCodeIndex(ctx, db)
		seen := map[string]bool{}
		for _, p := range pkgs {
			hits := idx[pkgKey(p.Ecosystem, p.Name, p.Version)]
			if len(hits) == 0 {
				continue
			}
			sid, _ := attr.service(p)
			for _, hit := range hits {
				vuln := strings.TrimPrefix(hit.F.RuleID, "SCA-")
				k := fmt.Sprintf("%d\x00%s\x00%s\x00%s", sid, vuln, p.Name, p.Version)
				if seen[k] {
					continue
				}
				seen[k] = true
				base := sevRankStr(hit.F.Severity)
				if p.Evidence != "loaded" && base > 1 {
					base-- // on disk, not loaded
				}
				r := appRisk{Kind: "code_vuln", Base: hit.F.Severity, Severity: sevName(base),
					Title: fmt.Sprintf("%s in %s %s", vuln, p.Name, p.Version), Detail: hit.F.Title, Fix: hit.F.Fix,
					Repo: hit.Repo, ConnID: hit.ConnID, Evidence: p.Evidence}
				if s := svcs[sid]; s != nil {
					r.ServiceID, r.Service, r.ServiceKey = s.ID, s.Name, s.Key
					r.Linked = linked[fmt.Sprintf("%d\x00%d\x00%s", s.ID, hit.ConnID, hit.Repo)]
					r.Severity = sevName(appRiskWeigh(base, st(s.ID)))
					s.CodeVulns++
				}
				h.CodeVulns++
				if r.Severity == "critical" {
					h.CodeCritical++
				}
				add(r)
			}
		}
	}

	if detail {
		h.ServiceList = make([]appHostService, 0, len(ids))
		for _, id := range ids {
			h.ServiceList = append(h.ServiceList, *svcs[id])
		}
		sort.SliceStable(h.ServiceList, func(i, j int) bool {
			a, b := h.ServiceList[i], h.ServiceList[j]
			if a.Tier != b.Tier {
				return a.Tier > b.Tier
			}
			if a.Tier == 0 && a.RoleRank != b.RoleRank {
				return a.RoleRank < b.RoleRank
			}
			return a.Name < b.Name
		})
		sortRisks(risks)
		if len(risks) > 500 {
			risks = risks[:500]
		}
		h.Risks = risks
		if h.Risks == nil {
			h.Risks = []appRisk{}
		}
	}
	return h
}

// appNameMatches: a package named like the service (nginx ~ nginx, redis ~ redis-server).
func appNameMatches(service, pkg string) bool {
	p := strings.ToLower(pkg)
	for _, v := range appNameVariants(service) {
		if len(v) >= 3 && (p == v || strings.HasPrefix(p, v+"-") || strings.HasPrefix(v, p+"-")) {
			return true
		}
	}
	return false
}

func appAgentsByID(ctx context.Context, db *store.DB) map[string]store.Agent {
	out := map[string]store.Agent{}
	if list, err := db.ListAgents(ctx); err == nil {
		for _, a := range list {
			out[a.ID] = a
		}
	}
	return out
}

// GET /api/v1/app/hosts - hosts with at least one live monitored service.
func appHandleHosts(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		since := time.Now().Add(-24 * time.Hour)
		insts := appLiveInstances(r.Context(), idb, nil, "", since)
		byAgent := map[string][]appLiveInst{}
		var agentsOrder []string
		for _, i := range insts {
			if _, ok := byAgent[i.AgentID]; !ok {
				agentsOrder = append(agentsOrder, i.AgentID)
			}
			byAgent[i.AgentID] = append(byAgent[i.AgentID], i)
		}
		agents := appAgentsByID(r.Context(), db)
		helpers := appHelperServices(r.Context(), idb)
		out := make([]appHostSummary, 0, len(agentsOrder))
		for _, a := range agentsOrder {
			out = append(out, appBuildHost(r.Context(), db, idb, backendDB, a, byAgent[a], agents, helpers, false))
		}
		sort.SliceStable(out, func(i, j int) bool {
			a, b := sevRankStr(out[i].TopSev), sevRankStr(out[j].TopSev)
			if a != b {
				return a > b
			}
			return out[i].Host < out[j].Host
		})
		writeJSON(w, http.StatusOK, map[string]any{"hosts": out})
	}
}

// GET /api/v1/app/hosts/{agent} - one host with its services and risks.
func appHandleHost(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		agent := r.PathValue("agent")
		insts := appLiveInstances(r.Context(), idb, nil, agent, time.Now().Add(-24*time.Hour))
		if len(insts) == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no monitored services on this host in the last 24 hours"})
			return
		}
		h := appBuildHost(r.Context(), db, idb, backendDB, agent, insts, appAgentsByID(r.Context(), db), appHelperServices(r.Context(), idb), true)
		writeJSON(w, http.StatusOK, h)
	}
}

// ── Service code tab ─────────────────────────────────────────────────────────

type appCodeLinkView struct {
	store.ServiceCodeLink
	Provider   string          `json:"provider"`
	Connector  string          `json:"connector"`
	ScanBranch string          `json:"scan_branch,omitempty"`
	ScannedAt  *time.Time      `json:"scanned_at,omitempty"`
	Engines    json.RawMessage `json:"engines,omitempty"`
	Counts     map[string]int  `json:"counts"`
	Dismissed  int             `json:"dismissed"`
	Scanning   bool            `json:"scanning"`
	// What runs: the commits the service's instances report, and which scan the
	// findings come from ("commit": the primary deployed commit; "branch": the
	// linked branch, while no commit is reported or its scan is pending).
	Deployments     []appDeployment `json:"deployments"`
	Showing         string          `json:"showing"`
	ShowingRevision string          `json:"showing_revision,omitempty"`
}

type appCodeFinding struct {
	SASTFinding
	ConnID       int64  `json:"connector_id"`
	ServiceReach string `json:"service_reach,omitempty"` // loaded | deployed | not_in_service | unknown (dependency findings)
	Priority     string `json:"priority"`                // severity after runtime and service weighting
}

// GET /api/v1/app/services/{id}/code
func appHandleServiceCode(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
			return
		}
		var name, env, source string
		var attrs []byte
		if err := idb.QueryRowContext(ctx, `SELECT name, environment, source, attrs FROM services WHERE id = $1`, id).Scan(&name, &env, &source, &attrs); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "service not found"})
			return
		}
		sm := appSettingsByID(ctx, db, []int64{id})
		appApplyExposure(ctx, idb, []int64{id}, sm)
		st, ok := sm[id]
		if !ok {
			st = appDefaultSettings()
		}

		// what this service's processes run
		since := time.Now().Add(-runtimeFresh)
		insts := appLiveInstances(ctx, idb, []int64{id}, "", since)
		agentSet := map[string]bool{}
		for _, i := range insts {
			agentSet[i.AgentID] = true
		}
		agentList := make([]string, 0, len(agentSet))
		for a := range agentSet {
			agentList = append(agentList, a)
		}
		// attribute against every live instance on those agents so a package
		// in another service's process is not counted here
		var all []appLiveInst
		for _, a := range agentList {
			all = append(all, appLiveInstances(ctx, idb, nil, a, since)...)
		}
		attr := newAppAttributor(all)
		pkgs, _ := db.RuntimePackagesOnAgents(ctx, agentList, since, 50000)
		mine := map[string]string{} // pkg key -> loaded | deployed
		agentsWithInv := map[string]bool{}
		for _, p := range pkgs {
			agentsWithInv[p.AgentID] = true
			if sid, ok := attr.service(p); ok && sid == id {
				k := pkgKey(p.Ecosystem, p.Name, p.Version)
				if p.Evidence == "loaded" || mine[k] == "" {
					mine[k] = p.Evidence
				}
			}
		}
		inventory := len(mine) > 0
		coverage := "none"
		switch {
		case inventory:
			coverage = "reported"
		case len(insts) == 0:
			coverage = "not_running"
		case len(agentsWithInv) > 0:
			coverage = "no_packages" // host reports inventory, nothing attributed to this service
		}

		reach := func(f SASTFinding) string {
			if f.Package == "" || f.Version == "" {
				return ""
			}
			if v := mine[pkgKey(f.Ecosystem, f.Package, f.Version)]; v != "" {
				return v
			}
			if !inventory {
				return "unknown"
			}
			return "not_in_service"
		}
		priority := func(f SASTFinding, rr string) string {
			base := sevRankStr(f.Severity)
			if base == 0 {
				base = 2
			}
			switch rr {
			case "loaded":
				return sevName(appRiskWeigh(base, st))
			case "not_in_service":
				if base > 1 {
					base--
				}
				return sevName(base)
			}
			return sevName(base)
		}

		links, _ := db.ServiceCodeLinks(ctx, []int64{id})
		conns := map[int64]store.DevOpsConnector{}
		if list, err := db.ListDevOpsConnectors(ctx); err == nil {
			for _, c := range list {
				conns[c.ID] = c
			}
		}
		deps := appDeployments(insts)
		views := []appCodeLinkView{}
		findings := []appCodeFinding{}
		linkedRepo := map[string]bool{}
		for _, l := range links {
			linkedRepo[fmt.Sprintf("%d\x00%s", l.ConnectorID, l.Repo)] = true
			v := appCodeLinkView{ServiceCodeLink: l, Counts: map[string]int{}}
			if c, ok := conns[l.ConnectorID]; ok {
				v.Provider, v.Connector = c.Provider, c.Label
				if v.Connector == "" {
					v.Connector = c.Org
				}
			}
			var pending int
			_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM code_scan_jobs WHERE connector_id=$1 AND repo=$2 AND status IN ('queued','running')`,
				l.ConnectorID, l.Repo).Scan(&pending)
			v.Scanning = pending > 0
			v.Deployments = appResolveDeployments(ctx, db, l, deps)
			fs, br, at, eng, ok := appLinkedScan(ctx, db, l)
			v.Showing = "branch"
			for _, d := range v.Deployments {
				if d.Primary && d.Scan.Status == "scanned" {
					fs, at, br, ok = d.findings, *d.Scan.ScannedAt, "@"+d.Revision, true
					v.Showing, v.ShowingRevision = "commit", d.Revision
				}
			}
			if ok {
				t := at
				v.ScannedAt, v.ScanBranch, v.Engines = &t, br, eng
				for _, f := range fs {
					if findingDismissed(f) {
						v.Dismissed++
						continue
					}
					v.Counts[f.Severity]++
					rr := reach(f)
					findings = append(findings, appCodeFinding{SASTFinding: f, ConnID: l.ConnectorID, ServiceReach: rr, Priority: priority(f, rr)})
				}
			}
			views = append(views, v)
		}
		reachOrder := map[string]int{"loaded": 0, "deployed": 1, "": 2, "unknown": 3, "not_in_service": 4}
		sort.SliceStable(findings, func(i, j int) bool {
			a, b := sevRankStr(findings[i].Priority), sevRankStr(findings[j].Priority)
			if a != b {
				return a > b
			}
			return reachOrder[findings[i].ServiceReach] < reachOrder[findings[j].ServiceReach]
		})
		if len(findings) > 2000 {
			findings = findings[:2000]
		}

		// vulnerable packages this service loads from repositories not linked to it
		type unlinked struct {
			Repo     string `json:"repo"`
			ConnID   int64  `json:"connector_id"`
			Vuln     string `json:"vuln"`
			Package  string `json:"package"`
			Version  string `json:"version"`
			Severity string `json:"severity"`
			Evidence string `json:"evidence"`
		}
		others := []unlinked{}
		if inventory {
			idx := appCodeIndex(ctx, db)
			seen := map[string]bool{}
			for k, ev := range mine {
				for _, h := range idx[k] {
					if linkedRepo[fmt.Sprintf("%d\x00%s", h.ConnID, h.Repo)] {
						continue
					}
					v := strings.TrimPrefix(h.F.RuleID, "SCA-")
					sk := h.Repo + v + k
					if seen[sk] {
						continue
					}
					seen[sk] = true
					others = append(others, unlinked{h.Repo, h.ConnID, v, h.F.Package, h.F.Version, h.F.Severity, ev})
				}
			}
			sort.SliceStable(others, func(i, j int) bool { return sevRankStr(others[i].Severity) > sevRankStr(others[j].Severity) })
			if len(others) > 100 {
				others = others[:100]
			}
		}

		// platform: the host's view of this service (OS package, port findings, CVEs)
		type platform struct {
			Host      string        `json:"host"`
			AgentID   string        `json:"agent_id"`
			Package   string        `json:"os_package,omitempty"`
			Version   string        `json:"os_package_version,omitempty"`
			Ports     []appPortRisk `json:"port_risks"`
			CVEs      []HostCVE     `json:"cves"`
			ScannedAt *time.Time    `json:"scanned_at,omitempty"`
		}
		plats := []platform{}
		role := appServiceRole(name, attrs, nil, appTier(source))
		hostSeen := map[string]bool{}
		for _, i := range insts {
			if hostSeen[i.AgentID] || len(plats) >= 10 {
				continue
			}
			hostSeen[i.AgentID] = true
			hv := appHostVuln(ctx, db, backendDB, i.Host)
			p := platform{Host: i.Host, AgentID: i.AgentID, Ports: []appPortRisk{}, CVEs: []HostCVE{}, ScannedAt: hv.ScannedAt}
			if role.Role != "app" && role.Role != "other" {
				p.Package, p.Version = appPackageForService(name, role, hv.packages)
			}
			ports := map[int]bool{}
			for _, x := range insts {
				if x.AgentID == i.AgentID {
					for _, pt := range x.Ports {
						ports[pt] = true
					}
				}
			}
			for _, pr := range hv.portRisks {
				if ports[pr.Port] {
					p.Ports = append(p.Ports, pr)
				}
			}
			for _, c := range hv.cveList {
				if (p.Package != "" && strings.EqualFold(p.Package, c.Package)) || appNameMatches(name, c.Package) {
					p.CVEs = append(p.CVEs, c)
				}
			}
			plats = append(plats, p)
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"links": views, "findings": findings, "unlinked_running": others, "platform": plats,
			"inventory": coverage, "instances": len(insts),
			"weighting": map[string]string{"exposure": st.Exposure, "exposure_effective": st.ExposureEffective, "criticality": st.Criticality},
		})
	}
}

// POST /api/v1/app/services/{id}/code-links {connector_id, repo, branch, is_default}
func appHandleAddCodeLink(db, backendDB *store.DB) http.HandlerFunc {
	idb := appIngestDB(db, backendDB)
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
			return
		}
		var n int
		if idb.QueryRowContext(ctx, `SELECT 1 FROM services WHERE id = $1`, id).Scan(&n) != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "service not found"})
			return
		}
		var body struct {
			ConnectorID int64  `json:"connector_id"`
			Repo        string `json:"repo"`
			Branch      string `json:"branch"`
			IsDefault   *bool  `json:"is_default"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		body.Repo, body.Branch = strings.TrimSpace(body.Repo), strings.TrimSpace(body.Branch)
		if body.ConnectorID == 0 || body.Repo == "" || len(body.Repo) > 300 || len(body.Branch) > 255 || strings.ContainsAny(body.Branch, " \t\n~^:?*[\\") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "connector_id and repo are required; branch must be a valid branch name"})
			return
		}
		if _, err := db.GetDevOpsConnectorRaw(ctx, body.ConnectorID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "connector not found"})
			return
		}
		isDef := body.Branch == "" || body.Branch == "HEAD"
		if body.IsDefault != nil {
			isDef = *body.IsDefault || isDef
		}
		if body.Branch == "HEAD" {
			body.Branch = ""
		}
		by := ""
		if c := auth.GetClaims(r); c != nil {
			by = c.Username
		}
		link := store.ServiceCodeLink{ServiceID: id, ConnectorID: body.ConnectorID, Repo: body.Repo, Branch: body.Branch, IsDefault: isDef, CreatedBy: by}
		lid, err := db.UpsertServiceCodeLink(ctx, link)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "save failed"})
			return
		}
		link.ID = lid
		appInvalidateCodeIndex()
		// Deployed commits are scanned exactly; the branch scan below covers
		// services that report no commit.
		deployedQueued := NewDeployedCommitWatcher(db, backendDB, nil).sweep(ctx, []int64{id})
		// Scan the branch now when there is no result for it yet.
		queued := false
		if _, _, _, _, ok := appLinkedScan(ctx, db, link); !ok {
			ref := body.Branch
			if isDef {
				ref = "HEAD"
			}
			enqueueCodeJob(ctx, db, store.CodeScanJob{ConnectorID: body.ConnectorID, Kind: "branch", Trigger: "service-link",
				Repo: body.Repo, Ref: ref, HeadSHA: "link:" + time.Now().UTC().Format(time.RFC3339)}, nil)
			queued = true
		}
		writeJSON(w, http.StatusOK, map[string]any{"link": link, "scan_queued": queued, "commit_scans_queued": deployedQueued})
	}
}

// DELETE /api/v1/app/services/{id}/code-links/{link}
func appHandleDeleteCodeLink(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err1 := strconv.ParseInt(r.PathValue("id"), 10, 64)
		lid, err2 := strconv.ParseInt(r.PathValue("link"), 10, 64)
		if err1 != nil || err2 != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
			return
		}
		ok, err := db.DeleteServiceCodeLink(r.Context(), id, lid)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "delete failed"})
			return
		}
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "link not found"})
			return
		}
		appInvalidateCodeIndex()
		writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
	}
}
