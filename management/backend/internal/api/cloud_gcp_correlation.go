package api

// cloud_gcp_correlation.go — Stateful multi-event correlation engine for GCP.
//
// Single-event rules miss attack sequences. This engine maintains sliding-window
// state keyed by (project, principal) and fires when a sequence of related
// events matches a known attack pattern.
//
// Patterns implemented:
//   CORR-GCP-001  SA key created then used from new IP within 10 min
//   CORR-GCP-002  3+ admin role grants within 1 hour (privilege creep)
//   CORR-GCP-003  Recon burst: 5+ list/describe calls within 2 min
//   CORR-GCP-004  Audit log disabled then sensitive operation within 15 min
//   CORR-GCP-005  SA key created then immediately used for API calls
//   CORR-GCP-006  New IP for principal, followed by IAM change within 5 min
//   CORR-GCP-007  Mass resource deletion sequence (3+ deletes in 5 min)
//   CORR-GCP-008  Role assumption chain: impersonation used for high-priv op

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/store"
)

// ── State types ───────────────────────────────────────────────────────────────

type corrEvent struct {
	Time      time.Time
	Method    string
	SrcIP     string
	Principal string
	Raw       string
}

type principalState struct {
	mu              sync.Mutex
	recentEvents    []corrEvent
	seenIDs         map[string]struct{} // G-27: per-event dedup (bounded)
	keyCreatedAt    *time.Time
	keyCreatedIP    string
	logDisabledAt   *time.Time
	knownIPs        map[string]time.Time // ip → first seen
	adminGrantCount int
	adminGrantStart *time.Time
	deleteCount     int
	deleteStart     *time.Time
	// CORR-GCP-009: Cloud Run deployed → invoked from new IP
	runDeployedAt  *time.Time
	runServiceName string
	// CORR-GCP-010: Secret accessed → GCS write → new IP
	secretAccessAt *time.Time
	gcsWriteAt     *time.Time
	// CORR-GCP-011: Org policy deleted → IAM change
	orgPolicyDeletedAt *time.Time
}

// GCPCorrelationEngine holds per-(project,principal) state and detects sequences.
type GCPCorrelationEngine struct {
	mu     sync.Mutex
	states map[string]*principalState // key: "project:principal"
	db     *store.DB
	logger *slog.Logger
}

func NewGCPCorrelationEngine(db *store.DB, logger *slog.Logger) *GCPCorrelationEngine {
	e := &GCPCorrelationEngine{
		states: make(map[string]*principalState),
		db:     db,
		logger: logger,
	}
	return e
}

func (e *GCPCorrelationEngine) Run(ctx context.Context) {
	// G-02: cursor-based paging over events.ingested_at (see pageEventCursor)
	// instead of a 2-5 minute wall-clock window — GCP audit events can land
	// in the DB 5+ minutes after they occurred (poll interval + log latency),
	// which made the old windowed query silently skip most events.
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	// Initial run
	e.runCursor(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.runCursor(ctx)
		}
	}
}

func (e *GCPCorrelationEngine) runCursor(ctx context.Context) {
	events, err := pageEventCursor(ctx, e.db, "cloud-gcp-correlation", store.EventFilter{
		EventType: "cloud.gcp_audit",
	}, 5*time.Minute, 2000)
	if err != nil {
		e.logger.Warn("gcp correlation: cursor query failed", "err", err)
		return
	}
	for _, ev := range events {
		e.ingest(ctx, ev)
	}
	// Prune stale state (principals idle > 2 hours)
	e.prune()
}

func (e *GCPCorrelationEngine) getState(key string) *principalState {
	e.mu.Lock()
	defer e.mu.Unlock()
	if s, ok := e.states[key]; ok {
		return s
	}
	s := &principalState{knownIPs: make(map[string]time.Time)}
	e.states[key] = s
	return s
}

func (e *GCPCorrelationEngine) prune() {
	e.mu.Lock()
	defer e.mu.Unlock()
	cutoff := time.Now().Add(-2 * time.Hour)
	for k, s := range e.states {
		s.mu.Lock()
		idle := len(s.recentEvents) == 0 ||
			s.recentEvents[len(s.recentEvents)-1].Time.Before(cutoff)
		s.mu.Unlock()
		if idle {
			delete(e.states, k)
		}
	}
}

func (e *GCPCorrelationEngine) ingest(ctx context.Context, ev store.Event) {
	// Extract fields from raw GCP audit event
	var raw struct {
		MethodName string `json:"method_name"`
		ConnID     int64  `json:"connector_id"`
	}
	var project string
	if ev.Raw != nil {
		json.Unmarshal(ev.Raw, &raw)
		// Host is project_id for GCP events
		project = ev.Host
	}
	if project == "" {
		return
	}

	principal := ""
	if ev.UserName != nil {
		principal = *ev.UserName
	}
	if principal == "" {
		return
	}

	srcIP := ""
	if ev.SrcIP != nil {
		srcIP = *ev.SrcIP
	}

	method := strings.ToLower(raw.MethodName)
	rawStr := ""
	if ev.Raw != nil {
		rawStr = strings.ToLower(string(ev.Raw))
	}

	key := project + ":" + principal
	s := e.getState(key)
	s.mu.Lock()
	defer s.mu.Unlock()

	// G-27: never count the same audit event twice (re-reads of overlapping
	// windows used to make one event satisfy "3+ grants" / "3+ deletes").
	if s.seenIDs == nil {
		s.seenIDs = make(map[string]struct{})
	}
	if ev.ID != "" {
		if _, dup := s.seenIDs[ev.ID]; dup {
			return
		}
		if len(s.seenIDs) >= 5000 {
			s.seenIDs = make(map[string]struct{})
		}
		s.seenIDs[ev.ID] = struct{}{}
	}

	ce := corrEvent{
		Time: ev.Time, Method: method,
		SrcIP: srcIP, Principal: principal, Raw: rawStr,
	}

	// Sliding window: keep last 30 minutes of events
	cutoff := ev.Time.Add(-30 * time.Minute)
	filtered := s.recentEvents[:0]
	for _, old := range s.recentEvents {
		if old.Time.After(cutoff) {
			filtered = append(filtered, old)
		}
	}
	s.recentEvents = append(filtered, ce)

	// ── CORR-GCP-001: SA key created then used from new IP ────────────────────
	if containsAny(method, "createserviceaccountkey", "iam.serviceaccounts.createkey") {
		t := ev.Time
		s.keyCreatedAt = &t
		s.keyCreatedIP = srcIP
	}
	if s.keyCreatedAt != nil && ev.Time.Sub(*s.keyCreatedAt) <= 10*time.Minute {
		if srcIP != "" && srcIP != s.keyCreatedIP &&
			!containsAny(method, "createserviceaccountkey", "list", "get") {
			e.fireAlert(ctx, "CORR-GCP-001",
				"[CORR] SA Key Created then Used from New IP",
				fmt.Sprintf("Service account key was created at %s from %s, then API call '%s' made from different IP %s within 10 minutes. Indicates possible key theft and immediate use.",
					s.keyCreatedAt.Format(time.RFC3339), s.keyCreatedIP, raw.MethodName, srcIP),
				5, "T1552.004", "Credential Access", ev)
			s.keyCreatedAt = nil // reset after firing
		}
	}

	// ── CORR-GCP-002: 3+ admin role grants in 1 hour ─────────────────────────
	if containsAny(rawStr, "setiampolicy") && containsAny(rawStr,
		"roles/owner", "roles/editor", "roles/iam.", "roles/resourcemanager.",
		"roles/compute.admin", "roles/storage.admin") {
		now := ev.Time
		if s.adminGrantStart == nil || ev.Time.Sub(*s.adminGrantStart) > time.Hour {
			s.adminGrantStart = &now
			s.adminGrantCount = 1
		} else {
			s.adminGrantCount++
		}
		if s.adminGrantCount >= 3 {
			e.fireAlert(ctx, "CORR-GCP-002",
				"[CORR] Rapid Admin Role Grant Sequence",
				fmt.Sprintf("Principal %s has granted admin-level IAM roles %d times within 1 hour on project %s. This pattern indicates privilege creep, insider threat, or compromised account performing persistence.",
					principal, s.adminGrantCount, project),
				5, "T1098.003", "Privilege Escalation", ev)
			s.adminGrantCount = 0
			s.adminGrantStart = nil
		}
	}

	// ── CORR-GCP-003: Recon burst — 5+ list/describe in 2 min ───────────────
	// G-28: matched on the final methodName segment's verb, not as a
	// substring of the whole name ("get" used to match "target", "budget").
	if isGCPReconMethod(method) {
		window := ev.Time.Add(-2 * time.Minute)
		reconCount := 0
		for _, past := range s.recentEvents {
			if past.Time.After(window) && isGCPReconMethod(past.Method) {
				reconCount++
			}
		}
		if reconCount >= 5 {
			e.fireAlert(ctx, "CORR-GCP-003",
				"[CORR] GCP Reconnaissance Burst Detected",
				fmt.Sprintf("Principal %s made %d list/describe API calls within 2 minutes on project %s — consistent with automated enumeration (ScoutSuite, Prowler, custom scripts).",
					principal, reconCount, project),
				4, "T1526", "Discovery", ev)
		}
	}

	// ── CORR-GCP-004: Audit log disabled then sensitive op within 15 min ─────
	if containsAny(method, "logging.sinks.delete", "deletesink",
		"logging.exclusions.create", "updateauditconfig") {
		t := ev.Time
		s.logDisabledAt = &t
	}
	if s.logDisabledAt != nil && ev.Time.Sub(*s.logDisabledAt) <= 15*time.Minute {
		if containsAny(method, "setiampolicy", "createserviceaccountkey",
			"deleteproject", "storage.setiampermissions", "bigquery.datasets.delete") {
			e.fireAlert(ctx, "CORR-GCP-004",
				"[CORR] Sensitive Operation After Audit Log Disabled",
				fmt.Sprintf("Principal %s disabled audit logging at %s, then performed sensitive operation '%s' within 15 minutes. Classic cover-tracks-then-attack pattern.",
					principal, s.logDisabledAt.Format(time.RFC3339), raw.MethodName),
				5, "T1562.008", "Defense Evasion", ev)
			s.logDisabledAt = nil
		}
	}

	// ── CORR-GCP-006: New source IP then IAM change within 5 min ─────────────
	if srcIP != "" {
		_, seen := s.knownIPs[srcIP]
		if !seen {
			s.knownIPs[srcIP] = ev.Time
			// Check if within 5 min they do an IAM change
		}
		// Check if this is an IAM change and the IP was first seen < 5 min ago
		if containsAny(method, "setiampolicy", "createserviceaccountkey",
			"setiam", "addrolebinding") {
			if firstSeen, ok := s.knownIPs[srcIP]; ok {
				if ev.Time.Sub(firstSeen) <= 5*time.Minute && firstSeen.After(ev.Time.Add(-5*time.Minute)) {
					e.fireAlert(ctx, "CORR-GCP-006",
						"[CORR] First-Seen IP Performing IAM Change",
						fmt.Sprintf("Principal %s called '%s' from IP %s which was first observed %.1f minutes ago on project %s. New IP performing IAM changes is a strong indicator of compromised credentials.",
							principal, raw.MethodName, srcIP,
							ev.Time.Sub(firstSeen).Minutes(), project),
						4, "T1078.004", "Initial Access", ev)
				}
			}
		}
	}

	// ── CORR-GCP-007: Mass deletion sequence (3+ deletes in 5 min) ───────────
	if containsAny(method, "delete") &&
		containsAny(method, "instance", "bucket", "database", "dataset",
			"cluster", "function", "secret", "key", "table", "sql") {
		now := ev.Time
		if s.deleteStart == nil || ev.Time.Sub(*s.deleteStart) > 5*time.Minute {
			s.deleteStart = &now
			s.deleteCount = 1
		} else {
			s.deleteCount++
		}
		if s.deleteCount >= 3 {
			e.fireAlert(ctx, "CORR-GCP-007",
				"[CORR] Mass Resource Deletion Sequence",
				fmt.Sprintf("Principal %s has deleted %d resources within 5 minutes on project %s. This pattern is consistent with ransomware, insider sabotage, or account takeover.",
					principal, s.deleteCount, project),
				5, "T1485", "Impact", ev)
			s.deleteCount = 0
			s.deleteStart = nil
		}
	}

	// ── CORR-GCP-008: SA impersonation then high-priv op ─────────────────────
	if containsAny(method, "generateaccesstoken", "signjwt", "signblob") {
		now := ev.Time
		_ = now // tracked via recentEvents already
	}
	if containsAny(method, "setiampolicy", "deleteproject", "createserviceaccountkey",
		"storage.setiampermissions") {
		window := ev.Time.Add(-5 * time.Minute)
		for _, past := range s.recentEvents {
			if past.Time.After(window) &&
				containsAny(past.Method, "generateaccesstoken", "signjwt", "signblob") {
				e.fireAlert(ctx, "CORR-GCP-008",
					"[CORR] SA Impersonation Followed by High-Privilege Operation",
					fmt.Sprintf("Principal %s impersonated a service account via '%s' at %s, then performed high-privilege operation '%s' within 5 minutes. Indicates privilege escalation via SA chaining.",
						principal, past.Method, past.Time.Format(time.RFC3339), raw.MethodName),
					5, "T1548.005", "Privilege Escalation", ev)
				break
			}
		}
	}

	// ── CORR-GCP-009: Cloud Run deployed → invoked from new IP within 5 min ──
	if containsAny(method, "run.services.create", "run.services.replaceservice",
		"google.cloud.run.v2.services.createservice", "google.cloud.run.v2.services.updateservice") {
		t := ev.Time
		s.runDeployedAt = &t
		// Extract service name from rawStr if possible
		if strings.Contains(rawStr, "\"serviceName\"") || strings.Contains(rawStr, "services/") {
			s.runServiceName = "cloud-run-service"
		}
	}
	if s.runDeployedAt != nil && ev.Time.Sub(*s.runDeployedAt) <= 5*time.Minute {
		if containsAny(method, "run.routes.invoke", "google.cloud.run",
			"run.googleapis.com") && !containsAny(method, "create", "update", "delete", "list", "get") {
			if srcIP != "" {
				if _, seen := s.knownIPs[srcIP]; !seen {
					e.fireAlert(ctx, "CORR-GCP-009",
						"[CORR] Cloud Run Deployed Then Immediately Invoked from New IP",
						fmt.Sprintf("Principal %s deployed a Cloud Run service at %s, then it was invoked from new IP %s within 5 minutes. Rapid deploy-and-invoke from an unseen IP indicates a backdoor endpoint being tested immediately after deployment.",
							principal, s.runDeployedAt.Format(time.RFC3339), srcIP),
						5, "T1190", "Initial Access", ev)
					s.runDeployedAt = nil
				}
			}
		}
	}

	// ── CORR-GCP-010: Secret access → GCS write → new external IP ────────────
	if containsAny(method, "secretmanager.versions.access", "accesssecretversion") {
		t := ev.Time
		s.secretAccessAt = &t
	}
	if s.secretAccessAt != nil && ev.Time.Sub(*s.secretAccessAt) <= 15*time.Minute {
		if containsAny(method, "storage.objects.create", "storage.objects.insert",
			"google.storage.objects.insert") {
			t := ev.Time
			s.gcsWriteAt = &t
		}
	}
	if s.secretAccessAt != nil && s.gcsWriteAt != nil &&
		s.gcsWriteAt.After(*s.secretAccessAt) &&
		ev.Time.Sub(*s.secretAccessAt) <= 15*time.Minute {
		if srcIP != "" {
			if _, seenBefore := s.knownIPs[srcIP]; !seenBefore {
				e.fireAlert(ctx, "CORR-GCP-010",
					"[CORR] Credential Exfiltration Chain: Secret → GCS Write → New IP",
					fmt.Sprintf("Principal %s accessed Secret Manager at %s, wrote to GCS at %s, then made API call from new IP %s. This three-stage sequence matches a credential harvest-stage-exfil pattern.",
						principal, s.secretAccessAt.Format(time.RFC3339),
						s.gcsWriteAt.Format(time.RFC3339), srcIP),
					5, "T1552.001", "Credential Access", ev)
				s.secretAccessAt = nil
				s.gcsWriteAt = nil
			}
		}
	}

	// ── CORR-GCP-011: Org policy deleted → IAM change within 10 min ──────────
	if containsAny(method, "setorgpolicy", "orgpolicies.delete",
		"cloudresourcemanager.projects.setorgpolicy") &&
		containsAny(rawStr, "restoredefault", "delete", "disable", "inherit") {
		t := ev.Time
		s.orgPolicyDeletedAt = &t
	}
	if s.orgPolicyDeletedAt != nil && ev.Time.Sub(*s.orgPolicyDeletedAt) <= 10*time.Minute {
		if containsAny(method, "setiampolicy", "createserviceaccountkey",
			"uploadserviceaccountkey", "setiam") {
			e.fireAlert(ctx, "CORR-GCP-011",
				"[CORR] Org Policy Guardrail Removed Then IAM Change",
				fmt.Sprintf("Principal %s deleted/disabled an org policy constraint at %s, then performed IAM operation '%s' within 10 minutes. The policy deletion was likely specifically to unblock this IAM change — a deliberate guardrail bypass.",
					principal, s.orgPolicyDeletedAt.Format(time.RFC3339), raw.MethodName),
				5, "T1562.001", "Defense Evasion", ev)
			s.orgPolicyDeletedAt = nil
		}
	}
}

func (e *GCPCorrelationEngine) fireAlert(ctx context.Context, corrID, title, desc string,
	sev int, mitre, category string, ev store.Event) {
	// Dedup per hour per correlation rule per principal
	hour := ev.Time.UTC().Format("2006010215")
	principal := ""
	if ev.UserName != nil {
		principal = *ev.UserName
	}
	dedupKey := fmt.Sprintf("corr:%s:host:%s:principal:%s:h:%s",
		corrID, ev.Host, principal, hour)

	full := fmt.Sprintf("%s\n\nMITRE ATT&CK: %s | Category: %s\nProject: %s | Principal: %s | Source IP: %s",
		desc, mitre, category, ev.Host, principal, func() string {
			if ev.SrcIP != nil {
				return *ev.SrcIP
			}
			return "-"
		}())

	alert := store.Alert{
		Title:         fmt.Sprintf("[%s] %s", mitre, title),
		Description:   full,
		Severity:      sev,
		AgentID:       ev.AgentID,
		Host:          ev.Host,
		EventType:     "cloud.gcp_correlation",
		EventID:       dedupKey,
		SourceEventID: ev.ID,
	}
	if _, inserted, err := e.db.CreateAlertDeduped(ctx, alert); err == nil && inserted {
		e.logger.Info("correlation alert fired", "rule", corrID, "principal", principal, "host", ev.Host)
	}
}

// isGCPReconMethod reports whether a methodName's final segment is a
// list/get/describe style enumeration call.
func isGCPReconMethod(method string) bool {
	m := strings.ToLower(method)
	if i := strings.LastIndex(m, "."); i >= 0 {
		m = m[i+1:]
	}
	for _, p := range []string{"list", "get", "describe", "aggregatedlist", "search", "query"} {
		if strings.HasPrefix(m, p) {
			return true
		}
	}
	return false
}
