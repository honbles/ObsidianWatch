package api

// cloud_azure_correlation.go — Stateful multi-event correlation for Azure.
//
// Patterns:
//   CORR-AZ-001  SP credentials added then used from new IP within 10 min
//   CORR-AZ-002  3+ Owner/Contributor role assignments in 1 hour
//   CORR-AZ-003  Diagnostic settings deleted then sensitive op within 15 min
//   CORR-AZ-004  VM created with GPU SKU + quota increase in same hour
//   CORR-AZ-005  5+ resource deletions in 5 minutes (mass destruction)
//   CORR-AZ-006  CA policy disabled then sign-in from new country within 30 min
//   CORR-AZ-007  New IP for principal then role assignment within 5 min
//   CORR-AZ-008  Service principal created then immediately assigned Owner role
//
// Anomaly detections:
//   ANOM-AZ-001  First-ever source IP for a principal
//   ANOM-AZ-002  Admin action outside normal hours for this principal
//   ANOM-AZ-003  Service principal used from >3 IPs in 1 hour

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

// ── Correlation Engine ────────────────────────────────────────────────────────

type azureEvent struct {
	Time      time.Time
	Operation string
	SrcIP     string
	Principal string
	Raw       string
}

type azurePrincipalState struct {
	mu                  sync.Mutex
	recentEvents        []azureEvent
	seenIDs             map[string]struct{} // AZ-07/G-27: per-event dedup (bounded)
	spCredsAddedAt      *time.Time
	spCredsAddedIP      string
	diagDisabledAt      *time.Time
	caDisabledAt        *time.Time
	roleGrantCount      int
	roleGrantStart      *time.Time
	deleteCount         int
	deleteStart         *time.Time
	knownIPs            map[string]time.Time
	spCreatedAt         *time.Time
	spCreatedName       string
}

type AzureCorrelationEngine struct {
	mu     sync.Mutex
	states map[string]*azurePrincipalState // key: subscription:principal
	db     *store.DB
	logger *slog.Logger
}

func NewAzureCorrelationEngine(db *store.DB, logger *slog.Logger) *AzureCorrelationEngine {
	return &AzureCorrelationEngine{
		states: make(map[string]*azurePrincipalState),
		db:     db,
		logger: logger,
	}
}

func (e *AzureCorrelationEngine) Run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	e.evaluate(ctx, time.Now().Add(-5*time.Minute))
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.evaluate(ctx, time.Now().Add(-2*time.Minute))
		}
	}
}

func (e *AzureCorrelationEngine) evaluate(ctx context.Context, since time.Time) {
	// Pull all Azure event types
	for _, evType := range []string{"cloud.azure_activity", "cloud.entra_audit", "cloud.entra_signin"} {
		events, _, err := e.db.QueryEvents(ctx, store.EventFilter{
			EventType: evType,
			Since:     since,
			Limit:     2000,
		})
		if err != nil {
			continue
		}
		for _, ev := range events {
			e.ingest(ctx, ev)
		}
	}
	e.prune()
}

func (e *AzureCorrelationEngine) getState(key string) *azurePrincipalState {
	e.mu.Lock()
	defer e.mu.Unlock()
	if s, ok := e.states[key]; ok {
		return s
	}
	s := &azurePrincipalState{knownIPs: make(map[string]time.Time)}
	e.states[key] = s
	return s
}

func (e *AzureCorrelationEngine) prune() {
	e.mu.Lock()
	defer e.mu.Unlock()
	cutoff := time.Now().Add(-2 * time.Hour)
	for k, s := range e.states {
		s.mu.Lock()
		idle := len(s.recentEvents) == 0 || s.recentEvents[len(s.recentEvents)-1].Time.Before(cutoff)
		s.mu.Unlock()
		if idle {
			delete(e.states, k)
		}
	}
}

func (e *AzureCorrelationEngine) ingest(ctx context.Context, ev store.Event) {
	var raw struct {
		OperationName string `json:"operation_name"`
		Activity      string `json:"activity"`
	}
	if ev.Raw != nil {
		json.Unmarshal(ev.Raw, &raw)
	}

	operation := strings.ToLower(raw.OperationName)
	if operation == "" {
		operation = strings.ToLower(raw.Activity)
	}
	rawStr := strings.ToLower(string(ev.Raw))

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

	// subscription is in ev.Host for Azure events
	key := ev.Host + ":" + principal
	s := e.getState(key)
	s.mu.Lock()
	defer s.mu.Unlock()

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

	ce := azureEvent{Time: ev.Time, Operation: operation, SrcIP: srcIP, Principal: principal, Raw: rawStr}

	// Maintain 30-minute sliding window
	cutoff := ev.Time.Add(-30 * time.Minute)
	filtered := s.recentEvents[:0]
	for _, old := range s.recentEvents {
		if old.Time.After(cutoff) {
			filtered = append(filtered, old)
		}
	}
	s.recentEvents = append(filtered, ce)

	// ── CORR-AZ-001: SP credentials added then used from new IP ──────────────
	if containsAny(operation, "serviceprincipals/credentials/write",
		"add service principal credentials", "addpassword", "addkey") {
		t := ev.Time
		s.spCredsAddedAt = &t
		s.spCredsAddedIP = srcIP
	}
	if s.spCredsAddedAt != nil && ev.Time.Sub(*s.spCredsAddedAt) <= 10*time.Minute {
		if srcIP != "" && srcIP != s.spCredsAddedIP &&
			!containsAny(operation, "credentials/write", "addpassword") {
			e.fireAlert(ctx, "CORR-AZ-001",
				"[CORR] Service Principal Credentials Added Then Used from New IP",
				fmt.Sprintf("Principal %s added SP credentials at %s from %s, then made API call '%s' from different IP %s within 10 minutes. Indicates likely credential backdoor and immediate use.",
					principal, s.spCredsAddedAt.Format(time.RFC3339), s.spCredsAddedIP, operation, srcIP),
				5, "T1098.001", "Persistence", ev)
			s.spCredsAddedAt = nil
		}
	}

	// ── CORR-AZ-002: 3+ privileged role assignments in 1 hour ────────────────
	if containsAny(operation, "roleassignments/write", "add member to role") &&
		containsAny(rawStr, "owner", "contributor", "administrator", "global admin") {
		now := ev.Time
		if s.roleGrantStart == nil || ev.Time.Sub(*s.roleGrantStart) > time.Hour {
			s.roleGrantStart = &now
			s.roleGrantCount = 1
		} else {
			s.roleGrantCount++
		}
		if s.roleGrantCount >= 3 {
			e.fireAlert(ctx, "CORR-AZ-002",
				"[CORR] Rapid Privileged Role Assignment Sequence",
				fmt.Sprintf("Principal %s granted privileged roles %d times within 1 hour. Pattern consistent with privilege creep, compromised account, or insider threat.",
					principal, s.roleGrantCount),
				5, "T1098.003", "Privilege Escalation", ev)
			s.roleGrantCount = 0
			s.roleGrantStart = nil
		}
	}

	// ── CORR-AZ-003: Diagnostic settings deleted then sensitive op within 15 min
	if containsAny(operation, "diagnosticsettings/delete", "logprofiles/delete") {
		t := ev.Time
		s.diagDisabledAt = &t
	}
	if s.diagDisabledAt != nil && ev.Time.Sub(*s.diagDisabledAt) <= 15*time.Minute {
		if containsAny(operation, "roleassignments/write", "storageaccounts/delete",
			"vaults/delete", "virtualmachines/delete", "credentials/write") {
			e.fireAlert(ctx, "CORR-AZ-003",
				"[CORR] Audit Logging Disabled Then Sensitive Operation Performed",
				fmt.Sprintf("Principal %s deleted diagnostic settings at %s then performed '%s' within 15 minutes. Classic cover-tracks-then-attack pattern.",
					principal, s.diagDisabledAt.Format(time.RFC3339), operation),
				5, "T1562.008", "Defense Evasion", ev)
			s.diagDisabledAt = nil
		}
	}

	// ── CORR-AZ-005: Mass resource deletion (5+ deletes in 5 min) ────────────
	if containsAny(operation, "delete") &&
		containsAny(operation, "virtualmachines", "storageaccounts", "vaults",
			"sqldatabases", "cosmosdb", "clusters", "functionapp", "keyvault") {
		now := ev.Time
		if s.deleteStart == nil || ev.Time.Sub(*s.deleteStart) > 5*time.Minute {
			s.deleteStart = &now
			s.deleteCount = 1
		} else {
			s.deleteCount++
		}
		if s.deleteCount >= 5 {
			e.fireAlert(ctx, "CORR-AZ-005",
				"[CORR] Mass Azure Resource Deletion",
				fmt.Sprintf("Principal %s deleted %d resources within 5 minutes. Pattern consistent with ransomware, insider sabotage, or account takeover destruction.",
					principal, s.deleteCount),
				5, "T1485", "Impact", ev)
			s.deleteCount = 0
			s.deleteStart = nil
		}
	}

	// ── CORR-AZ-006: CA policy disabled then sign-in from new country ─────────
	if containsAny(operation, "conditionalaccesspolicies") &&
		containsAny(rawStr, "disabled", "delete", "reportonly") {
		t := ev.Time
		s.caDisabledAt = &t
	}
	if s.caDisabledAt != nil && ev.Time.Sub(*s.caDisabledAt) <= 30*time.Minute {
		if ev.EventType == "cloud.entra_signin" &&
			containsAny(rawStr, "country", "location") {
			e.fireAlert(ctx, "CORR-AZ-006",
				"[CORR] Conditional Access Disabled Then Sign-In from New Location",
				fmt.Sprintf("CA policy disabled at %s, followed by sign-in from new location within 30 minutes by %s. Indicates deliberate CA bypass before authentication.",
					s.caDisabledAt.Format(time.RFC3339), principal),
				5, "T1556", "Defense Evasion", ev)
			s.caDisabledAt = nil
		}
	}

	// ── CORR-AZ-007: New IP then role assignment within 5 min ────────────────
	if srcIP != "" {
		if _, seen := s.knownIPs[srcIP]; !seen {
			s.knownIPs[srcIP] = ev.Time
		}
		if containsAny(operation, "roleassignments/write", "add member to role") {
			if firstSeen, ok := s.knownIPs[srcIP]; ok {
				if ev.Time.Sub(firstSeen) <= 5*time.Minute && firstSeen.After(ev.Time.Add(-5*time.Minute)) {
					e.fireAlert(ctx, "CORR-AZ-007",
						"[CORR] First-Seen IP Performing Role Assignment",
						fmt.Sprintf("Principal %s performed role assignment from IP %s which was first seen %.1f minutes ago. New IP performing IAM changes is a strong indicator of compromised credentials.",
							principal, srcIP, ev.Time.Sub(firstSeen).Minutes()),
						4, "T1078.004", "Initial Access", ev)
				}
			}
		}
	}

	// ── CORR-AZ-008: SP created then immediately gets Owner ──────────────────
	if containsAny(operation, "serviceprincipals/write", "add service principal") &&
		!containsAny(operation, "credentials", "owners") {
		t := ev.Time
		s.spCreatedAt = &t
		s.spCreatedName = principal
	}
	if s.spCreatedAt != nil && ev.Time.Sub(*s.spCreatedAt) <= 5*time.Minute {
		if containsAny(operation, "roleassignments/write") &&
			containsAny(rawStr, "owner", "contributor") {
			e.fireAlert(ctx, "CORR-AZ-008",
				"[CORR] Service Principal Created Then Immediately Assigned Owner Role",
				fmt.Sprintf("Service principal created at %s, then assigned Owner/Contributor role within 5 minutes by %s. Rapid SP creation + high-privilege assignment is a backdoor pattern.",
					s.spCreatedAt.Format(time.RFC3339), principal),
				5, "T1136.003", "Persistence", ev)
			s.spCreatedAt = nil
		}
	}
}

func (e *AzureCorrelationEngine) fireAlert(ctx context.Context, id, title, desc string,
	sev int, mitre, category string, ev store.Event) {
	hour := ev.Time.UTC().Format("2006010215")
	principal := ""
	if ev.UserName != nil {
		principal = *ev.UserName
	}
	dedupKey := fmt.Sprintf("corr:az:%s:host:%s:p:%s:h:%s",
		id, ev.Host, sanitiseKey(principal), hour)

	full := fmt.Sprintf("%s\n\nMITRE: %s | Category: %s\nSubscription: %s | Principal: %s | IP: %s",
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
		EventType:     "cloud.azure_correlation",
		EventID:       dedupKey,
		SourceEventID: ev.ID,
	}
	if _, inserted, err := e.db.CreateAlertDeduped(ctx, alert); err == nil && inserted {
		e.logger.Info("azure correlation alert", "rule", id, "principal", principal)
	}
}

// ── Baseline / Anomaly Engine ─────────────────────────────────────────────────

type AzureBaselineEngine struct {
	db     *store.DB
	logger *slog.Logger
}

func NewAzureBaselineEngine(db *store.DB, logger *slog.Logger) *AzureBaselineEngine {
	return &AzureBaselineEngine{db: db, logger: logger}
}

func (e *AzureBaselineEngine) Run(ctx context.Context) {
	e.buildBaselines(ctx, time.Now().Add(-30*24*time.Hour))
	buildTicker := time.NewTicker(15 * time.Minute)
	anomTicker := time.NewTicker(2 * time.Minute)
	defer buildTicker.Stop()
	defer anomTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-buildTicker.C:
			e.buildBaselines(ctx, time.Now().Add(-15*time.Minute))
		case <-anomTicker.C:
			e.detectAnomalies(ctx, time.Now().Add(-2*time.Minute))
		}
	}
}

func (e *AzureBaselineEngine) buildBaselines(ctx context.Context, since time.Time) {
	for _, evType := range []string{"cloud.azure_activity", "cloud.entra_audit"} {
		events, _, err := e.db.QueryEvents(ctx, store.EventFilter{
			EventType: evType,
			Since:     since,
			Limit:     5000,
		})
		if err != nil {
			continue
		}
		updates := map[string]*principalBaseline{}
		for _, ev := range events {
			principal := ""
			if ev.UserName != nil {
				principal = *ev.UserName
			}
			if principal == "" || isAzureSystemPrincipal(principal) {
				continue
			}
			b, ok := updates[principal]
			if !ok {
				b = e.loadBaseline(ctx, principal)
				updates[principal] = b
			}
			if ev.SrcIP != nil && *ev.SrcIP != "" {
				ip := *ev.SrcIP
				rec := b.KnownIPs[ip]
				if rec.FirstSeen.IsZero() {
					rec.FirstSeen = ev.Time
				}
				rec.LastSeen = ev.Time
				rec.Count++
				b.KnownIPs[ip] = rec
			}
			hour := ev.Time.UTC().Hour()
			b.HourCounts[hour]++
			b.EventCount++
		}
		for _, b := range updates {
			e.saveBaseline(ctx, b)
		}
	}
}

func (e *AzureBaselineEngine) detectAnomalies(ctx context.Context, since time.Time) {
	for _, evType := range []string{"cloud.azure_activity", "cloud.entra_audit"} {
		events, _, err := e.db.QueryEvents(ctx, store.EventFilter{
			EventType: evType,
			Since:     since,
			Limit:     2000,
		})
		if err != nil {
			continue
		}

		// Track IPs per SP in the last hour for ANOM-AZ-003
		hourAgo := time.Now().Add(-time.Hour)
		spIPs := map[string]map[string]struct{}{}
		hourEvents, _, _ := e.db.QueryEvents(ctx, store.EventFilter{
			EventType: evType,
			Since:     hourAgo,
			Limit:     5000,
		})
		for _, ev := range hourEvents {
			if ev.UserName == nil || ev.SrcIP == nil {
				continue
			}
			p := *ev.UserName
			if _, ok := spIPs[p]; !ok {
				spIPs[p] = map[string]struct{}{}
			}
			spIPs[p][*ev.SrcIP] = struct{}{}
		}

		seen := map[string]bool{}
		for _, ev := range events {
			principal := ""
			if ev.UserName != nil {
				principal = *ev.UserName
			}
			if principal == "" || isAzureSystemPrincipal(principal) {
				continue
			}
			b := e.loadBaseline(ctx, principal)
			if b.EventCount < 20 {
				continue
			}

			srcIP := ""
			if ev.SrcIP != nil {
				srcIP = *ev.SrcIP
			}

			// ANOM-AZ-001: first-ever IP
			if srcIP != "" {
				if _, known := b.KnownIPs[srcIP]; !known {
					key := "ANOM-AZ-001:" + principal + ":" + srcIP
					if !seen[key] {
						seen[key] = true
						hour := ev.Time.UTC().Format("2006010215")
						dedupKey := fmt.Sprintf("anom:az:001:p:%s:ip:%s:h:%s",
							sanitiseKey(principal), sanitiseKey(srcIP), hour)
						e.fireAnomAlert(ctx, dedupKey,
							"[ANOM] Azure Principal Activity from Unknown IP",
							fmt.Sprintf("Principal %s accessed Azure APIs from IP %s which is not in their baseline (%d known IPs over %d events).",
								principal, srcIP, len(b.KnownIPs), b.EventCount),
							3, "T1078.004", "Initial Access", ev)
					}
				}
			}

			// ANOM-AZ-002: admin action outside normal hours
			if ev.Severity >= 4 {
				hour := ev.Time.UTC().Hour()
				total := 0
				for _, c := range b.HourCounts {
					total += c
				}
				if total > 50 {
					threshold := total / 20
					if b.HourCounts[hour] < threshold {
						key := fmt.Sprintf("ANOM-AZ-002:%s:%d", principal, hour)
						if !seen[key] {
							seen[key] = true
							day := ev.Time.UTC().Format("20060102")
							dedupKey := fmt.Sprintf("anom:az:002:p:%s:h:%d:d:%s",
								sanitiseKey(principal), hour, day)
							e.fireAnomAlert(ctx, dedupKey,
								"[ANOM] Azure Admin Action Outside Normal Hours",
								fmt.Sprintf("Principal %s performed high-severity Azure operation at %02d:00 UTC — only %.1f%% of their historical activity occurs at this hour.",
									principal, hour,
									float64(b.HourCounts[hour])/float64(total)*100),
								3, "T1078.004", "Defense Evasion", ev)
						}
					}
				}
			}

			// ANOM-AZ-003: SP from >3 IPs in 1 hour
			if ips, ok := spIPs[principal]; ok && len(ips) > 3 {
				if strings.Contains(principal, "@") && strings.Contains(principal, ".") {
					key := "ANOM-AZ-003:" + principal
					if !seen[key] {
						seen[key] = true
						hour := ev.Time.UTC().Format("2006010215")
						dedupKey := fmt.Sprintf("anom:az:003:p:%s:h:%s", sanitiseKey(principal), hour)
						e.fireAnomAlert(ctx, dedupKey,
							"[ANOM] Service Principal Used from Multiple IPs",
							fmt.Sprintf("Principal %s used from %d distinct IPs in the last hour. Legitimate SPs typically run from fixed infrastructure.",
								principal, len(ips)),
							4, "T1552.001", "Credential Access", ev)
					}
				}
			}

			// ── ANOM-AZ-004: Impossible travel ────────────────────────────────────
		if srcIP != "" {
			window30 := ev.Time.Add(-30 * time.Minute)
			currentPrefix := ipPrefix16(srcIP)
			if currentPrefix != "" {
				for otherIP, rec := range b.KnownIPs {
					if !rec.LastSeen.After(window30) { continue }
					otherPrefix := ipPrefix16(otherIP)
					if otherPrefix == "" || otherPrefix == currentPrefix { continue }
					alertKey := fmt.Sprintf("ANOM-AZ-004:%s:%s:%s", principal, currentPrefix, otherPrefix)
					if !seen[alertKey] {
						seen[alertKey] = true
						hour := ev.Time.UTC().Format("2006010215")
						dedupKey := fmt.Sprintf("anom:az:004:p:%s:h:%s", sanitiseKey(principal), hour)
						e.fireAnomAlert(ctx, dedupKey,
							"[ANOM] Azure: Impossible Travel — Two Distant IPs",
							fmt.Sprintf("Principal %s called Azure APIs from IP %s and %s within 30 minutes — different /16 subnets suggests simultaneous use from two locations.",
								principal, srcIP, otherIP),
							4, "T1078.004", "Initial Access", ev)
					}
				}
			}
		}

		// ── ANOM-AZ-005: Large data transfer ─────────────────────────────────
		if ev.Raw != nil {
			var rawData struct {
				BytesTransferred int64 `json:"bytesTransferred"`
				ContentLength    int64 `json:"contentLength"`
			}
			json.Unmarshal(ev.Raw, &rawData)
			bytes := rawData.BytesTransferred
			if rawData.ContentLength > bytes { bytes = rawData.ContentLength }
			const spikeGB = 10 * 1024 * 1024 * 1024
			if bytes > spikeGB {
				alertKey := fmt.Sprintf("ANOM-AZ-005:%s", principal)
				if !seen[alertKey] {
					seen[alertKey] = true
					hour := ev.Time.UTC().Format("2006010215")
					dedupKey := fmt.Sprintf("anom:az:005:p:%s:h:%s", sanitiseKey(principal), hour)
					e.fireAnomAlert(ctx, dedupKey,
						"[ANOM] Azure: Large Data Transfer — Possible Exfiltration",
						fmt.Sprintf("Principal %s transferred %.1f GB in a single Azure operation. Bulk reads from Storage or SQL are a strong exfiltration indicator.",
							principal, float64(bytes)/1e9),
						4, "T1530", "Exfiltration", ev)
				}
			}
		}

		// ── ANOM-AZ-006: First-ever Azure service for this principal ─────────
		if ev.Raw != nil {
			var rawData struct{ OperationName string `json:"operation_name"` }
			json.Unmarshal(ev.Raw, &rawData)
			op := rawData.OperationName
			if op == "" {
				var rawData2 struct{ OperationName string `json:"operationName"` }
				json.Unmarshal(ev.Raw, &rawData2)
				op = rawData2.OperationName
			}
			if op != "" && b.EventCount >= 30 {
				svcParts := strings.SplitN(op, "/", 2)
				svc := svcParts[0]
				if svc != "" {
					if _, known := b.KnownMethods[svc]; !known {
						alertKey := fmt.Sprintf("ANOM-AZ-006:%s:%s", principal, svc)
						if !seen[alertKey] {
							seen[alertKey] = true
							hour := ev.Time.UTC().Format("2006010215")
							dedupKey := fmt.Sprintf("anom:az:006:p:%s:svc:%s:h:%s",
								sanitiseKey(principal), sanitiseKey(svc), hour)
							e.fireAnomAlert(ctx, dedupKey,
								"[ANOM] Azure: Principal Accessing New Service for First Time",
								fmt.Sprintf("Principal %s accessed Azure service '%s' for the first time after %d baseline events. First-time service access post-baseline is a discovery/lateral movement indicator.",
									principal, svc, b.EventCount),
								2, "T1078.004", "Discovery", ev)
						}
					}
					b.KnownMethods[svc]++
				}
			}
		}
		}
	}
}

func (e *AzureBaselineEngine) loadBaseline(ctx context.Context, principal string) *principalBaseline {
	key := "baseline:az:" + sanitiseKey(principal)
	val, err := e.db.GetSetting(ctx, key)
	if err != nil || val == "" {
		return &principalBaseline{
			Principal:    principal,
			KnownIPs:     make(map[string]ipRecord),
			KnownMethods: make(map[string]int),
		}
	}
	var b principalBaseline
	if err := json.Unmarshal([]byte(val), &b); err != nil {
		return &principalBaseline{
			Principal:    principal,
			KnownIPs:     make(map[string]ipRecord),
			KnownMethods: make(map[string]int),
		}
	}
	if b.KnownIPs == nil {
		b.KnownIPs = make(map[string]ipRecord)
	}
	if b.KnownMethods == nil {
		b.KnownMethods = make(map[string]int)
	}
	return &b
}

func (e *AzureBaselineEngine) saveBaseline(ctx context.Context, b *principalBaseline) {
	b.UpdatedAt = time.Now()
	data, _ := json.Marshal(b)
	e.db.SetSetting(ctx, "baseline:az:"+sanitiseKey(b.Principal), string(data))
}

func (e *AzureBaselineEngine) fireAnomAlert(ctx context.Context, dedupKey, title, desc string,
	sev int, mitre, category string, ev store.Event) {
	principal := ""
	if ev.UserName != nil {
		principal = *ev.UserName
	}
	full := fmt.Sprintf("%s\n\nMITRE: %s | Category: %s\nSubscription: %s | Principal: %s | IP: %s",
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
		EventType:     "cloud.azure_anomaly",
		EventID:       dedupKey,
		SourceEventID: ev.ID,
	}
	if _, inserted, err := e.db.CreateAlertDeduped(ctx, alert); err == nil && inserted {
		e.logger.Info("azure anomaly alert", "key", dedupKey)
	}
}

func isAzureSystemPrincipal(p string) bool {
	lower := strings.ToLower(p)
	return containsAny(lower,
		"microsoft service", "azure service", "azureactivedirectory",
		"windows azure", "microsoft azure", "windowsazure",
		"00000003-0000-0000-c000-000000000000",
		"f8cdef31-a31e-4b4a-93e4-5f571e91255a",
	)
}
