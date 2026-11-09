package api

// cloud_gcp_baseline.go — Behavioural baseline and anomaly detection for GCP.
//
// Maintains per-principal baselines persisted in the settings table:
//   - Known source IPs (with first/last seen and count)
//   - Known API method categories (with frequency)
//   - Normal operating hours (UTC)
//
// Fires alerts on:
//   ANOM-GCP-001  First-ever IP for this principal
//   ANOM-GCP-002  API method category never seen before for this principal
//   ANOM-GCP-003  High-severity action outside principal's normal hours
//   ANOM-GCP-004  SA accessed from >3 distinct IPs in 1 hour

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// ── Baseline data structures ──────────────────────────────────────────────────

type ipRecord struct {
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Count     int       `json:"count"`
}

type principalBaseline struct {
	Principal    string              `json:"principal"`
	KnownIPs     map[string]ipRecord `json:"known_ips"`
	KnownMethods map[string]int      `json:"known_methods"` // method_category → count
	HourCounts   [24]int             `json:"hour_counts"`   // UTC hour → event count
	UpdatedAt    time.Time           `json:"updated_at"`
	EventCount   int                 `json:"event_count"`
	// G-30: learning watermark (latest event time already folded in) makes the
	// rebuild idempotent — restarts and overlapping windows no longer double count.
	Watermark time.Time `json:"watermark,omitempty"`
}

const (
	baselineLearnDelay   = time.Hour           // learn only from events old enough to have been evaluated/triaged
	baselineMaxIPs       = 200                 // per principal
	baselineMaxMethods   = 200                 // per principal
	baselineIPExpiry     = 90 * 24 * time.Hour // forget IPs unseen this long
	baselineMaxLearnSev  = 3                   // events at severity >= 4 are never learned (likely alerted)
)

// pruneBaseline bounds the maps (G-30): drop expired IPs, then evict the
// least-recently-seen entries beyond the cap.
func pruneBaseline(b *principalBaseline, now time.Time) {
	for ip, rec := range b.KnownIPs {
		if now.Sub(rec.LastSeen) > baselineIPExpiry {
			delete(b.KnownIPs, ip)
		}
	}
	for len(b.KnownIPs) > baselineMaxIPs {
		oldestIP, oldest := "", now.Add(time.Hour)
		for ip, rec := range b.KnownIPs {
			if rec.LastSeen.Before(oldest) {
				oldestIP, oldest = ip, rec.LastSeen
			}
		}
		delete(b.KnownIPs, oldestIP)
	}
	for len(b.KnownMethods) > baselineMaxMethods {
		minM, minC := "", int(^uint(0)>>1)
		for m, c := range b.KnownMethods {
			if c < minC {
				minM, minC = m, c
			}
		}
		delete(b.KnownMethods, minM)
	}
}

// GCPBaselineEngine builds and queries per-principal baselines.
type GCPBaselineEngine struct {
	db     *store.DB
	logger *slog.Logger
}

func NewGCPBaselineEngine(db *store.DB, logger *slog.Logger) *GCPBaselineEngine {
	return &GCPBaselineEngine{db: db, logger: logger}
}

func (e *GCPBaselineEngine) Run(ctx context.Context) {
	// Build/update baselines from the last 30 days on startup
	e.buildBaselines(ctx, time.Now().Add(-30*24*time.Hour))

	// Update baselines every 15 min from recent events
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	// Run anomaly detection every 2 min
	anomTicker := time.NewTicker(2 * time.Minute)
	defer anomTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.buildBaselines(ctx, time.Now().Add(-3*time.Hour))
		case <-anomTicker.C:
			e.detectAnomaliesCursor(ctx)
		}
	}
}

// loadBaseline loads a principal's baseline from the settings table.
func (e *GCPBaselineEngine) loadBaseline(ctx context.Context, principal string) *principalBaseline {
	key := "baseline:gcp:" + sanitiseKey(principal)
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

// saveBaseline persists a principal's baseline to the settings table.
func (e *GCPBaselineEngine) saveBaseline(ctx context.Context, b *principalBaseline) {
	b.UpdatedAt = time.Now()
	data, err := json.Marshal(b)
	if err != nil {
		return
	}
	key := "baseline:gcp:" + sanitiseKey(b.Principal)
	e.db.SetSetting(ctx, key, string(data))
}

// buildBaselines ingests events and updates baselines without firing alerts.
func (e *GCPBaselineEngine) buildBaselines(ctx context.Context, since time.Time) {
	// G-30: only learn from events older than baselineLearnDelay so activity
	// that detection has just alerted on is not folded into "normal".
	cutoff := time.Now().Add(-baselineLearnDelay)
	events, _, err := e.db.QueryEvents(ctx, store.EventFilter{
		EventType: "cloud.gcp_audit",
		Since:     since,
		Until:     cutoff,
		Limit:     5000,
	})
	if err != nil {
		return
	}
	// Oldest first so the per-principal watermark advances monotonically.
	sort.Slice(events, func(i, j int) bool { return events[i].Time.Before(events[j].Time) })

	// Group by principal, batch updates
	updates := make(map[string]*principalBaseline)
	startWM := make(map[string]time.Time)

	for _, ev := range events {
		if int(ev.Severity) > baselineMaxLearnSev {
			continue
		}
		principal := ""
		if ev.UserName != nil {
			principal = *ev.UserName
		}
		if principal == "" || isSystemPrincipal(principal) {
			continue
		}

		b, ok := updates[principal]
		if !ok {
			b = e.loadBaseline(ctx, principal)
			updates[principal] = b
			startWM[principal] = b.Watermark
		}
		if !ev.Time.After(startWM[principal]) {
			continue // already learned in an earlier run
		}
		if ev.Time.After(b.Watermark) {
			b.Watermark = ev.Time
		}

		// Track IP
		if ev.SrcIP != nil && *ev.SrcIP != "" && !isGoogleInternalIP(*ev.SrcIP) {
			ip := *ev.SrcIP
			rec := b.KnownIPs[ip]
			if rec.FirstSeen.IsZero() {
				rec.FirstSeen = ev.Time
			}
			rec.LastSeen = ev.Time
			rec.Count++
			b.KnownIPs[ip] = rec
		}

		// Track method category
		method := extractMethodCategory(ev)
		if method != "" {
			b.KnownMethods[method]++
		}

		// Track hour
		hour := ev.Time.UTC().Hour()
		b.HourCounts[hour]++
		b.EventCount++
	}

	// Persist all updated baselines
	now := time.Now()
	for _, b := range updates {
		pruneBaseline(b, now)
		e.saveBaseline(ctx, b)
	}
}

// detectAnomaliesCursor (G-02) pages new events by events.ingested_at
// (pageEventCursor) instead of a 2-minute wall-clock window, so GCP audit
// events that land in the DB 5+ minutes after they occurred are still
// evaluated instead of silently falling outside the window.
func (e *GCPBaselineEngine) detectAnomaliesCursor(ctx context.Context) {
	events, err := pageEventCursor(ctx, e.db, "cloud-gcp-anomaly", store.EventFilter{
		EventType: "cloud.gcp_audit",
	}, 2*time.Minute, 2000)
	if err != nil {
		e.logger.Warn("gcp baseline: cursor query failed", "err", err)
		return
	}
	e.detectAnomalies(ctx, events)
}

// detectAnomalies checks the given events against baselines and fires alerts.
func (e *GCPBaselineEngine) detectAnomalies(ctx context.Context, events []store.Event) {

	// Track IPs seen per principal in last hour for ANOM-GCP-004
	ipsByPrincipal := make(map[string]map[string]struct{})
	hourAgo := time.Now().Add(-time.Hour)

	hourEvents, _, _ := e.db.QueryEvents(ctx, store.EventFilter{
		EventType: "cloud.gcp_audit",
		Since:     hourAgo,
		Limit:     5000,
	})
	for _, ev := range hourEvents {
		if ev.UserName == nil || ev.SrcIP == nil {
			continue
		}
		p := *ev.UserName
		if _, ok := ipsByPrincipal[p]; !ok {
			ipsByPrincipal[p] = make(map[string]struct{})
		}
		ipsByPrincipal[p][*ev.SrcIP] = struct{}{}
	}

	seen := make(map[string]bool) // deduplicate alerts within this cycle
	baselineCache := make(map[string]*principalBaseline) // G-30: one settings read per principal per cycle

	for _, ev := range events {
		principal := ""
		if ev.UserName != nil {
			principal = *ev.UserName
		}
		if principal == "" || isSystemPrincipal(principal) {
			continue
		}

		b, cached := baselineCache[principal]
		if !cached {
			b = e.loadBaseline(ctx, principal)
			baselineCache[principal] = b
		}

		// Need minimum baseline before alerting (avoid noise on new principals)
		if b.EventCount < 20 {
			continue
		}

		srcIP := ""
		if ev.SrcIP != nil {
			srcIP = *ev.SrcIP
		}

		// ── ANOM-GCP-001: First-ever IP for this principal ────────────────────
		if srcIP != "" && !isGoogleInternalIP(srcIP) {
			if _, known := b.KnownIPs[srcIP]; !known {
				alertKey := "ANOM-GCP-001:" + principal + ":" + srcIP
				if !seen[alertKey] {
					seen[alertKey] = true
					hour := ev.Time.UTC().Format("2006010215")
					dedupKey := fmt.Sprintf("anom:001:p:%s:ip:%s:h:%s",
						sanitiseKey(principal), sanitiseKey(srcIP), hour)
					e.fireAlert(ctx, dedupKey,
						"[ANOM] GCP Principal Activity from Unknown IP",
						fmt.Sprintf("Principal %s accessed GCP API from IP %s which has never been seen before in their baseline (baseline covers %d known IPs, %d total events). Operation: %s",
							principal, srcIP, len(b.KnownIPs), b.EventCount,
							extractMethod(ev)),
						3, "T1078.004", "Initial Access", ev)
				}
			}
		}

		// ── ANOM-GCP-002: Unknown method category ────────────────────────────
		method := extractMethodCategory(ev)
		if method != "" {
			if _, known := b.KnownMethods[method]; !known && ev.Severity >= 3 {
				alertKey := "ANOM-GCP-002:" + principal + ":" + method
				if !seen[alertKey] {
					seen[alertKey] = true
					hour := ev.Time.UTC().Format("2006010215")
					dedupKey := fmt.Sprintf("anom:002:p:%s:m:%s:h:%s",
						sanitiseKey(principal), sanitiseKey(method), hour)
					e.fireAlert(ctx, dedupKey,
						"[ANOM] GCP Principal Using New API Service",
						fmt.Sprintf("Principal %s called %s API for the first time (never seen in %d-event baseline). First use of a new GCP service area by a principal can indicate account compromise or privilege escalation.",
							principal, method, b.EventCount),
						2, "T1078.004", "Discovery", ev)
				}
			}
		}

		// ── ANOM-GCP-003: High-severity action outside normal hours ──────────
		if ev.Severity >= 4 {
			hour := ev.Time.UTC().Hour()
			totalEvents := 0
			for _, c := range b.HourCounts {
				totalEvents += c
			}
			if totalEvents > 50 {
				// Calculate normal hours: hours with >5% of activity
				normalActivity := b.HourCounts[hour]
				threshold := totalEvents / 20 // 5%
				if normalActivity < threshold {
					alertKey := fmt.Sprintf("ANOM-GCP-003:%s:%d", principal, hour)
					if !seen[alertKey] {
						seen[alertKey] = true
						day := ev.Time.UTC().Format("20060102")
						dedupKey := fmt.Sprintf("anom:003:p:%s:h:%d:d:%s",
							sanitiseKey(principal), hour, day)
						e.fireAlert(ctx, dedupKey,
							"[ANOM] GCP High-Severity Action Outside Normal Working Hours",
							fmt.Sprintf("Principal %s performed sensitive operation '%s' at %02d:00 UTC — this hour accounts for only %d/%d (%.1f%%) of their historical activity. After-hours admin actions are a common indicator of compromise or insider threat.",
								principal, extractMethod(ev), hour,
								normalActivity, totalEvents,
								float64(normalActivity)/float64(totalEvents)*100),
							3, "T1078.004", "Defense Evasion", ev)
					}
				}
			}
		}

		// ── ANOM-GCP-004: SA from >3 distinct IPs in 1 hour ──────────────────
		if ips, ok := ipsByPrincipal[principal]; ok && len(ips) > 3 {
			// Only fire for service accounts
			if strings.Contains(principal, "gserviceaccount.com") {
				alertKey := "ANOM-GCP-004:" + principal
				if !seen[alertKey] {
					seen[alertKey] = true
					hour := ev.Time.UTC().Format("2006010215")
					dedupKey := fmt.Sprintf("anom:004:p:%s:h:%s",
						sanitiseKey(principal), hour)
					ipList := make([]string, 0, len(ips))
					for ip := range ips {
						ipList = append(ipList, ip)
						if len(ipList) >= 5 {
							break
						}
					}
					e.fireAlert(ctx, dedupKey,
						"[ANOM] Service Account Used from Multiple IPs",
						fmt.Sprintf("Service account %s has been used from %d distinct IP addresses in the last hour (%s...). Legitimate SAs are typically used from a fixed set of IPs (VMs, Cloud Run, GKE nodes). Multiple IPs suggests key theft and shared credential use.",
							principal, len(ips), strings.Join(ipList, ", ")),
						4, "T1552.004", "Credential Access", ev)
				}
			}
		}

		// ── ANOM-GCP-005: Impossible travel — two events from distant IPs ────
		// G-31 interim: without a GeoIP source a /16 mismatch is only "different
		// network", not "distant" (phone hotspot, VPN). Service accounts are
		// covered by ANOM-004; severity drops to Medium and the title no
		// longer claims impossible travel until real GeoIP lands.
		if srcIP != "" && !isGoogleInternalIP(srcIP) && !strings.HasSuffix(principal, "gserviceaccount.com") {
			window30 := ev.Time.Add(-30 * time.Minute)
			currentPrefix := ipPrefix16(srcIP)
			for otherIP, rec := range b.KnownIPs {
				if !rec.LastSeen.After(window30) {
					continue
				}
				if isGoogleInternalIP(otherIP) {
					continue
				}
				otherPrefix := ipPrefix16(otherIP)
				if otherPrefix == "" || currentPrefix == "" || otherPrefix == currentPrefix {
					continue
				}
				alertKey := fmt.Sprintf("ANOM-GCP-005:%s:%s:%s", principal, currentPrefix, otherPrefix)
				if !seen[alertKey] {
					seen[alertKey] = true
					hour := ev.Time.UTC().Format("2006010215")
					dedupKey := fmt.Sprintf("anom:005:p:%s:ips:%s_%s:h:%s",
						sanitiseKey(principal), sanitiseKey(srcIP), sanitiseKey(otherIP), hour)
					e.fireAlert(ctx, dedupKey,
						"[ANOM] Concurrent Use from Two Different Networks",
						fmt.Sprintf("Principal %s made API calls from IP %s and IP %s within 30 minutes. These IPs are on different /16 subnets, which may indicate shared credentials — or a VPN / mobile hotspot. Verify with the user.",
							principal, srcIP, otherIP),
						3, "T1078.004", "Initial Access", ev)
				}
			}
		}

		// ── ANOM-GCP-006: Sudden data volume spike ────────────────────────────
		// Detect when bytes_processed from BigQuery or GCS reads spike >10x baseline
		if ev.Raw != nil {
			var rawData struct {
				BytesProcessed   string `json:"bytes_processed"`
				TotalBytesBilled string `json:"total_bytes_billed"`
				ResponseSize     int64  `json:"response_size"`
			}
			json.Unmarshal(ev.Raw, &rawData)
			var bytesThisEvent int64
			if rawData.BytesProcessed != "" {
				fmt.Sscanf(rawData.BytesProcessed, "%d", &bytesThisEvent)
			}
			if rawData.TotalBytesBilled != "" {
				var bb int64
				fmt.Sscanf(rawData.TotalBytesBilled, "%d", &bb)
				if bb > bytesThisEvent {
					bytesThisEvent = bb
				}
			}
			if rawData.ResponseSize > bytesThisEvent {
				bytesThisEvent = rawData.ResponseSize
			}

			const spikeThresholdGB = 10 * 1024 * 1024 * 1024 // 10 GB single event = always alert
			if bytesThisEvent > spikeThresholdGB {
				alertKey := fmt.Sprintf("ANOM-GCP-006:%s", principal)
				if !seen[alertKey] {
					seen[alertKey] = true
					hour := ev.Time.UTC().Format("2006010215")
					dedupKey := fmt.Sprintf("anom:006:p:%s:h:%s", sanitiseKey(principal), hour)
					e.fireAlert(ctx, dedupKey,
						"[ANOM] Large Data Read — Possible Exfiltration",
						fmt.Sprintf("Principal %s read %.1f GB of data in a single API call. Large single-read events from BigQuery or Cloud Storage are a strong indicator of bulk data exfiltration.",
							principal, float64(bytesThisEvent)/1e9),
						4, "T1530", "Exfiltration", ev)
				}
			}
		}

		// ── ANOM-GCP-007: New API service never seen for this principal ────────
		// Fire when a principal calls a GCP service they have never used in their baseline
		if method != "" {
			category := extractMethodCategory(ev)
			if category != "" {
				if _, knownCategory := b.KnownMethods[category]; !knownCategory && b.EventCount >= 50 {
					alertKey := fmt.Sprintf("ANOM-GCP-007:%s:%s", principal, category)
					if !seen[alertKey] {
						seen[alertKey] = true
						hour := ev.Time.UTC().Format("2006010215")
						dedupKey := fmt.Sprintf("anom:007:p:%s:svc:%s:h:%s",
							sanitiseKey(principal), sanitiseKey(category), hour)
						e.fireAlert(ctx, dedupKey,
							"[ANOM] Principal Accessing New GCP Service for First Time",
							fmt.Sprintf("Principal %s called a %s API for the first time (never seen in %d baseline events). First-time service access after a long history often indicates account compromise or privilege escalation exploration.",
								principal, category, b.EventCount),
							2, "T1078.004", "Discovery", ev)
					}
				}
				b.KnownMethods[category]++
			}
		}
	}
}

func (e *GCPBaselineEngine) fireAlert(ctx context.Context, dedupKey, title, desc string,
	sev int, mitre, category string, ev store.Event) {
	principal := ""
	if ev.UserName != nil {
		principal = *ev.UserName
	}
	full := fmt.Sprintf("%s\n\nMITRE ATT&CK: %s | Category: %s\nProject: %s | Principal: %s | IP: %s",
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
		EventType:     "cloud.gcp_anomaly",
		EventID:       dedupKey,
		SourceEventID: ev.ID,
	}
	if _, inserted, err := e.db.CreateAlertDeduped(ctx, alert); err == nil && inserted {
		e.logger.Info("anomaly alert fired", "key", dedupKey, "principal", principal)
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// extractMethodCategory returns the GCP service area from a raw audit event.
func extractMethodCategory(ev store.Event) string {
	method := extractMethod(ev)
	if method == "" {
		return ""
	}
	// method looks like "compute.instances.insert" or "google.iam.v1.IAM.SetIamPolicy"
	parts := strings.Split(strings.ToLower(method), ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

func extractMethod(ev store.Event) string {
	if ev.Raw == nil {
		return ""
	}
	var r struct {
		MethodName string `json:"method_name"`
	}
	json.Unmarshal(ev.Raw, &r)
	return r.MethodName
}

// isSystemPrincipal returns true for Google-managed system identities that
// have no customer-controlled credentials.
//
// G-32: Cloud Build and App Engine default service accounts used to be
// excluded here too. They are customer-usable, over-privileged by default
// and common attack targets, so they are now baselined like any other
// principal.
func isSystemPrincipal(p string) bool {
	return containsAny(strings.ToLower(p),
		"system:serviceaccount:kube-system",
		"@cloudservices.gserviceaccount.com",
		"@container-engine-robot.iam.gserviceaccount.com",
	)
}

// isGoogleInternalIP returns true for Google's internal/private infrastructure IPs.
func isGoogleInternalIP(ip string) bool {
	// G-29: parse the address and test real ranges. Substring matching
	// ("10.", "127.") treated any public IP containing e.g. ".110." as internal.
	l := strings.ToLower(ip)
	if strings.Contains(l, "gcp-internal") || strings.Contains(l, "googleusercontent") {
		return true
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsUnspecified() ||
		cgnatPrefix.Contains(addr)
}

// cgnatPrefix is the carrier-grade NAT range (100.64.0.0/10), not covered by IsPrivate.
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// sanitiseKey removes characters not safe for settings keys.
func sanitiseKey(s string) string {
	r := strings.NewReplacer(
		"@", "_at_", ".", "_", "/", "_", " ", "_",
		":", "_", "'", "", "\"", "", "\\", "_",
	)
	return r.Replace(s)
}

// ipPrefix16 returns the /16 prefix of an IPv4 address for heuristic geolocation comparison.
// Returns "" for IPv6 or unparseable addresses.
func ipPrefix16(ip string) string {
	if strings.Contains(ip, ":") {
		return ""
	} // IPv6 — skip
	parts := strings.Split(ip, ".")
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "." + parts[1]
}
