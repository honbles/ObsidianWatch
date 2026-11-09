package api

// cloud_aws_baseline.go — behavioural baseline for AWS CloudTrail principals.
// Reuses principalBaseline (known IPs, service categories) from the GCP engine.
//
//	ANOM-AWS-001  first-ever source IP for a principal
//	ANOM-AWS-002  principal uses an AWS service it has never used (severity >= 3)
//	ANOM-AWS-004  principal seen from more than 3 distinct IPs within an hour
//
// Assumed-role sessions are folded into the role ("role/Name"), otherwise every
// session would be a brand-new principal with an empty baseline.

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

type AWSBaselineEngine struct {
	db     *store.DB
	logger *slog.Logger
}

func NewAWSBaselineEngine(db *store.DB, logger *slog.Logger) *AWSBaselineEngine {
	return &AWSBaselineEngine{db: db, logger: logger}
}

// awsPrincipal returns the stable principal for an event, or "" to skip it.
func awsPrincipal(ev store.Event) string {
	p := ""
	if ev.UserName != nil {
		p = *ev.UserName
	}
	if i := strings.Index(p, ":assumed-role/"); i >= 0 {
		rest := p[i+len(":assumed-role/"):]
		if j := strings.Index(rest, "/"); j >= 0 {
			rest = rest[:j]
		}
		p = p[:i] + ":role/" + rest
	}
	l := strings.ToLower(p)
	if p == "" || strings.HasSuffix(l, ".amazonaws.com") || strings.Contains(l, "awsservicerole") || strings.Contains(l, "aws-service") {
		return ""
	}
	return p
}

// awsPublicIP reports whether s is a routable public address (service names
// like "ec2.amazonaws.com" and private addresses are ignored).
func awsPublicIP(s string) bool {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return false
	}
	a = a.Unmap()
	return !(a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() || cgnatPrefix.Contains(a))
}

// awsServiceCategory returns "iam" for event_source "iam.amazonaws.com".
func awsServiceCategory(ev store.Event) string {
	var r struct {
		Source string `json:"event_source"`
	}
	_ = json.Unmarshal(ev.Raw, &r)
	return strings.ToLower(strings.TrimSuffix(strings.SplitN(r.Source, ".", 2)[0], ""))
}

func (e *AWSBaselineEngine) Run(ctx context.Context) {
	e.buildBaselines(ctx, time.Now().Add(-30*24*time.Hour))
	learn := time.NewTicker(15 * time.Minute)
	detect := time.NewTicker(2 * time.Minute)
	defer learn.Stop()
	defer detect.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-learn.C:
			e.buildBaselines(ctx, time.Now().Add(-3*time.Hour))
		case <-detect.C:
			events, err := pageEventCursor(ctx, e.db, "cloud-aws-anomaly", store.EventFilter{EventType: "cloud.cloudtrail"}, 2*time.Minute, 2000)
			if err != nil {
				e.logger.Warn("aws baseline: cursor query failed", "err", err)
				continue
			}
			e.detect(ctx, events)
		}
	}
}

func (e *AWSBaselineEngine) load(ctx context.Context, principal string) *principalBaseline {
	b := &principalBaseline{Principal: principal}
	if val, err := e.db.GetSetting(ctx, "baseline:aws:"+sanitiseKey(principal)); err == nil && val != "" {
		_ = json.Unmarshal([]byte(val), b)
	}
	if b.KnownIPs == nil {
		b.KnownIPs = map[string]ipRecord{}
	}
	if b.KnownMethods == nil {
		b.KnownMethods = map[string]int{}
	}
	return b
}

func (e *AWSBaselineEngine) save(ctx context.Context, b *principalBaseline) {
	b.UpdatedAt = time.Now()
	if data, err := json.Marshal(b); err == nil {
		_ = e.db.SetSetting(ctx, "baseline:aws:"+sanitiseKey(b.Principal), string(data))
	}
}

func (e *AWSBaselineEngine) buildBaselines(ctx context.Context, since time.Time) {
	events, _, err := e.db.QueryEvents(ctx, store.EventFilter{
		EventType: "cloud.cloudtrail", Since: since, Until: time.Now().Add(-baselineLearnDelay), Limit: 5000})
	if err != nil {
		return
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Time.Before(events[j].Time) })
	updates := map[string]*principalBaseline{}
	startWM := map[string]time.Time{}
	for _, ev := range events {
		if int(ev.Severity) > baselineMaxLearnSev {
			continue
		}
		p := awsPrincipal(ev)
		if p == "" {
			continue
		}
		b, ok := updates[p]
		if !ok {
			b = e.load(ctx, p)
			updates[p], startWM[p] = b, b.Watermark
		}
		if !ev.Time.After(startWM[p]) {
			continue
		}
		if ev.Time.After(b.Watermark) {
			b.Watermark = ev.Time
		}
		if ev.SrcIP != nil && awsPublicIP(*ev.SrcIP) {
			rec := b.KnownIPs[*ev.SrcIP]
			if rec.FirstSeen.IsZero() {
				rec.FirstSeen = ev.Time
			}
			rec.LastSeen = ev.Time
			rec.Count++
			b.KnownIPs[*ev.SrcIP] = rec
		}
		if c := awsServiceCategory(ev); c != "" {
			b.KnownMethods[c]++
		}
		b.HourCounts[ev.Time.UTC().Hour()]++
		b.EventCount++
	}
	now := time.Now()
	for _, b := range updates {
		pruneBaseline(b, now)
		e.save(ctx, b)
	}
}

// awsAnomalies evaluates one event against a baseline. Pure, for testing.
// hourIPs is the number of distinct public IPs the principal used in the last hour.
func awsAnomalies(b *principalBaseline, ev store.Event, hourIPs int) []string {
	if b.EventCount < 20 {
		return nil
	}
	var out []string
	if ev.SrcIP != nil && awsPublicIP(*ev.SrcIP) {
		if _, known := b.KnownIPs[*ev.SrcIP]; !known {
			out = append(out, "ANOM-AWS-001")
		}
	}
	if c := awsServiceCategory(ev); c != "" && ev.Severity >= 3 {
		if _, known := b.KnownMethods[c]; !known {
			out = append(out, "ANOM-AWS-002")
		}
	}
	if hourIPs > 3 {
		out = append(out, "ANOM-AWS-004")
	}
	return out
}

func (e *AWSBaselineEngine) detect(ctx context.Context, events []store.Event) {
	if len(events) == 0 {
		return
	}
	ips := map[string]map[string]struct{}{}
	hourEvents, _, _ := e.db.QueryEvents(ctx, store.EventFilter{EventType: "cloud.cloudtrail", Since: time.Now().Add(-time.Hour), Limit: 5000})
	for _, ev := range hourEvents {
		p := awsPrincipal(ev)
		if p == "" || ev.SrcIP == nil || !awsPublicIP(*ev.SrcIP) {
			continue
		}
		if ips[p] == nil {
			ips[p] = map[string]struct{}{}
		}
		ips[p][*ev.SrcIP] = struct{}{}
	}
	cache := map[string]*principalBaseline{}
	seen := map[string]bool{}
	for _, ev := range events {
		p := awsPrincipal(ev)
		if p == "" {
			continue
		}
		b, ok := cache[p]
		if !ok {
			b = e.load(ctx, p)
			cache[p] = b
		}
		ip := "-"
		if ev.SrcIP != nil {
			ip = *ev.SrcIP
		}
		hour := ev.Time.UTC().Format("2006010215")
		for _, id := range awsAnomalies(b, ev, len(ips[p])) {
			cat := awsServiceCategory(ev)
			var title, desc, mitre, tactic, key string
			sev := 3
			switch id {
			case "ANOM-AWS-001":
				title, mitre, tactic, sev = "[ANOM] AWS Principal Activity from Unknown IP", "T1078.004", "Initial Access", 3
				desc = fmt.Sprintf("Principal %s called AWS from IP %s, never seen in its baseline (%d known IPs, %d events).", p, ip, len(b.KnownIPs), b.EventCount)
				key = fmt.Sprintf("anom:aws001:p:%s:ip:%s:h:%s", sanitiseKey(p), sanitiseKey(ip), hour)
			case "ANOM-AWS-002":
				title, mitre, tactic, sev = "[ANOM] AWS Principal Using New Service", "T1078.004", "Discovery", 2
				desc = fmt.Sprintf("Principal %s used the %s service for the first time (baseline of %d events).", p, cat, b.EventCount)
				key = fmt.Sprintf("anom:aws002:p:%s:s:%s:h:%s", sanitiseKey(p), sanitiseKey(cat), hour)
			case "ANOM-AWS-004":
				title, mitre, tactic, sev = "[ANOM] AWS Principal Used From Many IPs", "T1078.004", "Defense Evasion", 4
				desc = fmt.Sprintf("Principal %s was seen from %d distinct public IPs within the last hour.", p, len(ips[p]))
				key = fmt.Sprintf("anom:aws004:p:%s:h:%s", sanitiseKey(p), hour)
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			full := fmt.Sprintf("%s\n\nMITRE ATT&CK: %s | Category: %s\nRegion: %s | Principal: %s | IP: %s", desc, mitre, tactic, ev.Host, p, ip)
			alert := store.Alert{Title: fmt.Sprintf("[%s] %s", mitre, title), Description: full, Severity: sev,
				AgentID: ev.AgentID, Host: ev.Host, EventType: "cloud.aws_anomaly", EventID: key, SourceEventID: ev.ID}
			if _, inserted, err := e.db.CreateAlertDeduped(ctx, alert); err == nil && inserted {
				e.logger.Info("aws anomaly alert fired", "key", key, "principal", p)
			}
		}
	}
}
