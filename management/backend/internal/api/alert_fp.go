package api

// alert_fp.go - closing an endpoint alert as a false positive creates a suppression from the alert's own
// evidence, so the same activity stops alerting.
//
//	GET   /api/v1/alerts/{id}/false-positive   the suppression a false-positive close would create, and how many
//	                                            other open alerts it covers
//	POST  /api/v1/alerts/{id}/false-positive   close as false positive; creates the suppression unless asked not
//	                                            to, and closes the other open alerts it covers
//	PATCH /api/v1/alerts/{id}/reopen            reopen; optionally delete the suppression the close created
//
// Only endpoint alerts (built-in signatures, Sigma, threat-intel matches and rare binaries on agent events)
// record evidence and can be closed as false positive. Code, cloud and application alerts are refused (they
// close with a review). Defaults: all hosts, permanent. Threat-intel matches are suppressed by the indicator value
// for every intel source; other rules by the rule plus the strongest evidence (hash, program path, IP or
// domain, process name, file path). A suppression always names a rule and at least one piece of evidence.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

// rareBinaryRuleID is the rule ID of the fleet-prevalence "rare binary" alert.
const rareBinaryRuleID = "PREV-RARE-BINARY"

// AlertEvidence is what an endpoint alert was raised on (stored as alerts.evidence).
type AlertEvidence struct {
	Origin    string `json:"origin"`              // "endpoint"
	Kind      string `json:"kind"`                // signature | sigma | ioc | prevalence
	IOCType   string `json:"ioc_type,omitempty"`  // ioc: hash | ip | domain | url
	Indicator string `json:"indicator,omitempty"` // ioc: the matched indicator value
	EventType string `json:"event_type,omitempty"`
	Hash      string `json:"hash,omitempty"`
	Image     string `json:"image,omitempty"`
	Process   string `json:"process,omitempty"`
	Parent    string `json:"parent,omitempty"`
	User      string `json:"user,omitempty"`
	Cmdline   string `json:"cmdline,omitempty"`
	File      string `json:"file,omitempty"`
	IP        string `json:"ip,omitempty"`
	Domain    string `json:"domain,omitempty"`
	// Outcome is what the agent did about a prevention match: quarantined, killed, killed+quarantined,
	// blocked, ip_blocked, audit (not stopped) or failed.
	Outcome string `json:"outcome,omitempty"`
}

// isEndpointEvent: an agent event, not a code-platform, cloud or application event.
func isEndpointEvent(ev store.Event) bool {
	t := ev.EventType
	return !isCloudEvent(ev) && !strings.HasPrefix(t, "devops.") && !strings.HasPrefix(t, "app.") && t != "scheduled_search"
}

// endpointEvidence records an alert's evidence; nil for non-endpoint events. ioc: type and value.
func endpointEvidence(kind string, ev store.Event, ioc ...string) json.RawMessage {
	if !isEndpointEvent(ev) {
		return nil
	}
	e := AlertEvidence{Origin: "endpoint", Kind: kind, EventType: ev.EventType,
		Image: eventImagePath(ev), Process: derefStr(ev.ProcessName), Parent: eventParent(ev), User: derefStr(ev.UserName),
		File: derefStr(ev.FilePath)}
	if ev.CommandLine != nil && len(*ev.CommandLine) <= 1000 {
		e.Cmdline = *ev.CommandLine
	}
	if hs := eventHashes(ev); len(hs) > 0 {
		e.Hash = preferredHash(hs)
	}
	if ev.EventType == "dns" && ev.DstIP != nil {
		e.Domain = *ev.DstIP // every agent stores the DNS query name in dst_ip
	} else if ev.DstIP != nil && *ev.DstIP != "" {
		e.IP = *ev.DstIP
	} else if ev.SrcIP != nil {
		e.IP = *ev.SrcIP
	}
	if len(ioc) == 2 {
		e.IOCType, e.Indicator = strings.ToLower(ioc[0]), ioc[1]
	}
	if p, ok := prevOf(ev); ok {
		e.Outcome = p.Action
	}
	b, _ := json.Marshal(e)
	return b
}

// preferredHash: SHA-256 (64 hex) over SHA-1 over MD5.
func preferredHash(hs []string) string {
	best := hs[0]
	for _, h := range hs {
		if len(h) > len(best) {
			best = h
		}
	}
	return best
}

// evidenceEvent rebuilds the matching fields of an event from evidence, to test a suppression against it.
func evidenceEvent(host string, e AlertEvidence) store.Event {
	ev := store.Event{Host: host, EventType: e.EventType}
	set := func(v string) *string {
		if v == "" {
			return nil
		}
		return &v
	}
	ev.ProcessName, ev.ImagePath, ev.UserName, ev.CommandLine, ev.FilePath, ev.FileHash =
		set(e.Process), set(e.Image), set(e.User), set(e.Cmdline), set(e.File), set(e.Hash)
	if e.Domain != "" {
		ev.DstIP = set(e.Domain)
	} else {
		ev.DstIP = set(e.IP)
	}
	if e.Parent != "" {
		ev.Raw, _ = json.Marshal(map[string]string{"parent_exe": e.Parent, "ParentImage": e.Parent})
	}
	return ev
}

// interpreters run arbitrary code, so the program alone never identifies benign activity.
var interpreters = map[string]bool{
	"bash": true, "sh": true, "dash": true, "zsh": true, "ksh": true, "fish": true, "busybox": true,
	"python": true, "python2": true, "python3": true, "perl": true, "ruby": true, "node": true, "php": true, "lua": true,
	"osascript": true, "cmd": true, "powershell": true, "pwsh": true, "wscript": true, "cscript": true, "mshta": true,
	"rundll32": true, "regsvr32": true, "msbuild": true, "wmic": true,
}

func isInterpreter(image, process string) bool {
	n := image
	if n == "" {
		n = process
	}
	if n == "" {
		return false
	}
	b := strings.ToLower(suppBase(n))
	if interpreters[b] {
		return true
	}
	// python3.11, perl5.36, ...
	for _, p := range []string{"python", "perl", "ruby", "php"} {
		if strings.HasPrefix(b, p) && strings.Trim(b[len(p):], "0123456789.") == "" {
			return true
		}
	}
	return false
}

// isSystemProgram: a program shipped with the operating system (the paths the agents report).
func isSystemProgram(image string) bool {
	p := strings.ToLower(strings.ReplaceAll(image, `\`, "/"))
	for _, pre := range []string{"/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/usr/lib/systemd/",
		"/system/", "/library/apple/", "c:/windows/"} {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// globLiteral escapes glob metacharacters so a path matches only itself.
func globLiteral(s string) string {
	return strings.NewReplacer(`*`, `[*]`, `?`, `[?]`, `[`, `[[]`).Replace(s)
}

// fpProposal is the suppression a false-positive close of alert a creates by default; ok is false (with a
// reason) when the alert is not eligible.
func fpProposal(a store.Alert) (EndpointSuppression, *AlertEvidence, bool, string) {
	var e AlertEvidence
	if a.RuleID == "" || len(a.Evidence) == 0 || json.Unmarshal(a.Evidence, &e) != nil || e.Origin != "endpoint" {
		return EndpointSuppression{}, nil, false, "this is not an endpoint alert, or it was raised before alerts recorded their evidence. Use Close with Review."
	}
	s := EndpointSuppression{RuleID: a.RuleID, MatchMode: suppModeExact, Permanent: true, SourceAlertID: &a.ID,
		Reason: fmt.Sprintf("False positive: alert #%d (%s)", a.ID, a.Title)}
	if len(s.Reason) > 480 {
		s.Reason = s.Reason[:480]
	}
	switch {
	case e.Kind == "ioc" && e.Indicator != "":
		// The indicator itself is known good: every intel source, any host.
		s.RuleID, s.MatchMode, s.Indicator = "IOC:", suppModePrefix, e.Indicator
	case isInterpreter(e.Image, e.Process) || isSystemProgram(e.Image):
		// A shell, script host or operating-system program (curl, su, certutil...): its hash and path are the
		// same on every machine and are what the rule watches, so suppressing them would switch the rule off.
		// Narrow to what launched it, else to this command line.
		s.ImagePathGlob = globLiteral(e.Image)
		if s.ImagePathGlob == "" {
			s.ProcessName = e.Process
		}
		switch {
		case e.Parent != "" && !isInterpreter(e.Parent, ""):
			s.ParentProcess = suppBase(e.Parent)
		case e.Cmdline != "":
			c := e.Cmdline
			if len(c) > 255 {
				c = c[:255]
			}
			s.CmdlineContain = c
		default:
			return EndpointSuppression{}, &e, false, "The alert was raised on a system program or script host with no parent or command line to narrow the suppression to."
		}
	case e.Hash != "":
		s.FileHash = e.Hash
	case e.Image != "":
		s.ImagePathGlob = globLiteral(e.Image)
	case e.Domain != "":
		s.DNSDomain = e.Domain
	case e.IP != "":
		s.IP = e.IP
	case e.Process != "":
		s.ProcessName = e.Process
	case e.File != "":
		s.FilePathGlob = globLiteral(e.File)
	default:
		return EndpointSuppression{}, &e, false, "The alert records no hash, program, address or file to suppress on."
	}
	return s, &e, true, ""
}

func fpSuppressionMatches(s EndpointSuppression, a store.Alert, now time.Time) bool {
	var e AlertEvidence
	if a.RuleID == "" || json.Unmarshal(a.Evidence, &e) != nil || e.Origin != "endpoint" {
		return false
	}
	return suppressionMatchesIndicator(s, a.RuleID, e.Indicator, evidenceEvent(a.Host, e), now)
}

// coveredOpenAlerts: other open or acknowledged alerts the suppression would have stopped.
func coveredOpenAlerts(ctx context.Context, db *store.DB, s EndpointSuppression, except int64) ([]store.Alert, error) {
	pattern := s.RuleID
	if s.MatchMode == suppModePrefix {
		pattern = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s.RuleID) + "%"
	} else {
		pattern = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s.RuleID)
	}
	rows, err := db.QueryContext(ctx, `SELECT id, COALESCE(host,''), title, rule_id, evidence FROM alerts
		WHERE status IN ('open','acknowledged') AND rule_id LIKE $1 AND evidence IS NOT NULL AND id <> $2
		ORDER BY id LIMIT 5000`, pattern, except)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := time.Now()
	var out []store.Alert
	for rows.Next() {
		var a store.Alert
		if rows.Scan(&a.ID, &a.Host, &a.Title, &a.RuleID, (*[]byte)(&a.Evidence)) == nil && fpSuppressionMatches(s, a, now) {
			out = append(out, a)
		}
	}
	return out, rows.Err()
}

type fpRequest struct {
	Comment       string `json:"comment"`
	NoSuppression bool   `json:"no_suppression"`  // close as false positive only
	ThisHostOnly  bool   `json:"this_host_only"`  // narrow the default (all hosts)
	ExpiresInDays int    `json:"expires_in_days"` // 0: permanent (the default)
}

func applyFPScope(s *EndpointSuppression, a store.Alert, req fpRequest) {
	if req.ThisHostOnly {
		s.Host = a.Host
	}
	if req.ExpiresInDays > 0 {
		s.Permanent, s.ExpiresInDays = false, req.ExpiresInDays
	}
}

func alertIDParam(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid id"})
		return 0, false
	}
	return id, true
}

func handleFalsePositivePreview(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := alertIDParam(w, r)
		if !ok {
			return
		}
		a, err := db.GetAlert(r.Context(), id)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "alert not found"})
			return
		}
		s, ev, eligible, why := fpProposal(*a)
		resp := map[string]interface{}{"endpoint": ev != nil, "eligible": eligible, "reason": why, "evidence": ev, "host": a.Host}
		if eligible {
			req := fpRequest{ThisHostOnly: r.URL.Query().Get("this_host_only") == "true"}
			if d, _ := strconv.Atoi(r.URL.Query().Get("expires_in_days")); d > 0 {
				req.ExpiresInDays = d
			}
			applyFPScope(&s, *a, req)
			covered, _ := coveredOpenAlerts(r.Context(), db, s, a.ID)
			resp["suppression"], resp["covers_open"] = s, len(covered)
		}
		writeJSON(w, 200, resp)
	}
}

func handleFalsePositive(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := alertIDParam(w, r)
		if !ok {
			return
		}
		claims := auth.GetClaims(r)
		var req fpRequest
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		if req.ExpiresInDays < 0 || req.ExpiresInDays > suppMaxExpiryDays {
			writeJSON(w, 400, map[string]string{"error": "expires_in_days must be 0 (permanent) to 365"})
			return
		}
		req.Comment = strings.TrimSpace(req.Comment)
		a, err := db.GetAlert(r.Context(), id)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "alert not found"})
			return
		}
		if a.Status == "closed" {
			writeJSON(w, 409, map[string]string{"error": "the alert is already closed"})
			return
		}
		ctx := r.Context()
		s, ev, eligible, why := fpProposal(*a)
		if ev == nil {
			// Code, cloud and application alerts (and endpoint alerts from before evidence was recorded) are
			// closed with a review instead.
			writeJSON(w, 400, map[string]string{"error": "only endpoint alerts can be closed as false positive: " + why})
			return
		}
		var suppID *int64
		var closedOthers []int64
		if !req.NoSuppression {
			if eligible { // evidence with nothing to match on: close without a suppression
				applyFPScope(&s, *a, req)
				if req.Comment != "" {
					s.Reason = strings.TrimSpace(s.Reason + ". " + req.Comment)
					if len(s.Reason) > 500 {
						s.Reason = s.Reason[:500]
					}
				}
				if msg := validateSuppression(&s, time.Now()); msg != "" {
					writeJSON(w, 400, map[string]string{"error": "could not build the suppression: " + msg})
					return
				}
				var sid int64
				if err := db.QueryRowContext(ctx, `
					INSERT INTO endpoint_suppressions (rule_id, match_mode, host, process_name, image_path_glob, parent_process,
						user_name, cmdline_contains, file_path_glob, file_hash, ip, dns_domain, indicator, source_alert_id,
						reason, created_by, expires_at, permanent)
					VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) RETURNING id`,
					s.RuleID, s.MatchMode, s.Host, s.ProcessName, s.ImagePathGlob, s.ParentProcess, s.UserName, s.CmdlineContain,
					s.FilePathGlob, s.FileHash, s.IP, s.DNSDomain, s.Indicator, a.ID, s.Reason, claims.Username, s.ExpiresAt, s.Permanent,
				).Scan(&sid); err != nil {
					writeJSON(w, 500, map[string]string{"error": "could not save the suppression"})
					return
				}
				suppID = &sid
				db.WriteAudit(ctx, claims.Username, "create_suppression", "suppression:"+strconv.FormatInt(sid, 10), suppAuditDetail(s), clientIP(r))
				if covered, err := coveredOpenAlerts(ctx, db, s, a.ID); err == nil {
					note := fmt.Sprintf("Closed as false positive: covered by suppression #%d from alert #%d.", sid, a.ID)
					for _, c := range covered {
						if closeFalsePositive(ctx, db, c.ID, claims.Username, note, nil) == nil {
							closedOthers = append(closedOthers, c.ID)
						}
					}
				}
				refreshEndpointSuppressions(ctx, db)
			}
		}
		comment := req.Comment
		if comment == "" {
			comment = "False positive."
		}
		if err := closeFalsePositive(ctx, db, a.ID, claims.Username, comment, suppID); err != nil {
			writeJSON(w, 500, map[string]string{"error": "could not close the alert"})
			return
		}
		detail := comment
		if suppID != nil {
			detail = fmt.Sprintf("%s (suppression #%d; also closed %d alerts)", comment, *suppID, len(closedOthers))
		}
		db.WriteAudit(ctx, claims.Username, "close_alert_false_positive", strconv.FormatInt(a.ID, 10), detail, clientIP(r))
		if closedOthers == nil {
			closedOthers = []int64{}
		}
		writeJSON(w, 200, map[string]interface{}{"status": "closed", "disposition": "false_positive", "suppression_id": suppID, "also_closed": closedOthers})
	}
}

func closeFalsePositive(ctx context.Context, db *store.DB, id int64, by, comment string, suppID *int64) error {
	_, err := db.ExecContext(ctx, `UPDATE alerts SET status = 'closed', disposition = 'false_positive', closed_by = $2,
		closed_at = NOW(), review_comment = NULLIF($3, ''), suppression_id = COALESCE($4, suppression_id)
		WHERE id = $1 AND status <> 'closed'`, id, by, comment, suppID)
	return err
}

func handleReopenAlert(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := alertIDParam(w, r)
		if !ok {
			return
		}
		var req struct {
			RemoveSuppression bool `json:"remove_suppression"`
		}
		if r.ContentLength != 0 {
			r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, 400, map[string]string{"error": "invalid body"})
				return
			}
		}
		claims := auth.GetClaims(r)
		a, err := db.GetAlert(r.Context(), id)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "alert not found"})
			return
		}
		ctx := r.Context()
		removed := false
		if req.RemoveSuppression && a.SuppressionID != nil {
			res, err := db.ExecContext(ctx, `DELETE FROM endpoint_suppressions WHERE id = $1 AND source_alert_id = $2`, *a.SuppressionID, a.ID)
			if err == nil {
				if n, _ := res.RowsAffected(); n > 0 {
					removed = true
					db.WriteAudit(ctx, claims.Username, "delete_suppression", "suppression:"+strconv.FormatInt(*a.SuppressionID, 10),
						fmt.Sprintf("removed on reopening alert #%d", a.ID), clientIP(r))
					refreshEndpointSuppressions(ctx, db)
				}
			}
		}
		if _, err := db.ExecContext(ctx, `UPDATE alerts SET status = 'open', disposition = NULL, closed_by = NULL, closed_at = NULL,
			suppression_id = CASE WHEN $2 THEN NULL ELSE suppression_id END WHERE id = $1`, a.ID, removed); err != nil {
			writeJSON(w, 500, map[string]string{"error": "could not reopen the alert"})
			return
		}
		db.WriteAudit(ctx, claims.Username, "reopen_alert", strconv.FormatInt(a.ID, 10), fmt.Sprintf("suppression removed: %v", removed), clientIP(r))
		writeJSON(w, 200, map[string]interface{}{"status": "open", "suppression_removed": removed})
	}
}
