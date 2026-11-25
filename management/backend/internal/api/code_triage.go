package api

// code_triage.go - Code step 5: analyst triage of code findings, and triage
// that learns from those decisions.
//
// A decision (false positive, accepted risk, confirmed) is stored per
// finding fingerprint, which survives rescans and lines moving. A triage rule
// dismisses a rule for a repository (or every repository) and optionally a
// path prefix, now and in future scans. Dismissed findings are hidden by
// default, never block a PR check, get no PR comment and raise no
// running-vulnerability alert.
//
// Learning: when earlier findings of the same rule in the same repository
// were mostly dismissed (or dismissed across several repositories), new ones
// get a hint "likely false positive" with the evidence and a suggested triage
// rule (narrowed to the directory the dismissed ones share); when they were
// confirmed, "likely true positive". Hints never hide anything on their own.

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

type findingTriage struct {
	Status string    `json:"status"` // false_positive | accepted_risk | confirmed
	Reason string    `json:"reason,omitempty"`
	By     string    `json:"by,omitempty"`
	At     time.Time `json:"at"`
	RuleID int64     `json:"triage_rule_id,omitempty"` // set when a triage rule applied
}

type triageHint struct {
	Suggestion string               `json:"suggestion"` // likely_false_positive | likely_true_positive
	Basis      string               `json:"basis"`
	Rule       *suggestedTriageRule `json:"suggested_rule,omitempty"`
}

type suggestedTriageRule struct {
	Repo       string `json:"repo"`
	RuleID     string `json:"rule_id"`
	PathPrefix string `json:"path_prefix,omitempty"`
}

func dismissed(status string) bool { return status == "false_positive" || status == "accepted_risk" }

// findingDismissed reports whether triage hides this finding.
func findingDismissed(f SASTFinding) bool { return f.Triage != nil && dismissed(f.Triage.Status) }

// snippetCode extracts the flagged source lines from a stored snippet
// ("> 12: code" lines), without line numbers, so it survives lines moving.
func snippetCode(s string) string {
	var marked, all []string
	for _, ln := range strings.Split(s, "\n") {
		t := strings.TrimSpace(ln)
		isMarked := strings.HasPrefix(t, ">")
		t = strings.TrimSpace(strings.TrimPrefix(t, ">"))
		if i := strings.Index(t, ":"); i > 0 && i < 8 {
			if _, err := strconv.Atoi(t[:i]); err == nil {
				t = strings.TrimSpace(t[i+1:])
			}
		}
		if t == "" {
			continue
		}
		all = append(all, t)
		if isMarked {
			marked = append(marked, t)
		}
	}
	if len(marked) > 0 {
		return strings.Join(marked, "\n")
	}
	return strings.Join(all, "\n")
}

// findingFingerprint identifies a finding across scans: rule, file, and the
// package (dependencies) or the flagged code, else the title.
func findingFingerprint(f SASTFinding) string {
	parts := []string{f.RuleID, f.File}
	switch {
	case f.Package != "":
		parts = append(parts, f.Package, f.Version)
	case snippetCode(f.Snippet) != "":
		parts = append(parts, snippetCode(f.Snippet))
	default:
		parts = append(parts, f.Title)
	}
	sum := sha1.Sum([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:8])
}

// ── Index of decisions for one connector ──────────────────────────────────────

type triageRuleRow struct {
	ID         int64      `json:"id"`
	Repo       string     `json:"repo"`
	RuleID     string     `json:"rule_id"`
	PathPrefix string     `json:"path_prefix"`
	Status     string     `json:"status"`
	Reason     string     `json:"reason"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

type triageStats struct {
	dismissed, confirmed int
	dirs                 map[string]int // directory of dismissed findings -> count
}

type triageIndex struct {
	decisions         map[string]findingTriage // repo \x00 fingerprint
	rules             []triageRuleRow
	byRepo            map[string]*triageStats   // repo \x00 rule
	byRule            map[string]map[string]int // rule -> repo -> dismissed
	confirmedAnywhere map[string]int
}

func loadTriageIndex(ctx context.Context, db *store.DB, connID int64) *triageIndex {
	ix := &triageIndex{decisions: map[string]findingTriage{}, byRepo: map[string]*triageStats{},
		byRule: map[string]map[string]int{}, confirmedAnywhere: map[string]int{}}
	rows, err := db.QueryContext(ctx, `SELECT repo, fingerprint, rule_id, file, status, reason, decided_by, decided_at
		FROM code_finding_triage WHERE connector_id=$1`, connID)
	if err == nil {
		for rows.Next() {
			var repo, fp, rule, file string
			var t findingTriage
			if rows.Scan(&repo, &fp, &rule, &file, &t.Status, &t.Reason, &t.By, &t.At) != nil {
				continue
			}
			ix.decisions[repo+"\x00"+fp] = t
			k := repo + "\x00" + rule
			st := ix.byRepo[k]
			if st == nil {
				st = &triageStats{dirs: map[string]int{}}
				ix.byRepo[k] = st
			}
			if dismissed(t.Status) {
				st.dismissed++
				st.dirs[path.Dir(file)]++
				if ix.byRule[rule] == nil {
					ix.byRule[rule] = map[string]int{}
				}
				ix.byRule[rule][repo]++
			} else if t.Status == "confirmed" {
				st.confirmed++
				ix.confirmedAnywhere[rule]++
			}
		}
		rows.Close()
	}
	ix.rules = listTriageRules(ctx, db, connID)
	return ix
}

func listTriageRules(ctx context.Context, db *store.DB, connID int64) []triageRuleRow {
	rows, err := db.QueryContext(ctx, `SELECT id, repo, rule_id, path_prefix, status, reason, created_by, created_at, expires_at
		FROM code_triage_rules WHERE connector_id=$1 AND (expires_at IS NULL OR expires_at > NOW()) ORDER BY id`, connID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []triageRuleRow
	for rows.Next() {
		var r triageRuleRow
		if rows.Scan(&r.ID, &r.Repo, &r.RuleID, &r.PathPrefix, &r.Status, &r.Reason, &r.CreatedBy, &r.CreatedAt, &r.ExpiresAt) == nil {
			out = append(out, r)
		}
	}
	return out
}

func (ix *triageIndex) apply(f *SASTFinding) {
	f.Fingerprint = findingFingerprint(*f)
	if t, ok := ix.decisions[f.Repo+"\x00"+f.Fingerprint]; ok {
		f.Triage = &t
		return
	}
	for _, r := range ix.rules {
		if (r.Repo == "" || r.Repo == f.Repo) && r.RuleID == f.RuleID &&
			(r.PathPrefix == "" || strings.HasPrefix(f.File, r.PathPrefix)) {
			f.Triage = &findingTriage{Status: r.Status, Reason: r.Reason, By: r.CreatedBy, At: r.CreatedAt, RuleID: r.ID}
			return
		}
	}
	f.TriageHint = ix.hint(*f)
}

// hint derives a suggestion from earlier decisions on the same rule.
func (ix *triageIndex) hint(f SASTFinding) *triageHint {
	st := ix.byRepo[f.Repo+"\x00"+f.RuleID]
	if st != nil && st.dismissed >= 3 && st.dismissed >= 4*st.confirmed {
		h := &triageHint{Suggestion: "likely_false_positive",
			Basis: fmt.Sprintf("%d of %d earlier findings of rule %s in this repository were dismissed", st.dismissed, st.dismissed+st.confirmed, f.RuleID),
			Rule:  &suggestedTriageRule{Repo: f.Repo, RuleID: f.RuleID}}
		// Narrow to a directory the dismissed findings share with this one.
		dir := path.Dir(f.File)
		for d, n := range st.dirs {
			if n >= 2 && d != "." && (dir == d || strings.HasPrefix(dir, d+"/")) {
				h.Basis += fmt.Sprintf(" (%d of them under %s/)", n, d)
				h.Rule.PathPrefix = d + "/"
				break
			}
		}
		return h
	}
	if repos := ix.byRule[f.RuleID]; len(repos) >= 3 && ix.confirmedAnywhere[f.RuleID] == 0 {
		n := 0
		for _, c := range repos {
			n += c
		}
		return &triageHint{Suggestion: "likely_false_positive",
			Basis: fmt.Sprintf("rule %s was dismissed %d times across %d repositories of this connector and never confirmed", f.RuleID, n, len(repos)),
			Rule:  &suggestedTriageRule{RuleID: f.RuleID}}
	}
	if st != nil && st.confirmed >= 2 && st.dismissed == 0 {
		return &triageHint{Suggestion: "likely_true_positive",
			Basis: fmt.Sprintf("%d earlier findings of rule %s in this repository were confirmed", st.confirmed, f.RuleID)}
	}
	return nil
}

// enrichFindings adds fingerprints, triage, learned hints and runtime
// reachability. It is applied whenever findings are read.
func enrichFindings(ctx context.Context, db *store.DB, connID int64, findings []SASTFinding) []SASTFinding {
	if len(findings) == 0 {
		return findings
	}
	ix := loadTriageIndex(ctx, db, connID)
	issues := issueLinksByFingerprint(ctx, db, connID)
	for i := range findings {
		ix.apply(&findings[i])
		findings[i].IssueURL = issues[findings[i].Repo+"\x00"+findings[i].Fingerprint]
	}
	return labelFindings(ctx, db, findings)
}

func enrichFindingsJSON(ctx context.Context, db *store.DB, connID int64, raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var f []SASTFinding
	if json.Unmarshal(raw, &f) != nil || len(f) == 0 {
		return raw
	}
	b, err := json.Marshal(enrichFindings(ctx, db, connID, f))
	if err != nil {
		return raw
	}
	return b
}

// withoutDismissed drops findings triage hides.
func withoutDismissed(f []SASTFinding) (kept []SASTFinding, hidden int) {
	for _, x := range f {
		if findingDismissed(x) {
			hidden++
			continue
		}
		kept = append(kept, x)
	}
	return kept, hidden
}

// ── API ───────────────────────────────────────────────────────────────────────

var validTriage = map[string]bool{"false_positive": true, "accepted_risk": true, "confirmed": true}

// handleTriageFinding: POST /api/v1/devops-connectors/{id}/findings/triage
// {repo, finding, status, reason} records a decision; status "" clears it.
func handleTriageFinding(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		var body struct {
			Repo    string      `json:"repo"`
			Finding SASTFinding `json:"finding"`
			Status  string      `json:"status"`
			Reason  string      `json:"reason"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(&body) != nil || body.Finding.RuleID == "" {
			writeJSON(w, 400, map[string]string{"error": "finding with rule_id is required"})
			return
		}
		repo := body.Repo
		if repo == "" {
			repo = body.Finding.Repo
		}
		fp := findingFingerprint(body.Finding)
		if body.Status == "" {
			_, err = db.ExecContext(r.Context(), `DELETE FROM code_finding_triage WHERE connector_id=$1 AND repo=$2 AND fingerprint=$3`, connID, repo, fp)
		} else {
			if !validTriage[body.Status] {
				writeJSON(w, 400, map[string]string{"error": "status must be false_positive, accepted_risk or confirmed"})
				return
			}
			_, err = db.ExecContext(r.Context(), `
				INSERT INTO code_finding_triage (connector_id, repo, fingerprint, rule_id, file, status, reason, decided_by, decided_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
				ON CONFLICT (connector_id, repo, fingerprint) DO UPDATE SET
					status=EXCLUDED.status, reason=EXCLUDED.reason, decided_by=EXCLUDED.decided_by, decided_at=NOW()`,
				connID, repo, fp, body.Finding.RuleID, body.Finding.File, body.Status, truncate(body.Reason, 1000), claimsUsername(r))
		}
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"fingerprint": fp, "status": body.Status})
	}
}

func handleListTriageRules(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		rules := listTriageRules(r.Context(), db, connID)
		if rules == nil {
			rules = []triageRuleRow{}
		}
		writeJSON(w, 200, map[string]interface{}{"rules": rules})
	}
}

// handleCreateTriageRule: POST .../triage-rules {repo, rule_id, path_prefix,
// status, reason, days}. days > 0 makes the rule expire.
func handleCreateTriageRule(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		var b struct {
			Repo       string `json:"repo"`
			RuleID     string `json:"rule_id"`
			PathPrefix string `json:"path_prefix"`
			Status     string `json:"status"`
			Reason     string `json:"reason"`
			Days       int    `json:"days"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&b) != nil || b.RuleID == "" || !dismissed(b.Status) {
			writeJSON(w, 400, map[string]string{"error": "rule_id and a status of false_positive or accepted_risk are required"})
			return
		}
		if strings.TrimSpace(b.Reason) == "" {
			writeJSON(w, 400, map[string]string{"error": "a reason is required for a triage rule"})
			return
		}
		var exp interface{}
		if b.Days > 0 {
			exp = time.Now().AddDate(0, 0, b.Days)
		}
		var id int64
		err = db.QueryRowContext(r.Context(), `INSERT INTO code_triage_rules (connector_id, repo, rule_id, path_prefix, status, reason, created_by, expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
			connID, b.Repo, b.RuleID, strings.TrimPrefix(b.PathPrefix, "/"), b.Status, truncate(b.Reason, 1000), claimsUsername(r), exp).Scan(&id)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]int64{"id": id})
	}
}

func handleDeleteTriageRule(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connID, err1 := strconv.ParseInt(r.PathValue("id"), 10, 64)
		ruleID, err2 := strconv.ParseInt(r.PathValue("rule"), 10, 64)
		if err1 != nil || err2 != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		_, err := db.ExecContext(r.Context(), `DELETE FROM code_triage_rules WHERE id=$1 AND connector_id=$2`, ruleID, connID)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	}
}

// triageSummary counts decisions per status (for the Automation and SAST views).
func triageSummary(f []SASTFinding) map[string]int {
	out := map[string]int{}
	for _, x := range f {
		switch {
		case x.Triage != nil:
			out[x.Triage.Status]++
		case x.TriageHint != nil:
			out["hint_"+x.TriageHint.Suggestion]++
		}
	}
	return out
}

var _ = sort.Strings
