package api

// SA-08: one finding model over the three code scanners. SAST (rule-based and
// semgrep), the sync-time code scan, and DevOps posture each store results in
// their own shape; GET /api/v1/findings returns the latest result per
// connector (and per repo for SAST) normalised to a single schema so they can
// be filtered and triaged together. It is a read-time view: nothing is
// re-stored and scanners are unchanged. Overlapping hits from different
// scanners are collapsed by (repo, file, line, title).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

type UnifiedFinding struct {
	ID          string    `json:"id"`
	Source      string    `json:"source"` // first scanner that reported it: sast | code_scan | posture
	ConnectorID int64     `json:"connector_id"`
	Severity    string    `json:"severity"`
	Category    string    `json:"category"`
	Title       string    `json:"title"`
	Detail      string    `json:"detail,omitempty"`
	Repo        string    `json:"repo,omitempty"`
	File        string    `json:"file,omitempty"`
	Line        int       `json:"line,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
	RuleID      string    `json:"rule_id,omitempty"`
	CWE         string    `json:"cwe,omitempty"`
	ScannedAt   time.Time `json:"scanned_at"`
	Sources     []string  `json:"sources"` // every scanner that reported it
}

func normSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "5":
		return "critical"
	case "high", "4", "error":
		return "high"
	case "medium", "3", "warning", "moderate":
		return "medium"
	case "low", "2":
		return "low"
	}
	return "info"
}

func sevRankStr(s string) int {
	return map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[s]
}

func findingID(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])[:12]
}

func fromSAST(connID int64, scanned time.Time, raw json.RawMessage) []UnifiedFinding {
	var in []struct {
		RuleID   string `json:"rule_id"`
		Severity string `json:"severity"`
		CWE      string `json:"cwe"`
		Title    string `json:"title"`
		Detail   string `json:"detail"`
		Fix      string `json:"fix"`
		Repo     string `json:"repo"`
		File     string `json:"file"`
		Line     int    `json:"line"`
	}
	if json.Unmarshal(raw, &in) != nil {
		return nil
	}
	out := make([]UnifiedFinding, 0, len(in))
	for _, f := range in {
		out = append(out, UnifiedFinding{
			Source: "sast", ConnectorID: connID, Severity: normSeverity(f.Severity), Category: "code",
			Title: f.Title, Detail: f.Detail, Repo: f.Repo, File: f.File, Line: f.Line,
			Remediation: f.Fix, RuleID: f.RuleID, CWE: f.CWE, ScannedAt: scanned,
		})
	}
	return out
}

func fromCodeScan(connID int64, scanned time.Time, raw json.RawMessage) []UnifiedFinding {
	var in []CodeFinding
	if json.Unmarshal(raw, &in) != nil {
		return nil
	}
	out := make([]UnifiedFinding, 0, len(in))
	for _, f := range in {
		line, _ := strconv.Atoi(f.Line)
		out = append(out, UnifiedFinding{
			Source: "code_scan", ConnectorID: connID, Severity: normSeverity(f.Severity), Category: f.Category,
			Title: f.Title, Detail: f.Detail, Repo: f.Repo, File: f.File, Line: line,
			Remediation: f.Remediation, ScannedAt: scanned,
		})
	}
	return out
}

func fromPosture(connID int64, raw string) []UnifiedFinding {
	var in struct {
		Findings  []PostureFinding `json:"findings"`
		ScannedAt time.Time        `json:"scanned_at"`
	}
	if json.Unmarshal([]byte(raw), &in) != nil {
		return nil
	}
	out := make([]UnifiedFinding, 0, len(in.Findings))
	for _, f := range in.Findings {
		out = append(out, UnifiedFinding{
			Source: "posture", ConnectorID: connID, Severity: normSeverity(f.Severity), Category: "posture",
			Title: f.Title, Detail: f.Detail, Repo: f.Resource, Remediation: f.Fix, ScannedAt: in.ScannedAt,
		})
	}
	return out
}

// mergeUnified assigns IDs, collapses duplicates and sorts by severity.
func mergeUnified(in []UnifiedFinding) []UnifiedFinding {
	byKey := map[string]*UnifiedFinding{}
	var order []string
	for _, f := range in {
		key := strings.ToLower(f.Repo + "|" + f.File + "|" + strconv.Itoa(f.Line) + "|" + f.Title)
		if cur, ok := byKey[key]; ok {
			cur.Sources = append(cur.Sources, f.Source)
			if sevRankStr(f.Severity) > sevRankStr(cur.Severity) {
				cur.Severity = f.Severity
			}
			if cur.Remediation == "" {
				cur.Remediation = f.Remediation
			}
			continue
		}
		f.Sources = []string{f.Source}
		f.ID = findingID(f.Source, strconv.FormatInt(f.ConnectorID, 10), f.Repo, f.File, strconv.Itoa(f.Line), f.Title)
		c := f
		byKey[key] = &c
		order = append(order, key)
	}
	out := make([]UnifiedFinding, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	sort.SliceStable(out, func(i, j int) bool { return sevRankStr(out[i].Severity) > sevRankStr(out[j].Severity) })
	return out
}

func loadUnifiedFindings(ctx context.Context, db *store.DB) []UnifiedFinding {
	var all []UnifiedFinding
	// Latest SAST result per connector+repo.
	if rows, err := db.QueryContext(ctx, `
		SELECT DISTINCT ON (connector_id, COALESCE(repo,'')) connector_id, scanned_at, findings
		FROM sast_results ORDER BY connector_id, COALESCE(repo,''), scanned_at DESC`); err == nil {
		for rows.Next() {
			var id int64
			var at time.Time
			var raw json.RawMessage
			if rows.Scan(&id, &at, &raw) == nil {
				all = append(all, fromSAST(id, at, raw)...)
			}
		}
		rows.Close()
	}
	// Latest code-scan result per connector.
	if rows, err := db.QueryContext(ctx, `
		SELECT DISTINCT ON (connector_id) connector_id, scanned_at, findings
		FROM code_scan_results ORDER BY connector_id, scanned_at DESC`); err == nil {
		for rows.Next() {
			var id int64
			var at time.Time
			var raw json.RawMessage
			if rows.Scan(&id, &at, &raw) == nil {
				all = append(all, fromCodeScan(id, at, raw)...)
			}
		}
		rows.Close()
	}
	// Last posture result per connector (stored in settings by DR-02).
	if m, err := db.GetSettingsPrefix(ctx, postureResultPrefix); err == nil {
		for k, v := range m {
			if id, perr := strconv.ParseInt(strings.TrimPrefix(k, postureResultPrefix), 10, 64); perr == nil {
				all = append(all, fromPosture(id, v)...)
			}
		}
	}
	return mergeUnified(all)
}

func handleUnifiedFindings(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		minSev := sevRankStr(strings.ToLower(q.Get("min_severity")))
		src := q.Get("source")
		repo := strings.ToLower(q.Get("repo"))
		all := loadUnifiedFindings(r.Context(), db)
		out := make([]UnifiedFinding, 0, len(all))
		counts := map[string]int{}
		for _, f := range all {
			if minSev > 0 && sevRankStr(f.Severity) < minSev {
				continue
			}
			if src != "" {
				match := false
				for _, s := range f.Sources {
					if s == src {
						match = true
					}
				}
				if !match {
					continue
				}
			}
			if repo != "" && !strings.Contains(strings.ToLower(f.Repo), repo) {
				continue
			}
			counts[f.Severity]++
			out = append(out, f)
		}
		total := len(out)
		if len(out) > 1000 {
			out = out[:1000]
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"findings": out, "total": total, "by_severity": counts})
	}
}
