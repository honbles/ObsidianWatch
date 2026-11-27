package api

// sast_engine_select.go - which SAST engines a scan runs.
//
// A scan runs a chosen set of engines. With no choice it runs every installed
// non-AI engine, as before. A protected branch's scan profile (code
// automation policy) holds the set used by its scheduled scans, pull request
// checks and manual scans.
//
// A scan that runs only some engines keeps the stored findings of the
// engines it did not run, so running one engine never wipes the others'
// results for that branch.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"obsidianwatch/management/internal/config"
	"obsidianwatch/management/internal/store"
)

// Engine IDs as chosen by people (UI, policy, API).
const (
	engBuiltin       = "builtin"
	engSemgrep       = "semgrep"
	engCodeQL        = "codeql"
	engSecrets       = "secrets"
	engDependencies  = "dependencies"
	engBusinessLogic = "business_logic"
)

// engineCatalog is every selectable engine, in display order.
var engineCatalog = []struct {
	ID, Label, Help string
	AI              bool
}{
	{engBuiltin, "Built-in rules", "OWASP-aligned pattern rules, secrets in files, IaC checks. Always available.", false},
	{engSemgrep, "Opengrep", "Semgrep-compatible rules with taint tracking.", false},
	{engCodeQL, "CodeQL", "Deep data-flow analysis. Slow on large repositories.", false},
	{engSecrets, "Secrets in history", "Every commit of the branch (gitleaks, or the built-in history scan).", false},
	{engDependencies, "Dependencies, IaC and SBOM", "Trivy (or the built-in OSV lookup): vulnerable packages, licences, Dockerfiles.", false},
	{engBusinessLogic, "AI business logic", "Claude reads route handlers for authorization, workflow and trust flaws the pattern engines cannot see. Protected branches only.", true},
}

// engineSet is a chosen set of engine IDs. nil means "the default set".
type engineSet map[string]bool

// defaultEngineIDs is what a scan runs when nothing was chosen: every non-AI engine.
func defaultEngineIDs() []string {
	var out []string
	for _, e := range engineCatalog {
		if !e.AI {
			out = append(out, e.ID)
		}
	}
	return out
}

// parseEngineIDs validates and de-duplicates a list of engine IDs
// (also accepts "opengrep" for semgrep). Empty input returns nil.
func parseEngineIDs(ids []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, raw := range ids {
		id := strings.ToLower(strings.TrimSpace(raw))
		if id == "" {
			continue
		}
		if id == "opengrep" {
			id = engSemgrep
		}
		if id == "business-logic" {
			id = engBusinessLogic
		}
		ok := false
		for _, e := range engineCatalog {
			if e.ID == id {
				ok = true
				break
			}
		}
		if !ok {
			return nil, fmt.Errorf("unknown scan engine %q", raw)
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return engineOrder(out[i]) < engineOrder(out[j]) })
	return out, nil
}

func engineOrder(id string) int {
	for i, e := range engineCatalog {
		if e.ID == id {
			return i
		}
	}
	return len(engineCatalog)
}

func newEngineSet(ids []string) engineSet {
	if len(ids) == 0 {
		return nil
	}
	s := engineSet{}
	for _, id := range ids {
		s[id] = true
	}
	return s
}

// on reports whether an engine runs (nil set: the default, non-AI engines).
func (s engineSet) on(id string) bool {
	if s == nil {
		return id != engBusinessLogic
	}
	return s[id]
}

// partial reports whether the set leaves out a default engine, i.e. the
// stored findings of the engines left out must be kept.
func (s engineSet) partial() bool {
	if s == nil {
		return false
	}
	for _, id := range defaultEngineIDs() {
		if !s[id] {
			return true
		}
	}
	return false
}

func (s engineSet) ids() []string {
	if s == nil {
		return defaultEngineIDs()
	}
	var out []string
	for id := range s {
		out = append(out, id)
	}
	sort.SliceStable(out, func(i, j int) bool { return engineOrder(out[i]) < engineOrder(out[j]) })
	return out
}

// findingEngineID maps a finding's Engine field to the selectable engine
// that produced it.
func findingEngineID(f SASTFinding) string {
	switch f.Engine {
	case "semgrep":
		return engSemgrep
	case "codeql":
		return engCodeQL
	case "gitleaks", "history":
		return engSecrets
	case "trivy", "osv":
		return engDependencies
	case "business-logic":
		return engBusinessLogic
	}
	return engBuiltin
}

// reportKeyEngineID maps an engineReport key to the selectable engine.
func reportKeyEngineID(k string) string {
	switch k {
	case "semgrep":
		return engSemgrep
	case "codeql", "codeql-languages":
		return engCodeQL
	case "secrets-history", "gitleaks", "history":
		return engSecrets
	case "trivy", "osv":
		return engDependencies
	case "business-logic", "business-logic-files":
		return engBusinessLogic
	case "builtin":
		return engBuiltin
	}
	return "" // source, etc.
}

// mergeStoredEngines folds the stored result of the engines this scan did not
// run into its result: their findings, their engine statuses and, when the
// dependency engine did not run, the stored SBOM.
func mergeStoredEngines(ctx context.Context, db *store.DB, connID int64, repo, branch string, set engineSet,
	engines engineReport, findings []SASTFinding, sbom []byte) ([]SASTFinding, []byte) {
	if !set.partial() {
		return findings, sbom
	}
	var fj, ej, sb []byte
	err := db.QueryRowContext(ctx, `SELECT COALESCE(raw_findings, findings), engines, sbom FROM sast_results WHERE connector_id=$1 AND repo=$2 AND branch=$3`,
		connID, repo, branch).Scan(&fj, &ej, &sb)
	if err != nil {
		return findings, sbom
	}
	var stored []SASTFinding
	_ = json.Unmarshal(fj, &stored)
	for _, f := range stored {
		if !set[findingEngineID(f)] {
			f.Fingerprint, f.Triage, f.TriageHint, f.IssueURL, f.Reachability, f.Correlation = "", nil, nil, "", nil, nil
			findings = append(findings, f)
		}
	}
	var se engineReport
	if json.Unmarshal(ej, &se) == nil {
		for k, v := range se {
			if id := reportKeyEngineID(k); id != "" && !set[id] {
				if _, ran := engines[k]; !ran {
					engines[k] = v
				}
			}
		}
	}
	if !set[engDependencies] && len(sb) > 0 {
		sbom = sb
	}
	return findings, sbom
}

// engineStatus is one row of GET .../sast/engines.
type engineStatus struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Help      string `json:"help"`
	AI        bool   `json:"ai"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	Default   bool   `json:"default"`
}

func listEngineStatus(ctx context.Context, cfg *config.Config, db *store.DB) []engineStatus {
	var out []engineStatus
	for _, e := range engineCatalog {
		s := engineStatus{ID: e.ID, Label: e.Label, Help: e.Help, AI: e.AI, Available: true, Default: !e.AI}
		switch e.ID {
		case engSemgrep:
			if !semgrepAvailable() {
				s.Available, s.Reason = false, "no opengrep/semgrep binary or bundled rules on the server"
			}
		case engCodeQL:
			if !codeqlAvailable() {
				s.Available, s.Reason = false, "CodeQL is not installed on the server"
			}
		case engSecrets:
			if toolPath("git") == "" {
				s.Available, s.Reason = false, "git is not installed"
			}
		case engBusinessLogic:
			if err := businessLogicReady(ctx, cfg, db); err != nil {
				s.Available, s.Reason = false, err.Error()
			}
		}
		out = append(out, s)
	}
	return out
}

// handleSASTEngines: GET /api/v1/devops-connectors/{id}/sast/engines.
func handleSASTEngines(cfg *config.Config, db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]interface{}{"engines": listEngineStatus(r.Context(), cfg, db), "code_model": codeModelName(r.Context(), db)})
	}
}
