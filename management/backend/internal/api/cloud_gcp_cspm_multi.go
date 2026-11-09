package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// G-21: CSPM across every project a connector covers.

const gcpCSPMMaxProjects = 25

// mergeGCPCSPM folds per-project results into one. With more than one project,
// each finding's Resource is prefixed with its project so findings stay
// attributable, and IDs (already project-derived) are untouched.
func mergeGCPCSPM(projects []string, results []*CSPMResult, errs map[string]string) *CSPMResult {
	out := &CSPMResult{ScannedAt: time.Now().UTC()}
	if len(projects) == 1 && len(results) == 1 && results[0] != nil {
		return results[0]
	}
	out.ProjectID = fmt.Sprintf("%s (+%d more)", projects[0], len(projects)-1)
	seenSrc := map[string]bool{}
	for i, r := range results {
		if r == nil {
			continue
		}
		p := projects[i]
		for _, f := range r.Findings {
			f.Resource = p + " / " + f.Resource
			out.Findings = append(out.Findings, f)
		}
		out.Critical += r.Critical
		out.High += r.High
		out.Medium += r.Medium
		out.Low += r.Low
		out.Passed += r.Passed
		out.SCCFindings += r.SCCFindings
		out.SCCEnabled = out.SCCEnabled || r.SCCEnabled
		for _, s := range r.SCCSources {
			if !seenSrc[s] {
				seenSrc[s] = true
				out.SCCSources = append(out.SCCSources, s)
			}
		}
		for _, e := range r.Errors {
			out.Errors = append(out.Errors, p+": "+e)
		}
		for _, n := range r.NotAssessed {
			n.Check = p + ": " + n.Check
			out.NotAssessed = append(out.NotAssessed, n)
		}
	}
	for _, p := range projects {
		if e, bad := errs[p]; bad {
			out.Errors = append(out.Errors, p+": scan failed: "+e)
			out.NotAssessed = append(out.NotAssessed, NotAssessedCheck{Check: p + ": all checks", Reason: e})
		}
	}
	out.TotalFindings = len(out.Findings)
	return out
}

// RunGCPCSPMForConnector scans the connector's project(s). creds is the
// connector credential map; fallbackProject is used when none is configured.
func RunGCPCSPMForConnector(ctx context.Context, creds map[string]string, fallbackProject string) (*CSPMResult, error) {
	saJSON := creds["service_account"]
	var sa gcpServiceAccount
	_ = json.Unmarshal([]byte(saJSON), &sa)
	projects, err := resolveGCPProjects(ctx, sa, creds["project_id"], creds["org_id"], creds["folder_id"])
	if err != nil || len(projects) == 0 {
		if fallbackProject == "" {
			if err == nil {
				err = fmt.Errorf("no project configured")
			}
			return nil, err
		}
		projects = []string{fallbackProject}
	}
	truncated := 0
	if len(projects) > gcpCSPMMaxProjects {
		truncated = len(projects) - gcpCSPMMaxProjects
		projects = projects[:gcpCSPMMaxProjects]
	}
	start := time.Now()
	results := make([]*CSPMResult, len(projects))
	errs := map[string]string{}
	for i, p := range projects {
		pctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
		r, e := RunGCPCSPM(pctx, saJSON, p)
		cancel()
		if e != nil {
			errs[p] = e.Error()
			continue
		}
		results[i] = r
		if ctx.Err() != nil {
			break
		}
	}
	if len(errs) == len(projects) {
		var msgs []string
		for p, e := range errs {
			msgs = append(msgs, p+": "+e)
		}
		return nil, fmt.Errorf("all projects failed: %s", strings.Join(msgs, "; "))
	}
	out := mergeGCPCSPM(projects, results, errs)
	if truncated > 0 {
		out.Errors = append(out.Errors, fmt.Sprintf("%d additional project(s) not scanned (limit %d per run)", truncated, gcpCSPMMaxProjects))
	}
	out.ScanDuration = time.Since(start).Round(time.Millisecond).String()
	return out, nil
}
