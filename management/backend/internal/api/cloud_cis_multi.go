package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// G-21 / AZ-11: run the CIS subset against every project/subscription of a
// connector and merge. Controls keep their IDs; the title is prefixed with the
// scope so identical controls in different scopes stay distinguishable.

const cisMaxScopes = 25

type cisTally struct {
	passed, failed, unknown, total int
	l1Pass, l1Total, l2Pass, l2Tot int
	score, l1, l2                  float64
}

func tallyCIS(controls []CISControl) cisTally {
	var t cisTally
	for _, c := range controls {
		t.total++
		switch c.Status {
		case "PASS":
			t.passed++
			if c.Level == 1 {
				t.l1Pass++
				t.l1Total++
			} else {
				t.l2Pass++
				t.l2Tot++
			}
		case "FAIL":
			t.failed++
			if c.Level == 1 {
				t.l1Total++
			} else {
				t.l2Tot++
			}
		default:
			t.unknown++
		}
	}
	if d := t.passed + t.failed; d > 0 {
		t.score = float64(t.passed) / float64(d) * 100
	}
	if t.l1Total > 0 {
		t.l1 = float64(t.l1Pass) / float64(t.l1Total) * 100
	}
	if t.l2Tot > 0 {
		t.l2 = float64(t.l2Pass) / float64(t.l2Tot) * 100
	}
	return t
}

func prefixCISControls(scope string, in []CISControl) []CISControl {
	out := make([]CISControl, len(in))
	for i, c := range in {
		c.Title = "[" + scope + "] " + c.Title
		out[i] = c
	}
	return out
}

func mergeGCPCIS(scopes []string, results []*CISResult, errs map[string]string) *CISResult {
	if len(scopes) == 1 && len(results) == 1 && results[0] != nil {
		return results[0]
	}
	out := &CISResult{ScannedAt: time.Now().UTC(), ProjectID: fmt.Sprintf("%s (+%d more)", scopes[0], len(scopes)-1)}
	for i, r := range results {
		if r == nil {
			continue
		}
		out.Controls = append(out.Controls, prefixCISControls(scopes[i], r.Controls)...)
		for _, e := range r.Errors {
			out.Errors = append(out.Errors, scopes[i]+": "+e)
		}
	}
	for _, s := range scopes {
		if e, bad := errs[s]; bad {
			out.Errors = append(out.Errors, s+": scan failed: "+e)
		}
	}
	t := tallyCIS(out.Controls)
	out.TotalChecks, out.Passed, out.Failed, out.Unknown = t.total, t.passed, t.failed, t.unknown
	out.ScorePercent, out.Level1Score, out.Level2Score = t.score, t.l1, t.l2
	return out
}

func mergeAzureCIS(scopes []string, results []*CISAzureResult, errs map[string]string) *CISAzureResult {
	if len(scopes) == 1 && len(results) == 1 && results[0] != nil {
		return results[0]
	}
	out := &CISAzureResult{ScannedAt: time.Now().UTC(), SubscriptionID: fmt.Sprintf("%s (+%d more)", scopes[0], len(scopes)-1)}
	for i, r := range results {
		if r == nil {
			continue
		}
		out.Controls = append(out.Controls, prefixCISControls(scopes[i], r.Controls)...)
		if out.Benchmark == "" {
			out.Benchmark, out.CoverageNote, out.ControlsImplemented = r.Benchmark, r.CoverageNote, r.ControlsImplemented
		}
		for _, e := range r.Errors {
			out.Errors = append(out.Errors, scopes[i]+": "+e)
		}
	}
	for _, s := range scopes {
		if e, bad := errs[s]; bad {
			out.Errors = append(out.Errors, s+": scan failed: "+e)
		}
	}
	t := tallyCIS(out.Controls)
	out.TotalChecks, out.Passed, out.Failed, out.Unknown = t.total, t.passed, t.failed, t.unknown
	out.ScorePercent, out.Level1Score, out.Level2Score = t.score, t.l1, t.l2
	return out
}

func RunGCPCISForConnector(ctx context.Context, creds map[string]string, fallbackProject string) (*CISResult, error) {
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
	note := ""
	if len(projects) > cisMaxScopes {
		note = fmt.Sprintf("%d additional project(s) not scanned (limit %d per run)", len(projects)-cisMaxScopes, cisMaxScopes)
		projects = projects[:cisMaxScopes]
	}
	start := time.Now()
	results := make([]*CISResult, len(projects))
	errs := map[string]string{}
	for i, p := range projects {
		pctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		r, e := RunGCPCISBenchmark(pctx, saJSON, p)
		cancel()
		if e != nil {
			errs[p] = e.Error()
		} else {
			results[i] = r
		}
		if ctx.Err() != nil {
			break
		}
	}
	if len(errs) == len(projects) {
		var m []string
		for p, e := range errs {
			m = append(m, p+": "+e)
		}
		return nil, fmt.Errorf("all projects failed: %s", strings.Join(m, "; "))
	}
	out := mergeGCPCIS(projects, results, errs)
	if note != "" {
		out.Errors = append(out.Errors, note)
	}
	out.ScanDuration = time.Since(start).Round(time.Millisecond).String()
	return out, nil
}

func RunAzureCISForConnector(ctx context.Context, tenantID, clientID, clientSecret, setting, fallbackSub string) (*CISAzureResult, error) {
	var subs []string
	if strings.TrimSpace(setting) == "" && fallbackSub != "" {
		subs = []string{fallbackSub}
	} else {
		tok, err := getAzureToken(ctx, tenantID, clientID, clientSecret, "https://management.azure.com/")
		if err != nil {
			return nil, fmt.Errorf("Azure auth: %w", err)
		}
		subs, err = resolveAzureSubscriptions(ctx, tok.AccessToken, setting)
		if err != nil {
			if fallbackSub == "" {
				return nil, err
			}
			subs = []string{fallbackSub}
		}
	}
	note := ""
	if len(subs) > cisMaxScopes {
		note = fmt.Sprintf("%d additional subscription(s) not scanned (limit %d per run)", len(subs)-cisMaxScopes, cisMaxScopes)
		subs = subs[:cisMaxScopes]
	}
	results := make([]*CISAzureResult, len(subs))
	errs := map[string]string{}
	for i, s := range subs {
		sctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		r, e := RunAzureCISBenchmark(sctx, tenantID, clientID, clientSecret, s)
		cancel()
		if e != nil {
			errs[s] = e.Error()
		} else {
			results[i] = r
		}
		if ctx.Err() != nil {
			break
		}
	}
	if len(errs) == len(subs) {
		var m []string
		for s, e := range errs {
			m = append(m, s+": "+e)
		}
		return nil, fmt.Errorf("all subscriptions failed: %s", strings.Join(m, "; "))
	}
	out := mergeAzureCIS(subs, results, errs)
	if note != "" {
		out.Errors = append(out.Errors, note)
	}
	return out, nil
}
