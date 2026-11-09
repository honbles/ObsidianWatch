package api

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// AZ-11: CSPM across every subscription a connector covers. The scheduled scan
// also used to pass the raw (possibly list / "*") setting to a single-sub scan.

const azureCSPMMaxSubs = 25

func mergeAzureCSPM(subs []string, results []*AzureCSPMResult, errs map[string]string) *AzureCSPMResult {
	if len(subs) == 1 && len(results) == 1 && results[0] != nil {
		return results[0]
	}
	out := &AzureCSPMResult{ScannedAt: time.Now().UTC(), SubscriptionID: fmt.Sprintf("%s (+%d more)", subs[0], len(subs)-1)}
	for i, r := range results {
		if r == nil {
			continue
		}
		s := subs[i]
		for _, f := range r.Findings {
			f.Resource = s + " / " + f.Resource
			out.Findings = append(out.Findings, f)
		}
		out.Critical += r.Critical
		out.High += r.High
		out.Medium += r.Medium
		out.Low += r.Low
		out.Passed += r.Passed
		out.DefenderEnabled = out.DefenderEnabled || r.DefenderEnabled
		out.DefenderFindings += r.DefenderFindings
		for _, e := range r.Errors {
			out.Errors = append(out.Errors, s+": "+e)
		}
		for _, n := range r.NotAssessed {
			n.Check = s + ": " + n.Check
			out.NotAssessed = append(out.NotAssessed, n)
		}
	}
	for _, s := range subs {
		if e, bad := errs[s]; bad {
			out.Errors = append(out.Errors, s+": scan failed: "+e)
			out.NotAssessed = append(out.NotAssessed, NotAssessedCheck{Check: s + ": all checks", Reason: e})
		}
	}
	out.TotalFindings = len(out.Findings)
	return out
}

// RunAzureCSPMForConnector scans every subscription named by setting
// (comma list or "*"), falling back to fallbackSub when none is configured.
func RunAzureCSPMForConnector(ctx context.Context, tenantID, clientID, clientSecret, setting, fallbackSub string) (*AzureCSPMResult, error) {
	subs := []string{}
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
	truncated := 0
	if len(subs) > azureCSPMMaxSubs {
		truncated = len(subs) - azureCSPMMaxSubs
		subs = subs[:azureCSPMMaxSubs]
	}
	start := time.Now()
	results := make([]*AzureCSPMResult, len(subs))
	errs := map[string]string{}
	for i, s := range subs {
		sctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
		r, e := RunAzureCSPM(sctx, tenantID, clientID, clientSecret, s)
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
	out := mergeAzureCSPM(subs, results, errs)
	if truncated > 0 {
		out.Errors = append(out.Errors, fmt.Sprintf("%d additional subscription(s) not scanned (limit %d per run)", truncated, azureCSPMMaxSubs))
	}
	out.ScanDuration = time.Since(start).Round(time.Millisecond).String()
	return out, nil
}
