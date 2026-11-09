package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// G-21: blast radius across the projects of a connector. Identity and global
// resources (internet, service accounts, buckets) are shared nodes so a service
// account used in two projects links them; everything project-scoped is
// namespaced with the project ID to avoid collisions.

const blastMaxProjects = 10

func blastSharedID(id string) bool {
	return strings.HasPrefix(id, "internet:") || strings.HasPrefix(id, "sa:") || strings.HasPrefix(id, "bucket:")
}

func blastNS(project, id string) string {
	if blastSharedID(id) {
		return id
	}
	return project + "|" + id
}

// cspmForProject returns the findings that belong to one project with the
// "<project> / " prefix (added by the multi-project CSPM merge) removed, so
// the blast-radius risk annotation can match them by plain resource name.
func cspmForProject(c *CSPMResult, project string, multi bool) *CSPMResult {
	if c == nil || !multi {
		return c
	}
	pref := project + " / "
	out := &CSPMResult{}
	for _, f := range c.Findings {
		if strings.HasPrefix(f.Resource, pref) {
			f.Resource = strings.TrimPrefix(f.Resource, pref)
			out.Findings = append(out.Findings, f)
		}
	}
	return out
}

func mergeBlast(connID int64, projects []string, results []*BlastRadiusResult, errs map[string]string) *BlastRadiusResult {
	if len(projects) == 1 && len(results) == 1 && results[0] != nil {
		return results[0]
	}
	out := &BlastRadiusResult{ConnectorID: connID, ScannedAt: time.Now().UTC(),
		ProjectID: fmt.Sprintf("%s (+%d more)", projects[0], len(projects)-1)}
	idx := map[string]int{}
	for i, r := range results {
		if r == nil {
			continue
		}
		p := projects[i]
		for _, n := range r.Nodes {
			n.ID = blastNS(p, n.ID)
			if j, ok := idx[n.ID]; ok {
				ex := &out.Nodes[j]
				ex.FindingCount += n.FindingCount
				ex.HasFindings = ex.HasFindings || n.HasFindings
				if sevRank(n.Risk) > sevRank(ex.Risk) {
					ex.Risk = n.Risk
				}
				continue
			}
			idx[n.ID] = len(out.Nodes)
			out.Nodes = append(out.Nodes, n)
		}
		for _, e := range r.Edges {
			e.From, e.To = blastNS(p, e.From), blastNS(p, e.To)
			out.Edges = append(out.Edges, e)
		}
		for _, bp := range r.HighRiskPaths {
			bp.StartNode = blastNS(p, bp.StartNode)
			np := make([]string, len(bp.Path))
			for k, s := range bp.Path {
				np[k] = blastNS(p, s)
			}
			bp.Path = np
			out.HighRiskPaths = append(out.HighRiskPaths, bp)
		}
		out.Summary.PublicExposures += r.Summary.PublicExposures
		out.Summary.PrivEscPaths += r.Summary.PrivEscPaths
		for _, e := range r.Errors {
			out.Errors = append(out.Errors, p+": "+e)
		}
	}
	for _, p := range projects {
		if e, bad := errs[p]; bad {
			out.Errors = append(out.Errors, p+": scan failed: "+e)
		}
	}
	for _, n := range out.Nodes {
		if n.Risk == "critical" || n.Risk == "high" {
			out.Summary.HighRiskNodes++
		}
	}
	out.Summary.TotalNodes = len(out.Nodes)
	out.Summary.TotalEdges = len(out.Edges)
	out.Summary.CriticalPaths = len(out.HighRiskPaths)
	return out
}

func RunGCPBlastRadiusForConnector(ctx context.Context, creds map[string]string, fallbackProject string, cspm *CSPMResult, connID int64) (*BlastRadiusResult, error) {
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
	if len(projects) > blastMaxProjects {
		note = fmt.Sprintf("%d additional project(s) not mapped (limit %d per run)", len(projects)-blastMaxProjects, blastMaxProjects)
		projects = projects[:blastMaxProjects]
	}
	multi := len(projects) > 1
	results := make([]*BlastRadiusResult, len(projects))
	errs := map[string]string{}
	for i, p := range projects {
		pctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		r, e := RunGCPBlastRadius(pctx, saJSON, p, cspmForProject(cspm, p, multi), connID)
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
	out := mergeBlast(connID, projects, results, errs)
	if note != "" {
		out.Errors = append(out.Errors, note)
	}
	return out, nil
}

func azureCSPMForSub(c *AzureCSPMResult, sub string, multi bool) *AzureCSPMResult {
	if c == nil || !multi {
		return c
	}
	pref := sub + " / "
	out := &AzureCSPMResult{}
	for _, f := range c.Findings {
		if strings.HasPrefix(f.Resource, pref) {
			f.Resource = strings.TrimPrefix(f.Resource, pref)
			out.Findings = append(out.Findings, f)
		}
	}
	return out
}

// RunAzureBlastRadiusForConnector maps every subscription of a connector
// (comma list or "*"), merging with the same namespacing as GCP.
func RunAzureBlastRadiusForConnector(ctx context.Context, tenantID, clientID, clientSecret, setting, fallbackSub string, cspm *AzureCSPMResult, connID int64) (*BlastRadiusResult, error) {
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
	if len(subs) > blastMaxProjects {
		note = fmt.Sprintf("%d additional subscription(s) not mapped (limit %d per run)", len(subs)-blastMaxProjects, blastMaxProjects)
		subs = subs[:blastMaxProjects]
	}
	multi := len(subs) > 1
	results := make([]*BlastRadiusResult, len(subs))
	errs := map[string]string{}
	for i, s := range subs {
		sctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		r, e := RunAzureBlastRadius(sctx, tenantID, clientID, clientSecret, s, azureCSPMForSub(cspm, s, multi), connID)
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
	out := mergeBlast(connID, subs, results, errs)
	if note != "" {
		out.Errors = append(out.Errors, note)
	}
	return out, nil
}
