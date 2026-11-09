package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"sort"
)

// G-23: verify the permissions each ObsidianWatch feature needs via
// projects.testIamPermissions, so the connector test reports exactly which
// roles are missing instead of only proving a token can be minted.

var gcpFeaturePermissions = map[string][]string{
	"audit_logs":        {"logging.logEntries.list"},
	"posture_core":      {"compute.firewalls.list", "compute.instances.list", "storage.buckets.list", "storage.buckets.getIamPolicy", "iam.serviceAccounts.list", "resourcemanager.projects.getIamPolicy", "cloudsql.instances.list"},
	"posture_extended":  {"container.clusters.list", "cloudkms.keyRings.list", "bigquery.datasets.get", "secretmanager.secrets.list", "run.services.list", "cloudfunctions.functions.list", "pubsub.topics.list", "dns.managedZones.list"},
	"asset_inventory":   {"cloudasset.assets.listResource"},
	"scc_findings":      {"securitycenter.findings.list"},
	"service_account_keys": {"iam.serviceAccountKeys.list"},
}

// Roles that together cover the permissions above (all read-only).
var gcpRecommendedRoles = []string{
	"roles/logging.viewer", "roles/cloudasset.viewer", "roles/iam.securityReviewer",
	"roles/securitycenter.findingsViewer", "roles/browser",
}

type GCPFeatureAccess struct {
	Feature string   `json:"feature"`
	OK      bool     `json:"ok"`
	Missing []string `json:"missing,omitempty"`
}

func testGCPPermissions(ctx context.Context, token, projectID string) ([]GCPFeatureAccess, error) {
	var all []string
	for _, ps := range gcpFeaturePermissions {
		all = append(all, ps...)
	}
	body, _ := json.Marshal(map[string]interface{}{"permissions": all})
	u := fmt.Sprintf("https://cloudresourcemanager.googleapis.com/v1/projects/%s:testIamPermissions", neturl.PathEscape(projectID))
	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("testIamPermissions %d: %s", resp.StatusCode, string(rb)[:minInt(200, len(rb))])
	}
	var out struct {
		Permissions []string `json:"permissions"`
	}
	if err := json.Unmarshal(rb, &out); err != nil {
		return nil, err
	}
	granted := map[string]bool{}
	for _, p := range out.Permissions {
		granted[p] = true
	}
	res := []GCPFeatureAccess{}
	for feat, ps := range gcpFeaturePermissions {
		fa := GCPFeatureAccess{Feature: feat, OK: true}
		for _, p := range ps {
			if !granted[p] {
				fa.OK = false
				fa.Missing = append(fa.Missing, p)
			}
		}
		res = append(res, fa)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Feature < res[j].Feature })
	return res, nil
}
