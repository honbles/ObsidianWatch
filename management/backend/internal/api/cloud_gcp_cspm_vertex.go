package api

import (
	"context"
	"fmt"
	"strings"
)

// G-44: Vertex AI Workbench instances (notebooks API v2).

type gcpWorkbenchInstance struct {
	Name     string `json:"name"`
	State    string `json:"state"`
	GceSetup struct {
		DisablePublicIP *bool `json:"disablePublicIp"`
		ServiceAccounts []struct {
			Email string `json:"email"`
		} `json:"serviceAccounts"`
	} `json:"gceSetup"`
}

func evalGCPWorkbench(list []gcpWorkbenchInstance) ([]CSPMFinding, int) {
	var findings []CSPMFinding
	passed := 0
	for _, n := range list {
		label := n.Name[strings.LastIndex(n.Name, "/")+1:]
		bad := false
		// Public IP is the default for Workbench when the field is unset.
		if n.GceSetup.DisablePublicIP == nil || !*n.GceSetup.DisablePublicIP {
			bad = true
			findings = append(findings, CSPMFinding{
				Title:       fmt.Sprintf("Vertex AI Workbench instance '%s' has a public IP", label),
				Description: "A notebook VM with an external address is reachable from the internet and typically holds credentials and data access.",
				Severity:    "high", Category: "compute", Resource: label, ResourceType: "workbench_instance",
				Remediation: "Recreate the instance with public IP disabled and reach it through IAP or Private Google Access.",
				MITRE:       "T1190",
			})
		}
		for _, sa := range n.GceSetup.ServiceAccounts {
			if strings.HasSuffix(sa.Email, "-compute@developer.gserviceaccount.com") {
				bad = true
				findings = append(findings, CSPMFinding{
					Title:       fmt.Sprintf("Vertex AI Workbench instance '%s' runs as the default compute service account", label),
					Description: "The default compute service account is commonly granted Editor on the project, so anyone using the notebook inherits broad access.",
					Severity:    "medium", Category: "iam", Resource: label, ResourceType: "workbench_instance",
					Remediation: "Run the instance as a dedicated service account with only the roles the notebook needs.",
					MITRE:       "T1078.004",
				})
			}
		}
		if !bad {
			passed++
		}
	}
	return findings, passed
}

func checkVertexWorkbench(ctx context.Context, token, projectID string) ([]CSPMFinding, int, error) {
	var all []gcpWorkbenchInstance
	pageTok := ""
	for page := 0; page < 10; page++ {
		var resp struct {
			Instances     []gcpWorkbenchInstance `json:"instances"`
			NextPageToken string                 `json:"nextPageToken"`
		}
		u := fmt.Sprintf("https://notebooks.googleapis.com/v2/projects/%s/locations/-/instances?pageSize=100", projectID)
		if err := gcpCSPMGet(ctx, token, gcpPageURL(u, "pageToken", pageTok), &resp); err != nil {
			return nil, 0, err
		}
		all = append(all, resp.Instances...)
		if resp.NextPageToken == "" {
			break
		}
		pageTok = resp.NextPageToken
	}
	f, p := evalGCPWorkbench(all)
	return f, p, nil
}
