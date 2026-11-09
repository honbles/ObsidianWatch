package api

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// G-44: unrestricted API keys (CIS GCP 1.12-1.14 family). A key with no
// application restriction and no API target list can be used from anywhere
// against every enabled API.

type gcpAPIKey struct {
	Name         string `json:"name"`
	DisplayName  string `json:"displayName"`
	CreateTime   string `json:"createTime"`
	Restrictions *struct {
		BrowserKeyRestrictions *struct{} `json:"browserKeyRestrictions"`
		ServerKeyRestrictions  *struct{} `json:"serverKeyRestrictions"`
		AndroidKeyRestrictions *struct{} `json:"androidKeyRestrictions"`
		IosKeyRestrictions     *struct{} `json:"iosKeyRestrictions"`
		APITargets             []struct {
			Service string `json:"service"`
		} `json:"apiTargets"`
	} `json:"restrictions"`
}

func evalGCPAPIKeys(keys []gcpAPIKey, now time.Time) ([]CSPMFinding, int) {
	var findings []CSPMFinding
	passed := 0
	for _, k := range keys {
		label := k.DisplayName
		if label == "" {
			label = k.Name[strings.LastIndex(k.Name, "/")+1:]
		}
		appRestricted := k.Restrictions != nil && (k.Restrictions.BrowserKeyRestrictions != nil ||
			k.Restrictions.ServerKeyRestrictions != nil || k.Restrictions.AndroidKeyRestrictions != nil ||
			k.Restrictions.IosKeyRestrictions != nil)
		apiRestricted := k.Restrictions != nil && len(k.Restrictions.APITargets) > 0
		bad := false
		if !appRestricted && !apiRestricted {
			bad = true
			findings = append(findings, CSPMFinding{
				Title:       fmt.Sprintf("API key '%s' is unrestricted", label),
				Description: "This API key has neither an application restriction nor an API target list, so anyone who obtains it can call every enabled Google API with your project's quota and billing.",
				Severity:    "high", Category: "iam", Resource: label, ResourceType: "api_key",
				Remediation: "Restrict the key to its calling application (HTTP referrer, IP, or app ID) and to only the APIs it needs, or delete it if unused.",
				MITRE:       "T1552.001",
			})
		} else if !apiRestricted {
			bad = true
			findings = append(findings, CSPMFinding{
				Title:       fmt.Sprintf("API key '%s' has no API target restriction", label),
				Description: "The key is limited by application but can still call every enabled API.",
				Severity:    "medium", Category: "iam", Resource: label, ResourceType: "api_key",
				Remediation: "Add an API target list so the key can only call the services it requires.",
				MITRE:       "T1552.001",
			})
		}
		if t, err := time.Parse(time.RFC3339, k.CreateTime); err == nil && now.Sub(t) > 90*24*time.Hour {
			bad = true
			findings = append(findings, CSPMFinding{
				Title:       fmt.Sprintf("API key '%s' is older than 90 days", label),
				Description: "Long-lived API keys increase the window in which a leaked key stays useful.",
				Severity:    "low", Category: "iam", Resource: label, ResourceType: "api_key",
				Remediation: "Rotate the key at least every 90 days.",
				MITRE:       "T1552.001",
			})
		}
		if !bad {
			passed++
		}
	}
	return findings, passed
}

func checkAPIKeys(ctx context.Context, token, projectID string) ([]CSPMFinding, int, error) {
	var all []gcpAPIKey
	pageTok := ""
	for page := 0; page < 10; page++ {
		var resp struct {
			Keys          []gcpAPIKey `json:"keys"`
			NextPageToken string      `json:"nextPageToken"`
		}
		u := fmt.Sprintf("https://apikeys.googleapis.com/v2/projects/%s/locations/global/keys?pageSize=100", projectID)
		if err := gcpCSPMGet(ctx, token, gcpPageURL(u, "pageToken", pageTok), &resp); err != nil {
			return nil, 0, err
		}
		all = append(all, resp.Keys...)
		if resp.NextPageToken == "" {
			break
		}
		pageTok = resp.NextPageToken
	}
	f, p := evalGCPAPIKeys(all, time.Now())
	return f, p, nil
}
