package api

// cloud_aws_org.go — AWS Organizations onboarding (CR-02).
// Lists the member accounts of the organisation that the connector's
// (management-account) credentials belong to and creates one AWS connector per
// active account, each assuming a read-only role of a given name in that
// account. Every existing per-account feature (sync, CSPM, CIS, assets, blast
// radius, suppression) then works per account with no further changes.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

type awsOrgAccount struct {
	ID, Name, Email, Status string
}

var awsRoleNameRe = regexp.MustCompile(`^[\w+=,.@-]{1,64}$`)

const awsOrgMaxAccounts = 200

func parseAWSOrgAccounts(b []byte) (accts []awsOrgAccount, next string) {
	var r struct {
		Accounts []struct {
			ID     string `json:"Id"`
			Name   string `json:"Name"`
			Email  string `json:"Email"`
			Status string `json:"Status"`
		} `json:"Accounts"`
		NextToken string `json:"NextToken"`
	}
	if json.Unmarshal(b, &r) != nil {
		return nil, ""
	}
	for _, a := range r.Accounts {
		accts = append(accts, awsOrgAccount{a.ID, a.Name, a.Email, a.Status})
	}
	return accts, r.NextToken
}

// awsMemberCreds derives a member-account connector's credentials from the
// management connector's; the member's role is assumed with those base keys.
func awsMemberCreds(base map[string]string, acct awsOrgAccount, roleName, externalID string) map[string]string {
	c := map[string]string{
		"access_key_id":     base["access_key_id"],
		"secret_access_key": base["secret_access_key"],
		"region":            base["region"],
		"account_id":        acct.ID,
		"role_arn":          fmt.Sprintf("arn:aws:iam::%s:role/%s", acct.ID, roleName),
	}
	if base["session_token"] != "" {
		c["session_token"] = base["session_token"]
	}
	if externalID != "" {
		c["external_id"] = externalID
	}
	return c
}

func handleAWSOrgImport(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := parseID(r.PathValue("id"))
		conn, cerr := db.GetCloudConnectorRaw(r.Context(), id)
		if err != nil || cerr != nil || conn.Provider != "aws" {
			writeJSON(w, 404, map[string]string{"error": "AWS connector not found"})
			return
		}
		var req struct {
			RoleName   string `json:"role_name"`
			ExternalID string `json:"external_id"`
			DryRun     bool   `json:"dry_run"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&req) != nil || !awsRoleNameRe.MatchString(req.RoleName) {
			writeJSON(w, 400, map[string]string{"error": "role_name (the read-only role to assume in each member account) is required"})
			return
		}
		creds, err := resolveAWSCreds(r.Context(), conn.Credentials)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		creds.Region = "us-east-1" // Organizations is a global service served from us-east-1
		var all []awsOrgAccount
		next := ""
		for page := 0; page < 10 && len(all) < awsOrgMaxAccounts; page++ {
			body := `{"MaxResults":20}`
			if next != "" {
				nb, _ := json.Marshal(map[string]interface{}{"MaxResults": 20, "NextToken": next})
				body = string(nb)
			}
			b, code, perr := awsJSONPost(ctx, creds, "organizations", "organizations.us-east-1.amazonaws.com", "AWSOrganizationsV20161128.ListAccounts", body)
			if perr != nil || code != 200 {
				msg := "ListAccounts failed — the credentials must belong to the organisation's management (or delegated admin) account with organizations:ListAccounts"
				if perr == nil {
					msg += fmt.Sprintf(" (HTTP %d)", code)
				}
				writeJSON(w, 400, map[string]string{"error": msg})
				return
			}
			var accts []awsOrgAccount
			accts, next = parseAWSOrgAccounts(b)
			all = append(all, accts...)
			if next == "" {
				break
			}
		}
		type out struct {
			AccountID string `json:"account_id"`
			Name      string `json:"name"`
			Status    string `json:"status"`
			Connector int64  `json:"connector_id,omitempty"`
		}
		var res []out
		skipped := 0
		for _, a := range all {
			if a.Status != "ACTIVE" || a.ID == conn.AccountID || len(res) >= awsOrgMaxAccounts {
				skipped++
				continue
			}
			o := out{AccountID: a.ID, Name: a.Name, Status: "would_import"}
			if !req.DryRun {
				cid, uerr := db.UpsertCloudConnector(r.Context(), "aws", awsMemberCreds(conn.Credentials, a, req.RoleName, req.ExternalID))
				if uerr != nil {
					o.Status = "error"
				} else {
					o.Status, o.Connector = "imported", cid
					db.SetCloudConnectorLabel(r.Context(), cid, strings.TrimSpace(a.Name))
				}
			}
			res = append(res, o)
		}
		writeJSON(w, 200, map[string]interface{}{"accounts": res, "skipped": skipped, "dry_run": req.DryRun,
			"note": "Each imported account assumes " + req.RoleName + " using this connector's credentials; the role's trust policy must allow them."})
	}
}
