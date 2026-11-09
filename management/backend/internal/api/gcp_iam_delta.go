package api

// G-25: parse the IAM policy delta of SetIamPolicy audit entries so the
// Owner/Editor rules check the ADDed binding (role + member) rather than
// substring-matching the whole raw blob, which also contained the caller's
// own "user:" principal and REMOVE deltas.

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	"obsidianwatch/management/internal/store"
)

type gcpIAMGrant struct {
	Action string `json:"action"`
	Role   string `json:"role"`
	Member string `json:"member"`
}

// gcpIAMGrantsFromPayload extracts bindingDeltas from a protoPayload.
func gcpIAMGrantsFromPayload(payload json.RawMessage) []gcpIAMGrant {
	var p struct {
		ServiceData struct {
			PolicyDelta struct {
				BindingDeltas []gcpIAMGrant `json:"bindingDeltas"`
			} `json:"policyDelta"`
		} `json:"serviceData"`
	}
	if json.Unmarshal(payload, &p) != nil {
		return nil
	}
	return p.ServiceData.PolicyDelta.BindingDeltas
}

var (
	gcpDomMu      sync.RWMutex
	gcpIntDomains []string
)

// refreshGCPInternalDomains loads the setting gcp.internal_domains
// (comma-separated). Members in those domains are not "external".
func refreshGCPInternalDomains(ctx context.Context, db *store.DB) {
	v, _ := db.GetSetting(ctx, "gcp.internal_domains")
	var out []string
	for _, d := range strings.Split(strings.ToLower(v), ",") {
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, d)
		}
	}
	gcpDomMu.Lock()
	gcpIntDomains = out
	gcpDomMu.Unlock()
}

func emailDomain(s string) string {
	if i := strings.LastIndex(s, "@"); i >= 0 {
		return strings.ToLower(s[i+1:])
	}
	return ""
}

// gcpMemberExternal reports whether a user:/group:/domain: member is outside
// the organisation. With no configured domains, a member is external when its
// domain differs from the caller's own.
func gcpMemberExternal(member, caller string) bool {
	m := strings.ToLower(member)
	var email string
	switch {
	case strings.HasPrefix(m, "user:"), strings.HasPrefix(m, "group:"):
		email = m[strings.Index(m, ":")+1:]
	default:
		return false // serviceAccount:, allUsers etc. are handled by other rules
	}
	dom := emailDomain(email)
	gcpDomMu.RLock()
	doms := gcpIntDomains
	gcpDomMu.RUnlock()
	if len(doms) > 0 {
		for _, d := range doms {
			if dom == d {
				return false
			}
		}
		return true
	}
	cd := emailDomain(caller)
	if cd == "" || strings.HasSuffix(cd, "gserviceaccount.com") {
		return false // cannot tell without configuration; avoid noisy FPs
	}
	return dom != cd
}

func gcpGrantsOf(ev store.Event) []gcpIAMGrant {
	var r struct {
		Grants []gcpIAMGrant `json:"iam_grants"`
	}
	if json.Unmarshal(ev.Raw, &r) != nil {
		return nil
	}
	return r.Grants
}

// gcpExternalRoleGrant: an ADD of `role` to an external member.
func gcpExternalRoleGrant(ev store.Event, role string) bool {
	if ev.EventType != "cloud.gcp_audit" {
		return false
	}
	caller := ""
	if ev.UserName != nil {
		caller = *ev.UserName
	}
	for _, g := range gcpGrantsOf(ev) {
		if strings.EqualFold(g.Action, "ADD") && strings.EqualFold(g.Role, role) && gcpMemberExternal(g.Member, caller) {
			return true
		}
	}
	return false
}
