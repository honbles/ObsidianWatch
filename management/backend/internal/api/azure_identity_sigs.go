package api

// AZ-03: typed Entra sign-in rules. They read structured fields from the
// sign-in record instead of substring-matching the whole raw blob.

import (
	"encoding/json"
	"strings"

	"obsidianwatch/management/internal/store"
)

type entraSignInRaw struct {
	ClientApp string `json:"client_app_used"`
	CAStatus  string `json:"conditional_access_status"`
	RiskLevel string `json:"risk_level"`
	RiskState string `json:"risk_state"`
	Kind      string `json:"sign_in_kind"`
	Status    struct {
		ErrorCode int `json:"errorCode"`
	} `json:"status"`
}

func parseEntraSignIn(ev store.Event) (entraSignInRaw, bool) {
	var r entraSignInRaw
	if ev.EventType != "cloud.entra_signin" || len(ev.Raw) == 0 {
		return r, false
	}
	if json.Unmarshal(ev.Raw, &r) != nil {
		return r, false
	}
	return r, true
}

var entraLegacyClients = []string{"imap", "pop", "smtp", "exchange activesync", "other clients", "authenticated smtp", "autodiscover", "exchange web services", "mapi over http", "offline address book", "reporting web services", "exchange online powershell", "universal outlook"}

var entraIdentitySignatures = []ThreatSig{
	{
		ID: "C-AZ-ID-001", Name: "Entra Sign-in Flagged Risky",
		Description: "Entra ID Protection marked a successful sign-in as at risk or confirmed compromised.",
		Severity: 4, MITRE: "T1078.004", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			r, ok := parseEntraSignIn(ev)
			return ok && r.Status.ErrorCode == 0 &&
				(r.RiskState == "atRisk" || r.RiskState == "confirmedCompromised")
		},
	},
	{
		ID: "C-AZ-ID-002", Name: "Entra Legacy Authentication Succeeded",
		Description: "A sign-in succeeded using a legacy protocol (IMAP/POP/SMTP/ActiveSync) that cannot do MFA or Conditional Access — a common password-spray target.",
		Severity: 3, MITRE: "T1078.004", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			r, ok := parseEntraSignIn(ev)
			if !ok || r.Status.ErrorCode != 0 {
				return false
			}
			c := strings.ToLower(r.ClientApp)
			return c != "" && containsAny(c, entraLegacyClients...)
		},
	},
	{
		ID: "C-AZ-ID-003", Name: "Entra Sign-in Bypassed Conditional Access",
		Description: "A successful sign-in was not evaluated by any Conditional Access policy.",
		Severity: 2, MITRE: "T1556", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			r, ok := parseEntraSignIn(ev)
			return ok && r.Status.ErrorCode == 0 && strings.EqualFold(r.CAStatus, "notApplied")
		},
	},
	{
		ID: "C-AZ-ID-004", Name: "Entra High-Risk Sign-in Blocked or Failed",
		Description: "Entra ID Protection rated an attempted sign-in high risk (it did not complete).",
		Severity: 3, MITRE: "T1110", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			r, ok := parseEntraSignIn(ev)
			return ok && r.Status.ErrorCode != 0 && strings.EqualFold(r.RiskLevel, "high")
		},
	},
	{
		ID: "C-AZ-ID-005", Name: "Entra Service Principal Sign-in With Invalid Credential",
		Description: "A service principal or managed identity failed to authenticate with an invalid, expired or unknown secret/certificate (AADSTS7000215, 7000222, 7000112, 700027). Repeated failures can indicate a stolen or guessed application secret.",
		Severity: 3, MITRE: "T1078.004", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			r, ok := parseEntraSignIn(ev)
			if !ok || r.Kind != "service_principal" {
				return false
			}
			switch r.Status.ErrorCode {
			case 7000215, 7000222, 7000112, 700027:
				return true
			}
			return false
		},
	},
}
