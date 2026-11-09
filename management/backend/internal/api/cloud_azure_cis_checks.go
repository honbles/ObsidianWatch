package api

// H-7: pure, testable evaluation helpers for the Azure CIS subset.

import (
	"strconv"
	"strings"
)

type caPolicy struct {
	DisplayName string `json:"displayName"`
	State       string `json:"state"`
	Conditions  struct {
		Users struct {
			IncludeUsers []string `json:"includeUsers"`
			IncludeRoles []string `json:"includeRoles"`
		} `json:"users"`
		Applications struct {
			IncludeApplications []string `json:"includeApplications"`
		} `json:"applications"`
	} `json:"conditions"`
	GrantControls *struct {
		BuiltInControls []string `json:"builtInControls"`
		AuthStrength    any      `json:"authenticationStrength"`
	} `json:"grantControls"`
}

func hasStr(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

// requiresMFA: enabled policy whose grant controls demand MFA (built-in
// control or an authentication strength). Display names are ignored.
func (p caPolicy) requiresMFA() bool {
	if p.State != "enabled" || p.GrantControls == nil {
		return false
	}
	return hasStr(p.GrantControls.BuiltInControls, "mfa") || p.GrantControls.AuthStrength != nil
}

func (p caPolicy) allApps() bool {
	return hasStr(p.Conditions.Applications.IncludeApplications, "All")
}

// caCoversAllUsersMFA: MFA required for All users on All cloud apps.
func caCoversAllUsersMFA(ps []caPolicy) (string, bool) {
	for _, p := range ps {
		if p.requiresMFA() && hasStr(p.Conditions.Users.IncludeUsers, "All") && p.allApps() {
			return p.DisplayName, true
		}
	}
	return "", false
}

// caCoversPrivilegedMFA: MFA required for all users, or for directory roles.
func caCoversPrivilegedMFA(ps []caPolicy) (string, bool) {
	if n, ok := caCoversAllUsersMFA(ps); ok {
		return n, true
	}
	for _, p := range ps {
		if p.requiresMFA() && len(p.Conditions.Users.IncludeRoles) > 0 && p.allApps() {
			return p.DisplayName, true
		}
	}
	return "", false
}

type nsgRuleProps struct {
	Direction             string   `json:"direction"`
	Access                string   `json:"access"`
	Protocol              string   `json:"protocol"`
	SourceAddressPrefix   string   `json:"sourceAddressPrefix"`
	SourceAddressPrefixes []string `json:"sourceAddressPrefixes"`
	DestinationPortRange  string   `json:"destinationPortRange"`
	DestinationPortRanges []string `json:"destinationPortRanges"`
}

// portInRange handles "*", "3389", and "3000-4000".
func portInRange(spec string, port int) bool {
	spec = strings.TrimSpace(spec)
	if spec == "*" {
		return true
	}
	if lo, hi, ok := strings.Cut(spec, "-"); ok {
		l, e1 := strconv.Atoi(lo)
		h, e2 := strconv.Atoi(hi)
		return e1 == nil && e2 == nil && port >= l && port <= h
	}
	n, err := strconv.Atoi(spec)
	return err == nil && n == port
}

func isInternetSource(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "*", "internet", "any", "0.0.0.0/0", "0.0.0.0", "::/0":
		return true
	}
	return false
}

// nsgRuleExposes reports whether an inbound Allow rule opens port to the internet.
func nsgRuleExposes(r nsgRuleProps, port int) bool {
	if !strings.EqualFold(r.Direction, "Inbound") || !strings.EqualFold(r.Access, "Allow") {
		return false
	}
	if p := strings.ToLower(r.Protocol); p != "*" && p != "tcp" && p != "" {
		return false
	}
	portOK := portInRange(r.DestinationPortRange, port)
	for _, pr := range r.DestinationPortRanges {
		portOK = portOK || portInRange(pr, port)
	}
	if !portOK {
		return false
	}
	srcOK := isInternetSource(r.SourceAddressPrefix)
	for _, s := range r.SourceAddressPrefixes {
		srcOK = srcOK || isInternetSource(s)
	}
	return srcOK
}
