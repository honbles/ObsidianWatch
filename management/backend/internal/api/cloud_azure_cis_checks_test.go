package api

import (
	"encoding/json"
	"testing"
)

func TestCAPolicyMFA(t *testing.T) {
	var ps []caPolicy
	json.Unmarshal([]byte(`[
	 {"displayName":"Require something","state":"enabled","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},"grantControls":{"builtInControls":["compliantDevice"]}},
	 {"displayName":"x","state":"disabled","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},"grantControls":{"builtInControls":["mfa"]}}]`), &ps)
	if _, ok := caCoversAllUsersMFA(ps); ok {
		t.Fatal("name containing 'require' / disabled MFA policy must not pass")
	}
	ps = nil
	json.Unmarshal([]byte(`[{"displayName":"MFA all","state":"enabled","conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},"grantControls":{"builtInControls":["mfa"]}}]`), &ps)
	if _, ok := caCoversAllUsersMFA(ps); !ok {
		t.Fatal("real all-users MFA policy should pass")
	}
	ps = nil
	json.Unmarshal([]byte(`[{"displayName":"admins","state":"enabled","conditions":{"users":{"includeRoles":["r1"]},"applications":{"includeApplications":["All"]}},"grantControls":{"builtInControls":["mfa"]}}]`), &ps)
	if _, ok := caCoversPrivilegedMFA(ps); !ok {
		t.Fatal("role-scoped MFA should satisfy privileged check")
	}
	if _, ok := caCoversAllUsersMFA(ps); ok {
		t.Fatal("role-scoped MFA must not satisfy all-users check")
	}
}

func TestNSGExposure(t *testing.T) {
	cases := []struct {
		r    nsgRuleProps
		port int
		want bool
	}{
		{nsgRuleProps{Direction: "Inbound", Access: "Allow", Protocol: "Tcp", SourceAddressPrefix: "*", DestinationPortRange: "3389"}, 3389, true},
		{nsgRuleProps{Direction: "Inbound", Access: "Allow", Protocol: "*", SourceAddressPrefix: "Internet", DestinationPortRange: "*"}, 3389, true},
		{nsgRuleProps{Direction: "Inbound", Access: "Allow", Protocol: "Tcp", SourceAddressPrefix: "*", DestinationPortRange: "3000-4000"}, 3389, true},
		{nsgRuleProps{Direction: "Inbound", Access: "Allow", Protocol: "Tcp", SourceAddressPrefixes: []string{"10.0.0.0/8", "0.0.0.0/0"}, DestinationPortRanges: []string{"80", "22"}}, 22, true},
		{nsgRuleProps{Direction: "Inbound", Access: "Allow", Protocol: "Tcp", SourceAddressPrefix: "10.0.0.0/8", DestinationPortRange: "22"}, 22, false},
		{nsgRuleProps{Direction: "Inbound", Access: "Deny", Protocol: "Tcp", SourceAddressPrefix: "*", DestinationPortRange: "22"}, 22, false},
		{nsgRuleProps{Direction: "Inbound", Access: "Allow", Protocol: "Udp", SourceAddressPrefix: "*", DestinationPortRange: "22"}, 22, false},
		{nsgRuleProps{Direction: "Outbound", Access: "Allow", Protocol: "Tcp", SourceAddressPrefix: "*", DestinationPortRange: "22"}, 22, false},
	}
	for i, c := range cases {
		if got := nsgRuleExposes(c.r, c.port); got != c.want {
			t.Errorf("case %d: got %v want %v", i, got, c.want)
		}
	}
}
