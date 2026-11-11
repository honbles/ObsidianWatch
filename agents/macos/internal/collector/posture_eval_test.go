package collector

import "testing"

func macByID(cs []PostureCheck) map[string]PostureCheck {
	m := map[string]PostureCheck{}
	for _, c := range cs {
		m[c.ID] = c
	}
	return m
}

func TestMacPostureHealthy(t *testing.T) {
	got := evalMacPosture(macPostureRaw{
		FileVault: "FileVault is On.", SIP: "System Integrity Protection status: enabled.",
		Gatekeeper: "assessments enabled", FirewallState: "1", AutoUpdate: "1",
		RemoteLogin: "Remote Login: Off", GuestEnabled: "0",
		LaunchctlList: "123 0 com.apple.Finder", LaunchctlReady: true,
		AdminGroup: "GroupMembership: root alice",
	})
	if len(got) != 9 {
		t.Fatalf("expected 9 checks, got %d", len(got))
	}
	for _, c := range got {
		if c.Status != "pass" {
			t.Errorf("%s should pass: %+v", c.ID, c)
		}
	}
}

func TestMacPostureBad(t *testing.T) {
	m := macByID(evalMacPosture(macPostureRaw{
		FileVault: "FileVault is Off.", SIP: "System Integrity Protection status: disabled.",
		Gatekeeper: "assessments disabled", FirewallState: "0", AutoUpdate: "0",
		RemoteLogin: "Remote Login: On", GuestEnabled: "1",
		LaunchctlList: "400 0 com.apple.screensharing", LaunchctlReady: true,
		AdminGroup: "GroupMembership: root a b c",
	}))
	for id, c := range m {
		if c.Status != "fail" {
			t.Errorf("%s should fail: %+v", id, c)
		}
	}
}

func TestMacPostureUnreadableIsUnknown(t *testing.T) {
	m := macByID(evalMacPosture(macPostureRaw{RemoteLogin: "You need Full Disk Access to run systemsetup"}))
	for _, id := range []string{"EC-M-001", "EC-M-002", "EC-M-003", "EC-M-004", "EC-M-006", "EC-M-007", "EC-M-008", "EC-M-009"} {
		if m[id].Status != "unknown" {
			t.Errorf("%s should be unknown, got %s", id, m[id].Status)
		}
	}
	// SIP with a custom configuration is not a clean pass
	c := macByID(evalMacPosture(macPostureRaw{SIP: "System Integrity Protection status: enabled (Custom Configuration)."}))["EC-M-002"]
	if c.Status != "fail" {
		t.Errorf("custom SIP configuration must fail: %+v", c)
	}
}
