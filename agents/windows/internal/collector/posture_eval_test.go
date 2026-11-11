package collector

import (
	"encoding/json"
	"testing"
)

func bp(v bool) *bool     { return &v }
func ip(v int) *int       { return &v }
func sp(v string) *string { return &v }

func byID(cs []PostureCheck) map[string]PostureCheck {
	m := map[string]PostureCheck{}
	for _, c := range cs {
		m[c.ID] = c
	}
	return m
}

func TestWindowsPostureHealthyHost(t *testing.T) {
	var raw winPostureRaw
	if err := json.Unmarshal([]byte(`{
	 "av":[{"name":"Windows Defender","enabled":true,"up_to_date":true}],
	 "defender":{"realtime":true,"sig_age_days":1,"tamper":true},
	 "firewall":[{"name":"Domain","enabled":true},{"name":"Private","enabled":true},{"name":"Public","enabled":true}],
	 "bitlocker":"On","hotfix_age_days":12,"enable_lua":1,"smb1":false,"rdp_deny":1,
	 "guest_enabled":false,"admin_enabled":false,"local_admins":2,"min_password_length":14,"lockout_threshold":5,
	 "inactivity_secs":600,"secure_boot":true,"tpm_ready":true,"script_block_logging":1,"autorun_mask":255,
	 "run_as_ppl":1,"audit_logon":"Logon   Success and Failure"}`), &raw); err != nil {
		t.Fatal(err)
	}
	got := evalWindowsPosture(raw)
	if len(got) != 22 {
		t.Fatalf("expected 22 checks, got %d", len(got))
	}
	for _, c := range got {
		if c.Status != "pass" {
			t.Errorf("%s should pass on a hardened host: %+v", c.ID, c)
		}
	}
}

func TestWindowsPostureBadHost(t *testing.T) {
	raw := winPostureRaw{
		AV: json.RawMessage(`{"name":"Contoso AV","enabled":false,"up_to_date":false}`), // single object form
		Defender: &struct {
			Realtime   *bool `json:"realtime"`
			SigAgeDays *int  `json:"sig_age_days"`
			Tamper     *bool `json:"tamper"`
		}{Realtime: bp(false), SigAgeDays: ip(30), Tamper: bp(false)},
		Firewall:          json.RawMessage(`[{"name":"Public","enabled":false},{"name":"Domain","enabled":true}]`),
		BitLocker:         sp("Off"),
		HotfixAgeDays:     ip(200),
		EnableLUA:         ip(0),
		SMB1:              bp(true),
		RDPDeny:           ip(0),
		RDPNLA:            ip(0),
		GuestEnabled:      bp(true),
		AdminEnabled:      bp(true),
		LocalAdmins:       ip(9),
		MinPasswordLength: ip(6),
		LockoutThreshold:  ip(0),
		InactivitySecs:    ip(3600),
		AuditLogon:        "Logon   Success",
	}
	m := byID(evalWindowsPosture(raw))
	for _, id := range []string{"EC-W-001", "EC-W-002", "EC-W-003", "EC-W-004", "EC-W-005", "EC-W-006", "EC-W-007",
		"EC-W-008", "EC-W-009", "EC-W-010", "EC-W-011", "EC-W-012", "EC-W-013", "EC-W-014", "EC-W-015", "EC-W-016",
		"EC-W-019", "EC-W-020", "EC-W-021", "EC-W-022"} {
		if m[id].Status != "fail" {
			t.Errorf("%s should fail: %+v", id, m[id])
		}
	}
	for _, id := range []string{"EC-W-017", "EC-W-018"} {
		if m[id].Status != "unknown" {
			t.Errorf("%s should be unknown when not readable: %+v", id, m[id])
		}
	}
	if m["EC-W-005"].Detail != "off for: Public" {
		t.Errorf("firewall detail: %q", m["EC-W-005"].Detail)
	}
}

func TestThirdPartyAVWithPassiveDefenderIsFine(t *testing.T) {
	raw := winPostureRaw{
		AV: json.RawMessage(`[{"name":"CrowdStrike Falcon","enabled":true,"up_to_date":true},{"name":"Windows Defender","enabled":false,"up_to_date":true}]`),
	}
	raw.Defender = &struct {
		Realtime   *bool `json:"realtime"`
		SigAgeDays *int  `json:"sig_age_days"`
		Tamper     *bool `json:"tamper"`
	}{Realtime: bp(false), SigAgeDays: ip(90)}
	m := byID(evalWindowsPosture(raw))
	for _, id := range []string{"EC-W-001", "EC-W-002", "EC-W-003"} {
		if m[id].Status != "pass" {
			t.Errorf("%s: passive Defender beside an active third-party AV must not fail: %+v", id, m[id])
		}
	}
	if m["EC-W-004"].Status != "unknown" {
		t.Errorf("tamper state for passive Defender should be unknown: %+v", m["EC-W-004"])
	}
}

func TestNothingReadableYieldsUnknownNotPass(t *testing.T) {
	m := byID(evalWindowsPosture(winPostureRaw{}))
	for _, id := range []string{"EC-W-001", "EC-W-002", "EC-W-003", "EC-W-005", "EC-W-006", "EC-W-007", "EC-W-009", "EC-W-013", "EC-W-014"} {
		if m[id].Status != "unknown" {
			t.Errorf("%s: unreadable value must be unknown, got %s", id, m[id].Status)
		}
	}
}
