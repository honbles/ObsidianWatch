package collector

import "testing"

func lByID(cs []PostureCheck) map[string]PostureCheck {
	m := map[string]PostureCheck{}
	for _, c := range cs {
		m[c.ID] = c
	}
	return m
}

func TestLinuxPostureHardened(t *testing.T) {
	got := evalLinuxPosture(linuxPostureRaw{
		RootDeps: "lvm crypt disk", AppArmorEnabled: "Y", AppArmorProfs: "/usr/bin/x (enforce)",
		UFWStatus: "Status: active", SSHDInstalled: true,
		SSHDConfig: "permitrootlogin no\npasswordauthentication no\n",
		ASLR:       "2", Passwd: "root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n",
		Shadow: "root:!:1::::::\nalice:$6$x:1::::::\n", ShadowReadable: true,
		SecurityAgents: []string{"ClamAV"}, SudoersReadable: true,
		SudoersLines: []string{"# alice ALL=(ALL) NOPASSWD: ALL", "%admin ALL=(ALL) ALL"},
	})
	if len(got) != 10 {
		t.Fatalf("expected 10 checks, got %d", len(got))
	}
	for _, c := range got {
		if c.Status != "pass" {
			t.Errorf("%s should pass: %+v", c.ID, c)
		}
	}
}

func TestLinuxPostureBad(t *testing.T) {
	m := lByID(evalLinuxPosture(linuxPostureRaw{
		RootDeps: "part disk", SELinuxEnforce: "0", IptablesRules: "-P INPUT ACCEPT\n-P FORWARD ACCEPT",
		UFWStatus: "Status: inactive", SSHDInstalled: true,
		SSHDConfig: "permitrootlogin yes\npasswordauthentication yes\n", ASLR: "0",
		Passwd: "root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/:/bin/sh\n",
		Shadow: "bob::1::::::\n", ShadowReadable: true,
		SudoersReadable: true, SudoersLines: []string{"ubuntu ALL=(ALL) NOPASSWD:ALL"},
	}))
	for id, c := range m {
		if c.Status != "fail" {
			t.Errorf("%s should fail: %+v", id, c)
		}
	}
	if m["EC-L-007"].Detail != "extra UID 0 accounts: toor" || m["EC-L-008"].Detail != "accounts without a password: bob" {
		t.Errorf("details: %q / %q", m["EC-L-007"].Detail, m["EC-L-008"].Detail)
	}
}

func TestLinuxPostureUnreadableAndNoSSHD(t *testing.T) {
	m := lByID(evalLinuxPosture(linuxPostureRaw{}))
	for _, id := range []string{"EC-L-001", "EC-L-003", "EC-L-006", "EC-L-007", "EC-L-008", "EC-L-010"} {
		if m[id].Status != "unknown" {
			t.Errorf("%s should be unknown without data, got %s", id, m[id].Status)
		}
	}
	if m["EC-L-004"].Status != "pass" || m["EC-L-005"].Status != "pass" {
		t.Error("ssh checks are moot when sshd is not installed")
	}
	if lByID(evalLinuxPosture(linuxPostureRaw{SSHDInstalled: true, SSHDConfig: "permitrootlogin prohibit-password\npasswordauthentication no"}))["EC-L-004"].Status != "pass" {
		t.Error("prohibit-password is acceptable")
	}
}
