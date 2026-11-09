package api

import (
	"encoding/json"
	"testing"
)

func hcStatus(checks []HostCheck, id string) string {
	for _, c := range checks {
		if c.ID == id {
			return c.Status
		}
	}
	return "?"
}

func TestEvalHostChecksExtended(t *testing.T) {
	bad := json.RawMessage(`{"packages":[{"Name":"nmap","Version":"7"},{"Name":"openssh","Version":"1"}],
		"open_ports":[{"port":5900},{"port":22}],"udp_ports":[{"port":161}],
		"findings":[{"category":"SUID Binary","title":"Suspicious SUID binary: /usr/bin/find"}],
		"system":{"os_release":"Ubuntu 18.04.6 LTS"}}`)
	c := evalHostChecks(bad)
	for _, id := range []string{"HC-007", "HC-008", "HC-009", "HC-010", "HC-011"} {
		if hcStatus(c, id) != "fail" {
			t.Errorf("%s should fail", id)
		}
	}
	good := json.RawMessage(`{"packages":[{"Name":"unattended-upgrades","Version":"1"},{"Name":"auditd","Version":"1"},{"Name":"ufw","Version":"1"},{"Name":"chrony","Version":"1"}],
		"open_ports":[{"port":22}],"findings":[],"system":{"os_release":"Ubuntu 24.04 LTS"}}`)
	c = evalHostChecks(good)
	for _, id := range []string{"HC-007", "HC-008", "HC-009", "HC-010", "HC-011"} {
		if hcStatus(c, id) != "pass" {
			t.Errorf("%s should pass", id)
		}
	}
	if !eolRelease("Debian GNU/Linux 10 (buster)") || eolRelease("Debian GNU/Linux 12 (bookworm)") {
		t.Fatal("EOL detection wrong")
	}
}
