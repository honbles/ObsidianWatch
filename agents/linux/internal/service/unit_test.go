package service

import (
	"strings"
	"testing"
)

// The agent is an EDR: response actions and the live-response shell act on
// the real host, so the unit must not give it a read-only or private view of
// the file system (that made the live shell report "Read-only file system"
// and broke quarantine in home directories and disabling accounts).
func TestUnitGivesAgentTheRealHost(t *testing.T) {
	u := unitText()
	for _, bad := range []string{"ProtectSystem=", "ProtectHome=", "PrivateTmp=", "ReadOnlyPaths="} {
		if strings.Contains(u, bad) {
			t.Errorf("unit must not contain %s", bad)
		}
	}
	for _, want := range []string{"User=root", "NoNewPrivileges=true", "Restart=always"} {
		if !strings.Contains(u, want) {
			t.Errorf("unit missing %s", want)
		}
	}
}
