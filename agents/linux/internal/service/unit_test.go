package service

import (
	"strings"
	"testing"
)

func TestUnitSandboxDoesNotExposeAccountFiles(t *testing.T) {
	u := unitText()
	for _, bad := range []string{"/etc/shadow", "/etc/passwd", "/etc/group"} {
		if strings.Contains(u, bad) {
			t.Errorf("unit must not make %s writable", bad)
		}
	}
	for _, want := range []string{"ProtectSystem=strict", "NoNewPrivileges=true", "Restart=always"} {
		if !strings.Contains(u, want) {
			t.Errorf("unit missing %s", want)
		}
	}
}
