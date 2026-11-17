//go:build windows

package response

import (
	"net/netip"
	"strings"
	"testing"
)

func TestWinIsolationScript(t *testing.T) {
	s := winIsolationScript([]netip.Addr{netip.MustParseAddr("10.0.0.5")})
	for _, want := range []string{"-Action Block", "-Group $g", "10.0.0.0-10.0.0.4", "10.0.0.6-126.255.255.255", "-RemotePort '1-66','69-65535'", "41,47,50,51,132"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(s, "'10.0.0.5'") || strings.Contains(s, "10.0.0.5-") {
		t.Error("the allowed address must not be inside a blocked range")
	}
}
