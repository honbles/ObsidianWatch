package response

import (
	"net/netip"
	"strings"
	"testing"
)

func TestPfRules(t *testing.T) {
	r := pfRules([]netip.Addr{netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("2001:db8::1")})
	for _, w := range []string{"block drop all", "set skip on lo0", "pass out quick from any to { 10.0.0.5, 2001:db8::1 } keep state", "pass in quick from { 10.0.0.5, 2001:db8::1 } to any keep state", "port 68 to any port 67"} {
		if !strings.Contains(r, w) {
			t.Errorf("missing %q\n%s", w, r)
		}
	}
	if strings.Count(r, "pass") != 4 {
		t.Errorf("only DHCP + allow-list may be passed:\n%s", r)
	}
}
