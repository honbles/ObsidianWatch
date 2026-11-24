//go:build linux

package response

import (
	"net/netip"
	"os/exec"
	"strings"
	"testing"
)

func TestNftIPBlockScript(t *testing.T) {
	s := nftIPBlockScript([]netip.Addr{netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("2001:db8::9")})
	for _, want := range []string{"elements = { 203.0.113.9 }", "elements = { 2001:db8::9 }", "ip daddr @v4 drop", "ip6 saddr @v6 drop", "hook forward"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q:\n%s", want, s)
		}
	}
	if p, err := exec.LookPath("nft"); err == nil {
		cmd := exec.Command(p, "-c", "-f", "-")
		cmd.Stdin = strings.NewReader(s)
		if out, err := cmd.CombinedOutput(); err != nil && !strings.Contains(string(out), "Operation not permitted") {
			t.Fatalf("nft rejected:\n%s", out)
		}
	}
}
