//go:build linux

package response

import (
	"net/netip"
	"os/exec"
	"strings"
	"testing"
)

func TestNftScript(t *testing.T) {
	allow := []netip.Addr{netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("2001:db8::1")}
	s := nftScript(allow, false)
	for _, want := range []string{"policy drop", "ip daddr { 10.0.0.5, 203.0.113.7 } accept", "ip saddr { 10.0.0.5, 203.0.113.7 } accept",
		"ip6 daddr { 2001:db8::1 } accept", `iifname "lo" accept`, "chain forward"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	// nothing but the allow-list, loopback, DHCP and ND may be accepted
	if strings.Contains(s, "ip daddr 0.0.0.0") || strings.Contains(s, "accept\n  }\n  chain output {\n    type filter hook output priority -300; policy accept") {
		t.Fatal("unexpected open rule")
	}
	if p, err := exec.LookPath("nft"); err == nil {
		cmd := exec.Command(p, "-c", "-f", "-")
		cmd.Stdin = strings.NewReader(s)
		if out, err := cmd.CombinedOutput(); err != nil {
			if strings.Contains(string(out), "Operation not permitted") || strings.Contains(string(out), "Permission denied") {
				t.Skip("nft needs privileges: " + string(out))
			}
			t.Fatalf("nft rejected the ruleset: %v\n%s", err, out)
		}
	}
}

func TestIptablesCmds(t *testing.T) {
	allow := []netip.Addr{netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("2001:db8::1")}
	var j4, j6 []string
	for _, c := range iptablesCmds("iptables", allow) {
		j4 = append(j4, strings.Join(c, " "))
	}
	for _, c := range iptablesCmds("ip6tables", allow) {
		j6 = append(j6, strings.Join(c, " "))
	}
	a, b := strings.Join(j4, "\n"), strings.Join(j6, "\n")
	if !strings.Contains(a, "-A OW_ISO_OUT -d 10.0.0.5 -j ACCEPT") || strings.Contains(a, "2001:db8") {
		t.Fatalf("v4 rules wrong:\n%s", a)
	}
	if !strings.Contains(b, "-d 2001:db8::1 -j ACCEPT") || strings.Contains(b, "10.0.0.5") {
		t.Fatalf("v6 rules wrong:\n%s", b)
	}
	if !strings.Contains(a, "-I INPUT 1 -j OW_ISO_IN") || !strings.Contains(a, "-A OW_ISO_OUT -j DROP") {
		t.Fatal("hook/drop missing")
	}
}

func TestKillRefusesProtected(t *testing.T) {
	if _, err := killProcess(1, "", false); err == nil {
		t.Fatal("pid 1 killed")
	}
	if _, err := killProcess(2147483000, "", false); err == nil {
		t.Fatal("nonexistent pid should error")
	}
}

func TestBlockPageRedirectRules(t *testing.T) {
	allow := []netip.Addr{netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("2001:db8::1")}
	nat := nftNATScript(allow)
	for _, want := range []string{"type nat hook output priority -100", "udp dport 53 redirect to :15353", "tcp dport 53 redirect to :15353",
		"ip daddr != { 10.0.0.5 } tcp dport 80 redirect to :18080"} {
		if !strings.Contains(nat, want) {
			t.Errorf("nat: missing %q in\n%s", want, nat)
		}
	}
	with, without := nftScript(allow, true), nftScript(allow, false)
	if !strings.Contains(with, "meta nfproto ipv4 udp dport 53 accept") || strings.Contains(without, "dport 53") {
		t.Error("DNS/HTTP may only pass the filter when the NAT table is loaded")
	}
	if strings.Contains(with, "ip6") && strings.Contains(with, "ip6 dport") {
		t.Error("IPv6 DNS must stay blocked (no IPv6 redirect)")
	}
	if p, err := exec.LookPath("nft"); err == nil {
		for _, s := range []string{nat, with} {
			cmd := exec.Command(p, "-c", "-f", "-")
			cmd.Stdin = strings.NewReader(s)
			if out, err := cmd.CombinedOutput(); err != nil {
				if strings.Contains(string(out), "Operation not permitted") || strings.Contains(string(out), "Permission denied") {
					t.Skip("nft needs privileges")
				}
				t.Fatalf("nft rejected:\n%s\n%s", s, out)
			}
		}
	}
	cmds := iptablesNATCmds(allow)
	joined := ""
	for _, c := range cmds {
		joined += strings.Join(c, " ") + "\n"
	}
	for _, want := range []string{"-d 10.0.0.5 -p tcp --dport 80 -j RETURN", "--dport 53 -j REDIRECT --to-ports 15353", "-I OUTPUT 1 -j OW_BLOCKPAGE"} {
		if !strings.Contains(joined, want) {
			t.Errorf("iptables nat: missing %q", want)
		}
	}
}
