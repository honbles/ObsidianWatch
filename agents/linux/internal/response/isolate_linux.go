//go:build linux

package response

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

const nftTable = "obsidianwatch_isolate"

func run(stdin string, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

func splitFamilies(allow []netip.Addr) (v4, v6 []string) {
	for _, a := range allow {
		if a.Is4() {
			v4 = append(v4, a.String())
		} else {
			v6 = append(v6, a.String())
		}
	}
	return
}

// nftScript builds the isolation ruleset. Hooked at priority -300 so it runs
// before any distro/Docker/ufw chain; "drop" there is final.
func nftScript(allow []netip.Addr) string {
	v4, v6 := splitFamilies(allow)
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", nftTable)
	for _, dir := range []string{"input", "output"} {
		fmt.Fprintf(&b, "  chain %s {\n    type filter hook %s priority -300; policy drop;\n", dir, dir)
		if dir == "input" {
			b.WriteString("    iifname \"lo\" accept\n")
		} else {
			b.WriteString("    oifname \"lo\" accept\n")
		}
		side := "daddr"
		if dir == "input" {
			side = "saddr"
		}
		if len(v4) > 0 {
			fmt.Fprintf(&b, "    ip %s { %s } accept\n", side, strings.Join(v4, ", "))
		}
		if len(v6) > 0 {
			fmt.Fprintf(&b, "    ip6 %s { %s } accept\n", side, strings.Join(v6, ", "))
		}
		// keep the DHCP lease and IPv6 neighbour discovery working (link control, not host traffic)
		if dir == "input" {
			b.WriteString("    udp sport 67 udp dport 68 accept\n")
		} else {
			b.WriteString("    udp sport 68 udp dport 67 accept\n")
		}
		b.WriteString("    icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept\n")
		b.WriteString("  }\n")
	}
	b.WriteString("  chain forward {\n    type filter hook forward priority -300; policy drop;\n  }\n}\n")
	return b.String()
}

// iptablesCmds is the fallback for hosts without nft. One custom chain per
// direction, jumped to first from INPUT/OUTPUT/FORWARD.
func iptablesCmds(bin string, allow []netip.Addr) [][]string {
	var v4, v6 []string
	v4, v6 = splitFamilies(allow)
	ips := v4
	if strings.HasPrefix(bin, "ip6") {
		ips = v6
	}
	var c [][]string
	add := func(a ...string) { c = append(c, append([]string{bin}, a...)) }
	for _, ch := range []struct{ name, hook, flag, ifc string }{
		{"OW_ISO_IN", "INPUT", "-s", "-i"}, {"OW_ISO_OUT", "OUTPUT", "-d", "-o"},
	} {
		add("-N", ch.name)
		add("-F", ch.name)
		add("-A", ch.name, ch.ifc, "lo", "-j", "ACCEPT")
		for _, ip := range ips {
			add("-A", ch.name, ch.flag, ip, "-j", "ACCEPT")
		}
		if bin == "iptables" {
			if ch.hook == "INPUT" {
				add("-A", ch.name, "-p", "udp", "--sport", "67", "--dport", "68", "-j", "ACCEPT")
			} else {
				add("-A", ch.name, "-p", "udp", "--sport", "68", "--dport", "67", "-j", "ACCEPT")
			}
		} else {
			add("-A", ch.name, "-p", "ipv6-icmp", "-j", "ACCEPT")
		}
		add("-A", ch.name, "-j", "DROP")
		add("-D", ch.hook, "-j", ch.name) // make re-apply idempotent (ignore error)
		add("-I", ch.hook, "1", "-j", ch.name)
	}
	add("-N", "OW_ISO_FWD")
	add("-F", "OW_ISO_FWD")
	add("-A", "OW_ISO_FWD", "-j", "DROP")
	add("-D", "FORWARD", "-j", "OW_ISO_FWD")
	add("-I", "FORWARD", "1", "-j", "OW_ISO_FWD")
	return c
}

func have(bin string) bool { _, err := exec.LookPath(bin); return err == nil }

func applyIsolation(allow []netip.Addr, _ string) (string, error) {
	if have("nft") {
		_, _ = run("", "nft", "delete", "table", "inet", nftTable) // idempotent
		if out, err := run(nftScript(allow), "nft", "-f", "-"); err != nil {
			return "", fmt.Errorf("nft: %v: %s", err, out)
		}
		if _, err := run("", "nft", "list", "table", "inet", nftTable); err != nil {
			return "", fmt.Errorf("nft ruleset did not load")
		}
		return "nft", nil
	}
	applied := false
	for _, bin := range []string{"iptables", "ip6tables"} {
		if !have(bin) {
			continue
		}
		for _, c := range iptablesCmds(bin, allow) {
			out, err := run("", c[0], c[1:]...)
			if err != nil && c[1] != "-N" && c[1] != "-D" { // chain exists / rule absent are fine
				return "", fmt.Errorf("%s %s: %v: %s", c[0], strings.Join(c[1:], " "), err, out)
			}
		}
		applied = true
	}
	if !applied {
		return "", fmt.Errorf("neither nft nor iptables is installed; cannot isolate this host")
	}
	return "iptables", nil
}

func removeIsolation(_ string) error {
	if have("nft") {
		if out, err := run("", "nft", "delete", "table", "inet", nftTable); err != nil && !strings.Contains(out, "No such file") {
			return fmt.Errorf("nft: %v: %s", err, out)
		}
	}
	for _, bin := range []string{"iptables", "ip6tables"} {
		if !have(bin) {
			continue
		}
		for _, p := range [][2]string{{"INPUT", "OW_ISO_IN"}, {"OUTPUT", "OW_ISO_OUT"}, {"FORWARD", "OW_ISO_FWD"}} {
			for i := 0; i < 3; i++ { // remove duplicates if re-applied
				if _, err := run("", bin, "-D", p[0], "-j", p[1]); err != nil {
					break
				}
			}
			_, _ = run("", bin, "-F", p[1])
			_, _ = run("", bin, "-X", p[1])
		}
	}
	return nil
}
