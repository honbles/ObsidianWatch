//go:build linux

package response

import (
	"context"
	"fmt"
	"net/netip"
	"os/user"
	"strings"
)

const nftIPBlockTable = "obsidianwatch_ipblock"

// nftIPBlockScript drops traffic to and from the listed addresses. Priority
// -290: just after isolation, before distribution firewalls.
func nftIPBlockScript(ips []netip.Addr) string {
	var v4, v6 []string
	for _, a := range ips {
		if a.Is4() {
			v4 = append(v4, a.String())
		} else {
			v6 = append(v6, a.String())
		}
	}
	elems := func(l []string) string {
		if len(l) == 0 {
			return ""
		}
		return " elements = { " + strings.Join(l, ", ") + " };"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", nftIPBlockTable)
	fmt.Fprintf(&b, "  set v4 { type ipv4_addr;%s }\n  set v6 { type ipv6_addr;%s }\n", elems(v4), elems(v6))
	for _, c := range []struct{ name, hook string }{{"input", "input"}, {"output", "output"}, {"forward", "forward"}} {
		fmt.Fprintf(&b, "  chain %s {\n    type filter hook %s priority -290; policy accept;\n", c.name, c.hook)
		b.WriteString("    ip saddr @v4 drop\n    ip daddr @v4 drop\n    ip6 saddr @v6 drop\n    ip6 daddr @v6 drop\n  }\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func applyIPBlocks(ips []netip.Addr) error {
	if len(ips) > 0 {
		if err := ensureFirewallTool(context.Background()); err != nil {
			return err
		}
	}
	if have("nft") {
		_, _ = run("", "nft", "delete", "table", "inet", nftIPBlockTable)
		if len(ips) == 0 {
			return nil
		}
		if out, err := run(nftIPBlockScript(ips), "nft", "-f", "-"); err != nil {
			return fmt.Errorf("nft: %v: %s", err, out)
		}
		return nil
	}
	done := false
	for _, bin := range []string{"iptables", "ip6tables"} {
		if !have(bin) {
			continue
		}
		v6 := bin == "ip6tables"
		for _, hook := range []string{"INPUT", "OUTPUT", "FORWARD"} {
			for i := 0; i < 3; i++ {
				if _, err := run("", bin, "-D", hook, "-j", "OW_IPBLOCK"); err != nil {
					break
				}
			}
		}
		_, _ = run("", bin, "-F", "OW_IPBLOCK")
		_, _ = run("", bin, "-X", "OW_IPBLOCK")
		var mine []string
		for _, a := range ips {
			if a.Is6() == v6 {
				mine = append(mine, a.String())
			}
		}
		done = true
		if len(mine) == 0 {
			continue
		}
		cmds := [][]string{{"-N", "OW_IPBLOCK"}}
		for _, ip := range mine {
			cmds = append(cmds, []string{"-A", "OW_IPBLOCK", "-s", ip, "-j", "DROP"}, []string{"-A", "OW_IPBLOCK", "-d", ip, "-j", "DROP"})
		}
		for _, hook := range []string{"INPUT", "OUTPUT", "FORWARD"} {
			cmds = append(cmds, []string{"-I", hook, "1", "-j", "OW_IPBLOCK"})
		}
		for _, c := range cmds {
			if out, err := run("", bin, c...); err != nil {
				return fmt.Errorf("%s %s: %v: %s", bin, strings.Join(c, " "), err, out)
			}
		}
	}
	if !done && len(ips) > 0 {
		return fmt.Errorf("neither nft nor iptables is installed")
	}
	return nil
}

func refuseUID0(name string) error {
	u, err := user.Lookup(name)
	if err != nil {
		return fmt.Errorf("no local account %q", name)
	}
	if u.Uid == "0" {
		return fmt.Errorf("refusing to disable a uid 0 account")
	}
	return nil
}

func disableUser(name string) (string, error) {
	if err := refuseUID0(name); err != nil {
		return "", err
	}
	// Lock the password and expire the account: expiry also stops SSH key logins.
	if out, err := run("", "usermod", "-L", "-e", "1", name); err != nil {
		return "", fmt.Errorf("usermod: %v: %s", err, out)
	}
	_, _ = run("", "pkill", "-KILL", "-u", name) // exit 1 = no processes
	return "account " + name + " locked and expired; its processes were ended", nil
}

func enableUser(name string) (string, error) {
	if _, err := user.Lookup(name); err != nil {
		return "", fmt.Errorf("no local account %q", name)
	}
	out, err := run("", "usermod", "-U", "-e", "", name)
	if err != nil && strings.Contains(out, "passwordless") {
		if out2, err2 := run("", "usermod", "-e", "", name); err2 != nil {
			return "", fmt.Errorf("usermod: %v: %s", err2, out2)
		}
		return "account " + name + " no longer expired; its password stays locked because it had none (set one to allow password login)", nil
	}
	if err != nil {
		return "", fmt.Errorf("usermod: %v: %s", err, out)
	}
	return "account " + name + " unlocked", nil
}
