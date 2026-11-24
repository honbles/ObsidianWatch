//go:build darwin

package response

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/user"
	"strings"
)

// The block list lives in a pf anchor under com.apple/, which the stock
// /etc/pf.conf evaluates, so the system ruleset is left alone.
const (
	pfIPBlockAnchor = "com.apple/obsidianwatch-ipblock"
	pfIPBlockFile   = "/etc/pf.anchors/obsidianwatch.ipblock"
)

func pfIPBlockRules(ips []netip.Addr) string {
	l := make([]string, len(ips))
	for i, a := range ips {
		l[i] = a.String()
	}
	return "table <owblock> persist { " + strings.Join(l, ", ") + " }\n" +
		"block drop quick from <owblock> to any\nblock drop quick from any to <owblock>\n"
}

func applyIPBlocks(ips []netip.Addr) error {
	ctx := context.Background()
	if len(ips) == 0 {
		_, _ = run(ctx, "pfctl", "-a", pfIPBlockAnchor, "-F", "all")
		_ = os.Remove(pfIPBlockFile)
		return nil
	}
	if err := os.MkdirAll("/etc/pf.anchors", 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(pfIPBlockFile, []byte(pfIPBlockRules(ips)), 0o600); err != nil {
		return err
	}
	if out, err := run(ctx, "pfctl", "-e"); err != nil && !strings.Contains(out, "already enabled") {
		return fmt.Errorf("pfctl -e: %v: %s", err, out)
	}
	if out, err := run(ctx, "pfctl", "-a", pfIPBlockAnchor, "-f", pfIPBlockFile); err != nil {
		return fmt.Errorf("pfctl: %v: %s", err, out)
	}
	return nil
}

func disableUser(name string) (string, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return "", fmt.Errorf("no local account %q", name)
	}
	if u.Uid == "0" {
		return "", fmt.Errorf("refusing to disable a uid 0 account")
	}
	ctx := context.Background()
	if out, err := run(ctx, "pwpolicy", "-u", name, "disableuser"); err != nil {
		return "", fmt.Errorf("pwpolicy: %v: %s", err, out)
	}
	_, _ = run(ctx, "pkill", "-KILL", "-u", name)
	return "account " + name + " disabled; its processes were ended", nil
}

func enableUser(name string) (string, error) {
	if _, err := user.Lookup(name); err != nil {
		return "", fmt.Errorf("no local account %q", name)
	}
	if out, err := run(context.Background(), "pwpolicy", "-u", name, "enableuser"); err != nil {
		return "", fmt.Errorf("pwpolicy: %v: %s", err, out)
	}
	return "account " + name + " enabled", nil
}
