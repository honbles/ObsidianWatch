//go:build darwin

package response

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

const pfFile = "/etc/pf.obsidianwatch.conf"

func run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

var pfToken = regexp.MustCompile(`(?i)token\s*:\s*(\d+)`)

// applyIsolation loads the pf ruleset as the main ruleset and flushes states,
// so connections that were already open do not survive. saved carries the pf
// enable token needed to undo it.
func applyIsolation(allow []netip.Addr, saved string) (string, error) {
	if err := os.WriteFile(pfFile, []byte(pfRules(allow)), 0o600); err != nil {
		return "", err
	}
	ctx := context.Background()
	if saved == "" {
		out, err := run(ctx, "pfctl", "-E")
		if err != nil && !strings.Contains(out, "already enabled") {
			return "", fmt.Errorf("pfctl -E: %v: %s", err, out)
		}
		if m := pfToken.FindStringSubmatch(out); m != nil {
			saved = "token=" + m[1]
		} else {
			saved = "token="
		}
	}
	if out, err := run(ctx, "pfctl", "-f", pfFile); err != nil {
		return "", fmt.Errorf("pfctl -f: %v: %s", err, out)
	}
	_, _ = run(ctx, "pfctl", "-F", "states")
	return saved, nil
}

func removeIsolation(saved string) error {
	ctx := context.Background()
	if out, err := run(ctx, "pfctl", "-f", "/etc/pf.conf"); err != nil {
		return fmt.Errorf("pfctl -f /etc/pf.conf: %v: %s", err, out)
	}
	_, _ = run(ctx, "pfctl", "-F", "states")
	if tok := strings.TrimPrefix(saved, "token="); strings.HasPrefix(saved, "token=") && regexp.MustCompile(`^\d+$`).MatchString(tok) {
		_, _ = run(ctx, "pfctl", "-X", tok)
	}
	_ = os.Remove(pfFile)
	return nil
}
