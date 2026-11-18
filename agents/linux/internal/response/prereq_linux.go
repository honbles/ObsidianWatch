//go:build linux

package response

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Isolation needs a firewall tool (nft preferred, iptables as a fallback). The agent
// runs as root, so when neither exists it installs nftables with the host's package
// manager instead of making the operator do it by hand. It is attempted at agent start
// (so isolation is ready before anyone needs it) and again right before an isolate
// that finds nothing, and the outcome is remembered so a failure is not retried in a loop.
var (
	prereqMu      sync.Mutex
	prereqTried   time.Time
	prereqLastErr error
)

// installers lists package managers in the order they are tried.
var installers = []struct {
	bin  string
	args []string
	env  []string
}{
	{"apt-get", []string{"install", "-y", "-q", "nftables"}, []string{"DEBIAN_FRONTEND=noninteractive"}},
	{"dnf", []string{"install", "-y", "-q", "nftables"}, nil},
	{"yum", []string{"install", "-y", "-q", "nftables"}, nil},
	{"zypper", []string{"--non-interactive", "install", "nftables"}, nil},
	{"apk", []string{"add", "--no-cache", "nftables"}, nil},
	{"pacman", []string{"-S", "--noconfirm", "--needed", "nftables"}, nil},
}

func firewallToolPresent() bool { return have("nft") || have("iptables") }

// ensureFirewallTool returns nil when a usable tool exists (installing nftables if needed).
func ensureFirewallTool(ctx context.Context) error { return EnsureFirewallTool(ctx) }

// EnsureFirewallTool is exported so the installer can call it before the service starts.
func EnsureFirewallTool(ctx context.Context) error {
	if firewallToolPresent() {
		return nil
	}
	prereqMu.Lock()
	defer prereqMu.Unlock()
	if firewallToolPresent() {
		return nil
	}
	// Do not hammer a package manager that just failed.
	if !prereqTried.IsZero() && time.Since(prereqTried) < 10*time.Minute && prereqLastErr != nil {
		return prereqLastErr
	}
	prereqTried = time.Now()
	if os.Geteuid() != 0 {
		prereqLastErr = fmt.Errorf("neither nft nor iptables is installed and the agent is not root, so it cannot install nftables; run: sudo apt-get install nftables")
		return prereqLastErr
	}
	for _, in := range installers {
		if !have(in.bin) {
			continue
		}
		c, cancel := context.WithTimeout(ctx, 3*time.Minute)
		if in.bin == "apt-get" {
			// refresh the index first; a fresh VM often has none
			var u *exec.Cmd
			if sandboxed() && have("systemd-run") {
				u = exec.CommandContext(c, "systemd-run", "--quiet", "--wait", "--collect", "--pipe", "apt-get", "update", "-q")
			} else {
				u = exec.CommandContext(c, "apt-get", "update", "-q")
				u.Env = append(os.Environ(), in.env...)
			}
			_ = u.Run()
		}
		var cmd *exec.Cmd
		if sandboxed() && have("systemd-run") {
			// The agent service runs with ProtectSystem=strict and NoNewPrivileges, so it cannot
			// write to /usr. A transient unit is started by systemd itself, outside that sandbox.
			args := []string{"--quiet", "--wait", "--collect", "--pipe"}
			for _, e := range in.env {
				args = append(args, "--setenv="+e)
			}
			args = append(args, in.bin)
			args = append(args, in.args...)
			cmd = exec.CommandContext(c, "systemd-run", args...)
		} else {
			cmd = exec.CommandContext(c, in.bin, in.args...)
			cmd.Env = append(os.Environ(), in.env...)
		}
		out, err := cmd.CombinedOutput()
		cancel()
		if firewallToolPresent() {
			prereqLastErr = nil
			return nil
		}
		msg := strings.TrimSpace(string(out))
		if len(msg) > 300 {
			msg = msg[len(msg)-300:]
		}
		prereqLastErr = fmt.Errorf("neither nft nor iptables was installed and installing nftables with %s failed: %v: %s", in.bin, err, msg)
		return prereqLastErr
	}
	prereqLastErr = fmt.Errorf("neither nft nor iptables is installed and no supported package manager (apt, dnf, yum, zypper, apk, pacman) was found; install nftables manually")
	return prereqLastErr
}

// EnsurePrereqs is called once at agent start.
func (h *Handler) EnsurePrereqs(ctx context.Context) {
	if err := ensureFirewallTool(ctx); err != nil {
		h.logger.Warn("response: isolation prerequisite missing", "err", err)
	}
}

// sandboxed reports whether this process runs under a systemd unit (INVOCATION_ID is set).
func sandboxed() bool { return os.Getenv("INVOCATION_ID") != "" }
