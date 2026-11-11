//go:build darwin

package collector

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

func runTrim(name string, args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err == nil
}

// collectPosture reads the macOS compliance values. A command that fails
// contributes an empty string, which the evaluator reports as unknown.
func collectPosture() []PostureCheck {
	var r macPostureRaw
	r.FileVault, _ = runTrim("fdesetup", "status")
	r.SIP, _ = runTrim("csrutil", "status")
	r.Gatekeeper, _ = runTrim("spctl", "--status")
	if s, ok := runTrim("defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"); ok {
		r.FirewallState = s
	}
	if s, ok := runTrim("defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"); ok {
		r.AutoUpdate = s
	}
	r.RemoteLogin, _ = runTrim("systemsetup", "-getremotelogin")
	if s, ok := runTrim("defaults", "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"); ok {
		r.GuestEnabled = s
	}
	r.LaunchctlList, r.LaunchctlReady = runTrim("launchctl", "list")
	if s, ok := runTrim("dscl", ".", "-read", "/Groups/admin", "GroupMembership"); ok {
		r.AdminGroup = s
	}
	return evalMacPosture(r)
}
