//go:build windows

package response

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
)

const fwGroup = "ObsidianWatch-Isolation"

// psRun executes a PowerShell script (passed as -EncodedCommand, so no quoting
// problems) and returns its stdout.
func psRun(ctx context.Context, script string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	u := utf16.Encode([]rune(script))
	b := make([]byte, 0, len(u)*2)
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-EncodedCommand", base64.StdEncoding.EncodeToString(b))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("%v: %s", err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

func psList(ss []string) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = "'" + s + "'" // ranges/addresses only: digits, hex, '.', ':', '-'
	}
	return "@(" + strings.Join(q, ",") + ")"
}

func hasV6(allow []netip.Addr) bool {
	for _, a := range allow {
		if a.Is6() {
			return true
		}
	}
	return false
}

// winIsolationScript blocks, in both directions, everything except the allow
// list. Windows Firewall lets a block rule override any allow rule, so the
// block rules cover the complement of the allow list instead of relying on a
// default-deny policy that existing allow rules would defeat.
func winIsolationScript(allow []netip.Addr) string {
	main := psList(blockRanges(allow, false))
	nd := psList(blockRanges(allow, true)) // ICMPv6 keeps link-local so neighbour discovery works
	var b strings.Builder
	b.WriteString("$ErrorActionPreference='Stop'\n")
	fmt.Fprintf(&b, "$g='%s'\n", fwGroup)
	b.WriteString("$prev=(Get-NetFirewallProfile | ForEach-Object { \"$($_.Name)=$($_.Enabled)\" }) -join ','\n")
	b.WriteString("Get-NetFirewallRule -Group $g -ErrorAction SilentlyContinue | Remove-NetFirewallRule\n")
	b.WriteString("Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True\n")
	fmt.Fprintf(&b, "$main=%s\n$nd=%s\n", main, nd)
	b.WriteString(`foreach ($d in 'Outbound','Inbound') {
  New-NetFirewallRule -DisplayName "ObsidianWatch isolate TCP $d" -Group $g -Direction $d -Action Block -Protocol TCP -RemoteAddress $main -Profile Any | Out-Null
  New-NetFirewallRule -DisplayName "ObsidianWatch isolate UDP $d" -Group $g -Direction $d -Action Block -Protocol UDP -RemoteAddress $main -RemotePort '1-66','69-65535' -Profile Any | Out-Null
  New-NetFirewallRule -DisplayName "ObsidianWatch isolate ICMPv4 $d" -Group $g -Direction $d -Action Block -Protocol ICMPv4 -RemoteAddress $main -Profile Any | Out-Null
  New-NetFirewallRule -DisplayName "ObsidianWatch isolate ICMPv6 $d" -Group $g -Direction $d -Action Block -Protocol ICMPv6 -RemoteAddress $nd -Profile Any | Out-Null
  foreach ($p in 41,47,50,51,132) {
    New-NetFirewallRule -DisplayName "ObsidianWatch isolate proto$p $d" -Group $g -Direction $d -Action Block -Protocol $p -RemoteAddress $main -Profile Any | Out-Null
  }
}
$n=@(Get-NetFirewallRule -Group $g).Count
if ($n -lt 18) { throw "only $n isolation rules were created" }
Write-Output "PREV:$prev"
`)
	return b.String()
}

func applyIsolation(allow []netip.Addr, saved string) (string, error) {
	out, err := psRun(context.Background(), winIsolationScript(allow), 90*time.Second)
	if err != nil {
		return "", fmt.Errorf("windows firewall: %v", err)
	}
	if saved != "" {
		return saved, nil // re-apply: keep the ORIGINAL profile states
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "PREV:") {
			return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "PREV:")), nil
		}
	}
	return "Domain=True,Private=True,Public=True", nil
}

func removeIsolation(saved string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "$ErrorActionPreference='Stop'\nGet-NetFirewallRule -Group '%s' -ErrorAction SilentlyContinue | Remove-NetFirewallRule\n", fwGroup)
	// put each profile's enabled state back the way it was before isolation
	for _, kv := range strings.Split(saved, ",") {
		n, v, ok := strings.Cut(kv, "=")
		if !ok || (n != "Domain" && n != "Private" && n != "Public") || (v != "True" && v != "False") {
			continue
		}
		fmt.Fprintf(&b, "Set-NetFirewallProfile -Profile %s -Enabled %s\n", n, v)
	}
	_, err := psRun(context.Background(), b.String(), 60*time.Second)
	return err
}
