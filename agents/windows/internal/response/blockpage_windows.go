//go:build windows

package response

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// On Windows the block page listens on the standard loopback ports and the
// network adapters' DNS servers point at it while isolated (Windows Firewall
// cannot redirect). Loopback is not filtered by the isolation rules.
func blockPageAddrs() (string, string) { return "127.0.0.1:80", "127.0.0.1:53" }

// savedDNS is "ifIndex=servers;ifIndex=servers" where empty servers means
// the adapter took DNS from DHCP.
var savedDNSRe = regexp.MustCompile(`^(\d+=[0-9A-Fa-f.:, ]*)(;\d+=[0-9A-Fa-f.:, ]*)*$`)

func knownIndexes(saved string) []string {
	var idx []string
	for _, kv := range strings.Split(saved, ";") {
		if i, _, ok := strings.Cut(kv, "="); ok && i != "" {
			idx = append(idx, i)
		}
	}
	return idx
}

// pointDNSScript records the static DNS servers of every adapter that is up
// (adapters already recorded in saved are left as recorded) and points them
// at 127.0.0.1.
func pointDNSScript(saved string) string {
	known := "@()"
	if k := knownIndexes(saved); len(k) > 0 {
		known = "@(" + strings.Join(k, ",") + ")"
	}
	return `$ErrorActionPreference='Stop'
$known=` + known + `
$out=@()
foreach ($a in @(Get-NetAdapter | Where-Object Status -eq 'Up')) {
  if ($known -notcontains [int]$a.ifIndex) {
    $static=''
    try { $static=[string](Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($a.InterfaceGuid)" -Name NameServer -ErrorAction Stop).NameServer } catch {}
    $out += "$($a.ifIndex)=$static"
  }
  Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses '127.0.0.1'
}
Clear-DnsClientCache
Write-Output ("SAVED:" + ($out -join ';'))
`
}

func unpointDNSScript(saved string) string {
	var b strings.Builder
	b.WriteString("$ErrorActionPreference='Continue'\n")
	for _, kv := range strings.Split(saved, ";") {
		idx, servers, ok := strings.Cut(kv, "=")
		if !ok || idx == "" {
			continue
		}
		servers = strings.TrimSpace(strings.ReplaceAll(servers, " ", ","))
		if servers == "" {
			fmt.Fprintf(&b, "Set-DnsClientServerAddress -InterfaceIndex %s -ResetServerAddresses\n", idx)
		} else {
			fmt.Fprintf(&b, "Set-DnsClientServerAddress -InterfaceIndex %s -ServerAddresses %s\n", idx, psList(strings.Split(servers, ",")))
		}
	}
	b.WriteString("Clear-DnsClientCache\n")
	return b.String()
}

func pointToBlockPage(saved string) (string, error) {
	if saved != "" && !savedDNSRe.MatchString(saved) {
		saved = ""
	}
	out, err := psRun(context.Background(), pointDNSScript(saved), 60*time.Second)
	if err != nil {
		return saved, fmt.Errorf("dns: %v", err)
	}
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if rest, ok := strings.CutPrefix(l, "SAVED:"); ok && rest != "" {
			if saved == "" {
				return rest, nil
			}
			return saved + ";" + rest, nil
		}
	}
	if saved == "" {
		saved = "0=" // nothing was up; keep a marker so release runs
	}
	return saved, nil
}

func unpointBlockPage(saved string) error {
	if !savedDNSRe.MatchString(saved) {
		return fmt.Errorf("unrecognised saved DNS settings %q", saved)
	}
	_, err := psRun(context.Background(), unpointDNSScript(saved), 60*time.Second)
	return err
}
