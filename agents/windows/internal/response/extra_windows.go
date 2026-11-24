//go:build windows

package response

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

const ipBlockGroup = "ObsidianWatch-IPBlock"

func ipBlockScript(ips []netip.Addr) string {
	var b strings.Builder
	b.WriteString("$ErrorActionPreference='Stop'\n")
	fmt.Fprintf(&b, "Get-NetFirewallRule -Group '%s' -ErrorAction SilentlyContinue | Remove-NetFirewallRule\n", ipBlockGroup)
	if len(ips) > 0 {
		l := make([]string, len(ips))
		for i, a := range ips {
			l[i] = a.String()
		}
		// Block rules only act while the firewall is on.
		b.WriteString("Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True\n")
		fmt.Fprintf(&b, "$ips=%s\n", psList(l))
		b.WriteString("foreach ($d in 'Inbound','Outbound') {\n")
		fmt.Fprintf(&b, "  New-NetFirewallRule -DisplayName \"ObsidianWatch blocked addresses $d\" -Group '%s' -Direction $d -Action Block -RemoteAddress $ips -Profile Any | Out-Null\n}\n", ipBlockGroup)
	}
	return b.String()
}

func applyIPBlocks(ips []netip.Addr) error {
	if _, err := psRun(context.Background(), ipBlockScript(ips), 90*time.Second); err != nil {
		return fmt.Errorf("windows firewall: %v", err)
	}
	return nil
}

// Names are checked against userRe (no quotes), so they are safe inside '…'.
func disableUserScript(name string) string {
	return `$ErrorActionPreference='Stop'
try { $u=Get-LocalUser -Name '` + name + `' } catch { throw "no local account named '` + name + `' (domain accounts must be disabled in Active Directory)" }
$admins=@()
try { $admins=@(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.PrincipalSource -eq 'Local' -and $_.ObjectClass -eq 'User' } | ForEach-Object { Get-LocalUser -SID $_.SID -ErrorAction SilentlyContinue } | Where-Object Enabled) } catch {}
if ($admins.Count -eq 1 -and $admins[0].SID -eq $u.SID) { throw 'refusing to disable the last enabled local administrator' }
Disable-LocalUser -InputObject $u
$n=0
Get-Process -IncludeUserName -ErrorAction SilentlyContinue | Where-Object { $_.UserName -and ($_.UserName -split '\\')[-1] -ieq $u.Name } | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue; $n++ }
Write-Output "ENDED:$n"
`
}

func disableUser(name string) (string, error) {
	out, err := psRun(context.Background(), disableUserScript(name), 60*time.Second)
	if err != nil {
		return "", err
	}
	ended := "0"
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "ENDED:"); ok {
			ended = v
		}
	}
	return fmt.Sprintf("local account %s disabled; %s of its processes ended", name, ended), nil
}

func enableUser(name string) (string, error) {
	if _, err := psRun(context.Background(), "$ErrorActionPreference='Stop'\nEnable-LocalUser -Name '"+name+"'\n", 60*time.Second); err != nil {
		return "", err
	}
	return "local account " + name + " enabled", nil
}
