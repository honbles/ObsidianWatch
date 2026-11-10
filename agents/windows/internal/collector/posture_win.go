//go:build windows

package collector

// posture_win.go - reads endpoint compliance values with one PowerShell
// session. Every read is wrapped so a failure leaves the value null, which the
// evaluator reports as "unknown" rather than guessing.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os/exec"
	"time"
	"unicode/utf16"
)

const postureScript = `
$ErrorActionPreference = 'SilentlyContinue'
function T($b) { try { & $b } catch { $null } }
function Reg($p, $n) { try { (Get-ItemProperty -Path $p -Name $n -ErrorAction Stop).$n } catch { $null } }
$r = [ordered]@{}
$r.av = T { @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object {
  $h = '{0:X6}' -f [int]$_.productState
  @{ name = [string]$_.displayName; enabled = ($h.Substring(2,2) -in '10','11'); up_to_date = ($h.Substring(4,2) -eq '00') } }) }
$mp = T { Get-MpComputerStatus }
$r.defender = if ($mp) { @{ realtime = $mp.RealTimeProtectionEnabled; sig_age_days = $mp.AntivirusSignatureAge; tamper = $mp.IsTamperProtected } } else { $null }
$r.firewall = T { @(Get-NetFirewallProfile | ForEach-Object { @{ name = [string]$_.Name; enabled = ($_.Enabled.ToString() -eq 'True') } }) }
$r.bitlocker = T { [string](Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus }
$r.hotfix_age_days = T { $d = (Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn; if ($d) { [int]((Get-Date) - $d).TotalDays } else { $null } }
$sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$r.enable_lua = Reg $sys 'EnableLUA'
$r.smb1 = T { [bool](Get-SmbServerConfiguration).EnableSMB1Protocol }
$r.rdp_deny = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
$r.rdp_nla = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
$r.guest_enabled = T { [bool](Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }).Enabled }
$r.admin_enabled = T { [bool](Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }).Enabled }
$r.local_admins = T { @(Get-LocalGroupMember -SID 'S-1-5-32-544').Count }
$f = [IO.Path]::GetTempFileName()
T { secedit /export /cfg $f /areas SECURITYPOLICY | Out-Null }
$cfg = T { Get-Content $f }
Remove-Item $f -Force -ErrorAction SilentlyContinue
function Pol($k) { $m = $cfg | Select-String -Pattern ('^' + $k + '\s*=\s*(-?\d+)') | Select-Object -First 1; if ($m) { [int]$m.Matches[0].Groups[1].Value } else { $null } }
$r.min_password_length = Pol 'MinimumPasswordLength'
$r.lockout_threshold = Pol 'LockoutBadCount'
$r.inactivity_secs = Reg $sys 'InactivityTimeoutSecs'
$r.secure_boot = T { [bool](Confirm-SecureBootUEFI) }
$r.tpm_ready = T { [bool](Get-Tpm).TpmReady }
$r.script_block_logging = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
$r.autorun_mask = Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
$r.run_as_ppl = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
$r.audit_logon = T { (auditpol /get /category:'Logon/Logoff' | Out-String) }
$r | ConvertTo-Json -Depth 5 -Compress
`

// collectPosture runs the compliance script (hidden window, 90s cap) and
// evaluates it. On total failure it returns nil so the backend shows nothing
// rather than a wall of unknowns.
func collectPosture() []PostureCheck {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	u := utf16.Encode([]rune(postureScript))
	b := make([]byte, 0, len(u)*2)
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-EncodedCommand", base64.StdEncoding.EncodeToString(b))
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		return nil
	}
	var raw winPostureRaw
	if json.Unmarshal(out, &raw) != nil {
		return nil
	}
	return evalWindowsPosture(raw)
}
