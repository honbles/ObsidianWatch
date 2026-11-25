//go:build windows

package response

import (
	"context"
	"errors"
	"regexp"
	"strings"
)

// psQuote makes s a PowerShell single-quoted literal.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

var regPathRe = regexp.MustCompile(`(?i)^(HKLM|HKCU|HKU|HKCR|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_USERS|HKEY_CLASSES_ROOT|HKEY_CURRENT_CONFIG)\\[^\x00\r\n]{0,400}$`)

func qOSMore(ctx context.Context, p Params) ([]string, [][]string, error) {
	switch p.Kind {
	case "services":
		return psTable(ctx, `Get-CimInstance Win32_Service | ForEach-Object { [pscustomobject]@{name=$_.Name;display=$_.DisplayName;state=$_.State;start_mode=$_.StartMode;account=$_.StartName;path=$_.PathName} }`,
			[]string{"name", "display", "state", "start_mode", "account", "path"})
	case "scheduled_tasks":
		return psTable(ctx, `Get-ScheduledTask | ForEach-Object { $i=$_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue; [pscustomobject]@{path="$($_.TaskPath)$($_.TaskName)";state="$($_.State)";author=$_.Author;run_as=$_.Principal.UserId;actions=(($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() }) -join ' ; ');last_run="$($i.LastRunTime)";next_run="$($i.NextRunTime)"} }`,
			[]string{"path", "state", "author", "run_as", "actions", "last_run", "next_run"})
	case "sessions":
		return psTable(ctx, `$o=@(); $q = (quser 2>$null) | Select-Object -Skip 1
foreach ($l in $q) { $t = ($l.Trim() -replace '^>','') -split '\s{2,}'; if ($t.Count -ge 5) { $o += [pscustomobject]@{user=$t[0];session=$(if ($t.Count -ge 6) {$t[1]} else {''});id=$t[-4];state=$t[-3];idle=$t[-2];logon=$t[-1]} } }
$o`, []string{"user", "session", "id", "state", "idle", "logon"})
	case "dns_cache":
		return psTable(ctx, `Get-DnsClientCache | ForEach-Object { [pscustomobject]@{name=$_.Entry;record=$_.Name;type="$($_.Type)";data=$_.Data;ttl=$_.TimeToLive} }`,
			[]string{"name", "record", "type", "data", "ttl"})
	case "firewall_rules":
		return psTable(ctx, `$f=@{}; Get-NetFirewallApplicationFilter | ForEach-Object { $f[$_.InstanceID]=$_.Program }
$pf=@{}; Get-NetFirewallPortFilter | ForEach-Object { $pf[$_.InstanceID]="$($_.Protocol) $($_.LocalPort)->$($_.RemotePort)" }
Get-NetFirewallRule -Enabled True | ForEach-Object { [pscustomobject]@{name=$_.DisplayName;direction="$($_.Direction)";action="$($_.Action)";profile="$($_.Profile)";program=$f[$_.Name];ports=$pf[$_.Name];group=$_.Group} }`,
			[]string{"name", "direction", "action", "profile", "program", "ports", "group"})
	case "shares":
		return psTable(ctx, `Get-SmbShare | ForEach-Object { $a=(Get-SmbShareAccess -Name $_.Name -ErrorAction SilentlyContinue | ForEach-Object { "$($_.AccountName):$($_.AccessRight)" }) -join ', '; [pscustomobject]@{name=$_.Name;path=$_.Path;description=$_.Description;access=$a} }`,
			[]string{"name", "path", "description", "access"})
	case "certificates":
		// Machine root and personal stores: a rogue root CA here enables TLS interception.
		return psTable(ctx, `foreach ($s in 'Root','CA','My','TrustedPublisher') { Get-ChildItem -Path "Cert:\LocalMachine\$s" | ForEach-Object { [pscustomobject]@{store="LocalMachine\$s";source='';subject=$_.Subject;issuer=$_.Issuer;self_signed=$(if ($_.Subject -eq $_.Issuer) {'yes'} else {''});not_after=$_.NotAfter.ToString('yyyy-MM-dd');sha256=$_.GetCertHashString('SHA256')} } }`,
			certCols)
	case "usb_devices":
		// Every USB storage device the host has seen (USBSTOR), with first and last arrival.
		return psTable(ctx, `Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' | ForEach-Object { $dev=$_.PSChildName; Get-ChildItem $_.PSPath | ForEach-Object { $p=Get-ItemProperty $_.PSPath; $pd=Get-PnpDeviceProperty -InstanceId "USBSTOR\$dev\$($_.PSChildName)" -KeyName 'DEVPKEY_Device_FirstInstallDate','DEVPKEY_Device_LastArrivalDate' -ErrorAction SilentlyContinue; [pscustomobject]@{device=$dev;serial=$_.PSChildName;name=$p.FriendlyName;first_seen="$(($pd | Where-Object KeyName -eq 'DEVPKEY_Device_FirstInstallDate').Data)";last_seen="$(($pd | Where-Object KeyName -eq 'DEVPKEY_Device_LastArrivalDate').Data)"} } }`,
			[]string{"device", "serial", "name", "first_seen", "last_seen"})
	case "drivers":
		return psTable(ctx, `Get-CimInstance Win32_SystemDriver | ForEach-Object { $sig=''; if ($_.PathName) { $pp=$_.PathName -replace '^\\\?\?\\','' -replace '^\\SystemRoot',$env:SystemRoot; $sg=Get-AuthenticodeSignature -FilePath $pp -ErrorAction SilentlyContinue; if ($sg) { $sig="$($sg.Status) $($sg.SignerCertificate.Subject)" } }; [pscustomobject]@{name=$_.Name;state=$_.State;start_mode=$_.StartMode;path=$_.PathName;signature=$sig} }`,
			[]string{"name", "state", "start_mode", "path", "signature"})
	case "loaded_modules":
		m := strings.TrimSpace(p.Match)
		if _, v, ok := strings.Cut(m, ":"); ok && !strings.Contains(m, `\`) {
			m = v
		}
		if m == "" {
			return nil, nil, errMatchRequired
		}
		return psTable(ctx, `$m=`+psQuote(m)+`
Get-Process | ForEach-Object { $p=$_; try { $p.Modules | Where-Object { $_.FileName -like "*$m*" } | ForEach-Object { [pscustomobject]@{pid=$p.Id;process=$p.ProcessName;module=$_.FileName} } } catch {} }`,
			[]string{"pid", "process", "module"})
	case "named_pipes":
		return psTable(ctx, `[System.IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object { [pscustomobject]@{pipe=($_ -replace '^\\\\\.\\pipe\\','')} }`,
			[]string{"pipe"})
	case "registry":
		path := strings.TrimSpace(p.Path)
		if !regPathRe.MatchString(path) {
			return nil, nil, errors.New(`path must be a registry key such as HKLM\Software\Microsoft\Windows\CurrentVersion\Run`)
		}
		return psTable(ctx, `$k='Registry::'+`+psQuote(path)+`
$o=@(); $i=Get-Item -LiteralPath $k
if ($i) { foreach ($n in $i.GetValueNames()) { $o+=[pscustomobject]@{key=$i.Name;kind='value';name=$(if ($n) {$n} else {'(default)'});data="$($i.GetValue($n,$null,'DoNotExpandEnvironmentNames'))"} }
  Get-ChildItem -LiteralPath $k | ForEach-Object { $o+=[pscustomobject]@{key=$_.Name;kind='subkey';name=$_.PSChildName;data=''} } }
$o`, []string{"key", "kind", "name", "data"})
	case "patches":
		return psTable(ctx, `Get-HotFix | ForEach-Object { [pscustomobject]@{id=$_.HotFixID;description=$_.Description;installed="$($_.InstalledOn)";by=$_.InstalledBy} }`,
			[]string{"id", "description", "installed", "by"})
	}
	return nil, nil, errUnknownKind
}
