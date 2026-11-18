//go:build windows

package response

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// psTable runs a script that emits objects whose property names are cols and
// returns them as rows.
func psTable(ctx context.Context, script string, cols []string) ([]string, [][]string, error) {
	out, err := psRun(ctx, "$ErrorActionPreference='SilentlyContinue'\n"+script+" | ConvertTo-Json -Compress -Depth 3", 60*time.Second)
	if err != nil && strings.TrimSpace(out) == "" {
		return nil, nil, err
	}
	out = strings.TrimSpace(out)
	if out == "" || out == "null" {
		return cols, nil, nil
	}
	var recs []map[string]any
	if strings.HasPrefix(out, "[") {
		if err := json.Unmarshal([]byte(out), &recs); err != nil {
			return nil, nil, fmt.Errorf("cannot parse PowerShell output: %v", err)
		}
	} else {
		var one map[string]any
		if err := json.Unmarshal([]byte(out), &one); err != nil {
			return nil, nil, fmt.Errorf("cannot parse PowerShell output: %v", err)
		}
		recs = []map[string]any{one}
	}
	rows := make([][]string, 0, len(recs))
	for _, r := range recs {
		row := make([]string, len(cols))
		for i, c := range cols {
			if v, ok := r[c]; ok && v != nil {
				row[i] = fmt.Sprint(v)
			}
		}
		rows = append(rows, row)
	}
	return cols, rows, nil
}

func qProcesses(ctx context.Context) ([]string, [][]string, error) {
	return psTable(ctx, `$g=@{}; Get-Process -IncludeUserName -ErrorAction SilentlyContinue | ForEach-Object { $g[[int]$_.Id]=$_ }
Get-CimInstance Win32_Process | ForEach-Object { $x=$g[[int]$_.ProcessId]; [pscustomobject]@{pid=$_.ProcessId;ppid=$_.ParentProcessId;user=$(if ($x) {$x.UserName} else {''});name=$_.Name;mem_mb=[math]::Round($_.WorkingSetSize/1MB,1);path=$_.ExecutablePath;cmdline=$_.CommandLine} }`,
		[]string{"pid", "ppid", "user", "name", "mem_mb", "path", "cmdline"})
}

func qConnections(ctx context.Context) ([]string, [][]string, error) {
	return psTable(ctx, `$p=@{}; Get-Process | ForEach-Object { $p[[int]$_.Id]=$_.ProcessName }
$t=Get-NetTCPConnection | ForEach-Object { [pscustomobject]@{proto='tcp';state="$($_.State)";local="$($_.LocalAddress):$($_.LocalPort)";remote="$($_.RemoteAddress):$($_.RemotePort)";pid=$_.OwningProcess;process=$p[[int]$_.OwningProcess]} }
$u=Get-NetUDPEndpoint | ForEach-Object { [pscustomobject]@{proto='udp';state='UNCONN';local="$($_.LocalAddress):$($_.LocalPort)";remote='*';pid=$_.OwningProcess;process=$p[[int]$_.OwningProcess]} }
@($t)+@($u)`, []string{"proto", "state", "local", "remote", "pid", "process"})
}

func qPersistence(ctx context.Context) ([]string, [][]string, error) {
	return psTable(ctx, `$o=@()
foreach ($k in 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce') {
  $i=Get-ItemProperty -Path $k; if ($i) { $i.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $o+=[pscustomobject]@{type='run_key';location="$k\$($_.Name)";detail="$($_.Value)"} } } }
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object { $a=($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; '; $o+=[pscustomobject]@{type='scheduled_task';location="$($_.TaskPath)$($_.TaskName)";detail=$a} }
Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName -and $_.PathName -notmatch 'svchost.exe|\\Windows\\System32\\|\\Windows\\SysWOW64\\' } | ForEach-Object { $o+=[pscustomobject]@{type='service';location=$_.Name;detail="$($_.PathName) (as $($_.StartName))"} }
foreach ($d in "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp", "$env:SystemDrive\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup") { Get-ChildItem -Path $d -File -Force | ForEach-Object { $o+=[pscustomobject]@{type='startup_folder';location=$_.FullName;detail=''} } }
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer | ForEach-Object { $o+=[pscustomobject]@{type='wmi_consumer';location=$_.Name;detail="$($_.__CLASS)"} }
$o`, []string{"type", "location", "detail"})
}

func qSoftware(ctx context.Context) ([]string, [][]string, error) {
	return psTable(ctx, `$k='HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
Get-ItemProperty -Path $k | Where-Object { $_.DisplayName } | ForEach-Object { [pscustomobject]@{name=$_.DisplayName;version=$_.DisplayVersion;publisher=$_.Publisher} }`,
		[]string{"name", "version", "publisher"})
}

func qUsers(ctx context.Context) ([]string, [][]string, error) {
	return psTable(ctx, `$adm=@(Get-LocalGroupMember -Group Administrators | ForEach-Object { ($_.Name -split '\\')[-1] })
Get-LocalUser | ForEach-Object { [pscustomobject]@{user=$_.Name;enabled="$($_.Enabled)";last_logon="$($_.LastLogon)";admin=$(if ($adm -contains $_.Name) {'yes'} else {'no'})} }`,
		[]string{"user", "enabled", "last_logon", "admin"})
}
