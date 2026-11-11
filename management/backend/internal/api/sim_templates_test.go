package api

const psHeader = `#requires -Version 5.1
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

`

const psBody = `
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
`

const shHeader = `#!/usr/bin/env bash
# ObsidianWatch @@OS@@ alert self-test. GENERATED FILE - do not edit by hand.
# Regenerate: OW_UPDATE_SIM=1 go test ./internal/api -run TestSimScriptsUpToDate
#
# Runs harmless look-alikes of attacker behaviour on THIS machine: it only runs
# /bin/echo with the suspicious command text as arguments. Nothing is exploited,
# downloaded or executed. It then asks your management server whether each
# expected alert appeared and prints PASS/FAIL per rule.
#
# Use a test machine: it creates real alerts (and may email or webhook them).
# Every test carries the marker OWSIM-<nonce> so the alerts are easy to find.
# The ObsidianWatch agent must be running on this machine.
#
# Usage:
#   ./ow-simulate-*.sh --api https://obsidianwatch.example.com [--user admin] [--insecure]
#                      [--host NAME] [--wait 180] [--only ID,ID] [--no-verify] [--list] [--yes]
#   Set OW_TOKEN to skip the login prompt; OW_PASSWORD for non-interactive use.

API=""; USER_NAME="admin"; HOST_NAME="$(hostname -s 2>/dev/null || hostname)"; WAIT=180
ONLY=""; INSECURE=""; NOVERIFY=0; LIST=0; YES=0; TOKEN="${OW_TOKEN:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    --api) API="$2"; shift 2;;
    --user) USER_NAME="$2"; shift 2;;
    --host) HOST_NAME="$2"; shift 2;;
    --wait) WAIT="$2"; shift 2;;
    --only) ONLY="$2"; shift 2;;
    --insecure) INSECURE="-k"; shift;;
    --no-verify) NOVERIFY=1; shift;;
    --list) LIST=1; shift;;
    --yes) YES=1; shift;;
    -h|--help) sed -n '2,18p' "$0"; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done

IDS=(); TITLES=(); NEEDLES=(); CMDS=(); KINDS=(); NAMES=(); SKIPPED=()
selected() { [ -z "$ONLY" ] && return 0; case ",$ONLY," in *",$1,"*) return 0;; esac; return 1; }
# T id title json-title word...   (a runnable test)
T() { local id="$1" title="$2" needle="$3"; shift 3
  selected "$id" || return 0
  IDS+=("$id"); TITLES+=("$title"); NEEDLES+=("$needle"); KINDS+=("echo"); NAMES+=("")
  CMDS+=("$(printf '%s\037' "$@")")
}
# N id title json-title name word...  (a stand-in: a copy of /bin/echo named like the tool, run with its arguments)
N() { local id="$1" title="$2" needle="$3" name="$4"; shift 4
  selected "$id" || return 0
  IDS+=("$id"); TITLES+=("$title"); NEEDLES+=("$needle"); KINDS+=("named"); NAMES+=("$name")
  CMDS+=("$(printf '%s\037' "$@")")
}
# S "id: reason"                  (a rule that cannot be simulated safely)
S() { SKIPPED+=("$1"); }

# ---- generated tests ----
`

const shBody = `# ---- end of generated tests ----

if [ "$LIST" = 1 ]; then
  echo "${#IDS[@]} runnable tests:"
  for i in "${!IDS[@]}"; do printf '  %-14s %s\n' "${IDS[$i]}" "${TITLES[$i]}"; done
  echo; echo "${#SKIPPED[@]} rules cannot be simulated safely from a script:"
  for s in "${SKIPPED[@]}"; do echo "  $s"; done
  exit 0
fi

if [ "$NOVERIFY" = 0 ] && [ -z "$API" ]; then echo "Pass --api URL (or --no-verify to only run the actions)." >&2; exit 2; fi
if [ "$YES" = 0 ]; then
  printf "This will create about %s test alerts for host '%s'. Type YES to continue: " "${#IDS[@]}" "$HOST_NAME"
  read -r ans; [ "$ans" = "YES" ] || exit 0
fi

curl_api() { curl -s $INSECURE -H 'Content-Type: application/json' ${TOKEN:+-H "Authorization: Bearer $TOKEN"} "$@"; }
host_alerts() {
  local h
  for h in "$HOST_NAME" "$(printf '%s' "$HOST_NAME" | tr '[:lower:]' '[:upper:]')" "$(printf '%s' "$HOST_NAME" | tr '[:upper:]' '[:lower:]')"; do
    curl_api "$API/api/v1/alerts?host=$h" | grep -o '"id":[0-9]*,"created_at":"[^"]*","title":"[^"]*"'
  done | sort -u
}

BASE=0
if [ "$NOVERIFY" = 0 ]; then
  if [ -z "$TOKEN" ]; then
    PASS="${OW_PASSWORD:-}"
    if [ -z "$PASS" ]; then printf "Password for '%s': " "$USER_NAME"; stty -echo 2>/dev/null; read -r PASS; stty echo 2>/dev/null; echo; fi
    esc=$(printf '%s' "$PASS" | sed 's/\\/\\\\/g; s/"/\\"/g')
    TOKEN=$(curl_api -d "{\"username\":\"$USER_NAME\",\"password\":\"$esc\"}" "$API/auth/login" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
    [ -n "$TOKEN" ] || { echo "Login failed." >&2; exit 2; }
  fi
  BASE=$(host_alerts | sed 's/^"id":\([0-9]*\),.*/\1/' | sort -n | tail -1); BASE=${BASE:-0}
fi

NONCE="$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 8)"
SIMDIR="/var/tmp/owsim-$NONCE"; mkdir -p "$SIMDIR"; trap 'rm -rf "$SIMDIR"' EXIT
echo "Running ${#IDS[@]} tests (marker OWSIM-$NONCE)..."
for i in "${!IDS[@]}"; do
  IFS=$'\037' read -r -a W <<< "${CMDS[$i]}"
  if [ "${KINDS[$i]}" = named ]; then
    cp /bin/echo "$SIMDIR/${NAMES[$i]}" 2>/dev/null && "$SIMDIR/${NAMES[$i]}" "${W[@]}" "OWSIM-$NONCE" >/dev/null 2>&1
  else
    /bin/echo "OWSIM-$NONCE" "${W[@]}" >/dev/null 2>&1
  fi
  sleep 0.3
done
[ "$NOVERIFY" = 1 ] && { echo "Actions done; verification skipped."; exit 0; }

echo "Waiting up to ${WAIT}s for alerts (agent flush + detection cycle)..."
END=$(( $(date +%s) + WAIT )); FOUND=()
while :; do
  sleep 10
  NEW=$(host_alerts | awk -F'[:,]' -v b="$BASE" '$2+0 > b+0' )
  PENDING=0
  for i in "${!IDS[@]}"; do
    if echo "$NEW" | grep -qF "\"title\":${NEEDLES[$i]}"; then FOUND[$i]=1; else PENDING=$((PENDING+1)); fi
  done
  [ "$PENDING" = 0 ] && break
  [ "$(date +%s)" -ge "$END" ] && break
done

PASSN=0; FAILN=0; echo
for i in "${!IDS[@]}"; do
  if [ "${FOUND[$i]:-0}" = 1 ]; then printf 'PASS  %-14s %s\n' "${IDS[$i]}" "${TITLES[$i]}"; PASSN=$((PASSN+1))
  else printf 'FAIL  %-14s %s\n' "${IDS[$i]}" "${TITLES[$i]}"; FAILN=$((FAILN+1)); fi
done
echo; echo "$PASSN passed, $FAILN failed, ${#SKIPPED[@]} rules not simulable (run with --list)."
if [ "$FAILN" -gt 0 ]; then
  echo "A FAIL means the event never produced that alert. Check: agent running and connected; the rule is enabled and not in"
  echo "observe/allowlist mode; the host name matches --host; the alert was not suppressed."
fi
echo "Close the test alerts afterwards: search alerts for the marker OWSIM-$NONCE."
[ "$FAILN" -eq 0 ]
`
