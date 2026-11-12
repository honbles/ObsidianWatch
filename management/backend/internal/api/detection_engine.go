package api

// detection_engine.go — per-OS threat detection engine.
//
// Three separate signature sets: windowsSignatures, linuxSignatures, macosSignatures.
// Each set ONLY uses fields actually populated by that platform's collectors:
//
//  LINUX collectors populate:
//    process   → EventType="process", ProcessName, CommandLine, ImagePath  source=proc-poll/connector
//    journald  → EventType="logon",   ProcessName=syslogID, CommandLine=full_log_msg, UserName
//    network   → EventType="network", DstIP, DstPort, SrcIP, ProcessName  Severity=1 (always)
//    dns       → EventType="dns",     DstIP=queried_domain
//    file      → EventType="file",    FilePath, FileHash
//    registry  → EventType="registry",RegKey=config_path, FilePath=config_path  (configmon — NOT Windows registry)
//
//  WINDOWS collectors populate:
//    process   → EventType="process", ProcessName, CommandLine, ImagePath, UserName  source=ETW
//    sysmon    → EventType="process"|"network"|"file"|"registry"|"sysmon"
//               ProcessName, CommandLine, ImagePath, DstIP, DstPort, FilePath, RegKey
//    eventlog  → EventType="logon"|"process"|"raw", EventID, ProcessName, CommandLine, UserName
//    network   → EventType="network", DstIP, DstPort  Severity=1 (always low from iphlpapi)
//    registry  → EventType="registry", RegKey, RegValue, RegData
//    fim       → EventType="file",   FilePath
//    dns       → EventType="dns",    DstIP=queried_domain  (Sysmon event 22)
//
//  MACOS collectors populate:
//    process   → EventType="process", ProcessName, CommandLine  (no ImagePath)
//    syslog    → EventType="syslog",  ProcessName, CommandLine=message
//    network   → EventType="network", DstIP, DstPort  Severity=1 (always)
//    dns       → EventType="dns",     DstIP=queried_domain
//    file      → EventType="file",    FilePath, FileHash
//    registry  → EventType="registry",RegKey=config_path  (configmon)

import (
	"regexp"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/notify"
	"obsidianwatch/management/internal/store"
)

// ── Signature type ────────────────────────────────────────────────────────────

type ThreatSig struct {
	ID          string
	Name        string
	Description string
	Severity    int
	MITRE       string
	Category    string
	Match       func(ev store.Event) bool
}

// ── Field extractors (all return lowercase) ───────────────────────────────────

func cl(ev store.Event) string {
	if ev.CommandLine == nil {
		return ""
	}
	return strings.ToLower(*ev.CommandLine)
}
func proc(ev store.Event) string {
	if ev.ProcessName == nil {
		return ""
	}
	return strings.ToLower(*ev.ProcessName)
}
func img(ev store.Event) string {
	if ev.ImagePath == nil {
		return ""
	}
	return strings.ToLower(*ev.ImagePath)
}
// procIn reports whether the process base name (lower-case, without a
// directory or ".exe") is exactly one of names. Substring matching on short
// names ("sh", "nc", "host", "tar") matched ssh, sync, ghost, start-stop-daemon.
func procIn(ev store.Event, names ...string) bool {
	if ev.ProcessName == nil {
		return false
	}
	n := strings.ToLower(strings.TrimSpace(*ev.ProcessName))
	if i := strings.LastIndexAny(n, `/\`); i >= 0 {
		n = n[i+1:]
	}
	n = strings.TrimSuffix(n, ".exe")
	for _, w := range names {
		if n == w {
			return true
		}
	}
	return false
}

func fp(ev store.Event) string {
	if ev.FilePath == nil {
		return ""
	}
	return strings.ToLower(*ev.FilePath)
}
func rk(ev store.Event) string {
	if ev.RegKey == nil {
		return ""
	}
	return strings.ToLower(*ev.RegKey)
}
func dstip(ev store.Event) string {
	if ev.DstIP == nil {
		return ""
	}
	return strings.ToLower(*ev.DstIP)
}
// G-12: rawStr lower-cases the full raw JSON; it is called by hundreds of
// rules per event, so memoise the most recent conversion (keyed by the raw
// buffer's address + length). Events are evaluated one at a time against all
// rules, so a single-entry cache removes nearly all repeats.
var (
	rawCacheMu  sync.Mutex
	rawCachePtr *byte
	rawCacheLen int
	rawCacheVal string
)

func rawStr(ev store.Event) string {
	if len(ev.Raw) == 0 {
		return ""
	}
	p := &ev.Raw[0]
	rawCacheMu.Lock()
	if rawCachePtr == p && rawCacheLen == len(ev.Raw) {
		v := rawCacheVal
		rawCacheMu.Unlock()
		return v
	}
	rawCacheMu.Unlock()
	v := strings.ToLower(string(ev.Raw))
	rawCacheMu.Lock()
	rawCachePtr, rawCacheLen, rawCacheVal = p, len(ev.Raw), v
	rawCacheMu.Unlock()
	return v
}
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// ══════════════════════════════════════════════════════════════════════════════
// LINUX SIGNATURES
// ══════════════════════════════════════════════════════════════════════════════
var linuxSignatures = []ThreatSig{

	// ── Execution ────────────────────────────────────────────────────────────
	{
		ID: "L-T1059.004a", Name: "Shell Suspicious Execution",
		Description: "Shell running a suspicious inline command — common dropper and execution technique.",
		Severity:    4, MITRE: "T1059.004", Category: "Execution",
		Match: func(ev store.Event) bool {
			if ev.EventType != "process" {
				return false
			}
			isShell := procIn(ev, "bash", "sh", "zsh", "dash", "ksh", "fish")
			// Match shells running -c with suspicious content (pipe content IS in -c argument)
			// OR shells running from suspicious paths
			return isShell && (containsAny(cl(ev),
				"-c curl", "-c wget", "-c python", "-c nc ", "-c ncat",
				"/dev/shm", "/dev/tcp", "0>&1") ||
				shPipeToShellRe.MatchString(cl(ev)) || shInteractiveRe.MatchString(cl(ev)))
		},
	},
	{
		ID: "L-T1059.004b", Name: "Executable Run from /tmp or /dev/shm",
		Description: "Process spawned from /tmp, /dev/shm, or /var/tmp — common malware staging.",
		Severity:    5, MITRE: "T1059.004", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && execFromDir(ev, "/tmp/", "/dev/shm/", "/var/tmp/")
		},
	},
	{
		ID: "L-T1059.006", Name: "Python/Perl/Ruby Reverse Shell",
		Description: "Interpreter running inline code with socket/exec — reverse shell technique.",
		Severity:    5, MITRE: "T1059.006", Category: "Execution",
		Match: func(ev store.Event) bool {
			if ev.EventType != "process" {
				return false
			}
			isInterp := containsAny(proc(ev), "python", "python3", "perl", "ruby", "php", "node")
			// -c flag with socket/exec content is visible in /proc/cmdline
			return isInterp && containsAny(cl(ev),
				"-c import socket", "-c \"import socket", "socket.socket",
				"connect((", "/dev/tcp", "pty.spawn", "subprocess.call",
				"os.execv", "os.system", "popen(")
		},
	},
	{
		ID: "L-T1059.004c", Name: "Netcat Reverse Shell",
		Description: "Netcat with -e or -c flag — classic reverse shell payload.",
		Severity:    5, MITRE: "T1059.004", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" &&
				procIn(ev, "nc", "ncat", "netcat", "nc.openbsd", "nc.traditional") &&
				containsAny(cl(ev), " -e ", " -c ", "--exec", "-e /bin", "-e sh", "-e bash")
		},
	},
	{
		ID: "L-T1105", Name: "curl/wget Suspicious Download",
		Description: "curl or wget downloading from internet to stdout or temp location — dropper technique.",
		Severity:    3, MITRE: "T1105", Category: "Execution",
		Match: func(ev store.Event) bool {
			if ev.EventType != "process" {
				return false
			}
			isFetcher := containsAny(proc(ev), "curl", "wget")
			// A real download (URL present) written to a staging directory or
			// to stdout for piping — not just any curl that mentions /tmp.
			return isFetcher && containsAny(cl(ev), "://") && containsAny(cl(ev),
				"-o /tmp", "-o /dev/shm", "-o /var/tmp", "-O /tmp", "-O /dev/shm",
				"--output /tmp", "--output /dev/shm", "--output /var/tmp",
				"-o-", "--output-", "-p /tmp", "--directory-prefix=/tmp", "--directory-prefix=/dev/shm")
		},
	},

	// ── Discovery ────────────────────────────────────────────────────────────
	{
		ID: "L-T1087.001", Name: "Linux User Enumeration",
		Description: "Commands enumerating local users and sudo privileges.",
		Severity:    2, MITRE: "T1087.001", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && (containsAny(cl(ev),
				"cat /etc/passwd", "getent passwd", "id -a", "sudo -l", "lastlog") ||
				procIn(ev, "last", "who", "w"))
		},
	},
	{
		ID: "L-T1046", Name: "Network Scanning Tool",
		Description: "nmap, masscan, or similar scanner detected.",
		Severity:    3, MITRE: "T1046", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev)+cl(ev), "nmap", "masscan", "zmap", "arp-scan", "netdiscover")
		},
	},
	{
		ID: "L-T1592", Name: "Packet Capture Tool",
		Description: "tcpdump or tshark running — may capture credentials.",
		Severity:    4, MITRE: "T1592", Category: "Reconnaissance",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev)+cl(ev), "tcpdump", "tshark", "wireshark", "dumpcap")
		},
	},
	{
		ID: "L-T1590", Name: "DNS/Domain Reconnaissance",
		Description: "dig, nslookup, or dnsrecon used for domain enumeration.",
		Severity:    2, MITRE: "T1590", Category: "Reconnaissance",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && procIn(ev, "dig", "nslookup", "host", "dnsenum", "dnsrecon", "fierce", "whois")
		},
	},

	// ── Privilege Escalation ─────────────────────────────────────────────────
	{
		ID: "L-T1548.001a", Name: "SUID Bit Set (chmod +s)",
		Description: "chmod setting SUID bit — privilege escalation vector.",
		Severity:    4, MITRE: "T1548.001", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "chmod") &&
				containsAny(cl(ev), "+s", "4755", "4777", "u+s")
		},
	},
	{
		ID: "L-T1548.001b", Name: "Sudo Root Shell",
		Description: "sudo used to spawn an interactive root shell.",
		Severity:    4, MITRE: "T1548.001", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "sudo") &&
				containsAny(cl(ev), "sudo su", "sudo bash", "sudo sh", "sudo -s", "sudo -i")
		},
	},
	{
		ID: "L-T1547.006", Name: "Kernel Module Loaded",
		Description: "insmod or modprobe executed — possible rootkit installation.",
		Severity:    5, MITRE: "T1547.006", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "insmod", "modprobe")
		},
	},
	{
		ID: "L-T1611", Name: "Container Escape Indicator",
		Description: "docker.sock accessed or container escape tools detected.",
		Severity:    5, MITRE: "T1611", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return containsAny(fp(ev)+cl(ev)+proc(ev), "docker.sock", "/var/run/docker.sock",
				"nsenter", "--privileged", "cap_sys_admin", "pivot_root", "deepce", "amicontained")
		},
	},

	// ── Credential Access ────────────────────────────────────────────────────
	{
		ID: "L-T1003.008", Name: "/etc/shadow Read",
		Description: "Direct read of /etc/shadow — password hash dumping.",
		Severity:    5, MITRE: "T1003.008", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return containsAny(fp(ev)+cl(ev)+rk(ev), "/etc/shadow", "/etc/gshadow") ||
				(ev.EventType == "process" && containsAny(cl(ev), "unshadow", "hashcat", "john --"))
		},
	},
	{
		ID: "L-T1110.001", Name: "SSH Brute Force (journald)",
		Description: "Repeated SSH authentication failures in journald — brute force detected.",
		Severity:    4, MITRE: "T1110.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			// journald sets EventType="logon", CommandLine=full sshd message
			return ev.EventType == "logon" && containsAny(cl(ev),
				"failed password", "authentication failure", "invalid user",
				"ssh_brute_force", "maximum authentication attempts")
		},
	},
	{
		ID: "L-T1552.004", Name: "SSH Private Key Access",
		Description: "SSH private key file accessed — credential theft.",
		Severity:    4, MITRE: "T1552.004", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return containsAny(fp(ev)+cl(ev), "id_rsa", "id_ed25519", "id_ecdsa", "/.ssh/", ".pem")
		},
	},
	{
		ID: "L-T1552.005", Name: "Cloud Credential File Access",
		Description: "AWS, GCP, or Azure credential files read — cloud credential theft.",
		Severity:    5, MITRE: "T1552.005", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return containsAny(fp(ev)+cl(ev), ".aws/credentials", ".aws/config",
				".config/gcloud", "application_default_credentials.json",
				".azure/", "terraform.tfstate")
		},
	},

	// ── Persistence ──────────────────────────────────────────────────────────
	{
		ID: "L-T1053.003", Name: "Cron Persistence",
		Description: "Crontab file written — common Linux persistence mechanism.",
		Severity:    4, MITRE: "T1053.003", Category: "Persistence",
		Match: func(ev store.Event) bool {
			// configmon emits EventType="registry" for config file changes on Linux
			return (ev.EventType == "file" || ev.EventType == "registry") &&
				containsAny(fp(ev)+rk(ev), "/etc/cron", "/var/spool/cron", "crontab")
		},
	},
	{
		ID: "L-T1543.002", Name: "New Systemd Service",
		Description: "Systemd unit file written to system directories — persistence.",
		Severity:    4, MITRE: "T1543.002", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return (ev.EventType == "file" || ev.EventType == "registry") &&
				containsAny(fp(ev)+rk(ev), "/etc/systemd/system/", "/usr/lib/systemd/", "/lib/systemd/") &&
				containsAny(fp(ev)+rk(ev), ".service", ".timer", ".socket")
		},
	},
	{
		ID: "L-T1546.004", Name: "Shell Profile Modified",
		Description: ".bashrc, .profile, or /etc/profile written — shell-based persistence.",
		Severity:    4, MITRE: "T1546.004", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return (ev.EventType == "file" || ev.EventType == "registry") &&
				containsAny(fp(ev)+rk(ev), ".bashrc", ".bash_profile", ".zshrc", "/etc/profile", "/etc/bash.bashrc")
		},
	},
	{
		ID: "L-T1574.006", Name: "LD_PRELOAD Hijacking",
		Description: "LD_PRELOAD or /etc/ld.so.preload set — shared library hijacking.",
		Severity:    5, MITRE: "T1574.006", Category: "Persistence",
		Match: func(ev store.Event) bool {
			// Process command lines and file events only: raw log text and
			// environment dumps mention LD_PRELOAD without anyone using it.
			if ev.EventType != "process" && ev.EventType != "file" {
				return false
			}
			c := cl(ev)
			if strings.Contains(fp(ev), "ld.so.preload") || strings.Contains(c, "ld.so.preload") {
				return true
			}
			if !strings.Contains(c, "ld_preload=") {
				return false
			}
			for _, lib := range benignPreloadLibs {
				if strings.Contains(c, strings.ToLower(lib)) {
					return false
				}
			}
			return true
		},
	},

	// ── Defence Evasion ──────────────────────────────────────────────────────
	{
		ID: "L-T1070.002", Name: "Log File Deletion or History Wipe",
		Description: "System logs deleted or shell history cleared — covering tracks.",
		Severity:    5, MITRE: "T1070.002", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			if ev.EventType == "process" {
				return containsAny(cl(ev), "rm /var/log", "rm -rf /var/log", "> /var/log",
					"history -c", "unset histfile", "histsize=0", "truncate -s 0")
			}
			return (ev.EventType == "file" || ev.EventType == "registry") &&
				containsAny(fp(ev)+rk(ev), "/var/log/auth", "/var/log/syslog", "/var/log/secure", "/var/log/messages")
		},
	},
	{
		ID: "L-T1222.002", Name: "World-Writable File (chmod 777)",
		Description: "chmod 777 or a+w executed — permissive file created.",
		Severity:    3, MITRE: "T1222.002", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "chmod") &&
				containsAny(cl(ev), "777", "a+w", "o+w")
		},
	},

	// ── Lateral Movement ────────────────────────────────────────────────────
	{
		ID: "L-T1021.004", Name: "SSH Tunnel / Port Forward",
		Description: "SSH -L/-R/-D flag — tunnelling or SOCKS proxy.",
		Severity:    4, MITRE: "T1021.004", Category: "Lateral Movement",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && procIn(ev, "ssh") &&
				containsAny(cl(ev), " -l ", " -r ", " -d ", "-nfl", "-nfr", "-nfd")
		},
	},

	// ── Command and Control ──────────────────────────────────────────────────
	{
		ID: "L-T1572", Name: "DNS Tunnelling Indicator",
		Description: "Unusually long DNS hostname — possible DNS tunnelling for C2.",
		Severity:    4, MITRE: "T1572", Category: "Command and Control",
		Match: func(ev store.Event) bool {
			return ev.EventType == "dns" && ev.DstIP != nil && len(*ev.DstIP) > 60
		},
	},
	{
		ID: "L-T1219", Name: "Remote Access Tool",
		Description: "Known commercial remote access tool detected.",
		Severity:    3, MITRE: "T1219", Category: "Command and Control",
		Match: func(ev store.Event) bool {
			return containsAny(proc(ev)+cl(ev), "anydesk", "teamviewer", "rustdesk", "screenconnect", "logmein")
		},
	},
	{
		ID: "L-T1090.003", Name: "Tor / Proxy Tool",
		Description: "Tor or proxychains detected — anonymous communication channel.",
		Severity:    4, MITRE: "T1090.003", Category: "Command and Control",
		Match: func(ev store.Event) bool {
			return containsAny(proc(ev)+cl(ev)+fp(ev), "tor ", "torsocks", "proxychains", "proxifier")
		},
	},
	{
		ID: "L-T1078.004", Name: "Cloud Metadata Service Access",
		Description: "Access to 169.254.169.254 — instance credential theft.",
		Severity:    4, MITRE: "T1078.004", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return containsAny(dstip(ev)+cl(ev), "169.254.169.254", "metadata.google.internal")
		},
	},

	// ── Exfiltration ────────────────────────────────────────────────────────
	{
		ID: "L-T1048", Name: "curl POST Data Exfiltration",
		Description: "curl sending data with POST or upload flags — possible exfiltration.",
		Severity:    3, MITRE: "T1048", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "curl") &&
				containsAny(cl(ev), " -d @", " --data @", " --data-binary @", " --data-raw @", " -t /", " -t ~", "--upload-file", " -f file=@", " --form ")
		},
	},
	{
		ID: "L-T1560", Name: "Archive of Sensitive Directory",
		Description: "tar/zip archiving /etc, /home, or sensitive directories — staging for exfil.",
		Severity:    3, MITRE: "T1560.001", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && procIn(ev, "tar", "zip", "7z", "7za", "gzip", "bzip2", "xz") &&
				containsAny(cl(ev), "/home/", "/etc/", "/root/", "database", ".sql", "dump") &&
				!containsAny(cl(ev), "/var/backups/")
		},
	},
	{
		ID: "L-T1567", Name: "Paste/File Sharing Service Contact",
		Description: "Connection to known paste or file-sharing site — C2 or exfil channel.",
		Severity:    4, MITRE: "T1567.001", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			return containsAny(dstip(ev)+cl(ev), "pastebin.com", "paste.ee", "hastebin.com",
				"wetransfer.com", "mega.nz", "transfer.sh", "0x0.st", "gofile.io")
		},
	},
	{
		ID: "L-DLP-010", Name: "Database Dump Command",
		Description: "mysqldump, pg_dump, or mongodump executed — bulk data extraction.",
		Severity:    4, MITRE: "T1005", Category: "Data Loss Prevention",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev),
				"mysqldump", "pg_dump", "pg_dumpall", "mongodump", "mongoexport", "sqlite3", "expdp")
		},
	},
}

// ══════════════════════════════════════════════════════════════════════════════
// WINDOWS SIGNATURES
// ══════════════════════════════════════════════════════════════════════════════
// endpointAgentSignatures apply to every endpoint OS (agent-originated events
// such as tamper and posture regressions).
var endpointAgentSignatures = []ThreatSig{
	{
		ID: "AGENT-TAMPER-001", Name: "ObsidianWatch Agent Stopping (Possible Tamper)",
		Description: "The agent reported a shutdown/stop request before exiting. Expected during maintenance or upgrades; otherwise indicates an attempt to blind the host. Correlate with a following silent-agent alert.",
		Severity:    3, MITRE: "T1562.001", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "agent.tamper"
		},
	},
	{
		ID: "M-POSTURE-001", Name: "macOS Security Control Disabled (Posture Regression)",
		Description: "A macOS hardening control (SIP, Gatekeeper, FileVault or the application firewall) was turned off since the previous scan.",
		Severity:    4, MITRE: "T1562.001", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "config.posture_regression"
		},
	},
}

var windowsSignatures = []ThreatSig{

	// ── Execution ────────────────────────────────────────────────────────────
	{
		ID: "W-T1059.001a", Name: "PowerShell Encoded Command",
		Description: "PowerShell -EncodedCommand flag — common malware obfuscation.",
		Severity:    4, MITRE: "T1059.001", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev), "-enc ", "-encodedcommand", "-e jab", "-e sqb")
		},
	},
	{
		ID: "W-T1059.001b", Name: "PowerShell Download Cradle",
		Description: "PowerShell downloading and executing code from internet.",
		Severity:    5, MITRE: "T1059.001", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"downloadstring", "downloadfile", "iex(", "invoke-expression",
				"webclient", "invoke-webrequest", "start-bitstransfer")
		},
	},
	{
		ID: "W-T1059.003", Name: "Suspicious CMD Execution",
		Description: "cmd.exe running reconnaissance or download commands.",
		Severity:    3, MITRE: "T1059.003", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "cmd.exe", "cmd") &&
				containsAny(cl(ev), "/c whoami", "/c net ", "/c ipconfig", "certutil", "bitsadmin")
		},
	},
	{
		ID: "W-T1218.011", Name: "Rundll32 Suspicious Execution",
		Description: "rundll32.exe executing JavaScript, VBScript, or remote content — LOLBAS.",
		Severity:    4, MITRE: "T1218.011", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "rundll32") &&
				containsAny(cl(ev), "javascript:", "vbscript:", "shell32", ",control_rundll", "http")
		},
	},
	{
		ID: "W-T1218.005", Name: "MSHTA Execution",
		Description: "mshta.exe executing HTA file — frequently used for initial access.",
		Severity:    4, MITRE: "T1218.005", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "mshta")
		},
	},
	{
		ID: "W-T1218.010", Name: "Regsvr32 Squiblydoo Bypass",
		Description: "regsvr32.exe loading a remote scriptlet — AppLocker bypass.",
		Severity:    5, MITRE: "T1218.010", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "regsvr32") &&
				containsAny(cl(ev), "http", "/u ", "/s ", "scrobj")
		},
	},
	{
		ID: "W-T1059.005", Name: "WScript/CScript Execution",
		Description: "Windows Script Host executing a script.",
		Severity:    3, MITRE: "T1059.005", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "wscript.exe", "cscript.exe")
		},
	},
	{
		ID: "W-T1197", Name: "BITS Job Abuse",
		Description: "bitsadmin used to download or execute — LOLBAS technique.",
		Severity:    4, MITRE: "T1197", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev)+cl(ev), "bitsadmin", "start-bitstransfer") &&
				containsAny(cl(ev), "/transfer", "/addfile", "/setnotifycmdline", "http")
		},
	},
	{
		ID: "W-T1047", Name: "WMI Remote Execution",
		Description: "WMI used for remote code execution.",
		Severity:    4, MITRE: "T1047", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev)+cl(ev), "wmic", "wmiexec", "invoke-wmimethod") &&
				containsAny(cl(ev), "/node:", "process call create", "win32_process")
		},
	},
	{
		ID: "W-T1218.007", Name: "Msiexec Remote Install",
		Description: "msiexec installing a package from URL — malware delivery.",
		Severity:    4, MITRE: "T1218.007", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "msiexec") &&
				containsAny(cl(ev), "http://", "https://")
		},
	},
	{
		ID: "W-T1566.001", Name: "Shell Spawned with Office-Related Arguments",
		Description: "cmd/PowerShell/script host spawned with document-related paths or macro keywords — possible Office macro execution.",
		Severity:    5, MITRE: "T1566.001", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			if ev.EventType != "process" {
				return false
			}
			isShellChild := containsAny(proc(ev), "cmd.exe", "powershell", "wscript", "cscript", "mshta", "rundll32", "regsvr32")
			if !isShellChild {
				return false
			}
			// Sysmon: parent image contains Office app
			if containsAny(img(ev)+rawStr(ev), "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe") {
				return true
			}
			// Non-Sysmon: shell child with document-related path in cmdline
			return containsAny(cl(ev), "\\appdata\\roaming\\microsoft\\", "\\desktop\\", ".docm", ".xlsm", ".pptm", "wscript.shell", "shell.application")
		},
	},

	// ── Discovery ────────────────────────────────────────────────────────────
	{
		ID: "W-T1057", Name: "Process Discovery",
		Description: "tasklist or Get-Process — reconnaissance.",
		Severity:    2, MITRE: "T1057", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev), "tasklist", "get-process", "qprocess")
		},
	},
	{
		ID: "W-T1016", Name: "Network Configuration Discovery",
		Description: "ipconfig, netstat, arp — network enumeration.",
		Severity:    2, MITRE: "T1016", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev), "ipconfig", "netstat", "arp -a", "route print", "nslookup", "net view")
		},
	},
	{
		ID: "W-T1087", Name: "Account Enumeration",
		Description: "net user, net localgroup, or Get-ADUser — account discovery.",
		Severity:    3, MITRE: "T1087", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"net user", "net localgroup", "net group", "get-aduser", "whoami /all", "query user")
		},
	},
	{
		ID: "W-T1595", Name: "Port Scanning Tool",
		Description: "nmap or masscan on a Windows host.",
		Severity:    3, MITRE: "T1595.001", Category: "Reconnaissance",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev)+cl(ev), "nmap", "masscan", "rustscan", "nessus", "nikto")
		},
	},

	// ── Privilege Escalation ─────────────────────────────────────────────────
	{
		ID: "W-T1548.002", Name: "UAC Bypass Technique",
		Description: "Known UAC bypass tool or technique detected.",
		Severity:    5, MITRE: "T1548.002", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev), "eventvwr", "fodhelper", "sdclt", "computerdefaults", "bypassuac", "cmstp")
		},
	},
	{
		ID: "W-T1055", Name: "Process Injection",
		Description: "Known process injection API calls or tools detected.",
		Severity:    5, MITRE: "T1055", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"virtualalloc", "writeprocessmemory", "createremotethread", "mimikatz", "procdump", "reflectiveload")
		},
	},
	{
		ID: "W-T1134", Name: "Token Impersonation",
		Description: "Token manipulation — privilege escalation via token theft.",
		Severity:    5, MITRE: "T1134", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"impersonateloggedonuser", "duplicatetoken", "adjusttokenprivileges",
				"incognito", "getsystem", "steal_token")
		},
	},

	// ── Credential Access ────────────────────────────────────────────────────
	{
		ID: "W-T1003.001", Name: "LSASS Memory Dump",
		Description: "Attempt to dump LSASS memory — credential harvesting.",
		Severity:    5, MITRE: "T1003.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return lsassDump(ev)
		},
	},
	{
		ID: "W-T1003.002", Name: "SAM Database Access",
		Description: "Attempt to access the SAM database — Windows password hashes.",
		Severity:    5, MITRE: "T1003.002", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return containsAny(fp(ev)+rk(ev)+cl(ev),
				`system\currentcontrolset\control\lsa`, `sam\sam\domains`, `reg save hklm\sam`)
		},
	},
	{
		ID: "W-T1110", Name: "Failed Logon (EventID 4625)",
		Description: "Windows failed logon — one failure is usually a typo; repeated failures indicate brute force.",
		Severity:    2, MITRE: "T1110", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "logon" && ev.EventID != nil && *ev.EventID == 4625
		},
	},
	{
		ID: "W-T1552.001", Name: "Credential Search in Files",
		Description: "findstr searching for passwords in files.",
		Severity:    3, MITRE: "T1552.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			// Searching for credentials, not merely mentioning the word.
			return ev.EventType == "process" && containsAny(cl(ev),
				"findstr /si password", "findstr /s /i password", "findstr /spin", "dir /s *pass*", "dir /s *cred*",
				"unattend.xml", "sysprep.xml", "cmdkey /list", "vaultcmd /list", "vaultcmd.exe /list")
		},
	},
	{
		ID: "W-T1552.005", Name: "Cloud Credential File Access",
		Description: "AWS, Azure, or GCP credential files accessed — cloud credential theft.",
		Severity:    5, MITRE: "T1552.005", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			// File events on the credential stores, or a process whose command
			// line points at one. Raw event text is not searched (log lines and
			// registry dumps mention these paths without reading them), and
			// "terraform.tfstate" / ".aws config" are ordinary tool arguments.
			if ev.EventType != "file" && ev.EventType != "process" {
				return false
			}
			if ev.EventType == "process" && procIn(ev, "aws", "az", "gcloud", "terraform", "aws.cmd", "az.cmd") {
				return false // the cloud CLIs read their own stores
			}
			return containsAny(fp(ev)+cl(ev),
				".aws\\credentials", ".aws/credentials",
				"accesstokens.json", "msal_token_cache", "azureprofile.json",
				".config\\gcloud\\credentials", ".config/gcloud/credentials", ".config/gcloud/legacy_credentials",
				"application_default_credentials.json")
		},
	},

	// ── Persistence ──────────────────────────────────────────────────────────
	{
		ID: "W-T1547.001", Name: "Run Key Persistence",
		Description: "Registry Run key modified — common Windows persistence.",
		Severity:    4, MITRE: "T1547.001", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return runKeySuspicious(ev)
		},
	},
	{
		ID: "W-T1547.001b", Name: "Run Key Entry Added",
		Description: "A program was registered to start at logon or boot from a location outside Program Files and the Windows directory. Common for installers and updaters; review if unexpected.",
		Severity:    2, MITRE: "T1547.001", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return runKeyUntrusted(ev)
		},
	},
	{
		ID: "W-T1053.005", Name: "Scheduled Task Created",
		Description: "New scheduled task — persistence or lateral movement.",
		Severity:    3, MITRE: "T1053.005", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return (ev.EventType == "process" && containsAny(cl(ev), "schtasks /create", "new-scheduledtask")) ||
				(ev.EventID != nil && (*ev.EventID == 4698 || *ev.EventID == 4702))
		},
	},
	{
		ID: "W-T1543.003", Name: "New Service Created",
		Description: "New Windows service installed via sc.exe or PowerShell.",
		Severity:    4, MITRE: "T1543.003", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev), "sc create", "new-service", "sc.exe create")
		},
	},
	{
		ID: "W-T1546.003", Name: "WMI Event Subscription",
		Description: "WMI event subscription created — fileless persistence.",
		Severity:    5, MITRE: "T1546.003", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"__eventfilter", "__eventconsumer", "commandlineeventconsumer", "activescripteventconsumer")
		},
	},
	{
		ID: "W-T1546.012", Name: "IFEO Debugger Hijack",
		Description: "Image File Execution Options debugger key set — process hijacking.",
		Severity:    5, MITRE: "T1546.012", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return containsAny(rk(ev), "image file execution options", `\ifeo\`) &&
				containsAny(rk(ev)+rawStr(ev), "debugger", "globalflag")
		},
	},

	// ── Defence Evasion ──────────────────────────────────────────────────────
	{
		ID: "W-T1562.001a", Name: "Security Tool Disabled",
		Description: "Windows Defender or firewall disabled via command line.",
		Severity:    5, MITRE: "T1562.001", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"set-mppreference -disablerealtime", "netsh advfirewall set allprofiles state off",
				"sc stop windefend", "sc config windefend start= disabled", "disableantispyware")
		},
	},
	{
		ID: "W-T1562.001c", Name: "Defender Protection Disabled or Exclusion Added",
		Description: "Windows Defender operational log reports real-time protection/scanning disabled (5001, 5010, 5012) or a configuration change that adds an exclusion (5007).",
		Severity:    4, MITRE: "T1562.001", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			if ev.EventID == nil || ev.Channel == nil ||
				!strings.Contains(strings.ToLower(*ev.Channel), "windows defender") {
				return false
			}
			switch *ev.EventID {
			case 5001, 5010, 5012:
				return true
			case 5007:
				return strings.Contains(rawStr(ev), "\\\\exclusions\\\\") || strings.Contains(rawStr(ev), "\\exclusions\\")
			}
			return false
		},
	},
	{
		ID: "W-T1070.001", Name: "Event Log Cleared",
		Description: "Windows event log cleared — attacker covering tracks.",
		Severity:    5, MITRE: "T1070.001", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return (ev.EventID != nil && (*ev.EventID == 1102 || *ev.EventID == 104)) ||
				containsAny(cl(ev), "wevtutil cl", "clear-eventlog", "clearev")
		},
	},
	{
		ID: "W-T1027", Name: "Obfuscated Command",
		Description: "Base64 decode or heavy obfuscation in command line.",
		Severity:    4, MITRE: "T1027", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && (containsAny(cl(ev), "frombase64string", "[convert]::", "char(", "chr(", "`i`e`x", "iex(") ||
				strings.Count(cl(ev), "^") > 5)
		},
	},
	{
		ID: "W-T1036", Name: "Process Name Masquerading",
		Description: "Known system process running from unexpected path.",
		Severity:    4, MITRE: "T1036", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			trusted := []string{"svchost.exe", "lsass.exe", "explorer.exe", "winlogon.exe", "csrss.exe"}
			p := proc(ev)
			i := img(ev)
			for _, t := range trusted {
				if strings.Contains(p, t) && i != "" && !containsAny(i, `\system32\`, `\syswow64\`, `\windows\`) {
					return true
				}
			}
			return false
		},
	},
	{
		ID: "W-T1562.001b", Name: "AMSI Bypass Attempt",
		Description: "Antimalware Scan Interface bypass technique detected.",
		Severity:    5, MITRE: "T1562.001", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"amsiutils", "amsi.dll", "[ref].assembly", "amsicontext", "amsiinitmemfailed")
		},
	},
	{
		ID: "W-T1574.002", Name: "DLL in User-Writable Path",
		Description: "DLL dropped in Temp, Downloads, Desktop or Public — search order hijacking. (Normal AppData/ProgramData application DLLs are not flagged.)",
		Severity:    3, MITRE: "T1574.002", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "file" && strings.HasSuffix(fp(ev), ".dll") &&
				containsAny(fp(ev), `\temp\`, `\downloads\`, `\desktop\`, `\users\public\`)
		},
	},

	// ── Lateral Movement ────────────────────────────────────────────────────
	{
		ID: "W-T1021.001", Name: "RDP Lateral Movement",
		Description: "mstsc or RDP connection detected.",
		Severity:    3, MITRE: "T1021.001", Category: "Lateral Movement",
		Match: func(ev store.Event) bool {
			return (ev.EventType == "logon" && ev.EventID != nil && *ev.EventID == 4648 &&
				containsAny(rawStr(ev), "3389", "termserv", "mstsc")) ||
				(ev.EventType == "process" && containsAny(proc(ev)+cl(ev), "mstsc"))
		},
	},
	{
		ID: "W-T1570", Name: "PsExec / Remote Execution Tool",
		Description: "PsExec or similar remote execution tool detected.",
		Severity:    4, MITRE: "T1570", Category: "Lateral Movement",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev)+cl(ev), "psexec", "paexec", "wmiexec", "winrm")
		},
	},

	// ── Impact ───────────────────────────────────────────────────────────────
	{
		ID: "W-T1490", Name: "Shadow Copy Deletion",
		Description: "Volume Shadow Copy deletion — ransomware pre-cursor.",
		Severity:    5, MITRE: "T1490", Category: "Impact",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"vssadmin delete shadows", "wmic shadowcopy delete",
				"bcdedit /set {default} recoveryenabled no", "wbadmin delete catalog")
		},
	},
	{
		ID: "W-T1486", Name: "Ransomware File Extension",
		Description: "Files renamed to known ransomware extensions.",
		Severity:    5, MITRE: "T1486", Category: "Impact",
		Match: func(ev store.Event) bool {
			return ev.EventType == "file" && containsAny(fp(ev), ".locked", ".encrypted", ".crypto", ".crypt", ".enc", ".ransom", ".locky")
		},
	},
}

// ── Domain Controller Signatures ─────────────────────────────────────────────
var dcSignatures = []ThreatSig{
	// DCSync — attacker replicates all password hashes from DC
	// 4662 with access mask 0x100 on DS-Replication-Get-Changes objects
	{
		ID: "DC-T1003.006", Name: "DCSync Attack Detected",
		Description: "A non-DC account performed AD replication (DS-Replication-Get-Changes-All). This is the core primitive of DCSync — used to dump all domain password hashes without touching LSASS.",
		Severity:    5, MITRE: "T1003.006", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			if ev.EventType != "ad_object_access" {
				return false
			}
			if ev.CommandLine == nil {
				return false
			}
			// Object type must be domainDNS or DS replication class
			cl := strings.ToLower(*ev.CommandLine)
			if !strings.Contains(cl, "domaindns") && !strings.Contains(cl, "19195a5b") {
				return false
			}
			// Exclude legitimate DC accounts doing normal replication
			if ev.UserName != nil {
				u := strings.ToUpper(*ev.UserName)
				if strings.HasSuffix(u, "$") {
					return false // Machine accounts are legit DC replication
				}
			}
			return true
		},
	},
	// Kerberoasting — request service tickets with RC4 encryption for offline cracking
	{
		ID: "DC-T1558.003", Name: "Kerberoasting — RC4 Service Ticket Request",
		Description: "A Kerberos service ticket was requested using RC4 encryption (0x17). Attackers request tickets for service accounts to crack offline. Modern systems use AES; RC4 requests are suspicious.",
		Severity:    4, MITRE: "T1558.003", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			if ev.EventType != "kerberos" || ev.EventID == nil || *ev.EventID != 4769 {
				return false
			}
			// RC4 = 0x17 = 23 in TicketEncryptionType
			// ProcessName holds ServiceName from our parser
			if ev.ProcessName != nil && strings.HasSuffix(*ev.ProcessName, "$") {
				return false // Skip machine accounts
			}
			return true
		},
	},
	// AS-REP Roasting — account with no pre-auth required
	{
		ID: "DC-T1558.004", Name: "AS-REP Roasting — Pre-Auth Not Required",
		Description: "Kerberos AS-REP returned without pre-authentication (error 0x0 with no pre-auth). Accounts with DONT_REQUIRE_PREAUTH set are vulnerable to offline password cracking.",
		Severity:    4, MITRE: "T1558.004", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "kerberos" && ev.EventID != nil && *ev.EventID == 4768 &&
				ev.Severity >= 3
		},
	},
	// Golden Ticket — TGT for non-existent or privileged accounts
	{
		ID: "DC-T1558.001", Name: "Possible Golden Ticket Usage",
		Description: "Kerberos TGT request anomaly — ticket lifetime or encryption inconsistent with domain policy. Golden tickets are forged TGTs signed with the krbtgt hash.",
		Severity:    5, MITRE: "T1558.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			// 4769 for krbtgt service = golden ticket usage
			if ev.EventType != "kerberos" || ev.EventID == nil || *ev.EventID != 4769 {
				return false
			}
			return ev.ProcessName != nil && strings.EqualFold(*ev.ProcessName, "krbtgt")
		},
	},
	// Domain Policy Changed
	{
		ID: "DC-T1484.001", Name: "Domain Policy Modified",
		Description: "Domain-wide security policy was changed (Event 4739). Attackers modify domain policies to weaken security, disable lockouts, or set minimum password age to 0.",
		Severity:    5, MITRE: "T1484.001", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "ad_change" && ev.EventID != nil && *ev.EventID == 4739
		},
	},
	// AdminSDHolder abuse — modifying protected object to persist access
	{
		ID: "DC-T1078.002", Name: "AdminSDHolder Modification",
		Description: "The AdminSDHolder object was modified in Active Directory. Attackers modify AdminSDHolder to persist privileged access — SDProp propagates the ACL to all protected accounts every 60 minutes.",
		Severity:    5, MITRE: "T1078.002", Category: "Persistence",
		Match: func(ev store.Event) bool {
			if ev.EventType != "ad_change" {
				return false
			}
			return ev.FilePath != nil && strings.Contains(strings.ToLower(*ev.FilePath), "adminsdholder")
		},
	},
	// GPO tampering
	{
		ID: "DC-T1484.001b", Name: "Group Policy Object Modified",
		Description: "A Group Policy Object was created or modified (Event 5136/5137 on groupPolicyContainer). Attackers tamper with GPOs for lateral movement, persistence, or disabling defences.",
		Severity:    4, MITRE: "T1484.001", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			if ev.EventType != "ad_change" {
				return false
			}
			return ev.FilePath != nil && strings.Contains(strings.ToLower(*ev.FilePath), "grouppolicycontainer")
		},
	},
	// New privileged account created
	{
		ID: "DC-T1136.002", Name: "Domain Admin Account Created",
		Description: "A new account was added to Domain Admins, Enterprise Admins, or Schema Admins (Events 4728/4732/4756 on privileged groups). Immediate investigation required.",
		Severity:    5, MITRE: "T1136.002", Category: "Persistence",
		Match: func(ev store.Event) bool {
			if ev.EventID == nil {
				return false
			}
			if *ev.EventID != 4728 && *ev.EventID != 4732 && *ev.EventID != 4756 {
				return false
			}
			// Only flag privileged groups
			if ev.ProcessName == nil {
				return false
			}
			pn := strings.ToLower(*ev.ProcessName)
			return strings.Contains(pn, "domain admins") ||
				strings.Contains(pn, "enterprise admins") ||
				strings.Contains(pn, "schema admins") ||
				strings.Contains(pn, "administrators")
		},
	},
	// Mass Kerberos failures — password spray against DC
	{
		ID: "DC-T1110.003", Name: "Kerberos Password Spray",
		Description: "Multiple Kerberos pre-authentication failures (4771) from the same source IP within a short window — consistent with password spraying against the domain.",
		Severity:    4, MITRE: "T1110.003", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "kerberos" && ev.EventID != nil && *ev.EventID == 4771
		},
	},
}

// ══════════════════════════════════════════════════════════════════════════════
// MACOS SIGNATURES
// ══════════════════════════════════════════════════════════════════════════════
var macosSignatures = []ThreatSig{

	// ── Execution ────────────────────────────────────────────────────────────
	{
		ID: "M-T1059.002a", Name: "osascript AppleScript Abuse",
		Description: "osascript executing AppleScript — UI automation attack or privilege escalation.",
		Severity:    4, MITRE: "T1059.002", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "osascript") &&
				containsAny(cl(ev), "-e ", "do shell script", "administrator privileges", "keystroke", "with administrator")
		},
	},
	{
		ID: "M-T1059.002b", Name: "osascript Credential Phishing Prompt",
		Description: "osascript displaying password dialog — social engineering to harvest credentials.",
		Severity:    5, MITRE: "T1059.002", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "osascript") &&
				containsAny(cl(ev), "display dialog", "password", "default answer")
		},
	},
	{
		ID: "M-T1059.004", Name: "Shell Pipe to Interpreter",
		Description: "Shell executing piped commands — dropper technique.",
		Severity:    4, MITRE: "T1059.004", Category: "Execution",
		Match: func(ev store.Event) bool {
			if ev.EventType != "process" {
				return false
			}
			isShell := procIn(ev, "bash", "sh", "zsh", "dash")
			return isShell && (containsAny(cl(ev), "| bash", "|bash", "| sh", "|sh") || shPipeToShellRe.MatchString(cl(ev)) ||
				(containsAny(cl(ev), "-c curl", "-c wget") && containsAny(cl(ev), "/tmp/", "/var/tmp/", "/dev/shm/")))
		},
	},
	{
		ID: "M-T1059.004b", Name: "Executable Run from /tmp",
		Description: "Process spawned from /tmp — common macOS malware staging.",
		Severity:    5, MITRE: "T1059.004", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && execFromDir(ev, "/tmp/", "/var/tmp/", "/private/tmp/", "/private/var/tmp/")
		},
	},
	{
		ID: "M-T1105", Name: "curl/wget Pipe to Shell",
		Description: "curl or wget piped to shell — dropper technique.",
		Severity:    5, MITRE: "T1105", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "curl", "wget") &&
				containsAny(cl(ev), "| bash", "|bash", "| sh", "|sh", "| python", "exec(")
		},
	},
	{
		ID: "M-T1218.001", Name: "Compiled AppleScript Execution",
		Description: "Compiled .scpt file executed — common in macOS malware.",
		Severity:    3, MITRE: "T1218.001", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev), ".scpt", ".applescript") &&
				containsAny(proc(ev), "osascript", "osacompile")
		},
	},

	// ── Discovery ────────────────────────────────────────────────────────────
	{
		ID: "M-T1087.001", Name: "macOS User Enumeration",
		Description: "dscl, dscacheutil, or id used to enumerate users.",
		Severity:    2, MITRE: "T1087.001", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"dscl . list /users", "dscacheutil -q user", "finger ", "id -a", "dsmemberutil")
		},
	},
	{
		ID: "M-T1082", Name: "macOS System Info Enumeration",
		Description: "system_profiler, sw_vers, or ioreg used for system profiling.",
		Severity:    2, MITRE: "T1082", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev)+cl(ev),
				"system_profiler", "sw_vers", "ioreg -rd1", "nvram -p", "sysctl -a")
		},
	},
	{
		ID: "M-T1046", Name: "Network Scanning Tool",
		Description: "nmap or arp-scan on macOS — internal reconnaissance.",
		Severity:    3, MITRE: "T1046", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev)+cl(ev), "nmap", "masscan", "arp-scan", "netdiscover")
		},
	},
	{
		ID: "M-T1592", Name: "Packet Capture Tool",
		Description: "tcpdump or Wireshark running on macOS.",
		Severity:    4, MITRE: "T1592", Category: "Reconnaissance",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev)+cl(ev), "tcpdump", "tshark", "wireshark", "dumpcap")
		},
	},

	// ── Privilege Escalation ─────────────────────────────────────────────────
	{
		ID: "M-T1548.001", Name: "SUID Bit Set",
		Description: "chmod +s — SUID privilege escalation.",
		Severity:    4, MITRE: "T1548.001", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "chmod") &&
				containsAny(cl(ev), "+s", "4755", "4777", "u+s")
		},
	},
	{
		ID: "M-T1548.004", Name: "macOS Sudo Root Shell",
		Description: "sudo spawning a root shell on macOS.",
		Severity:    4, MITRE: "T1548.004", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "sudo") &&
				containsAny(cl(ev), "sudo su", "sudo bash", "sudo sh", "sudo -s", "sudo -i")
		},
	},
	{
		ID: "M-T1553.001", Name: "Gatekeeper Bypass via xattr",
		Description: "xattr removing quarantine attribute — Gatekeeper bypass.",
		Severity:    4, MITRE: "T1553.001", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "xattr") &&
				containsAny(cl(ev), "com.apple.quarantine", "-d ", "-c ")
		},
	},
	{
		ID: "M-T1562.001", Name: "SIP Tamper Attempt",
		Description: "csrutil used to disable System Integrity Protection.",
		Severity:    5, MITRE: "T1562.001", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev)+cl(ev),
				"csrutil disable", "csrutil enable --without", "nvram boot-args")
		},
	},

	// ── Credential Access ────────────────────────────────────────────────────
	{
		ID: "M-T1555.001a", Name: "Keychain Dump via security Command",
		Description: "security command extracting keychain passwords — credential theft.",
		Severity:    5, MITRE: "T1555.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "security") &&
				containsAny(cl(ev), "find-generic-password", "find-internet-password", "dump-keychain", "login.keychain")
		},
	},
	{
		ID: "M-T1555.001b", Name: "Keychain File Direct Access",
		Description: "Direct access to keychain database files.",
		Severity:    5, MITRE: "T1555.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "file" && containsAny(fp(ev), "login.keychain", "system.keychain", "library/keychains/")
		},
	},
	{
		ID: "M-T1110.001", Name: "SSH Brute Force (syslog)",
		Description: "Repeated SSH authentication failures in syslog.",
		Severity:    4, MITRE: "T1110.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			// macOS syslog: EventType="syslog", CommandLine=message body
			return (ev.EventType == "syslog" || ev.EventType == "logon") &&
				containsAny(cl(ev), "failed password", "authentication failure", "invalid user", "too many authentication failures")
		},
	},
	{
		ID: "M-T1552.004", Name: "SSH Private Key Access",
		Description: "SSH private key file accessed on macOS.",
		Severity:    4, MITRE: "T1552.004", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return containsAny(fp(ev)+cl(ev), "id_rsa", "id_ed25519", "/.ssh/", ".pem")
		},
	},
	{
		ID: "M-T1552.005", Name: "Cloud Credential File Access",
		Description: "AWS, GCP, or Azure credential files accessed on macOS.",
		Severity:    5, MITRE: "T1552.005", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return containsAny(fp(ev)+cl(ev), ".aws/credentials", ".aws/config",
				".config/gcloud", "application_default_credentials.json", ".azure/", "terraform.tfstate")
		},
	},

	// ── Persistence ──────────────────────────────────────────────────────────
	{
		ID: "M-T1543.004", Name: "LaunchDaemon/LaunchAgent Written",
		Description: "New plist written to LaunchDaemons or LaunchAgents — macOS persistence.",
		Severity:    4, MITRE: "T1543.004", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "file" && containsAny(fp(ev),
				"/library/launchdaemons/", "/library/launchagents/", "~/library/launchagents/")
		},
	},
	{
		ID: "M-T1546.004", Name: "Shell Profile Modified",
		Description: ".bashrc, .zshrc, or /etc/profile modified — shell persistence.",
		Severity:    4, MITRE: "T1546.004", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return (ev.EventType == "file" || ev.EventType == "registry") &&
				containsAny(fp(ev)+rk(ev), ".bashrc", ".zshrc", ".bash_profile", "/etc/profile", "/etc/bash.bashrc")
		},
	},
	{
		ID: "M-T1547.015", Name: "macOS Login Hook Set",
		Description: "defaults writing LoginHook — persistent code execution on login.",
		Severity:    4, MITRE: "T1547.015", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "defaults") &&
				containsAny(cl(ev), "loginhook", "logouthook", "com.apple.loginwindow")
		},
	},
	{
		ID: "M-T1053.003", Name: "Cron Modified on macOS",
		Description: "Crontab written — persistence mechanism.",
		Severity:    4, MITRE: "T1053.003", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return (ev.EventType == "file" || ev.EventType == "registry") &&
				containsAny(fp(ev)+rk(ev), "/etc/cron", "/var/spool/cron", "crontab")
		},
	},

	// ── Defence Evasion ──────────────────────────────────────────────────────
	{
		ID: "M-T1070.002", Name: "macOS Log Cleared",
		Description: "System log deleted or cleared — attacker covering tracks.",
		Severity:    4, MITRE: "T1070.002", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			if ev.EventType == "process" {
				return containsAny(cl(ev), "log erase", "syslog -c", "rm /var/log/", "rm /private/var/log/", "> /var/log/system.log")
			}
			return ev.EventType == "file" && containsAny(fp(ev), "/var/log/system.log", "/private/var/log/")
		},
	},
	{
		ID: "M-T1574.006", Name: "DYLD_INSERT_LIBRARIES Injection",
		Description: "macOS shared library hijacking via DYLD_INSERT_LIBRARIES.",
		Severity:    5, MITRE: "T1574.006", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return containsAny(cl(ev)+rawStr(ev), "dyld_insert_libraries", "dyld_force_flat_namespace")
		},
	},

	// ── Lateral Movement / C2 ────────────────────────────────────────────────
	{
		ID: "M-T1021.004", Name: "SSH Tunnel / Port Forward",
		Description: "SSH -L/-R/-D flag — tunnelling or SOCKS proxy.",
		Severity:    4, MITRE: "T1021.004", Category: "Lateral Movement",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && procIn(ev, "ssh") &&
				containsAny(cl(ev), " -l ", " -r ", " -d ", "-nfl", "-nfr", "-nfd")
		},
	},
	{
		ID: "M-T1572", Name: "DNS Tunnelling Indicator",
		Description: "Unusually long DNS query — possible DNS tunnelling.",
		Severity:    4, MITRE: "T1572", Category: "Command and Control",
		Match: func(ev store.Event) bool {
			return ev.EventType == "dns" && ev.DstIP != nil && len(*ev.DstIP) > 60
		},
	},
	{
		ID: "M-T1219", Name: "Remote Access Tool",
		Description: "Commercial remote access tool detected on macOS.",
		Severity:    3, MITRE: "T1219", Category: "Command and Control",
		Match: func(ev store.Event) bool {
			return containsAny(proc(ev)+cl(ev), "anydesk", "teamviewer", "rustdesk", "screenconnect", "logmein", "splashtop")
		},
	},
	{
		ID: "M-T1048", Name: "curl POST Exfiltration",
		Description: "curl sending data via POST on macOS — possible exfiltration.",
		Severity:    3, MITRE: "T1048", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "curl") &&
				containsAny(cl(ev), " -d @", " --data @", " --data-binary @", " --data-raw @", " -t /", " -t ~", "--upload-file", " -f file=@", " --form ")
		},
	},
	{
		ID: "M-T1560", Name: "Archive of Sensitive Directory",
		Description: "tar or zip archiving /Users or sensitive paths.",
		Severity:    3, MITRE: "T1560.001", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && procIn(ev, "tar", "zip", "7z", "7za", "gzip", "bzip2", "xz") &&
				containsAny(cl(ev), "/users/", "documents", "desktop", "/etc/", ".sql")
		},
	},
	{
		ID: "M-T1090.003", Name: "Tor / Proxy Tool",
		Description: "Tor or proxychains detected on macOS.",
		Severity:    4, MITRE: "T1090.003", Category: "Command and Control",
		Match: func(ev store.Event) bool {
			return containsAny(proc(ev)+cl(ev)+fp(ev), "tor ", "torsocks", "proxychains", "proxifier")
		},
	},
}

// ── DNS blocklist signatures (all platforms) ──────────────────────────────────
var dnsCatSignatures = []ThreatSig{
	{
		ID: "DNS-CAT-001", Name: "Malware C2 Domain Contact",
		Description: "DNS query to a domain flagged as malware C2 by Quad9/SURBL/Spamhaus.",
		Severity:    5, MITRE: "T1071.001", Category: "Command and Control",
		Match: func(ev store.Event) bool {
			return (ev.EventType == "dns" || ev.EventType == "network") &&
				ev.DstIP != nil && domainHasCategory(*ev.DstIP, "malware", "botnet_cc")
		},
	},
	{
		ID: "DNS-CAT-002", Name: "Phishing Domain Contact",
		Description: "DNS query to a domain flagged as phishing.",
		Severity:    4, MITRE: "T1566.002", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "dns" && ev.DstIP != nil && domainHasCategory(*ev.DstIP, "phishing")
		},
	},
	{
		ID: "DNS-CAT-003", Name: "Malicious Domain (Quad9 Block)",
		Description: "DNS query to a domain blocked by Quad9 threat intelligence.",
		Severity:    4, MITRE: "T1071.001", Category: "Command and Control",
		Match: func(ev store.Event) bool {
			return ev.EventType == "dns" && ev.DstIP != nil && domainHasCategory(*ev.DstIP, "malicious")
		},
	},
	{
		ID: "DNS-CAT-004", Name: "Spam Infrastructure Domain",
		Description: "DNS query to a spam-flagged domain — possible exfil relay.",
		Severity:    3, MITRE: "T1048", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			return ev.EventType == "dns" && ev.DstIP != nil && domainHasCategory(*ev.DstIP, "spam")
		},
	},
}

var dnsCatCache = make(map[string][]string)

func domainHasCategory(domain string, categories ...string) bool {
	domain = strings.ToLower(domain)
	cats, ok := dnsCatCache[domain]
	if !ok {
		return false
	}
	for _, want := range categories {
		for _, have := range cats {
			if have == want {
				return true
			}
		}
	}
	return false
}

// ── Detection Engine ─────────────────────────────────────────────────────────

type DetectionEngine struct {
	db         *store.DB
	mailer     *notify.Mailer
	logger     *slog.Logger
	suppressor *GCPSuppressor
	auth       *authCorrelator
	seq        *seqCorrelator
	geo        *entraGeoTracker
}

func NewDetectionEngine(db *store.DB, mailer *notify.Mailer, logger *slog.Logger) *DetectionEngine {
	return &DetectionEngine{db: db, mailer: mailer, logger: logger, suppressor: NewGCPSuppressor(db), auth: newAuthCorrelator(), seq: newSeqCorrelator(), geo: newEntraGeoTracker()}
}

func (e *DetectionEngine) Run(ctx context.Context) {
	// First run per cursor falls back to these lookback windows; every run
	// after that resumes exactly from the persisted cursor regardless of
	// how long the gap since the last poll was.
	loadCorrelatorState(ctx, e.db, e.auth, e.seq) // D-07
	e.runCursor(ctx)
	e.runDevOpsCursor(ctx)
	ticker := time.NewTicker(detectionInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			saveCorrelatorState(context.Background(), e.db, e.auth, e.seq)
			return
		case <-ticker.C:
			e.runCursor(ctx)
			e.runDevOpsCursor(ctx)
			saveCorrelatorState(ctx, e.db, e.auth, e.seq)
		}
	}
}

// runDevOpsCursor (D-01/D-02): DevOps events arrive via periodic connector
// syncs (not live agent push), which can backfill commits/PRs that are
// hours or days old — a wall-clock window on `time` would miss those
// entirely. Its own cursor + a generous 7-day initial lookback covers it.
func (e *DetectionEngine) runDevOpsCursor(ctx context.Context) {
	events, err := pageEventCursor(ctx, e.db, "detection-devops", store.EventFilter{OS: "devops"}, 7*24*time.Hour, 2000)
	if err != nil {
		e.logger.Warn("detection: devops cursor query failed", "err", err)
		return
	}
	if len(events) == 0 {
		return
	}
	e.logger.Info("detection: devops catch-up", "events", len(events))
	created := 0
	for _, ev := range events {
		for _, sig := range devopsSignatures {
			if !azureStatusAllows(sig, ev) || !awsErrorAllows(sig, ev) {
				continue
			}
			if !sig.Match(ev) {
				continue
			}
			day := ev.Time.UTC().Format("20060102")
			dedupKey := fmt.Sprintf("sig:%s:host:%s:d:%s:e:%s", sig.ID, ev.Host, day, alertEntityKey(ev)) // D-06: entity fingerprint folded in
			alert := store.Alert{
				Title:         fmt.Sprintf("[%s] %s", sig.MITRE, sig.Name),
				Description:   fmt.Sprintf("%s\n\nMITRE: %s | Host: %s", sig.Description, sig.MITRE, ev.Host),
				Severity:      sig.Severity,
				Host:          ev.Host,
				EventType:     ev.EventType,
				EventID:       dedupKey,
				SourceEventID: ev.ID,
			}
			if _, inserted, err := e.db.CreateAlertDeduped(ctx, alert); err == nil && inserted {
				created++
			}
		}
	}
	if created > 0 {
		e.logger.Info("detection: devops catch-up alerts created", "count", created)
	}
}

// runCursor (D-01/D-02): replaces the old evaluateSince(time.Now().Add(-N))
// wall-clock polling with cursor-based paging over events.ingested_at — see
// pageEventCursor for why this matters (a backlogged/reconnecting agent's
// events used to be able to fall permanently outside every future window).
func (e *DetectionEngine) runCursor(ctx context.Context) {
	events, err := pageEventCursor(ctx, e.db, "detection", store.EventFilter{}, 2*time.Hour, 5000)
	if err != nil {
		e.logger.Warn("detection: cursor query failed", "err", err)
		return
	}
	e.evaluateEvents(ctx, events)
}

func (e *DetectionEngine) evaluateEvents(ctx context.Context, events []store.Event) {
	if len(events) == 0 {
		return // nothing to evaluate; skip the per-cycle refresh work entirely
	}
	e.logger.Info("detection: evaluating events", "count", len(events))

	e.recordPrevalence(events)
	e.alertRareBinaries(ctx, events)
	refreshBusinessHours(ctx, e.db)
	refreshGCPInternalDomains(ctx, e.db)
	refreshEndpointSuppressions(ctx, e.db)
	// Refresh suppression rules before this evaluation cycle
	if e.suppressor != nil {
		e.suppressor.Refresh(ctx)
	}
	states, _ := e.db.GetSignatureStates(ctx)
	ipIOCs, domainIOCs, hashIOCs := e.loadIOCs(ctx)

	// Check if Sigma detection is globally enabled
	sigmaGlobalEnabled := true
	if v, _ := e.db.GetSetting(ctx, "detection.sigma_enabled"); v == "false" {
		sigmaGlobalEnabled = false
	}

	// Load enabled Sigma rules — pre-index by category for performance
	// Avoids O(events * 1211 rules) — instead O(events * relevant_rules_for_os)
	allSigmaRules, _ := e.db.ListSigmaRules(ctx, true)
	if !sigmaGlobalEnabled {
		allSigmaRules = nil
	}
	sigmaByCategory := make(map[string][]store.SigmaRule)
	for _, r := range allSigmaRules {
		cat := strings.ToLower(r.Category)
		sigmaByCategory[cat] = append(sigmaByCategory[cat], r)
	}

	created := 0
	for _, ev := range events {
		if e.auth != nil {
			if hits := e.auth.Observe(ev); len(hits) > 0 {
				e.raiseAuthHits(ctx, ev, hits)
			}
		}
		if e.geo != nil {
			if hits := e.geo.observe(ev, dbGeoSeed(ctx, e.db)); len(hits) > 0 {
				e.raiseAuthHits(ctx, ev, hits)
			}
		}
		if e.seq != nil {
			if hits := e.seq.Observe(ev); len(hits) > 0 {
				e.raiseAuthHits(ctx, ev, hits)
			}
		}

		// Skip events generated by ObsidianWatch itself to prevent self-alerting:
		// 1. Vuln scanner events and health checks
		// 2. Agent process showing up in process events
		if ev.EventType == "vulnerability.scan" || ev.EventType == "health" {
			continue
		}
		if ev.Source == "vuln-scanner" || ev.Source == "health-monitor" {
			continue
		}
		// Skip if the process IS the ObsidianWatch agent binary
		if isOwnAgentProcess(ev) || isSelfActivity(ev) || isOwnSysmon(ev) {
			continue
		}

		// Select OS-specific signatures
		var sigs []ThreatSig
		switch strings.ToLower(ev.OS) {
		case "windows":
			sigs = append(append([]ThreatSig{}, windowsSignatures...), dnsCatSignatures...)
			sigs = append(sigs, windowsTamperSignatures...)
			sigs = append(sigs, windowsUSBSignatures...)
			sigs = append(sigs, windowsAccountSignatures...)
			sigs = append(sigs, remoteSessionSignatures...)
			sigs = append(sigs, endpointAgentSignatures...)
			// DC events (ad_object_access, ad_change, kerberos) always get DC sigs
			if ev.EventType == "ad_object_access" || ev.EventType == "ad_change" ||
				ev.EventType == "kerberos" {
				sigs = append(sigs, dcSignatures...)
			}
		case "macos", "darwin":
			sigs = append(append(append([]ThreatSig{}, macosSignatures...), usbSignatures...), dnsCatSignatures...)
			sigs = append(sigs, endpointAgentSignatures...)
		case "devops":
			// DevOps events — only apply devops sigs, skip endpoint sigs entirely
			sigs = append(sigs, devopsSignatures...)
		case "network-probe":
			// [NET-DISPATCH-BEGIN]
			// Network probe events — only apply network sigs
			sigs = append(sigs, networkSignatures...)
			// [NET-DISPATCH-END]
		default:
			// linux or unknown
			sigs = append(append(append(append([]ThreatSig{}, linuxSignatures...), usbSignatures...), linuxAccountSignatures...), dnsCatSignatures...)
			sigs = append(sigs, softwareSignatures...)
			sigs = append(sigs, endpointAgentSignatures...)
		}

		// Cloud events get the extended cloud signature set regardless of OS
		if isCloudEvent(ev) {
			// CC-03: cloud events no longer run the Linux endpoint rules (OS
			// "gcp"/"aws"/"azure" used to fall into the default branch) nor
			// every other provider's rule set; dispatch by provider.
			sigs = nil
			provider := strings.ToLower(ev.OS)
			if provider != "gcp" && provider != "azure" && provider != "aws" {
				provider = cloudProviderFromEventType(strings.ToLower(string(ev.EventType)))
			}
			sigs = append(sigs, cloudSignaturesExtended...)
			sigs = append(sigs, cloudReconSignatures...)
			sigs = append(sigs, cloudNetworkSignatures...)
			sigs = append(sigs, cloudLateralSignatures...)
			sigs = append(sigs, cloudComputeAbuseSignatures...)
			sigs = append(sigs, awsExtraSignatures...)
			if provider == "gcp" || provider == "cloud" {
				// GCP-specific extended rules
				sigs = append(sigs, gcpIAMSignatures...)
				sigs = append(sigs, gcpCredentialSignatures...)
				sigs = append(sigs, gcpComputeSignatures...)
				sigs = append(sigs, gcpDataSignatures...)
				sigs = append(sigs, gcpNetworkSignatures...)
				sigs = append(sigs, gcpDefenseEvasionSignatures...)
				sigs = append(sigs, gcpPersistenceSignatures...)
				sigs = append(sigs, gcpSCCSignatures...)
				sigs = append(sigs, gcpNewSignatures...)
				sigs = append(sigs, gcpPolicySignatures...)
				sigs = append(sigs, gcpEscalationSignatures...)
			sigs = append(sigs, gcpTelemetrySignatures...)
			}
			if provider == "azure" || provider == "cloud" {
				// Azure-specific extended rules
				sigs = append(sigs, azureIAMSignatures...)
				sigs = append(sigs, entraIdentitySignatures...)
				sigs = append(sigs, azureComputeSignatures...)
				sigs = append(sigs, azureDataSignatures...)
				sigs = append(sigs, azureNetworkSignatures...)
				sigs = append(sigs, azureDefenseEvasionSignatures...)
				sigs = append(sigs, azureDefenderSignatures...)
				sigs = append(sigs, azureResourceSignatures...)
				sigs = append(sigs, azureAuditSignatures...)
			}
		}
		// Network events also get cloud network sigs (metadata endpoint access)
		if ev.EventType == "network" {
			sigs = append(sigs, cloudNetworkSignatures...)
		}
		// DevOps events (GitHub, GitLab) get DevOps signatures
		if isDevOpsEvent(ev) {
			sigs = append(sigs, devopsSignatures...)
		}
		// [FOUNDATION-HOOK] rules registered by the Network/Application builds
		sigs = append(sigs, extraSignaturesFor(ev)...)
		// Signature matching
		for _, sig := range sigs {
			if retiredSigIDs[sig.ID] || endpointSuppressed(sig.ID, ev) {
				continue
			}
			if state, ok := states[sig.ID]; ok && !state.Enabled {
				continue
			}
			// Check suppression rules for GCP events
			if isCloudEvent(ev) && e.suppressor != nil && e.suppressor.IsSuppressed(sig.ID, ev) {
				continue
			}
			sev := sig.Severity
			if state, ok := states[sig.ID]; ok && state.Severity != nil {
				sev = *state.Severity
			}
			if !sig.Match(ev) {
				continue
			}
			// [FOUNDATION-HOOK] rule contract: enable / observe / allowlist
			gateAdjust, gateSkip := engineGate(ctx, e.db, sig.ID, ev)
			if gateSkip {
				continue
			}
			sev = gateAdjust(sev)
			// DevOps events: dedup per day (bulk syncs replay many historical commits)
			// Agent events: dedup per hour (high-frequency, need tighter windows)
			var dedupKey string
			if ev.OS == "devops" || strings.HasPrefix(ev.EventType, "devops.") {
				day := ev.Time.UTC().Format("20060102")
				dedupKey = fmt.Sprintf("sig:%s:host:%s:d:%s", sig.ID, ev.Host, day)
			} else {
				hour := ev.Time.UTC().Format("2006010215")
				dedupKey = fmt.Sprintf("sig:%s:host:%s:h:%s", sig.ID, ev.Host, hour)
			}
			desc := fmt.Sprintf(
				"%s\n\nMITRE ATT&CK: %s | Category: %s\nHost: %s | OS: %s | User: %s | Process: %s\nCommand: %s",
				sig.Description, sig.MITRE, sig.Category,
				ev.Host, ev.OS, strOrDash(ev.UserName), strOrDash(ev.ProcessName), strOrDash(ev.CommandLine),
			)
			alert := store.Alert{
				Title:         fmt.Sprintf("[%s] %s", sig.MITRE, sig.Name),
				Description:   desc,
				Severity:      sev,
				AgentID:       ev.AgentID,
				Host:          ev.Host,
				EventType:     ev.EventType,
				EventID:       dedupKey,
				SourceEventID: ev.ID,
			}
			if id, inserted, err := e.db.CreateAlertDeduped(ctx, alert); err == nil && !inserted && id > 0 {
				// Duplicate within the hour: record this process as an extra
				// anchor on the existing alert (capped) so the Alert Graph
				// still reaches it, without raising alert volume.
				if k := processAnchorKey(ev); k != "" {
					_ = e.db.LinkAlertEntityCapped(ctx, id, EntityProcess, k, maxProcessAnchorsPerAlert)
				}
			} else if err == nil && inserted {
				created++
				engineLinkEntities(ctx, e.db, id, ev) // [FOUNDATION-HOOK]
				alert.CreatedAt = time.Now()
				if e.mailer.Enabled() && sev >= e.mailer.MinSeverity() {
					alert.ID = id
					e.mailer.QueueAlert(alert)
				}
			}
		}

		// IOC matching
		if ioc := e.matchIOC(ev, ipIOCs, domainIOCs, hashIOCs); ioc != nil && ioc.Confidence >= 0 && !(ioc.Confidence > 0 && ioc.Confidence < 25) {
			// D-14: confidence weighting. IOCs under 25% confidence are
			// ignored (noise); 25-49% are alerted one level lower.
			if ioc.Confidence > 0 && ioc.Confidence < 50 && ioc.Severity > 2 {
				adj := *ioc
				adj.Severity--
				ioc = &adj
			}
			hour := ev.Time.UTC().Format("2006010215")
			dedupKey := fmt.Sprintf("ioc:%s:%s:host:%s:h:%s:e:%s", ioc.Source, ioc.Value, ev.Host, hour, alertEntityKey(ev)) // D-06: entity fingerprint folded in
			source := strings.ToUpper(ioc.Source)
			desc := fmt.Sprintf(
				"[%s] Matched known malicious %s: %s\n\nMalware: %s | Threat: %s | Confidence: %d%%\nHost: %s | OS: %s | Process: %s",
				source, ioc.IOCType, ioc.Value, ioc.Malware, ioc.ThreatType, ioc.Confidence,
				ev.Host, ev.OS, strOrDash(ev.ProcessName),
			)
			alert := store.Alert{
				Title:         fmt.Sprintf("[%s] %s IOC Match — %s", source, titleCase(ioc.IOCType), ioc.Value),
				Description:   desc,
				Severity:      ioc.Severity,
				AgentID:       ev.AgentID,
				Host:          ev.Host,
				EventType:     ev.EventType,
				EventID:       dedupKey,
				SourceEventID: ev.ID,
			}
			if id, inserted, err := e.db.CreateAlertDeduped(ctx, alert); err == nil && inserted {
				created++
				alert.CreatedAt = time.Now()
				if e.mailer.Enabled() && ioc.Severity >= e.mailer.MinSeverity() {
					alert.ID = id
					e.mailer.QueueAlert(alert)
				}
			}
		}

		// Sigma rule matching — only evaluate rules relevant to this event type
		relevantSigma := sigmaRelevantRules(sigmaByCategory, ev)

		for _, rule := range relevantSigma {
			if !matchSigmaRule(rule, ev) {
				continue
			}
			sigSev, sigOK := sigmaAlertSeverity(rule)
			if !sigOK {
				continue
			}

			hour := ev.Time.UTC().Format("2006010215")
			dedupKey := fmt.Sprintf("sig:sigma:%s:host:%s:h:%s:e:%s", rule.ID, ev.Host, hour, alertEntityKey(ev)) // D-06: entity fingerprint folded in
			mitre := rule.MITRE
			if mitre == "" {
				mitre = "Sigma"
			}
			alert := store.Alert{
				Title: fmt.Sprintf("[Sigma] %s", rule.Title),
				Description: fmt.Sprintf("%s\n\nRule: %s | Level: %s | Category: %s\nMITRE: %s\nHost: %s | OS: %s | Process: %s | Command: %s",
					rule.Description, rule.Title, rule.Level, rule.Category,
					mitre, ev.Host, ev.OS, strOrDash(ev.ProcessName), strOrDash(ev.CommandLine)),
				Severity:      sigSev,
				AgentID:       ev.AgentID,
				Host:          ev.Host,
				EventType:     ev.EventType,
				EventID:       dedupKey,
				SourceEventID: ev.ID,
			}
			if id, inserted, err := e.db.CreateAlertDeduped(ctx, alert); err == nil && inserted {
				created++
				alert.CreatedAt = time.Now()
				if e.mailer.Enabled() && sigSev >= e.mailer.MinSeverity() {
					alert.ID = id
					e.mailer.QueueAlert(alert)
				}
			}
		}
	}
	if created > 0 {
		e.logger.Info("detection engine: alerts created", "count", created)
	}
}

// sigmaRelevantRules returns Sigma rules relevant to a given event —
// pre-filters by OS/category to avoid evaluating all 1200+ rules per event.
func sigmaRelevantRules(byCategory map[string][]store.SigmaRule, ev store.Event) []store.SigmaRule {
	evOS := strings.ToLower(ev.OS)
	var rules []store.SigmaRule
	seen := make(map[string]bool)
	add := func(cats ...string) {
		for _, cat := range cats {
			for _, r := range byCategory[cat] {
				if seen[r.ID] {
					continue
				}
				// Skip rules that target a different OS
				ls := strings.ToLower(r.LogSource)
				if strings.Contains(ls, "product: windows") && evOS != "windows" {
					continue
				}
				if strings.Contains(ls, "product: linux") && evOS != "linux" {
					continue
				}
				if strings.Contains(ls, "product: macos") && evOS != "macos" && evOS != "darwin" {
					continue
				}
				seen[r.ID] = true
				rules = append(rules, r)
			}
		}
	}
	// Always include rules with no category (catch-all)
	add("")
	// Map event_type to sigma categories
	switch ev.EventType {
	case "process":
		add("process_creation", "process_access", "process_tampering")
	case "network":
		add("network_connection", "firewall", "proxy")
	case "dns":
		add("dns_query", "dns")
	case "file":
		add("file_event", "file_change", "file_delete", "file_rename")
	case "registry":
		add("registry_event", "registry_set", "registry_add", "registry_delete")
	case "logon":
		add("user_logon", "logon_failed", "authentication")
	case "sysmon":
		add("process_creation", "network_connection", "file_event", "registry_event")
	}
	// Windows event-log rules (logsource product+service, stored under the
	// "windows" category) apply to events that carry an event-log channel.
	if ev.Channel != nil && evOS == "windows" {
		add("windows")
	}
	// Add OS-specific rules — only add broad OS categories for process/sysmon events
	// to avoid false positives (e.g. "windows" rules matching network events)
	switch strings.ToLower(ev.OS) {
	case "windows":
		if ev.EventType == "process" || ev.EventType == "sysmon" {
			add("windows", "antivirus", "application")
		}
	case "linux":
		if ev.EventType == "process" || ev.EventType == "file" {
			add("linux", "auditd")
		}
	case "macos", "darwin":
		if ev.EventType == "process" || ev.EventType == "file" {
			add("macos", "darwin")
		}
	}
	return rules
}

// debugSigmaRule logs exactly why a rule matched or failed — call manually for troubleshooting.
func debugSigmaRule(rule store.SigmaRule, ev store.Event, logger *slog.Logger) {
	fields := buildEventText(ev)
	logger.Info("sigma-debug: testing rule",
		"rule", rule.Title,
		"category", rule.Category,
		"event_type", ev.EventType,
		"image", strOrDash(ev.ImagePath),
		"cmdline", strOrDash(ev.CommandLine),
		"procname", strOrDash(ev.ProcessName),
		"detection_len", len(rule.Detection),
	)
	result := matchSigmaRule(rule, ev)
	logger.Info("sigma-debug: result", "rule", rule.Title, "matched", result, "fields_len", len(fields))
}

func buildEventText(ev store.Event) string {
	fields := []string{
		ev.EventType, ev.OS, ev.Host, ev.Source,
		strOrDash(ev.ProcessName), strOrDash(ev.CommandLine), strOrDash(ev.ImagePath),
		strOrDash(ev.UserName), strOrDash(ev.FilePath), strOrDash(ev.FileHash),
		strOrDash(ev.DstIP), strOrDash(ev.SrcIP), strOrDash(ev.RegKey),
	}
	if ev.Raw != nil {
		fields = append(fields, strings.ToLower(string(ev.Raw)))
	}
	return strings.ToLower(strings.Join(fields, " "))
}

func (e *DetectionEngine) matchIOC(ev store.Event,
	ipIOCs, domainIOCs, hashIOCs map[string]store.IOCIndicator) *store.IOCIndicator {

	// IP match — network events
	if ev.EventType == "network" && ev.DstIP != nil {
		ip := strings.ToLower(*ev.DstIP)
		if ioc, ok := ipIOCs[ip]; ok {
			return &ioc
		}
	}

	// Domain match — DNS events (DstIP holds the queried domain on all platforms)
	if ev.EventType == "dns" && ev.DstIP != nil {
		domain := strings.ToLower(*ev.DstIP)
		if ioc, ok := domainIOCs[domain]; ok {
			return &ioc
		}
		// Parent domain (sub.evil.com → evil.com)
		parts := strings.SplitN(domain, ".", 2)
		if len(parts) == 2 {
			if ioc, ok := domainIOCs[parts[1]]; ok {
				return &ioc
			}
		}
	}

	// URL indicators — URLs appearing in command lines (curl, powershell, ...)
	if ev.CommandLine != nil {
		if ioc := matchURLIOC(*ev.CommandLine, domainIOCs); ioc != nil {
			return ioc
		}
	}

	// Cloud events — SrcIP against IP IOCs
	if isCloudEvent(ev) && ev.SrcIP != nil && *ev.SrcIP != "" {
		if ioc, ok := ipIOCs[strings.ToLower(*ev.SrcIP)]; ok {
			return &ioc
		}
	}

	// G-08: outbound VPC-flow destinations and GCP DNS query names.
	if (ev.EventType == "cloud.gcp_vpc_flow" || ev.EventType == "cloud.gcp_dns") && len(ev.Raw) > 0 {
		var f struct {
			DstIP     string `json:"dst_ip"`
			QueryName string `json:"query_name"`
		}
		if json.Unmarshal(ev.Raw, &f) == nil {
			if f.DstIP != "" {
				if ioc, ok := ipIOCs[strings.ToLower(f.DstIP)]; ok {
					return &ioc
				}
			}
			if q := strings.ToLower(strings.TrimSuffix(f.QueryName, ".")); q != "" {
				if ioc, ok := domainIOCs[q]; ok {
					return &ioc
				}
				if parts := strings.SplitN(q, ".", 2); len(parts) == 2 {
					if ioc, ok := domainIOCs[parts[1]]; ok {
						return &ioc
					}
				}
			}
		}
	}

	// Hash match — file events
	if ev.EventType == "file" && ev.FileHash != nil {
		for _, part := range strings.Split(*ev.FileHash, ",") {
			hash := strings.ToLower(strings.TrimSpace(part))
			if idx := strings.Index(hash, "="); idx >= 0 {
				hash = hash[idx+1:]
			}
			if hash == "" {
				continue
			}
			if ioc, ok := hashIOCs[hash]; ok {
				return &ioc
			}
		}
	}
	return nil
}

func strOrDash(s *string) string {
	if s == nil || *s == "" {
		return "—"
	}
	return *s
}

func titleCase(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ownAgentBinaries are the exact process names our agents run as.
var ownAgentBinaries = map[string]bool{
	"obsidianwatch-agent":         true,
	"obsidianwatch-agent.exe":     true,
	"obsidianwatch-network-probe": true,
}

// ownAgentDirs are the install locations (lower-case, normalised to "/").
var ownAgentDirs = []string{
	"/usr/local/bin/",
	"/library/obsidianwatch/",
	"/opt/obsidianwatch/",
	"c:/program files/obsidianwatch/",
}

// isOwnAgentProcess reports whether a process event is one of our own agents
// (D-03). It used to skip any process whose name merely *contained*
// "obsidianwatch" / "ow-agent", so malware could evade every rule by naming
// itself that. Now the name must match exactly and, when the event carries
// an image path, that path must be inside an install directory — a binary
// called obsidianwatch-agent running from /tmp is NOT exempt. (Events with
// no image path fall back to the exact-name check; hash/signature
// verification is the stronger follow-up.)
func isOwnAgentProcess(ev store.Event) bool {
	if ev.ProcessName == nil {
		return false
	}
	if !ownAgentBinaries[strings.ToLower(strings.TrimSpace(*ev.ProcessName))] {
		return false
	}
	if ev.ImagePath == nil || strings.TrimSpace(*ev.ImagePath) == "" {
		return true
	}
	p := strings.ToLower(strings.ReplaceAll(*ev.ImagePath, "\\", "/"))
	for _, d := range ownAgentDirs {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

// shInteractiveRe matches an interactive bash/sh (reverse-shell staple) without
// matching "zsh -il" style login shells.
// shPipeToShellRe: a downloader piped into an interpreter.
var shPipeToShellRe = regexp.MustCompile(`(curl|wget)[^|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b`)

var shInteractiveRe = regexp.MustCompile(`(^|[\s/])(bash|sh) -i(\s|$)`)
