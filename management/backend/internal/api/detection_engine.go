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
	"context"
	"fmt"
	"log/slog"
	"strings"
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
	if ev.CommandLine == nil { return "" }
	return strings.ToLower(*ev.CommandLine)
}
func proc(ev store.Event) string {
	if ev.ProcessName == nil { return "" }
	return strings.ToLower(*ev.ProcessName)
}
func img(ev store.Event) string {
	if ev.ImagePath == nil { return "" }
	return strings.ToLower(*ev.ImagePath)
}
func fp(ev store.Event) string {
	if ev.FilePath == nil { return "" }
	return strings.ToLower(*ev.FilePath)
}
func rk(ev store.Event) string {
	if ev.RegKey == nil { return "" }
	return strings.ToLower(*ev.RegKey)
}
func dstip(ev store.Event) string {
	if ev.DstIP == nil { return "" }
	return strings.ToLower(*ev.DstIP)
}
func rawStr(ev store.Event) string {
	if ev.Raw == nil { return "" }
	return strings.ToLower(string(ev.Raw))
}
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, strings.ToLower(sub)) { return true }
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
		Severity: 4, MITRE: "T1059.004", Category: "Execution",
		Match: func(ev store.Event) bool {
			if ev.EventType != "process" { return false }
			isShell := containsAny(proc(ev), "bash", "sh", "zsh", "dash", "ksh", "fish")
			// Match shells running -c with suspicious content (pipe content IS in -c argument)
			// OR shells running from suspicious paths
			return isShell && containsAny(cl(ev),
				"-c curl", "-c wget", "-c python", "-c nc ", "-c ncat",
				"/dev/shm", "/dev/tcp",
				"bash -i", "sh -i", "0>&1", ">&2", "/dev/null 2>&1",
				"http://", "https://")
		},
	},
	{
		ID: "L-T1059.004b", Name: "Executable Run from /tmp or /dev/shm",
		Description: "Process spawned from /tmp, /dev/shm, or /var/tmp — common malware staging.",
		Severity: 5, MITRE: "T1059.004", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(img(ev)+cl(ev), "/tmp/", "/dev/shm/", "/var/tmp/")
		},
	},
	{
		ID: "L-T1059.006", Name: "Python/Perl/Ruby Reverse Shell",
		Description: "Interpreter running inline code with socket/exec — reverse shell technique.",
		Severity: 5, MITRE: "T1059.006", Category: "Execution",
		Match: func(ev store.Event) bool {
			if ev.EventType != "process" { return false }
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
		Severity: 5, MITRE: "T1059.004", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" &&
				containsAny(proc(ev), "nc", "ncat", "netcat") &&
				containsAny(cl(ev), " -e ", " -c ", "--exec", "-e /bin", "-e sh", "-e bash")
		},
	},
	{
		ID: "L-T1105", Name: "curl/wget Suspicious Download",
		Description: "curl or wget downloading from internet to stdout or temp location — dropper technique.",
		Severity: 4, MITRE: "T1105", Category: "Execution",
		Match: func(ev store.Event) bool {
			if ev.EventType != "process" { return false }
			isFetcher := containsAny(proc(ev), "curl", "wget")
			// Downloading to stdout (-o- or no -o flag with URL) or to /tmp
			return isFetcher && containsAny(cl(ev),
				"-o /tmp", "-o /dev/shm", "-O /tmp",
				"--output /tmp", "--output /dev/shm",
				"-o-", "--output-",
				"/tmp/", "/dev/shm/", "/var/tmp/")
		},
	},

	// ── Discovery ────────────────────────────────────────────────────────────
	{
		ID: "L-T1087.001", Name: "Linux User Enumeration",
		Description: "Commands enumerating local users and sudo privileges.",
		Severity: 2, MITRE: "T1087.001", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"cat /etc/passwd", "getent passwd", "id -a", "sudo -l",
				"last ", "lastlog", "who ", "w ")
		},
	},
	{
		ID: "L-T1046", Name: "Network Scanning Tool",
		Description: "nmap, masscan, or similar scanner detected.",
		Severity: 3, MITRE: "T1046", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev)+cl(ev), "nmap", "masscan", "zmap", "arp-scan", "netdiscover")
		},
	},
	{
		ID: "L-T1592", Name: "Packet Capture Tool",
		Description: "tcpdump or tshark running — may capture credentials.",
		Severity: 4, MITRE: "T1592", Category: "Reconnaissance",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev)+cl(ev), "tcpdump", "tshark", "wireshark", "dumpcap")
		},
	},
	{
		ID: "L-T1590", Name: "DNS/Domain Reconnaissance",
		Description: "dig, nslookup, or dnsrecon used for domain enumeration.",
		Severity: 2, MITRE: "T1590", Category: "Reconnaissance",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "dig", "nslookup", "host", "dnsenum", "dnsrecon", "fierce", "whois")
		},
	},

	// ── Privilege Escalation ─────────────────────────────────────────────────
	{
		ID: "L-T1548.001a", Name: "SUID Bit Set (chmod +s)",
		Description: "chmod setting SUID bit — privilege escalation vector.",
		Severity: 4, MITRE: "T1548.001", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "chmod") &&
				containsAny(cl(ev), "+s", "4755", "4777", "u+s")
		},
	},
	{
		ID: "L-T1548.001b", Name: "Sudo Root Shell",
		Description: "sudo used to spawn an interactive root shell.",
		Severity: 4, MITRE: "T1548.001", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "sudo") &&
				containsAny(cl(ev), "sudo su", "sudo bash", "sudo sh", "sudo -s", "sudo -i")
		},
	},
	{
		ID: "L-T1547.006", Name: "Kernel Module Loaded",
		Description: "insmod or modprobe executed — possible rootkit installation.",
		Severity: 5, MITRE: "T1547.006", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "insmod", "modprobe")
		},
	},
	{
		ID: "L-T1611", Name: "Container Escape Indicator",
		Description: "docker.sock accessed or container escape tools detected.",
		Severity: 5, MITRE: "T1611", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return containsAny(fp(ev)+cl(ev)+proc(ev), "docker.sock", "/var/run/docker.sock",
				"nsenter", "--privileged", "cap_sys_admin", "pivot_root", "deepce", "amicontained")
		},
	},

	// ── Credential Access ────────────────────────────────────────────────────
	{
		ID: "L-T1003.008", Name: "/etc/shadow Read",
		Description: "Direct read of /etc/shadow — password hash dumping.",
		Severity: 5, MITRE: "T1003.008", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return containsAny(fp(ev)+cl(ev)+rk(ev), "/etc/shadow", "/etc/gshadow") ||
				(ev.EventType == "process" && containsAny(cl(ev), "unshadow", "hashcat", "john --"))
		},
	},
	{
		ID: "L-T1110.001", Name: "SSH Brute Force (journald)",
		Description: "Repeated SSH authentication failures in journald — brute force detected.",
		Severity: 4, MITRE: "T1110.001", Category: "Credential Access",
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
		Severity: 4, MITRE: "T1552.004", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return containsAny(fp(ev)+cl(ev), "id_rsa", "id_ed25519", "id_ecdsa", "/.ssh/", ".pem")
		},
	},
	{
		ID: "L-T1552.005", Name: "Cloud Credential File Access",
		Description: "AWS, GCP, or Azure credential files read — cloud credential theft.",
		Severity: 5, MITRE: "T1552.005", Category: "Credential Access",
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
		Severity: 4, MITRE: "T1053.003", Category: "Persistence",
		Match: func(ev store.Event) bool {
			// configmon emits EventType="registry" for config file changes on Linux
			return (ev.EventType == "file" || ev.EventType == "registry") &&
				containsAny(fp(ev)+rk(ev), "/etc/cron", "/var/spool/cron", "crontab")
		},
	},
	{
		ID: "L-T1543.002", Name: "New Systemd Service",
		Description: "Systemd unit file written to system directories — persistence.",
		Severity: 4, MITRE: "T1543.002", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return (ev.EventType == "file" || ev.EventType == "registry") &&
				containsAny(fp(ev)+rk(ev), "/etc/systemd/system/", "/usr/lib/systemd/", "/lib/systemd/") &&
				containsAny(fp(ev)+rk(ev), ".service", ".timer", ".socket")
		},
	},
	{
		ID: "L-T1546.004", Name: "Shell Profile Modified",
		Description: ".bashrc, .profile, or /etc/profile written — shell-based persistence.",
		Severity: 4, MITRE: "T1546.004", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return (ev.EventType == "file" || ev.EventType == "registry") &&
				containsAny(fp(ev)+rk(ev), ".bashrc", ".bash_profile", ".zshrc", "/etc/profile", "/etc/bash.bashrc")
		},
	},
	{
		ID: "L-T1574.006", Name: "LD_PRELOAD Hijacking",
		Description: "LD_PRELOAD or /etc/ld.so.preload set — shared library hijacking.",
		Severity: 5, MITRE: "T1574.006", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return containsAny(fp(ev)+rk(ev)+cl(ev)+rawStr(ev), "ld_preload", "ld.so.preload")
		},
	},

	// ── Defence Evasion ──────────────────────────────────────────────────────
	{
		ID: "L-T1070.002", Name: "Log File Deletion or History Wipe",
		Description: "System logs deleted or shell history cleared — covering tracks.",
		Severity: 5, MITRE: "T1070.002", Category: "Defence Evasion",
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
		Severity: 3, MITRE: "T1222.002", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "chmod") &&
				containsAny(cl(ev), "777", "a+w", "o+w")
		},
	},

	// ── Lateral Movement ────────────────────────────────────────────────────
	{
		ID: "L-T1021.004", Name: "SSH Tunnel / Port Forward",
		Description: "SSH -L/-R/-D flag — tunnelling or SOCKS proxy.",
		Severity: 4, MITRE: "T1021.004", Category: "Lateral Movement",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "ssh") &&
				containsAny(cl(ev), " -l ", " -r ", " -d ", "-nfl", "-nfr", "-nfd")
		},
	},

	// ── Command and Control ──────────────────────────────────────────────────
	{
		ID: "L-T1572", Name: "DNS Tunnelling Indicator",
		Description: "Unusually long DNS hostname — possible DNS tunnelling for C2.",
		Severity: 4, MITRE: "T1572", Category: "Command and Control",
		Match: func(ev store.Event) bool {
			return ev.EventType == "dns" && ev.DstIP != nil && len(*ev.DstIP) > 60
		},
	},
	{
		ID: "L-T1219", Name: "Remote Access Tool",
		Description: "Known commercial remote access tool detected.",
		Severity: 3, MITRE: "T1219", Category: "Command and Control",
		Match: func(ev store.Event) bool {
			return containsAny(proc(ev)+cl(ev), "anydesk", "teamviewer", "rustdesk", "screenconnect", "logmein")
		},
	},
	{
		ID: "L-T1090.003", Name: "Tor / Proxy Tool",
		Description: "Tor or proxychains detected — anonymous communication channel.",
		Severity: 4, MITRE: "T1090.003", Category: "Command and Control",
		Match: func(ev store.Event) bool {
			return containsAny(proc(ev)+cl(ev)+fp(ev), "tor ", "torsocks", "proxychains", "proxifier")
		},
	},
	{
		ID: "L-T1078.004", Name: "Cloud Metadata Service Access",
		Description: "Access to 169.254.169.254 — instance credential theft.",
		Severity: 4, MITRE: "T1078.004", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return containsAny(dstip(ev)+cl(ev), "169.254.169.254", "metadata.google.internal")
		},
	},

	// ── Exfiltration ────────────────────────────────────────────────────────
	{
		ID: "L-T1048", Name: "curl POST Data Exfiltration",
		Description: "curl sending data with POST or upload flags — possible exfiltration.",
		Severity: 3, MITRE: "T1048", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "curl") &&
				containsAny(cl(ev), " -d ", " --data ", " -f ", " -t ", "--upload-file", "-x post")
		},
	},
	{
		ID: "L-T1560", Name: "Archive of Sensitive Directory",
		Description: "tar/zip archiving /etc, /home, or sensitive directories — staging for exfil.",
		Severity: 3, MITRE: "T1560.001", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "tar", "zip", "7z", "gzip") &&
				containsAny(cl(ev), "/home/", "/etc/", "/root/", "database", ".sql", "backup", "dump")
		},
	},
	{
		ID: "L-T1567", Name: "Paste/File Sharing Service Contact",
		Description: "Connection to known paste or file-sharing site — C2 or exfil channel.",
		Severity: 4, MITRE: "T1567.001", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			return containsAny(dstip(ev)+cl(ev), "pastebin.com", "paste.ee", "hastebin.com",
				"wetransfer.com", "mega.nz", "transfer.sh", "0x0.st", "gofile.io")
		},
	},
	{
		ID: "L-DLP-010", Name: "Database Dump Command",
		Description: "mysqldump, pg_dump, or mongodump executed — bulk data extraction.",
		Severity: 4, MITRE: "T1005", Category: "Data Loss Prevention",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev),
				"mysqldump", "pg_dump", "pg_dumpall", "mongodump", "mongoexport", "sqlite3", "expdp")
		},
	},
}

// ══════════════════════════════════════════════════════════════════════════════
// WINDOWS SIGNATURES
// ══════════════════════════════════════════════════════════════════════════════
var windowsSignatures = []ThreatSig{

	// ── Execution ────────────────────────────────────────────────────────────
	{
		ID: "W-T1059.001a", Name: "PowerShell Encoded Command",
		Description: "PowerShell -EncodedCommand flag — common malware obfuscation.",
		Severity: 4, MITRE: "T1059.001", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev), "-enc ", "-encodedcommand", "-e jab", "-e sqb")
		},
	},
	{
		ID: "W-T1059.001b", Name: "PowerShell Download Cradle",
		Description: "PowerShell downloading and executing code from internet.",
		Severity: 5, MITRE: "T1059.001", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"downloadstring", "downloadfile", "iex(", "invoke-expression",
				"webclient", "invoke-webrequest", "start-bitstransfer")
		},
	},
	{
		ID: "W-T1059.003", Name: "Suspicious CMD Execution",
		Description: "cmd.exe running reconnaissance or download commands.",
		Severity: 3, MITRE: "T1059.003", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "cmd.exe", "cmd") &&
				containsAny(cl(ev), "/c whoami", "/c net ", "/c ipconfig", "certutil", "bitsadmin")
		},
	},
	{
		ID: "W-T1218.011", Name: "Rundll32 Suspicious Execution",
		Description: "rundll32.exe executing JavaScript, VBScript, or remote content — LOLBAS.",
		Severity: 4, MITRE: "T1218.011", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "rundll32") &&
				containsAny(cl(ev), "javascript:", "vbscript:", "shell32", ",control_rundll", "http")
		},
	},
	{
		ID: "W-T1218.005", Name: "MSHTA Execution",
		Description: "mshta.exe executing HTA file — frequently used for initial access.",
		Severity: 4, MITRE: "T1218.005", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "mshta")
		},
	},
	{
		ID: "W-T1218.010", Name: "Regsvr32 Squiblydoo Bypass",
		Description: "regsvr32.exe loading a remote scriptlet — AppLocker bypass.",
		Severity: 5, MITRE: "T1218.010", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "regsvr32") &&
				containsAny(cl(ev), "http", "/u ", "/s ", "scrobj")
		},
	},
	{
		ID: "W-T1059.005", Name: "WScript/CScript Execution",
		Description: "Windows Script Host executing a script.",
		Severity: 3, MITRE: "T1059.005", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "wscript.exe", "cscript.exe")
		},
	},
	{
		ID: "W-T1197", Name: "BITS Job Abuse",
		Description: "bitsadmin used to download or execute — LOLBAS technique.",
		Severity: 4, MITRE: "T1197", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev)+cl(ev), "bitsadmin", "start-bitstransfer") &&
				containsAny(cl(ev), "/transfer", "/addfile", "/setnotifycmdline", "http")
		},
	},
	{
		ID: "W-T1047", Name: "WMI Remote Execution",
		Description: "WMI used for remote code execution.",
		Severity: 4, MITRE: "T1047", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev)+cl(ev), "wmic", "wmiexec", "invoke-wmimethod") &&
				containsAny(cl(ev), "/node:", "process call create", "win32_process")
		},
	},
	{
		ID: "W-T1218.007", Name: "Msiexec Remote Install",
		Description: "msiexec installing a package from URL — malware delivery.",
		Severity: 4, MITRE: "T1218.007", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "msiexec") &&
				containsAny(cl(ev), "http://", "https://", "/i ", "/q ")
		},
	},
	{
		ID: "W-T1566.001", Name: "Shell Spawned with Office-Related Arguments",
		Description: "cmd/PowerShell/script host spawned with document-related paths or macro keywords — possible Office macro execution.",
		Severity: 5, MITRE: "T1566.001", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			if ev.EventType != "process" { return false }
			isShellChild := containsAny(proc(ev), "cmd.exe", "powershell", "wscript", "cscript", "mshta", "rundll32", "regsvr32")
			if !isShellChild { return false }
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
		Severity: 2, MITRE: "T1057", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev), "tasklist", "get-process", "qprocess")
		},
	},
	{
		ID: "W-T1016", Name: "Network Configuration Discovery",
		Description: "ipconfig, netstat, arp — network enumeration.",
		Severity: 2, MITRE: "T1016", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev), "ipconfig", "netstat", "arp -a", "route print", "nslookup", "net view")
		},
	},
	{
		ID: "W-T1087", Name: "Account Enumeration",
		Description: "net user, net localgroup, or Get-ADUser — account discovery.",
		Severity: 3, MITRE: "T1087", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"net user", "net localgroup", "net group", "get-aduser", "whoami /all", "query user")
		},
	},
	{
		ID: "W-T1595", Name: "Port Scanning Tool",
		Description: "nmap or masscan on a Windows host.",
		Severity: 3, MITRE: "T1595.001", Category: "Reconnaissance",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev)+cl(ev), "nmap", "masscan", "rustscan", "nessus", "nikto")
		},
	},

	// ── Privilege Escalation ─────────────────────────────────────────────────
	{
		ID: "W-T1548.002", Name: "UAC Bypass Technique",
		Description: "Known UAC bypass tool or technique detected.",
		Severity: 5, MITRE: "T1548.002", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev), "eventvwr", "fodhelper", "sdclt", "computerdefaults", "bypassuac", "cmstp")
		},
	},
	{
		ID: "W-T1055", Name: "Process Injection",
		Description: "Known process injection API calls or tools detected.",
		Severity: 5, MITRE: "T1055", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"virtualalloc", "writeprocessmemory", "createremotethread", "mimikatz", "procdump", "reflectiveload")
		},
	},
	{
		ID: "W-T1134", Name: "Token Impersonation",
		Description: "Token manipulation — privilege escalation via token theft.",
		Severity: 5, MITRE: "T1134", Category: "Privilege Escalation",
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
		Severity: 5, MITRE: "T1003.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return containsAny(cl(ev)+fp(ev)+rawStr(ev), "lsass", "procdump", "comsvcs.dll,minidump", "sekurlsa")
		},
	},
	{
		ID: "W-T1003.002", Name: "SAM Database Access",
		Description: "Attempt to access the SAM database — Windows password hashes.",
		Severity: 5, MITRE: "T1003.002", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return containsAny(fp(ev)+rk(ev)+cl(ev),
				`system\currentcontrolset\control\lsa`, `sam\sam\domains`, `reg save hklm\sam`)
		},
	},
	{
		ID: "W-T1110", Name: "Failed Logon (EventID 4625)",
		Description: "Windows failed logon — possible brute force.",
		Severity: 3, MITRE: "T1110", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "logon" && ev.EventID != nil && *ev.EventID == 4625
		},
	},
	{
		ID: "W-T1552.001", Name: "Credential Search in Files",
		Description: "findstr searching for passwords in files.",
		Severity: 3, MITRE: "T1552.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"findstr /si password", ".kdbx", "unattend.xml", "credential", "vault")
		},
	},
	{
		ID: "W-T1552.005", Name: "Cloud Credential File Access",
		Description: "AWS, Azure, or GCP credential files accessed — cloud credential theft.",
		Severity: 5, MITRE: "T1552.005", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			// FIM file event (if watched path) OR process reading credential file in cl/raw
			return containsAny(fp(ev)+cl(ev)+rawStr(ev),
				".aws\\credentials", ".aws/credentials", ".aws\\config", ".aws/config",
				".azure\\", ".azure/",
				"accesstokens.json", ".config\\gcloud", ".config/gcloud",
				"application_default_credentials.json", "terraform.tfstate")
		},
	},

	// ── Persistence ──────────────────────────────────────────────────────────
	{
		ID: "W-T1547.001", Name: "Run Key Persistence",
		Description: "Registry Run key modified — common Windows persistence.",
		Severity: 4, MITRE: "T1547.001", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "registry" && containsAny(rk(ev),
				`\currentversion\run`, `\currentversion\runonce`, `policies\explorer\run`)
		},
	},
	{
		ID: "W-T1053.005", Name: "Scheduled Task Created",
		Description: "New scheduled task — persistence or lateral movement.",
		Severity: 3, MITRE: "T1053.005", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return (ev.EventType == "process" && containsAny(cl(ev), "schtasks /create", "new-scheduledtask")) ||
				(ev.EventID != nil && (*ev.EventID == 4698 || *ev.EventID == 4702))
		},
	},
	{
		ID: "W-T1543.003", Name: "New Service Created",
		Description: "New Windows service installed via sc.exe or PowerShell.",
		Severity: 4, MITRE: "T1543.003", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev), "sc create", "new-service", "sc.exe create")
		},
	},
	{
		ID: "W-T1546.003", Name: "WMI Event Subscription",
		Description: "WMI event subscription created — fileless persistence.",
		Severity: 5, MITRE: "T1546.003", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"__eventfilter", "__eventconsumer", "commandlineeventconsumer", "activescripteventconsumer")
		},
	},
	{
		ID: "W-T1546.012", Name: "IFEO Debugger Hijack",
		Description: "Image File Execution Options debugger key set — process hijacking.",
		Severity: 5, MITRE: "T1546.012", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return containsAny(rk(ev), "image file execution options", `\ifeo\`) &&
				containsAny(rk(ev)+rawStr(ev), "debugger", "globalflag")
		},
	},

	// ── Defence Evasion ──────────────────────────────────────────────────────
	{
		ID: "W-T1562.001a", Name: "Security Tool Disabled",
		Description: "Windows Defender or firewall disabled via command line.",
		Severity: 5, MITRE: "T1562.001", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"set-mppreference -disablerealtime", "netsh advfirewall set allprofiles state off",
				"sc stop windefend", "sc config windefend start= disabled", "disableantispyware")
		},
	},
	{
		ID: "W-T1070.001", Name: "Event Log Cleared",
		Description: "Windows event log cleared — attacker covering tracks.",
		Severity: 5, MITRE: "T1070.001", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return (ev.EventID != nil && (*ev.EventID == 1102 || *ev.EventID == 104)) ||
				containsAny(cl(ev), "wevtutil cl", "clear-eventlog", "clearev")
		},
	},
	{
		ID: "W-T1027", Name: "Obfuscated Command",
		Description: "Base64 decode or heavy obfuscation in command line.",
		Severity: 4, MITRE: "T1027", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && (
				containsAny(cl(ev), "frombase64string", "[convert]::", "char(", "chr(", "`i`e`x", "iex(") ||
					strings.Count(cl(ev), "^") > 5)
		},
	},
	{
		ID: "W-T1036", Name: "Process Name Masquerading",
		Description: "Known system process running from unexpected path.",
		Severity: 4, MITRE: "T1036", Category: "Defence Evasion",
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
		Severity: 5, MITRE: "T1562.001", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"amsiutils", "amsi.dll", "[ref].assembly", "amsicontext", "amsiinitmemfailed")
		},
	},
	{
		ID: "W-T1574.002", Name: "DLL in User-Writable Path",
		Description: "DLL placed in AppData or Temp — search order hijacking.",
		Severity: 4, MITRE: "T1574.002", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "file" && containsAny(fp(ev), ".dll") &&
				containsAny(fp(ev), `\appdata\`, `\temp\`, `\downloads\`, `\desktop\`, `\programdata\`)
		},
	},

	// ── Lateral Movement ────────────────────────────────────────────────────
	{
		ID: "W-T1021.001", Name: "RDP Lateral Movement",
		Description: "mstsc or RDP connection detected.",
		Severity: 3, MITRE: "T1021.001", Category: "Lateral Movement",
		Match: func(ev store.Event) bool {
			return (ev.EventType == "logon" && ev.EventID != nil && *ev.EventID == 4648 &&
				containsAny(rawStr(ev), "3389", "termserv", "mstsc")) ||
				(ev.EventType == "process" && containsAny(proc(ev)+cl(ev), "mstsc"))
		},
	},
	{
		ID: "W-T1570", Name: "PsExec / Remote Execution Tool",
		Description: "PsExec or similar remote execution tool detected.",
		Severity: 4, MITRE: "T1570", Category: "Lateral Movement",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev)+cl(ev), "psexec", "paexec", "wmiexec", "winrm")
		},
	},

	// ── Impact ───────────────────────────────────────────────────────────────
	{
		ID: "W-T1490", Name: "Shadow Copy Deletion",
		Description: "Volume Shadow Copy deletion — ransomware pre-cursor.",
		Severity: 5, MITRE: "T1490", Category: "Impact",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"vssadmin delete shadows", "wmic shadowcopy delete",
				"bcdedit /set {default} recoveryenabled no", "wbadmin delete catalog")
		},
	},
	{
		ID: "W-T1486", Name: "Ransomware File Extension",
		Description: "Files renamed to known ransomware extensions.",
		Severity: 5, MITRE: "T1486", Category: "Impact",
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
		Severity: 5, MITRE: "T1003.006", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			if ev.EventType != "ad_object_access" {
				return false
			}
			if ev.CommandLine == nil {
				return false
			}
			// Object type must be domainDNS or DS replication class
			cl := strings.ToLower(*ev.CommandLine)
			if !strings.Contains(cl, "domainDNS") && !strings.Contains(cl, "19195a5b") {
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
		Severity: 4, MITRE: "T1558.003", Category: "Credential Access",
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
		Severity: 4, MITRE: "T1558.004", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "kerberos" && ev.EventID != nil && *ev.EventID == 4768 &&
				ev.Severity >= 3
		},
	},
	// Golden Ticket — TGT for non-existent or privileged accounts
	{
		ID: "DC-T1558.001", Name: "Possible Golden Ticket Usage",
		Description: "Kerberos TGT request anomaly — ticket lifetime or encryption inconsistent with domain policy. Golden tickets are forged TGTs signed with the krbtgt hash.",
		Severity: 5, MITRE: "T1558.001", Category: "Credential Access",
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
		Severity: 5, MITRE: "T1484.001", Category: "Defense Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "ad_change" && ev.EventID != nil && *ev.EventID == 4739
		},
	},
	// AdminSDHolder abuse — modifying protected object to persist access
	{
		ID: "DC-T1078.002", Name: "AdminSDHolder Modification",
		Description: "The AdminSDHolder object was modified in Active Directory. Attackers modify AdminSDHolder to persist privileged access — SDProp propagates the ACL to all protected accounts every 60 minutes.",
		Severity: 5, MITRE: "T1078.002", Category: "Persistence",
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
		Severity: 4, MITRE: "T1484.001", Category: "Defense Evasion",
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
		Severity: 5, MITRE: "T1136.002", Category: "Persistence",
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
		Severity: 4, MITRE: "T1110.003", Category: "Credential Access",
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
		Severity: 4, MITRE: "T1059.002", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "osascript") &&
				containsAny(cl(ev), "-e ", "do shell script", "administrator privileges", "keystroke", "with administrator")
		},
	},
	{
		ID: "M-T1059.002b", Name: "osascript Credential Phishing Prompt",
		Description: "osascript displaying password dialog — social engineering to harvest credentials.",
		Severity: 5, MITRE: "T1059.002", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "osascript") &&
				containsAny(cl(ev), "display dialog", "password", "default answer")
		},
	},
	{
		ID: "M-T1059.004", Name: "Shell Pipe to Interpreter",
		Description: "Shell executing piped commands — dropper technique.",
		Severity: 4, MITRE: "T1059.004", Category: "Execution",
		Match: func(ev store.Event) bool {
			if ev.EventType != "process" { return false }
			isShell := containsAny(proc(ev), "bash", "sh", "zsh", "dash")
			return isShell && containsAny(cl(ev), "| bash", "|bash", "| sh", "|sh", "/tmp/", "/var/tmp/", "http://", "https://")
		},
	},
	{
		ID: "M-T1059.004b", Name: "Executable Run from /tmp",
		Description: "Process spawned from /tmp — common macOS malware staging.",
		Severity: 5, MITRE: "T1059.004", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev), "/tmp/", "/var/tmp/", "/private/tmp/")
		},
	},
	{
		ID: "M-T1105", Name: "curl/wget Pipe to Shell",
		Description: "curl or wget piped to shell — dropper technique.",
		Severity: 5, MITRE: "T1105", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "curl", "wget") &&
				containsAny(cl(ev), "| bash", "|bash", "| sh", "|sh", "| python", "exec(")
		},
	},
	{
		ID: "M-T1218.001", Name: "Compiled AppleScript Execution",
		Description: "Compiled .scpt file executed — common in macOS malware.",
		Severity: 3, MITRE: "T1218.001", Category: "Execution",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev), ".scpt", ".applescript") &&
				containsAny(proc(ev), "osascript", "osacompile")
		},
	},

	// ── Discovery ────────────────────────────────────────────────────────────
	{
		ID: "M-T1087.001", Name: "macOS User Enumeration",
		Description: "dscl, dscacheutil, or id used to enumerate users.",
		Severity: 2, MITRE: "T1087.001", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(cl(ev),
				"dscl . list /users", "dscacheutil -q user", "finger ", "id -a", "dsmemberutil")
		},
	},
	{
		ID: "M-T1082", Name: "macOS System Info Enumeration",
		Description: "system_profiler, sw_vers, or ioreg used for system profiling.",
		Severity: 2, MITRE: "T1082", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev)+cl(ev),
				"system_profiler", "sw_vers", "ioreg -rd1", "nvram -p", "sysctl -a")
		},
	},
	{
		ID: "M-T1046", Name: "Network Scanning Tool",
		Description: "nmap or arp-scan on macOS — internal reconnaissance.",
		Severity: 3, MITRE: "T1046", Category: "Discovery",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev)+cl(ev), "nmap", "masscan", "arp-scan", "netdiscover")
		},
	},
	{
		ID: "M-T1592", Name: "Packet Capture Tool",
		Description: "tcpdump or Wireshark running on macOS.",
		Severity: 4, MITRE: "T1592", Category: "Reconnaissance",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev)+cl(ev), "tcpdump", "tshark", "wireshark", "dumpcap")
		},
	},

	// ── Privilege Escalation ─────────────────────────────────────────────────
	{
		ID: "M-T1548.001", Name: "SUID Bit Set",
		Description: "chmod +s — SUID privilege escalation.",
		Severity: 4, MITRE: "T1548.001", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "chmod") &&
				containsAny(cl(ev), "+s", "4755", "4777", "u+s")
		},
	},
	{
		ID: "M-T1548.004", Name: "macOS Sudo Root Shell",
		Description: "sudo spawning a root shell on macOS.",
		Severity: 4, MITRE: "T1548.004", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "sudo") &&
				containsAny(cl(ev), "sudo su", "sudo bash", "sudo sh", "sudo -s", "sudo -i")
		},
	},
	{
		ID: "M-T1553.001", Name: "Gatekeeper Bypass via xattr",
		Description: "xattr removing quarantine attribute — Gatekeeper bypass.",
		Severity: 4, MITRE: "T1553.001", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "xattr") &&
				containsAny(cl(ev), "com.apple.quarantine", "-d ", "-c ")
		},
	},
	{
		ID: "M-T1562.001", Name: "SIP Tamper Attempt",
		Description: "csrutil used to disable System Integrity Protection.",
		Severity: 5, MITRE: "T1562.001", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev)+cl(ev),
				"csrutil disable", "csrutil enable --without", "nvram boot-args")
		},
	},

	// ── Credential Access ────────────────────────────────────────────────────
	{
		ID: "M-T1555.001a", Name: "Keychain Dump via security Command",
		Description: "security command extracting keychain passwords — credential theft.",
		Severity: 5, MITRE: "T1555.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "security") &&
				containsAny(cl(ev), "find-generic-password", "find-internet-password", "dump-keychain", "login.keychain")
		},
	},
	{
		ID: "M-T1555.001b", Name: "Keychain File Direct Access",
		Description: "Direct access to keychain database files.",
		Severity: 5, MITRE: "T1555.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "file" && containsAny(fp(ev), "login.keychain", "system.keychain", "library/keychains/")
		},
	},
	{
		ID: "M-T1110.001", Name: "SSH Brute Force (syslog)",
		Description: "Repeated SSH authentication failures in syslog.",
		Severity: 4, MITRE: "T1110.001", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			// macOS syslog: EventType="syslog", CommandLine=message body
			return (ev.EventType == "syslog" || ev.EventType == "logon") &&
				containsAny(cl(ev), "failed password", "authentication failure", "invalid user", "too many authentication failures")
		},
	},
	{
		ID: "M-T1552.004", Name: "SSH Private Key Access",
		Description: "SSH private key file accessed on macOS.",
		Severity: 4, MITRE: "T1552.004", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return containsAny(fp(ev)+cl(ev), "id_rsa", "id_ed25519", "/.ssh/", ".pem")
		},
	},
	{
		ID: "M-T1552.005", Name: "Cloud Credential File Access",
		Description: "AWS, GCP, or Azure credential files accessed on macOS.",
		Severity: 5, MITRE: "T1552.005", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			return containsAny(fp(ev)+cl(ev), ".aws/credentials", ".aws/config",
				".config/gcloud", "application_default_credentials.json", ".azure/", "terraform.tfstate")
		},
	},

	// ── Persistence ──────────────────────────────────────────────────────────
	{
		ID: "M-T1543.004", Name: "LaunchDaemon/LaunchAgent Written",
		Description: "New plist written to LaunchDaemons or LaunchAgents — macOS persistence.",
		Severity: 4, MITRE: "T1543.004", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "file" && containsAny(fp(ev),
				"/library/launchdaemons/", "/library/launchagents/", "~/library/launchagents/")
		},
	},
	{
		ID: "M-T1546.004", Name: "Shell Profile Modified",
		Description: ".bashrc, .zshrc, or /etc/profile modified — shell persistence.",
		Severity: 4, MITRE: "T1546.004", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return (ev.EventType == "file" || ev.EventType == "registry") &&
				containsAny(fp(ev)+rk(ev), ".bashrc", ".zshrc", ".bash_profile", "/etc/profile", "/etc/bash.bashrc")
		},
	},
	{
		ID: "M-T1547.015", Name: "macOS Login Hook Set",
		Description: "defaults writing LoginHook — persistent code execution on login.",
		Severity: 4, MITRE: "T1547.015", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "defaults") &&
				containsAny(cl(ev), "loginhook", "logouthook", "com.apple.loginwindow")
		},
	},
	{
		ID: "M-T1053.003", Name: "Cron Modified on macOS",
		Description: "Crontab written — persistence mechanism.",
		Severity: 4, MITRE: "T1053.003", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return (ev.EventType == "file" || ev.EventType == "registry") &&
				containsAny(fp(ev)+rk(ev), "/etc/cron", "/var/spool/cron", "crontab")
		},
	},

	// ── Defence Evasion ──────────────────────────────────────────────────────
	{
		ID: "M-T1070.002", Name: "macOS Log Cleared",
		Description: "System log deleted or cleared — attacker covering tracks.",
		Severity: 4, MITRE: "T1070.002", Category: "Defence Evasion",
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
		Severity: 5, MITRE: "T1574.006", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return containsAny(cl(ev)+rawStr(ev), "dyld_insert_libraries", "dyld_force_flat_namespace")
		},
	},

	// ── Lateral Movement / C2 ────────────────────────────────────────────────
	{
		ID: "M-T1021.004", Name: "SSH Tunnel / Port Forward",
		Description: "SSH -L/-R/-D flag — tunnelling or SOCKS proxy.",
		Severity: 4, MITRE: "T1021.004", Category: "Lateral Movement",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "ssh") &&
				containsAny(cl(ev), " -l ", " -r ", " -d ", "-nfl", "-nfr", "-nfd")
		},
	},
	{
		ID: "M-T1572", Name: "DNS Tunnelling Indicator",
		Description: "Unusually long DNS query — possible DNS tunnelling.",
		Severity: 4, MITRE: "T1572", Category: "Command and Control",
		Match: func(ev store.Event) bool {
			return ev.EventType == "dns" && ev.DstIP != nil && len(*ev.DstIP) > 60
		},
	},
	{
		ID: "M-T1219", Name: "Remote Access Tool",
		Description: "Commercial remote access tool detected on macOS.",
		Severity: 3, MITRE: "T1219", Category: "Command and Control",
		Match: func(ev store.Event) bool {
			return containsAny(proc(ev)+cl(ev), "anydesk", "teamviewer", "rustdesk", "screenconnect", "logmein", "splashtop")
		},
	},
	{
		ID: "M-T1048", Name: "curl POST Exfiltration",
		Description: "curl sending data via POST on macOS — possible exfiltration.",
		Severity: 3, MITRE: "T1048", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "curl") &&
				containsAny(cl(ev), " -d ", " --data ", " -f ", "--upload-file", "-x post")
		},
	},
	{
		ID: "M-T1560", Name: "Archive of Sensitive Directory",
		Description: "tar or zip archiving /Users or sensitive paths.",
		Severity: 3, MITRE: "T1560.001", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && containsAny(proc(ev), "tar", "zip", "7z", "gzip") &&
				containsAny(cl(ev), "/users/", "documents", "desktop", "/etc/", ".sql", "backup")
		},
	},
	{
		ID: "M-T1090.003", Name: "Tor / Proxy Tool",
		Description: "Tor or proxychains detected on macOS.",
		Severity: 4, MITRE: "T1090.003", Category: "Command and Control",
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
		Severity: 5, MITRE: "T1071.001", Category: "Command and Control",
		Match: func(ev store.Event) bool {
			return (ev.EventType == "dns" || ev.EventType == "network") &&
				ev.DstIP != nil && domainHasCategory(*ev.DstIP, "malware", "botnet_cc")
		},
	},
	{
		ID: "DNS-CAT-002", Name: "Phishing Domain Contact",
		Description: "DNS query to a domain flagged as phishing.",
		Severity: 4, MITRE: "T1566.002", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			return ev.EventType == "dns" && ev.DstIP != nil && domainHasCategory(*ev.DstIP, "phishing")
		},
	},
	{
		ID: "DNS-CAT-003", Name: "Malicious Domain (Quad9 Block)",
		Description: "DNS query to a domain blocked by Quad9 threat intelligence.",
		Severity: 4, MITRE: "T1071.001", Category: "Command and Control",
		Match: func(ev store.Event) bool {
			return ev.EventType == "dns" && ev.DstIP != nil && domainHasCategory(*ev.DstIP, "malicious")
		},
	},
	{
		ID: "DNS-CAT-004", Name: "Spam Infrastructure Domain",
		Description: "DNS query to a spam-flagged domain — possible exfil relay.",
		Severity: 3, MITRE: "T1048", Category: "Exfiltration",
		Match: func(ev store.Event) bool {
			return ev.EventType == "dns" && ev.DstIP != nil && domainHasCategory(*ev.DstIP, "spam")
		},
	},
}

var dnsCatCache = make(map[string][]string)

func domainHasCategory(domain string, categories ...string) bool {
	domain = strings.ToLower(domain)
	cats, ok := dnsCatCache[domain]
	if !ok { return false }
	for _, want := range categories {
		for _, have := range cats {
			if have == want { return true }
		}
	}
	return false
}


// ── Detection Engine ─────────────────────────────────────────────────────────

type DetectionEngine struct {
	db     *store.DB
	mailer *notify.Mailer
	logger *slog.Logger
}

func NewDetectionEngine(db *store.DB, mailer *notify.Mailer, logger *slog.Logger) *DetectionEngine {
	return &DetectionEngine{db: db, mailer: mailer, logger: logger}
}

func (e *DetectionEngine) Run(ctx context.Context) {
	// Standard 2h catch-up for agent events
	e.evaluateSince(ctx, time.Now().Add(-2*time.Hour))
	// Extended 7-day catch-up for DevOps events (syncs can bring in old commits)
	e.evaluateDevOpsSince(ctx, time.Now().Add(-7*24*time.Hour))
	ticker := time.NewTicker(45 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.evaluateSince(ctx, time.Now().Add(-2*time.Minute))
		}
	}
}

func (e *DetectionEngine) evaluateDevOpsSince(ctx context.Context, since time.Time) {
	f := store.EventFilter{Since: since, Limit: 2000, OS: "devops"}
	events, _, err := e.db.QueryEvents(ctx, f)
	if err != nil || len(events) == 0 { return }
	e.logger.Info("detection: devops catch-up", "events", len(events))
	created := 0
	for _, ev := range events {
		for _, sig := range devopsSignatures {
			if !sig.Match(ev) { continue }
			day := ev.Time.UTC().Format("20060102")
			dedupKey := fmt.Sprintf("sig:%s:host:%s:d:%s", sig.ID, ev.Host, day)
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
	if created > 0 { e.logger.Info("detection: devops catch-up alerts created", "count", created) }
}

func (e *DetectionEngine) evaluateSince(ctx context.Context, since time.Time) {
	events, _, err := e.db.QueryEvents(ctx, store.EventFilter{Since: since, Limit: 5000})
	if err != nil {
		e.logger.Warn("detection: query failed", "err", err)
		return
	}
	if len(events) > 0 {
		e.logger.Info("detection: evaluating events", "count", len(events), "since", since.Format("15:04:05"))
	}


	states, _     := e.db.GetSignatureStates(ctx)
	ipIOCs, _     := e.db.GetAllIOCsOfType(ctx, "ip")
	domainIOCs, _ := e.db.GetAllIOCsOfType(ctx, "domain")
	hashIOCs, _   := e.db.GetAllIOCsOfType(ctx, "hash")

	// Refresh DNS blocklist cache
	domainCats, _ := e.db.GetAllIOCsOfType(ctx, "domain_category")
	for domain, ioc := range domainCats {
		if ioc.Tags != "" && ioc.Tags != "clean" {
			dnsCatCache[domain] = strings.Split(ioc.Tags, ",")
		}
	}

	// Check if Sigma detection is globally enabled
	sigmaGlobalEnabled := true
	if v, _ := e.db.GetSetting(ctx, "detection.sigma_enabled"); v == "false" {
		sigmaGlobalEnabled = false
	}

	// Load enabled Sigma rules — pre-index by category for performance
	// Avoids O(events * 1211 rules) — instead O(events * relevant_rules_for_os)
	allSigmaRules, _ := e.db.ListSigmaRules(ctx, true)
	if !sigmaGlobalEnabled { allSigmaRules = nil }
	sigmaByCategory := make(map[string][]store.SigmaRule)
	for _, r := range allSigmaRules {
		cat := strings.ToLower(r.Category)
		sigmaByCategory[cat] = append(sigmaByCategory[cat], r)
	}


	created := 0
	for _, ev := range events {

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
		if ev.ProcessName != nil && containsAny(strings.ToLower(*ev.ProcessName),
			"obsidianwatch", "obsidian-watch", "ow-agent") {
			continue
		}

		// Select OS-specific signatures
		var sigs []ThreatSig
		switch strings.ToLower(ev.OS) {
		case "windows":
			sigs = append(windowsSignatures, dnsCatSignatures...)
			// DC events (ad_object_access, ad_change, kerberos) always get DC sigs
			if ev.EventType == "ad_object_access" || ev.EventType == "ad_change" ||
				ev.EventType == "kerberos" {
				sigs = append(sigs, dcSignatures...)
			}
		case "macos", "darwin":
			sigs = append(macosSignatures, dnsCatSignatures...)
		case "devops":
			// DevOps events — only apply devops sigs, skip endpoint sigs entirely
			sigs = append(sigs, devopsSignatures...)
		case "network-probe":
			// Network probe events — only apply network sigs
			sigs = append(sigs, networkSignatures...)
		default:
			// linux or unknown
			sigs = append(linuxSignatures, dnsCatSignatures...)
		}

		// Cloud events get the extended cloud signature set regardless of OS
		if isCloudEvent(ev) {
			sigs = append(sigs, cloudSignaturesExtended...)
			sigs = append(sigs, cloudReconSignatures...)
			sigs = append(sigs, cloudNetworkSignatures...)
			sigs = append(sigs, cloudLateralSignatures...)
			sigs = append(sigs, cloudComputeAbuseSignatures...)
		}
		// Network events also get cloud network sigs (metadata endpoint access)
		if ev.EventType == "network" {
			sigs = append(sigs, cloudNetworkSignatures...)
		}
		// DevOps events (GitHub, GitLab) get DevOps signatures
		if isDevOpsEvent(ev) {
			sigs = append(sigs, devopsSignatures...)
		}
		// Signature matching
		for _, sig := range sigs {
			if state, ok := states[sig.ID]; ok && !state.Enabled {
				continue
			}
			sev := sig.Severity
			if state, ok := states[sig.ID]; ok && state.Severity != nil {
				sev = *state.Severity
			}
			if !sig.Match(ev) {
				continue
			}
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
			if id, inserted, err := e.db.CreateAlertDeduped(ctx, alert); err == nil && inserted {
				created++
				alert.CreatedAt = time.Now()
				if e.mailer.Enabled() && sev >= e.mailer.MinSeverity() {
					go func(a store.Alert, aid int64) {
						a.ID = aid
						e.mailer.SendAlert(a)
					}(alert, id)
				}
			}
		}

		// IOC matching
		if ioc := e.matchIOC(ev, ipIOCs, domainIOCs, hashIOCs); ioc != nil {
			hour := ev.Time.UTC().Format("2006010215")
			dedupKey := fmt.Sprintf("ioc:%s:%s:host:%s:h:%s", ioc.Source, ioc.Value, ev.Host, hour)
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
					go func(a store.Alert, aid int64) {
						a.ID = aid
						e.mailer.SendAlert(a)
					}(alert, id)
				}
			}
		}

		// Sigma rule matching — only evaluate rules relevant to this event type
		relevantSigma := sigmaRelevantRules(sigmaByCategory, ev)

		for _, rule := range relevantSigma {
			if !matchSigmaRule(rule, ev) {
				continue
			}

			hour := ev.Time.UTC().Format("2006010215")
			dedupKey := fmt.Sprintf("sig:sigma:%s:host:%s:h:%s", rule.ID, ev.Host, hour)
			mitre := rule.MITRE
			if mitre == "" { mitre = "Sigma" }
			alert := store.Alert{
				Title:       fmt.Sprintf("[Sigma] %s", rule.Title),
				Description: fmt.Sprintf("%s\n\nRule: %s | Level: %s | Category: %s\nMITRE: %s\nHost: %s | OS: %s | Process: %s | Command: %s",
					rule.Description, rule.Title, rule.Level, rule.Category,
					mitre, ev.Host, ev.OS, strOrDash(ev.ProcessName), strOrDash(ev.CommandLine)),
				Severity:      rule.Severity,
				AgentID:       ev.AgentID,
				Host:          ev.Host,
				EventType:     ev.EventType,
				EventID:       dedupKey,
				SourceEventID: ev.ID,
			}
			if id, inserted, err := e.db.CreateAlertDeduped(ctx, alert); err == nil && inserted {
				created++
				alert.CreatedAt = time.Now()
				if e.mailer.Enabled() && rule.Severity >= e.mailer.MinSeverity() {
					go func(a store.Alert, aid int64) {
						a.ID = aid
						e.mailer.SendAlert(a)
					}(alert, id)
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
				if seen[r.ID] { continue }
				// Skip rules that target a different OS
				ls := strings.ToLower(r.LogSource)
				if strings.Contains(ls, "product: windows") && evOS != "windows" { continue }
				if strings.Contains(ls, "product: linux") && evOS != "linux" { continue }
				if strings.Contains(ls, "product: macos") && evOS != "macos" && evOS != "darwin" { continue }
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
	if ev.Raw != nil { fields = append(fields, strings.ToLower(string(ev.Raw))) }
	return strings.ToLower(strings.Join(fields, " "))
}

// matchSigmaRule evaluates a Sigma rule detection block against an event.
// Handles the standard Sigma YAML structure:
//   detection:           <- outer container (indent 0)
//       selection:       <- selection name (indent 4)
//           Image: ...   <- field (indent 8)
//       condition: sel
func matchSigmaRule(rule store.SigmaRule, ev store.Event) bool {
	if rule.Detection == "" { return false }
	fields := []string{
		ev.EventType, ev.OS, ev.Host, ev.Source,
		strOrDash(ev.ProcessName), strOrDash(ev.CommandLine), strOrDash(ev.ImagePath),
		strOrDash(ev.UserName), strOrDash(ev.FilePath), strOrDash(ev.FileHash),
		strOrDash(ev.DstIP), strOrDash(ev.SrcIP), strOrDash(ev.RegKey),
	}
	if ev.Raw != nil { fields = append(fields, strings.ToLower(string(ev.Raw))) }
	eventText := strings.ToLower(strings.Join(fields, " "))

	type entry struct{ field string; patterns []string }
	selections := make(map[string][]entry)
	var condition, currentSel, currentField string
	detectionIndent := -1
	selectionIndent := -1

	for _, line := range strings.Split(rule.Detection, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") { continue }
		indent := len(line) - len(strings.TrimLeft(line, " \t"))

		// Find "detection:" container
		if indent == 0 && (trimmed == "detection:" || strings.HasPrefix(trimmed, "detection:")) {
			detectionIndent = 0
			continue
		}

		// Other top-level keys (logsource, title, etc.) — skip
		if indent == 0 { continue }

		// At detection+N indent: selection names or condition
		if detectionIndent >= 0 && selectionIndent < 0 {
			// First indented key under detection — this is the selection indent level
			if strings.Contains(trimmed, ":") {
				k, v, _ := strings.Cut(trimmed, ":")
				k = strings.TrimSpace(k); v = strings.TrimSpace(v)
				if k == "condition" { condition = v; continue }
				if v == "" && !strings.Contains(k, "|") {
					// New named selection
					selectionIndent = indent
					currentSel = k
					currentField = ""
					continue
				}
			}
			continue
		}

		// At selection indent level: new selection names or condition
		if indent == selectionIndent {
			if strings.Contains(trimmed, ":") {
				k, v, _ := strings.Cut(trimmed, ":")
				k = strings.TrimSpace(k); v = strings.TrimSpace(v)
				if k == "condition" { condition = v; continue }
				if v == "" && !strings.Contains(k, "|") {
					currentSel = k
					currentField = ""
					continue
				}
			}
			continue
		}

		// Deeper indent: field definitions and values
		if currentSel == "" { continue }

		if strings.HasPrefix(trimmed, "- ") {
			val := strings.ToLower(strings.Trim(strings.TrimPrefix(trimmed, "- "), `'"`))
			if val == "" || val == "null" { continue }
			if currentField == "" { currentField = "*" }
			sels := selections[currentSel]
			added := false
			for i := len(sels)-1; i >= 0; i-- {
				if sels[i].field == currentField { sels[i].patterns = append(sels[i].patterns, val); selections[currentSel] = sels; added = true; break }
			}
			if !added { selections[currentSel] = append(selections[currentSel], entry{currentField, []string{val}}) }
		} else if strings.Contains(trimmed, ":") {
			k, v, _ := strings.Cut(trimmed, ":")
			k = strings.TrimSpace(k); v = strings.TrimSpace(v)
			if k == "condition" { condition = v; continue }
			if v == "" && !strings.Contains(k, "|") {
				// Sub-selection or nested key — treat as new field group
				currentField = k
				continue
			}
			currentField = k
			if idx := strings.Index(currentField, "|"); idx >= 0 { currentField = currentField[:idx] }
			if v != "" && v != "null" { selections[currentSel] = append(selections[currentSel], entry{currentField, []string{strings.ToLower(strings.Trim(v, `'"`))}})}
		}
	}

	if len(selections) == 0 { return false }
	selResults := make(map[string]bool)
	for name, entries := range selections {
		allMatch := len(entries) > 0
		for _, e := range entries {
			ft := eventText
			switch strings.ToLower(e.field) {
			case "commandline", "command_line": ft = strings.ToLower(strOrDash(ev.CommandLine))
			case "image", "imagepath": ft = strings.ToLower(strOrDash(ev.ImagePath))
			case "processname", "process_name": ft = strings.ToLower(strOrDash(ev.ProcessName))
			case "parentimage", "parentprocessname": ft = strings.ToLower(strOrDash(ev.ProcessName))
			case "username", "user": ft = strings.ToLower(strOrDash(ev.UserName))
			case "targetfilename", "filepath": ft = strings.ToLower(strOrDash(ev.FilePath))
			case "queryname", "destinationhostname": ft = strings.ToLower(strOrDash(ev.DstIP))
			case "regkey", "targetobject": ft = strings.ToLower(strOrDash(ev.RegKey))
			case "eventid":
				if ev.EventID != nil { ft = fmt.Sprintf("%d", *ev.EventID) } else { ft = "" }
			}
			matched := false
			for _, pat := range e.patterns {
				if strings.HasPrefix(pat, "*") && strings.HasSuffix(pat, "*") {
					if strings.Contains(ft, strings.Trim(pat, "*")) { matched = true; break }
				} else if strings.HasPrefix(pat, "*") {
					if strings.HasSuffix(ft, strings.TrimPrefix(pat, "*")) { matched = true; break }
				} else if strings.HasSuffix(pat, "*") {
					if strings.HasPrefix(ft, strings.TrimSuffix(pat, "*")) { matched = true; break }
				} else if strings.Contains(ft, pat) { matched = true; break }
			}
			if !matched { allMatch = false; break }
		}
		selResults[name] = allMatch
	}
	if condition == "" {
		for _, v := range selResults { if !v { return false } }
		return true
	}
	cond := strings.TrimSpace(strings.ToLower(condition))
	if strings.HasPrefix(cond, "1 of ") {
		prefix := strings.TrimSuffix(strings.TrimPrefix(cond, "1 of "), "*")
		for n, v := range selResults { if strings.HasPrefix(strings.ToLower(n), prefix) && v { return true } }
		return false
	}
	if strings.HasPrefix(cond, "all of ") {
		prefix := strings.TrimSuffix(strings.TrimPrefix(cond, "all of "), "*")
		for n, v := range selResults { if strings.HasPrefix(strings.ToLower(n), prefix) && !v { return false } }
		return true
	}
	// Simple condition: just a selection name
	return selResults[cond]
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

	// Cloud events — SrcIP against IP IOCs
	if isCloudEvent(ev) && ev.SrcIP != nil && *ev.SrcIP != "" {
		if ioc, ok := ipIOCs[strings.ToLower(*ev.SrcIP)]; ok {
			return &ioc
		}
	}

	// Hash match — file events
	if ev.EventType == "file" && ev.FileHash != nil {
		for _, part := range strings.Split(*ev.FileHash, ",") {
			hash := strings.ToLower(strings.TrimSpace(part))
			if idx := strings.Index(hash, "="); idx >= 0 {
				hash = hash[idx+1:]
			}
			if hash == "" { continue }
			if ioc, ok := hashIOCs[hash]; ok {
				return &ioc
			}
		}
	}
	return nil
}

func strOrDash(s *string) string {
	if s == nil || *s == "" { return "—" }
	return *s
}

func titleCase(s string) string {
	if s == "" { return "" }
	return strings.ToUpper(s[:1]) + s[1:]
}
