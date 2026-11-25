package api

// linux_lineage_sigs.go - Linux rules that need process lineage
// (store.Event.Ancestors, filled by lineage.go) or the kernel sensor's fields
// (argv copied in the kernel, exe, sensor "ebpf", connects with their pid),
// plus high-signal command patterns the original set did not cover.

import (
	"encoding/json"
	"regexp"
	"strings"

	"obsidianwatch/management/internal/store"
)

var linuxShells = []string{"bash", "sh", "dash", "zsh", "ksh", "ash", "busybox", "fish"}

// Web servers and their workers: a shell under one of these is the classic
// web-shell or exploited-application signal.
var linuxWebServers = []string{"nginx", "apache2", "httpd", "lighttpd", "caddy", "php-fpm", "php-cgi", "uwsgi", "openresty"}

// Database servers never start shells in normal operation.
var linuxDatabases = []string{"mysqld", "mariadbd", "postgres", "postmaster", "redis-server", "mongod", "memcached", "clickhouse-server"}

var (
	b64ToShellRe = regexp.MustCompile(`(base64\s+(-d|--decode|-D)|openssl\s+(enc\s+)?(-d\s+)?-?base64\s+-d|xxd\s+-r).*\|\s*(sudo\s+)?(ba|da|z|k)?sh\b`)
	fdExecRe     = regexp.MustCompile(`^/(proc/self|proc/\d+|dev)/fd/\d+$`)
	minerPoolRe  = regexp.MustCompile(`stratum\+(tcp|ssl|tls)://|--donate-level|--coin[= ]|-a\s+(rx/0|cryptonight)|--cpu-priority`)
)

type rawProc struct {
	Exe    string   `json:"exe"`
	Argv   []string `json:"argv"`
	Sensor string   `json:"sensor"`
	Action string   `json:"action"`
}

func rawProcOf(ev store.Event) rawProc {
	var r rawProc
	if len(ev.Raw) > 0 {
		_ = json.Unmarshal(ev.Raw, &r)
	}
	return r
}

// procStart is a Linux process start (exec) event.
func procStart(ev store.Event) bool {
	return ev.EventType == "process" && isProcessStart(ev)
}

// imagePath is the executable path: raw exe, then ImagePath.
func imagePath(ev store.Event) string {
	if r := rawProcOf(ev); r.Exe != "" {
		return r.Exe
	}
	return deref(ev.ImagePath)
}

var linuxLineageSignatures = []ThreatSig{
	{
		ID: "L-T1505.003", Name: "Shell Started by a Web Server",
		Description: "A shell was started by a web server or one of its workers (directly or one level down). This is how web shells and exploited web applications run commands.",
		Severity:    4, MITRE: "T1505.003", Category: "Persistence",
		Match: func(ev store.Event) bool {
			return procStart(ev) && exeIn(ev, linuxShells...) && ancestorIn(ev, 2, linuxWebServers...)
		},
	},
	{
		ID: "L-T1190.db", Name: "Shell Started by a Database Server",
		Description: "A database server started a shell. Database servers do not do this in normal operation; it follows exploits such as Redis module loading, PostgreSQL COPY ... PROGRAM or MySQL UDFs.",
		Severity:    5, MITRE: "T1190", Category: "Initial Access",
		Match: func(ev store.Event) bool {
			return procStart(ev) && exeIn(ev, linuxShells...) && ancestorIn(ev, 2, linuxDatabases...)
		},
	},
	{
		ID: "L-T1105.exec", Name: "Downloaded File Executed from a Staging Directory",
		Description: "A program in /tmp, /var/tmp or /dev/shm was run by a shell whose command line downloads from a URL: the download-and-run step of a dropper.",
		Severity:    5, MITRE: "T1105", Category: "Execution",
		Match: func(ev store.Event) bool {
			if !procStart(ev) || len(ev.Ancestors) == 0 {
				return false
			}
			p := strings.ToLower(imagePath(ev))
			if !strings.HasPrefix(p, "/tmp/") && !strings.HasPrefix(p, "/var/tmp/") && !strings.HasPrefix(p, "/dev/shm/") {
				return false
			}
			parent := strings.ToLower(ev.Ancestors[0].CommandLine)
			return strings.Contains(parent, "://") && containsAny(parent, "curl", "wget", "fetch ", "busybox wget")
		},
	},
	{
		ID: "L-T1059.004.net", Name: "Shell Connecting Out to the Internet",
		Description: "A shell process itself opened an outbound TCP connection to a public address. Shells do not do this except through /dev/tcp redirection, the usual reverse shell.",
		Severity:    4, MITRE: "T1059.004", Category: "Execution",
		Match: func(ev store.Event) bool {
			if ev.EventType != "network" || ev.DstIP == nil || !isExternal(*ev.DstIP) {
				return false
			}
			return procIn(ev, linuxShells...)
		},
	},
	{
		ID: "L-T1620", Name: "Program Run from Memory (memfd or file descriptor)",
		Description: "A program was executed from an anonymous memory file or a file descriptor (fexecve), leaving nothing on disk. Used by fileless loaders.",
		Severity:    5, MITRE: "T1620", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			if !procStart(ev) {
				return false
			}
			p := imagePath(ev)
			return strings.HasPrefix(p, "/memfd:") || fdExecRe.MatchString(p)
		},
	},
	{
		ID: "L-T1070.004", Name: "Program Run from a Deleted File",
		Description: "The program's file was deleted while it started, so only the running copy remains. Malware does this to remove its trace from disk.",
		Severity:    4, MITRE: "T1070.004", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return procStart(ev) && strings.HasSuffix(imagePath(ev), " (deleted)") && !strings.HasPrefix(imagePath(ev), "/memfd:")
		},
	},
	{
		ID: "L-T1036.004", Name: "Process Disguised as a Kernel Thread",
		Description: "A program started with a name like [kworker/0:1]. Kernel threads are never executed from a file, so a bracketed name on an exec is a disguise.",
		Severity:    5, MITRE: "T1036.004", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			if !procStart(ev) {
				return false
			}
			a := argv(ev)
			if len(a) == 0 {
				return false
			}
			a0 := strings.TrimSpace(a[0])
			return len(a0) > 2 && a0[0] == '[' && a0[len(a0)-1] == ']' && imagePath(ev) != ""
		},
	},
	{
		ID: "L-T1140", Name: "Decoded Payload Piped to a Shell",
		Description: "Base64 or hex content decoded and piped straight into a shell, which hides the real command from casual review.",
		Severity:    4, MITRE: "T1140", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			return ev.EventType == "process" && b64ToShellRe.MatchString(cl(ev))
		},
	},
	{
		ID: "L-T1562.001", Name: "Security or Audit Tooling Disabled",
		Description: "SELinux, AppArmor, auditd or an endpoint agent was turned off or its rules were cleared.",
		Severity:    4, MITRE: "T1562.001", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			if ev.EventType != "process" {
				return false
			}
			c := cl(ev)
			if containsAny(c, "setenforce 0", "setenforce permissive", "auditctl -d", "auditctl -e 0", "aa-teardown", "apparmor_parser -r -k") {
				return true
			}
			stop := containsAny(c, "systemctl stop", "systemctl disable", "systemctl mask", "service ", "pkill", "killall", "kill -9")
			return stop && containsAny(c, "auditd", "apparmor", "falcon-sensor", "wazuh-agent", "osqueryd", "obsidianwatch", "sysdig", "elastic-agent", "sentinelone", "cbagentd")
		},
	},
	{
		ID: "L-T1562.004", Name: "Host Firewall Rules Flushed",
		Description: "All iptables or nftables rules were flushed or the firewall was disabled. Administrators do this, but so does malware opening the host up.",
		Severity:    2, MITRE: "T1562.004", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			if ev.EventType != "process" {
				return false
			}
			c := cl(ev)
			return (exeIn(ev, "iptables", "ip6tables", "iptables-nft", "iptables-legacy") && containsAny(c, " -f", " --flush")) ||
				(exeIn(ev, "nft") && strings.Contains(c, "flush ruleset")) ||
				(exeIn(ev, "ufw") && strings.Contains(c, "disable"))
		},
	},
	{
		ID: "L-T1496", Name: "Cryptocurrency Miner",
		Description: "A known miner was started, or a program was pointed at a mining pool (stratum URL or miner-only options).",
		Severity:    5, MITRE: "T1496", Category: "Impact",
		Match: func(ev store.Event) bool {
			if ev.EventType != "process" {
				return false
			}
			return exeIn(ev, "xmrig", "xmr-stak", "minerd", "cpuminer", "nbminer", "t-rex", "lolminer", "kdevtmpfsi", "kinsing") ||
				minerPoolRe.MatchString(cl(ev))
		},
	},
	{
		ID: "L-T1564.001", Name: "Hidden Program Run from a Temporary Directory",
		Description: "A program whose file or directory name starts with a dot was run from /tmp, /var/tmp or /dev/shm, a common way to hide a dropped tool.",
		Severity:    4, MITRE: "T1564.001", Category: "Defence Evasion",
		Match: func(ev store.Event) bool {
			if !procStart(ev) {
				return false
			}
			p := imagePath(ev)
			for _, dir := range []string{"/tmp/", "/var/tmp/", "/dev/shm/"} {
				if strings.HasPrefix(p, dir) && strings.Contains(p[len(dir)-1:], "/.") {
					return true
				}
			}
			return false
		},
	},
	{
		ID: "L-T1098.004", Name: "SSH Authorized Keys Changed from the Command Line",
		Description: "A key was appended to or copied over an authorized_keys file by a command, which grants SSH access to whoever holds the key.",
		Severity:    3, MITRE: "T1098.004", Category: "Persistence",
		Match: func(ev store.Event) bool {
			if ev.EventType != "process" || exeIn(ev, "ssh-copy-id") {
				return false
			}
			c := cl(ev)
			return strings.Contains(c, "authorized_keys") && containsAny(c, ">>", "> ", "tee ", "cp ", "mv ", "cat ")
		},
	},
	{
		ID: "L-T1548.003", Name: "Sudoers Changed Without visudo",
		Description: "A command wrote to /etc/sudoers or /etc/sudoers.d directly, the usual way to grant passwordless root after a compromise.",
		Severity:    4, MITRE: "T1548.003", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			if ev.EventType != "process" || exeIn(ev, "visudo") {
				return false
			}
			c := cl(ev)
			return strings.Contains(c, "/etc/sudoers") && containsAny(c, ">>", "> /etc/sudoers", "tee ", "sed -i", "cp ", "mv ", "nopasswd")
		},
	},
	{
		ID: "L-T1055.008", Name: "Debugger Attached to a Running Process",
		Description: "gdb attached to another process, or a process read another's memory through /proc/<pid>/mem: used to dump credentials from sshd or other services.",
		Severity:    3, MITRE: "T1055.008", Category: "Credential Access",
		Match: func(ev store.Event) bool {
			if ev.EventType != "process" {
				return false
			}
			c := cl(ev)
			return (exeIn(ev, "gdb", "gcore") && containsAny(c, " -p ", " --pid", " attach ", "gcore ")) ||
				(strings.Contains(c, "/proc/") && strings.Contains(c, "/mem") && containsAny(c, "dd ", "cat ", "python"))
		},
	},
	{
		ID: "L-T1068.pkexec", Name: "pkexec Started with No Arguments (PwnKit)",
		Description: "pkexec was executed with an empty argument list, the trigger for CVE-2021-4034. Seen only by the kernel sensor, which reads the real argv.",
		Severity:    5, MITRE: "T1068", Category: "Privilege Escalation",
		Match: func(ev store.Event) bool {
			if !procStart(ev) || !exeIn(ev, "pkexec") {
				return false
			}
			r := rawProcOf(ev)
			return r.Sensor == "ebpf" && len(r.Argv) == 0
		},
	},
}
