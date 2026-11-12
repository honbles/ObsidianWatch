package api

// Replay corpus of ordinary, benign endpoint activity: what a workstation or
// server does all day. No rule may fire on it. When a rule change makes one of
// these alert, the change reintroduces a false positive; fix the rule, or, if
// the activity really is suspicious, remove it from the corpus with a reason.
//
// The test also prints a per-rule-set noise report (go test -v -run TestBenignCorpus).

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"obsidianwatch/management/internal/store"
)

type benignEvent struct {
	Note string
	Ev   store.Event
}

func benignEvents() []benignEvent {
	p := fxProc
	return []benignEvent{
		// ── Windows background and apps ──
		{"svchost scheduler", p("svchost.exe", `C:\Windows\System32\svchost.exe -k netsvcs -p -s Schedule`)},
		{"svchost wuauserv", p("svchost.exe", `C:\Windows\system32\svchost.exe -k netsvcs -p -s wuauserv`)},
		{"chrome renderer", p("chrome.exe", `"C:\Program Files\Google\Chrome\Application\chrome.exe" --type=renderer --lang=en-US`)},
		{"edge", p("msedge.exe", `"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=utility`)},
		{"teams", p("ms-teams.exe", `"C:\Program Files\WindowsApps\MSTeams_24\ms-teams.exe" --system-initiated`)},
		{"onedrive", p("OneDrive.exe", `C:\Users\a\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background`)},
		{"outlook", p("OUTLOOK.EXE", `"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE" /recycle`)},
		{"word", p("WINWORD.EXE", `"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n "C:\Users\a\doc.docx"`)},
		{"wmi provider host", p("WmiPrvSE.exe", `C:\Windows\system32\wbem\wmiprvse.exe -secured -Embedding`)},
		{"defender", p("MsMpEng.exe", `"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2\MsMpEng.exe"`)},
		{"defender scan", p("MpCmdRun.exe", `"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2\MpCmdRun.exe" -Scan -ScanType 1`)},
		{"windows update", p("TiWorker.exe", `C:\Windows\winsxs\amd64_microsoft-windows-servicingstack\TiWorker.exe -Embedding`)},
		{"search indexer", p("SearchProtocolHost.exe", `"C:\Windows\system32\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe1_`)},
		{"explorer", p("explorer.exe", `C:\Windows\Explorer.EXE`)},
		{"conhost", p("conhost.exe", `\??\C:\Windows\system32\conhost.exe 0x4`)},
		{"task host", p("taskhostw.exe", `taskhostw.exe`)},
		{"runtime broker", p("RuntimeBroker.exe", `C:\Windows\System32\RuntimeBroker.exe -Embedding`)},
		{"backup script", p("powershell.exe", `powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\scripts\backup.ps1`)},
		{"ps get-childitem", p("powershell.exe", `powershell.exe -NoLogo -Command Get-ChildItem C:\logs | Sort-Object LastWriteTime`)},
		{"cmd dir", p("cmd.exe", `C:\Windows\system32\cmd.exe /c dir C:\temp`)},
		{"msi install", p("msiexec.exe", `C:\Windows\System32\msiexec.exe /i C:\Users\a\Downloads\app.msi /qn`)},
		{"git", p("git.exe", `"C:\Program Files\Git\cmd\git.exe" pull origin main`)},
		{"node build", p("node.exe", `"C:\Program Files\nodejs\node.exe" C:\proj\node_modules\.bin\vite build`)},
		{"python script", p("python.exe", `python.exe C:\proj\manage.py runserver`)},
		{"vscode", p("Code.exe", `"C:\Users\a\AppData\Local\Programs\Microsoft VS Code\Code.exe" --type=renderer`)},
		{"docker desktop", p("Docker Desktop.exe", `"C:\Program Files\Docker\Docker\Docker Desktop.exe"`)},
		{"zoom", p("Zoom.exe", `"C:\Users\a\AppData\Roaming\Zoom\bin\Zoom.exe" --url=zoommtg://zoom.us`)},
		{"7zip", p("7z.exe", `"C:\Program Files\7-Zip\7z.exe" a C:\backup\docs.7z C:\Users\a\Documents`)},
		{"agent itself", p("obsidianwatch-agent.exe", `"C:\ProgramData\ObsidianWatch\obsidianwatch-agent.exe"`)},
		// registry / file / eventlog
		{"teams run key", fxRegData(`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\com.squirrel.Teams.Teams`, `C:\Users\a\AppData\Local\Microsoft\Teams\Update.exe --processStart "Teams.exe"`)},
		{"onedrive run key", fxRegData(`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive`, `"C:\Users\a\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background`)},
		{"slack run key", fxRegData(`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\slack`, `C:\Users\a\AppData\Local\slack\slack.exe --process-start-args --startup`)},
		{"defender run key", fxRegData(`HKLM\Software\Microsoft\Windows\CurrentVersion\Run\SecurityHealth`, `%windir%\system32\SecurityHealthSystray.exe`)},
		{"explorer advanced", fxReg(`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`)},
		{"user doc file", fxFile(`C:\Users\a\Documents\report.docx`)},
		{"temp file", fxFile(`C:\Users\a\AppData\Local\Temp\tmp1234.tmp`)},
		{"logon interactive", fxWinEvent(4624, `{"event_data":{"LogonType":"2"}}`)},
		{"service installed by app", fxWinEvent(7045, `{"event_data":{"ImagePath":"\"C:\\Program Files\\Vendor\\svc.exe\" -service"}}`)},
		{"service running", fxWinEvent(7036, `{"event_data":{"param1":"Windows Update","param2":"running"}}`)},
		{"event log service stop at shutdown", fxWinEvent(7036, `{"event_data":{"param1":"Windows Event Log","param2":"stopped"}}`)},
		{"lsass logon process registered", store.Event{EventType: "logon", Raw: []byte(`{"event_data":{"LogonProcessName":"C:\\Windows\\System32\\lsass.exe"}}`)}},

		// ── Linux server and desktop ──
		{"sshd", p("sshd", `sshd: deploy [priv]`)},
		{"sshd daemon", p("sshd", `/usr/sbin/sshd -D`)},
		{"cron", p("cron", `/usr/sbin/cron -f`)},
		{"cron job", p("sh", `/bin/sh -c /usr/local/bin/backup.sh`)},
		{"systemd user", p("systemd", `/lib/systemd/systemd --user`)},
		{"journald", p("systemd-journald", `/lib/systemd/systemd-journald`)},
		{"apt update", p("apt-get", `apt-get update`)},
		{"apt install", p("apt-get", `apt-get install -y htop curl`)},
		{"dpkg", p("dpkg", `/usr/bin/dpkg --status-fd 20 --configure --pending`)},
		{"unattended upgrades", p("python3", `/usr/bin/python3 /usr/bin/unattended-upgrade`)},
		{"nginx worker", p("nginx", `nginx: worker process`)},
		{"postgres", p("postgres", `postgres: checkpointer`)},
		{"docker run", p("docker", `docker run --rm hello-world`)},
		{"docker compose", p("docker", `docker compose up -d`)},
		{"git pull", p("git", `git pull origin main`)},
		{"npm build", p("npm", `npm run build`)},
		{"python manage", p("python3", `python3 manage.py migrate`)},
		{"curl health", p("curl", `curl -fsS https://api.example.com/health`)},
		{"curl api post", p("curl", `curl -X POST -H "Content-Type: application/json" https://api.example.com/v1/events`)},
		{"wget package", p("wget", `wget -q https://example.com/release.tar.gz`)},
		{"sudo apt", p("sudo", `sudo apt install -y htop`)},
		{"sudo systemctl", p("sudo", `sudo systemctl restart nginx`)},
		{"ls", p("ls", `ls -la /home/deploy`)},
		{"ls tmp", p("ls", `ls /tmp/`)},
		{"rm tmp", p("rm", `rm -rf /tmp/build-cache`)},
		{"cat log", p("cat", `cat /var/log/syslog`)},
		{"tail log", p("tail", `tail -f /var/log/nginx/access.log`)},
		{"journalctl", p("journalctl", `journalctl -u nginx --since today`)},
		{"crontab list", p("crontab", `crontab -l`)},
		{"ps", p("ps", `ps aux`)},
		{"top", p("top", `top -b -n 1`)},
		{"df", p("df", `df -h`)},
		{"tar backup", p("tar", `tar czf /var/backups/site.tgz /var/www/html`)},
		{"rsync", p("rsync", `rsync -az /var/www/ backup:/srv/www/`)},
		{"ssh client", p("ssh", `ssh deploy@10.0.0.5 uptime`)},
		{"redis jemalloc", p("sh", `LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libjemalloc.so.2 redis-server /etc/redis/redis.conf`)},
		{"vim", p("vim", `vim /etc/nginx/nginx.conf`)},
		{"usermod shell", p("usermod", `usermod -s /bin/zsh deploy`)},
		{"systemctl status", p("systemctl", `systemctl status sshd`)},
		{"ghost cms", p("ghost-cms", `ghost-cms start`)},
		{"normal file edit", fxFile(`/var/www/html/index.html`)},
		{"cron-style sh", p("sh", `/bin/sh -c cd /srv/app && ./run.sh >/dev/null 2>&1`)},
		{"sh -c health curl", p("bash", `bash -c "curl -fsS https://example.com/health >/dev/null"`)},
		{"curl post to api reading tmp", p("curl", `curl -fsS -X POST https://api.example.com/v1/x --data-binary @/tmp/payload.json`)},
		{"wget to home", p("wget", `wget https://example.com/file.tar.gz -O /home/deploy/file.tar.gz`)},
		{"dll in appdata", fxFile(`C:\Users\a\AppData\Local\Microsoft\Teams\current\app.dll`)},
		{"dll in programdata", fxFile(`C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\x.dll`)},
		{"app log write", fxFile(`/var/log/myapp/app.log`)},
		{"ssh login ok", fxLogonMsg(`Accepted publickey for deploy from 10.0.0.5 port 51234 ssh2`)},

		// ── macOS ──
		{"mac xpcproxy", p("xpcproxy", `/usr/libexec/xpcproxy com.apple.Safari`)},
		{"mac slack", p("Slack", `/Applications/Slack.app/Contents/MacOS/Slack`)},
		{"mac chrome", p("Google Chrome", `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`)},
		{"mac brew", p("brew", `brew update`)},
		{"mac zsh", p("zsh", `/bin/zsh -il`)},
		{"mac softwareupdate", p("softwareupdate", `/usr/sbin/softwareupdate -l`)},
		{"mac curl", p("curl", `/usr/bin/curl -sS https://api.example.com/health`)},
		{"mac ls tmp", p("ls", `/bin/ls /private/tmp/`)},
		{"mac defaults", p("defaults", `/usr/bin/defaults read com.apple.dock`)},
		{"mac xcode", p("xcodebuild", `/usr/bin/xcodebuild -scheme App build`)},
	}
}

// corpusSets are the endpoint rule sets the corpus is replayed against.
var corpusSets = []string{"linux", "windows", "windowsTamper", "macos", "endpoint", "winAccount", "linAccount", "remoteSession", "usb", "software", "winUSB", "dc", "dns"}

// knownBenignHits documents rules that fire on a corpus event by design
// (activity that is benign here but legitimately worth a low-severity alert).
// The value is the reason. Keep this list short.
var knownBenignHits = map[string]string{
	"L-T1048|curl post to api reading tmp": "uploading a file with curl is recorded (Medium) — worth a look when unexpected",
	"M-T1048|curl post to api reading tmp": "uploading a file with curl is recorded (Medium) — worth a look when unexpected",
	"L-ACCT-001|usermod shell":             "account-change audit rule (Low): changing a login shell is worth a record",
	"M-T1560|7zip":                         "corpus replays every OS rule on every event; the macOS rule is not applied to Windows hosts",
	"W-T1547.001b|teams run key":           "Low-severity audit: Run key outside Program Files is recorded, not escalated",
	"W-T1547.001b|onedrive run key":        "Low-severity audit: Run key outside Program Files is recorded, not escalated",
	"W-T1547.001b|slack run key":           "Low-severity audit: Run key outside Program Files is recorded, not escalated",
}

func TestBenignCorpusProducesNoAlerts(t *testing.T) {
	sets := allSignatureSets()
	events := benignEvents()
	hits := map[string][]string{} // rule id -> notes
	perSet := map[string]int{}
	for _, name := range corpusSets {
		for _, sig := range sets[name] {
			for _, be := range events {
				if retiredSigIDs[sig.ID] || !sig.Match(be.Ev) {
					continue
				}
				if _, ok := knownBenignHits[sig.ID+"|"+be.Note]; ok {
					continue
				}
				hits[sig.ID] = append(hits[sig.ID], be.Note)
				perSet[name]++
			}
		}
	}
	var ids []string
	for id := range hits {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		t.Errorf("false positive: %s fired on benign activity: %s", id, strings.Join(hits[id], "; "))
	}

	// noise report
	var lines []string
	for _, name := range corpusSets {
		lines = append(lines, fmt.Sprintf("%s: %d rules, %d false hits", name, len(sets[name]), perSet[name]))
	}
	t.Logf("benign corpus: %d events replayed\n%s", len(events), strings.Join(lines, "\n"))
}
