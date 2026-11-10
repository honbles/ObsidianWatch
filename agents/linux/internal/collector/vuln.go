//go:build linux

package collector

// vuln.go — Enterprise vulnerability scanner (Linux)
//
// What it collects:
//   1. Full TCP port scan 1-65535 (200 concurrent, 500ms timeout)
//   2. Service banner grab + version extraction per open port
//   3. Installed packages via dpkg / rpm / apk
//   4. Running services via systemctl / /proc
//   5. Kernel version, OS release
//   6. SUID binaries, world-writable dirs
//   7. Listening UDP ports
//
// All findings sent to management as vulnerability.scan event.
// Management backend runs AI analysis to produce CVE matches + remediation.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"obsidianwatch/linux-agent/pkg/schema"
)

// ── Port scanning ─────────────────────────────────────────────────────────────

type PortResult struct {
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"`
	State       string `json:"state"`
	Service     string `json:"service,omitempty"`
	Version     string `json:"version,omitempty"` // extracted from banner
	Banner      string `json:"banner,omitempty"`
	Product     string `json:"product,omitempty"` // e.g. "OpenSSH", "nginx"
	RiskLabel   string `json:"risk_label,omitempty"`
	RiskDetail  string `json:"risk_detail,omitempty"`
	Severity    int    `json:"severity"` // 1=info 2=low 3=medium 4=high 5=critical
}

// ── Installed software ────────────────────────────────────────────────────────

type InstalledPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Manager string `json:"manager"` // dpkg / rpm / apk
}

// ── System info ───────────────────────────────────────────────────────────────

type SystemInfo struct {
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	KernelVersion string `json:"kernel_version"`
	OSRelease     string `json:"os_release"`
	Arch          string `json:"arch"`
}

// ── Running services ──────────────────────────────────────────────────────────

type RunningService struct {
	Name    string `json:"name"`
	State   string `json:"state"`
	PID     string `json:"pid,omitempty"`
}

// ── Findings ──────────────────────────────────────────────────────────────────

type SecurityFinding struct {
	Category string `json:"category"`
	Severity int    `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Fix      string `json:"fix,omitempty"`
}

// ── Full scan result ──────────────────────────────────────────────────────────

type VulnScanResult struct {
	ScannedAt        time.Time          `json:"scanned_at"`
	Host             string             `json:"host"`
	OS               string             `json:"os"`
	System           SystemInfo         `json:"system"`
	OpenPorts        []PortResult       `json:"open_ports"`
	UDPPorts         []PortResult       `json:"udp_ports,omitempty"`
	Packages         []InstalledPackage `json:"packages,omitempty"`
	Services         []RunningService   `json:"services,omitempty"`
	Findings         []SecurityFinding  `json:"findings,omitempty"`
	Posture          []PostureCheck     `json:"posture,omitempty"`
	TotalOpen        int                `json:"total_open"`
	CriticalCount    int                `json:"critical_count"`
	HighCount        int                `json:"high_count"`
	MediumCount      int                `json:"medium_count"`
	ScanDurationSecs float64            `json:"scan_duration_secs"`
}

// ── Config & constructor ──────────────────────────────────────────────────────

type VulnScannerConfig struct {
	Enabled      bool
	ScanInterval time.Duration
	Timeout      time.Duration
	Concurrency  int
}

type VulnScanner struct {
	cfg     VulnScannerConfig
	agentID string
	host    string
	os      string
	out     chan<- schema.Event
	logger  *slog.Logger
}

func NewVulnScanner(cfg VulnScannerConfig, agentID, host, osStr string,
	out chan<- schema.Event, logger *slog.Logger) *VulnScanner {
	if cfg.ScanInterval == 0 { cfg.ScanInterval = 5 * 24 * time.Hour }
	if cfg.Timeout == 0      { cfg.Timeout = 500 * time.Millisecond }
	if cfg.Concurrency == 0  { cfg.Concurrency = 200 }
	return &VulnScanner{cfg: cfg, agentID: agentID, host: host, os: osStr, out: out, logger: logger}
}

func (v *VulnScanner) Run(ctx context.Context) {
	if !v.cfg.Enabled { return }
	v.logger.Info("vuln: scanner ready — first scan in 30s")
	select { case <-ctx.Done(): return; case <-time.After(30 * time.Second): }
	v.scan(ctx)
	ticker := time.NewTicker(v.cfg.ScanInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done(): return
		case <-ticker.C: v.scan(ctx)
		}
	}
}

// ── Main scan ─────────────────────────────────────────────────────────────────

func (v *VulnScanner) scan(ctx context.Context) {
	v.logger.Info("vuln: starting full host scan")
	start := time.Now()

	result := VulnScanResult{
		ScannedAt: time.Now().UTC(),
		Host:      v.host,
		OS:        v.os,
	}

	// 1. System info
	result.System = collectSystemInfo()

	// 2. Full TCP port scan
	v.logger.Info("vuln: scanning all 65535 TCP ports")
	result.OpenPorts = v.scanTCP(ctx)

	// 3. Common UDP ports
	result.UDPPorts = v.scanUDP(ctx)

	// 4. Installed packages (cap at 500 to keep event size manageable)
	v.logger.Info("vuln: collecting installed packages")
	pkgs := collectPackages()
	if len(pkgs) > 500 {
		pkgs = pkgs[:500]
	}
	result.Packages = pkgs

	// 5. Running services
	result.Services = collectServices()

	// 6. Security findings (SUID, world-writable, etc.)
	result.Findings = collectSecurityFindings()
	result.Posture = collectPosture()

	// Totals
	result.TotalOpen   = len(result.OpenPorts)
	result.ScanDurationSecs = time.Since(start).Seconds()
	for _, p := range result.OpenPorts {
		switch {
		case p.Severity >= 5: result.CriticalCount++
		case p.Severity >= 4: result.HighCount++
		case p.Severity >= 3: result.MediumCount++
		}
	}
	for _, f := range result.Findings {
		switch {
		case f.Severity >= 5: result.CriticalCount++
		case f.Severity >= 4: result.HighCount++
		case f.Severity >= 3: result.MediumCount++
		}
	}

	sev := 1
	if result.CriticalCount > 0   { sev = 5 } else
	if result.HighCount > 0        { sev = 4 } else
	if result.MediumCount > 0      { sev = 3 } else
	if result.TotalOpen > 0        { sev = 2 }

	v.logger.Info("vuln: scan complete",
		"tcp_open", result.TotalOpen,
		"critical", result.CriticalCount,
		"high", result.HighCount,
		"packages", len(result.Packages),
		"findings", len(result.Findings),
		"duration_s", fmt.Sprintf("%.1f", result.ScanDurationSecs),
	)

	raw, _ := json.Marshal(result)
	ev := schema.Event{
		ID:        fmt.Sprintf("vuln:%s:%d", v.agentID, time.Now().Unix()),
		Time:      time.Now().UTC(),
		AgentID:   v.agentID,
		Host:      v.host,
		OS:        v.os,
		EventType: "vulnerability.scan",
		Severity:  schema.Severity(sev),
		Source:    "vuln-scanner",
		Raw:       raw,
	}
	// Blocking send — a vuln scan is a critical once-every-5-days event.
	// We must not silently drop it. Wait up to 30s for the channel to drain.
	select {
	case v.out <- ev:
		v.logger.Info("vuln: scan result queued for forwarding")
	case <-time.After(30 * time.Second):
		v.logger.Warn("vuln: output channel blocked for 30s, dropping scan result")
	case <-ctx.Done():
	}
}

// ── TCP port scan ─────────────────────────────────────────────────────────────

func (v *VulnScanner) scanTCP(ctx context.Context) []PortResult {
	sem := make(chan struct{}, v.cfg.Concurrency)
	mu  := sync.Mutex{}
	var results []PortResult
	var wg sync.WaitGroup

	for port := 1; port <= 65535; port++ {
		select { case <-ctx.Done(): goto done; default: }
		wg.Add(1); sem <- struct{}{}
		go func(p int) {
			defer wg.Done(); defer func() { <-sem }()
			if r := v.probeTCP(p); r != nil {
				mu.Lock(); results = append(results, *r); mu.Unlock()
			}
		}(port)
	}
done:
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })
	return results
}

func (v *VulnScanner) probeTCP(port int) *PortResult {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), v.cfg.Timeout)
	if err != nil { return nil }
	defer conn.Close()

	r := &PortResult{Port: port, Protocol: "tcp", State: "open", Severity: 1}

	// Banner grab
	conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n > 0 {
		r.Banner = sanitizeBanner(buf[:n])
		r.Product, r.Version = extractProductVersion(r.Banner, port)
		r.Service = r.Product
		if r.Service == "" { r.Service = commonServiceName(port) }
	} else {
		r.Service = commonServiceName(port)
		// Send a probe for services that don't banner first
		conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
		conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
		conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		n2, _ := conn.Read(buf)
		if n2 > 0 {
			r.Banner = sanitizeBanner(buf[:n2])
			r.Product, r.Version = extractProductVersion(r.Banner, port)
			if r.Product != "" { r.Service = r.Product }
		}
	}

	// Risk assessment
	assessPortRisk(r)
	return r
}

// ── UDP scan (common ports only — UDP is stateless, harder to scan) ───────────

var udpPorts = []int{53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1194, 1900, 4500, 5353}

func (v *VulnScanner) scanUDP(ctx context.Context) []PortResult {
	var results []PortResult
	for _, port := range udpPorts {
		select { case <-ctx.Done(): return results; default: }
		conn, err := net.DialTimeout("udp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond)
		if err != nil { continue }
		conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		conn.Write([]byte("\x00"))
		conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		buf := make([]byte, 64)
		n, _ := conn.Read(buf)
		conn.Close()
		if n > 0 || err == nil {
			r := &PortResult{
				Port: port, Protocol: "udp", State: "open|filtered",
				Service: commonServiceName(port), Severity: 1,
			}
			assessPortRisk(r)
			results = append(results, *r)
		}
	}
	return results
}

// ── System info ───────────────────────────────────────────────────────────────

func collectSystemInfo() SystemInfo {
	info := SystemInfo{}

	// Hostname
	info.Hostname, _ = os.Hostname()

	// Kernel version
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		info.KernelVersion = strings.TrimSpace(string(out))
	}

	// Arch
	if out, err := exec.Command("uname", "-m").Output(); err == nil {
		info.Arch = strings.TrimSpace(string(out))
	}

	// OS release
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				info.OSRelease = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
				break
			}
		}
	}

	return info
}

// ── Installed packages ────────────────────────────────────────────────────────

func collectPackages() []InstalledPackage {
	var pkgs []InstalledPackage

	// Try dpkg (Debian/Ubuntu)
	if out, err := exec.Command("dpkg-query", "-W", "-f=${Package}\t${Version}\n").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.SplitN(strings.TrimSpace(line), "\t", 2)
			if len(parts) == 2 && parts[0] != "" {
				pkgs = append(pkgs, InstalledPackage{Name: parts[0], Version: parts[1], Manager: "dpkg"})
			}
		}
		return pkgs
	}

	// Try rpm (RHEL/CentOS/Fedora)
	if out, err := exec.Command("rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.SplitN(strings.TrimSpace(line), "\t", 2)
			if len(parts) == 2 && parts[0] != "" {
				pkgs = append(pkgs, InstalledPackage{Name: parts[0], Version: parts[1], Manager: "rpm"})
			}
		}
		return pkgs
	}

	// Try apk (Alpine)
	if out, err := exec.Command("apk", "list", "--installed").Output(); err == nil {
		// Format: package-version-release [installed]
		re := regexp.MustCompile(`^(\S+?)-(\d\S*)\s`)
		for _, line := range strings.Split(string(out), "\n") {
			if m := re.FindStringSubmatch(line); len(m) >= 3 {
				pkgs = append(pkgs, InstalledPackage{Name: m[1], Version: m[2], Manager: "apk"})
			}
		}
	}

	return pkgs
}

// ── Running services ──────────────────────────────────────────────────────────

func collectServices() []RunningService {
	var services []RunningService

	// systemctl
	out, err := exec.Command("systemctl", "list-units", "--type=service",
		"--state=running", "--no-pager", "--no-legend").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				name := strings.TrimSuffix(fields[0], ".service")
				services = append(services, RunningService{Name: name, State: "running"})
			}
		}
		return services
	}

	// /proc fallback — read /proc/*/comm
	entries, err := os.ReadDir("/proc")
	if err != nil { return services }
	seen := map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() { continue }
		comm, err := os.ReadFile("/proc/" + e.Name() + "/comm")
		if err != nil { continue }
		name := strings.TrimSpace(string(comm))
		if name == "" || seen[name] { continue }
		seen[name] = true
		services = append(services, RunningService{Name: name, State: "running", PID: e.Name()})
		if len(services) >= 100 { break } // cap at 100
	}
	return services
}

// ── Security findings ─────────────────────────────────────────────────────────

func collectSecurityFindings() []SecurityFinding {
	var findings []SecurityFinding

	// Check for SUID binaries in common locations
	out, err := exec.Command("find", "/usr/bin", "/usr/local/bin", "/bin", "/sbin",
		"-perm", "-4000", "-type", "f").Output()
	if err == nil {
		binaries := strings.Fields(strings.TrimSpace(string(out)))
		suspicious := []string{"nmap", "nc", "netcat", "python", "perl", "ruby", "bash", "sh",
			"curl", "wget", "vim", "nano", "awk", "find", "env"}
		for _, b := range binaries {
			for _, s := range suspicious {
				if strings.Contains(strings.ToLower(b), s) {
					findings = append(findings, SecurityFinding{
						Category: "SUID Binary",
						Severity: 4,
						Title:    fmt.Sprintf("Suspicious SUID binary: %s", b),
						Detail:   fmt.Sprintf("SUID bit set on %s — can be used for privilege escalation", b),
						Fix:      fmt.Sprintf("Remove SUID bit: chmod u-s %s", b),
					})
				}
			}
		}
		if len(binaries) > 20 {
			findings = append(findings, SecurityFinding{
				Category: "SUID Binaries",
				Severity: 2,
				Title:    fmt.Sprintf("%d SUID binaries found", len(binaries)),
				Detail:   "Large number of SUID binaries — review for privilege escalation risk",
				Fix:      "Audit SUID binaries with: find / -perm -4000 -type f 2>/dev/null",
			})
		}
	}

	// Check SSH config
	if sshCfg, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil {
		cfg := string(sshCfg)
		if !strings.Contains(cfg, "PermitRootLogin no") && !strings.Contains(cfg, "PermitRootLogin prohibit-password") {
			findings = append(findings, SecurityFinding{
				Category: "SSH Configuration",
				Severity: 4,
				Title:    "SSH root login may be permitted",
				Detail:   "sshd_config does not explicitly disable root login",
				Fix:      "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd",
			})
		}
		if strings.Contains(cfg, "PasswordAuthentication yes") {
			findings = append(findings, SecurityFinding{
				Category: "SSH Configuration",
				Severity: 3,
				Title:    "SSH password authentication enabled",
				Detail:   "Password authentication is enabled — prefer key-based auth to prevent brute force",
				Fix:      "Set 'PasswordAuthentication no' and use SSH keys instead",
			})
		}
	}

	// Check for world-writable directories in PATH
	out2, err2 := exec.Command("find", "/usr/local/bin", "/usr/bin", "/bin",
		"-writable", "-type", "d").Output()
	if err2 == nil && len(strings.TrimSpace(string(out2))) > 0 {
		for _, dir := range strings.Split(strings.TrimSpace(string(out2)), "\n") {
			if dir == "" { continue }
			findings = append(findings, SecurityFinding{
				Category: "File Permissions",
				Severity: 5,
				Title:    fmt.Sprintf("World-writable PATH directory: %s", dir),
				Detail:   "World-writable directory in PATH allows privilege escalation via binary hijacking",
				Fix:      fmt.Sprintf("chmod o-w %s", dir),
			})
		}
	}

	// Check /etc/passwd for users with UID 0 other than root
	if passwdData, err := os.ReadFile("/etc/passwd"); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(passwdData)))
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.Split(line, ":")
			if len(parts) >= 4 && parts[2] == "0" && parts[0] != "root" {
				findings = append(findings, SecurityFinding{
					Category: "User Accounts",
					Severity: 5,
					Title:    fmt.Sprintf("Non-root user with UID 0: %s", parts[0]),
					Detail:   "User has root-level UID — this is a critical security issue",
					Fix:      fmt.Sprintf("Investigate and remove: userdel %s", parts[0]),
				})
			}
		}
	}

	// Check if firewall is active
	ufw, _ := exec.Command("ufw", "status").Output()
	iptables, _ := exec.Command("iptables", "-L", "-n").Output()
	if !strings.Contains(string(ufw), "active") &&
		(len(iptables) == 0 || strings.Contains(string(iptables), "ACCEPT     all  --  0.0.0.0/0")) {
		findings = append(findings, SecurityFinding{
			Category: "Firewall",
			Severity: 4,
			Title:    "No active firewall detected",
			Detail:   "Neither ufw nor iptables rules appear to be restricting traffic",
			Fix:      "Enable ufw: ufw enable && ufw default deny incoming && ufw allow ssh",
		})
	}

	return findings
}

// ── Version extraction ────────────────────────────────────────────────────────

var versionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`OpenSSH[_\s](\S+)`),
	regexp.MustCompile(`SSH-[\d.]+-OpenSSH[_\s]?(\S+)`),
	regexp.MustCompile(`Apache/(\S+)`),
	regexp.MustCompile(`nginx/(\S+)`),
	regexp.MustCompile(`\bMySQL\s+([\d.]+)`),
	regexp.MustCompile(`\bMariaDB\s+([\d.]+)`),
	regexp.MustCompile(`PostgreSQL\s+([\d.]+)`),
	regexp.MustCompile(`Redis\s+server\s+v=([\d.]+)`),
	regexp.MustCompile(`MongoDB\s+([\d.]+)`),
	regexp.MustCompile(`Elasticsearch\s+([\d.]+)`),
	regexp.MustCompile(`FTP.+?([\d.]+\d)`),
	regexp.MustCompile(`ESMTP.+?([\d.]+)`),
	regexp.MustCompile(`\bv([\d]+\.[\d]+\.[\d]+)\b`),
}

var productPatterns = []struct {
	pattern *regexp.Regexp
	product string
}{
	{regexp.MustCompile(`(?i)openssh`), "OpenSSH"},
	{regexp.MustCompile(`(?i)apache`), "Apache httpd"},
	{regexp.MustCompile(`(?i)nginx`), "nginx"},
	{regexp.MustCompile(`(?i)mysql`), "MySQL"},
	{regexp.MustCompile(`(?i)mariadb`), "MariaDB"},
	{regexp.MustCompile(`(?i)postgresql`), "PostgreSQL"},
	{regexp.MustCompile(`(?i)redis`), "Redis"},
	{regexp.MustCompile(`(?i)mongodb`), "MongoDB"},
	{regexp.MustCompile(`(?i)elasticsearch`), "Elasticsearch"},
	{regexp.MustCompile(`(?i)rabbitmq`), "RabbitMQ"},
	{regexp.MustCompile(`(?i)postfix`), "Postfix"},
	{regexp.MustCompile(`(?i)dovecot`), "Dovecot"},
	{regexp.MustCompile(`(?i)exim`), "Exim"},
	{regexp.MustCompile(`(?i)vsftpd`), "vsftpd"},
	{regexp.MustCompile(`(?i)proftpd`), "ProFTPD"},
	{regexp.MustCompile(`(?i)pure-ftpd`), "Pure-FTPd"},
	{regexp.MustCompile(`(?i)memcached`), "Memcached"},
	{regexp.MustCompile(`(?i)kubernetes`), "Kubernetes"},
	{regexp.MustCompile(`(?i)docker`), "Docker"},
	{regexp.MustCompile(`(?i)jenkins`), "Jenkins"},
	{regexp.MustCompile(`(?i)grafana`), "Grafana"},
}

// sanitizeBanner converts raw banner bytes to a clean printable string.
// Strips null bytes, control characters, and invalid UTF-8 that would
// corrupt JSON encoding and cause the backend to reject the event.
func sanitizeBanner(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		// Keep printable ASCII and common whitespace
		if c == 0x00 {
			continue // null byte — kills JSON
		}
		if c < 0x20 && c != 0x09 && c != 0x0a && c != 0x0d {
			continue // control characters except tab/LF/CR
		}
		out = append(out, c)
	}
	// Ensure valid UTF-8
	return strings.TrimSpace(strings.ToValidUTF8(string(out), ""))
}

func extractProductVersion(banner string, port int) (product, version string) {
	for _, pp := range productPatterns {
		if pp.pattern.MatchString(banner) {
			product = pp.product
			break
		}
	}
	if product == "" {
		product = commonServiceName(port)
	}
	for _, vp := range versionPatterns {
		if m := vp.FindStringSubmatch(banner); len(m) >= 2 {
			version = m[1]
			break
		}
	}
	return product, version
}

// ── Risk assessment ───────────────────────────────────────────────────────────

type portRisk struct {
	label    string
	detail   string
	severity int
}

var portRisks = map[int]portRisk{
	21:    {label: "FTP", detail: "FTP transmits credentials and data in plaintext. Use SFTP or FTPS instead.", severity: 4},
	23:    {label: "Telnet", detail: "Telnet transmits all traffic including credentials in plaintext. Replace with SSH immediately.", severity: 5},
	25:    {label: "SMTP open relay", detail: "SMTP port exposed — verify relay restrictions to prevent spam abuse.", severity: 3},
	53:    {label: "DNS", detail: "DNS service exposed — ensure recursion is restricted to authorised clients.", severity: 2},
	69:    {label: "TFTP", detail: "TFTP has no authentication. Remove if not required.", severity: 4},
	79:    {label: "Finger", detail: "Finger protocol exposes user information. Disable immediately.", severity: 4},
	111:   {label: "RPC portmapper", detail: "RPC portmapper enables discovery of RPC services. Restrict to internal networks.", severity: 3},
	135:   {label: "MSRPC", detail: "Microsoft RPC endpoint mapper — common attack surface.", severity: 3},
	137:   {label: "NetBIOS", detail: "NetBIOS exposes hostname and domain information. Block at perimeter.", severity: 3},
	139:   {label: "NetBIOS Session", detail: "NetBIOS session service — legacy, often exploited. Disable if not needed.", severity: 3},
	445:   {label: "SMB", detail: "SMB is the primary vector for ransomware (EternalBlue/WannaCry). Ensure patched and not internet-facing.", severity: 4},
	512:   {label: "rexec", detail: "Remote execution service with no encryption. Disable immediately.", severity: 5},
	513:   {label: "rlogin", detail: "Remote login with no encryption. Disable immediately.", severity: 5},
	514:   {label: "rsh/syslog", detail: "Remote shell (rsh) has no authentication. Disable if not syslog-only.", severity: 4},
	873:   {label: "rsync", detail: "rsync exposed — verify authentication is configured to prevent data exfiltration.", severity: 3},
	1080:  {label: "SOCKS proxy", detail: "SOCKS proxy exposed — could be used for traffic proxying by attackers.", severity: 4},
	1433:  {label: "MSSQL", detail: "Microsoft SQL Server exposed on network. Restrict to application servers only.", severity: 4},
	1521:  {label: "Oracle DB", detail: "Oracle database exposed on network. Restrict to application servers only.", severity: 4},
	2049:  {label: "NFS", detail: "NFS share exposed — check export permissions to prevent unauthorised access.", severity: 3},
	2375:  {label: "Docker API (unauthenticated)", detail: "Docker daemon API exposed WITHOUT TLS. Full root container escape possible. Close immediately.", severity: 5},
	2376:  {label: "Docker API (TLS)", detail: "Docker daemon API exposed with TLS. Verify certificate authentication is required.", severity: 3},
	3306:  {label: "MySQL", detail: "MySQL database exposed on network. Bind to localhost or restrict via firewall.", severity: 4},
	3389:  {label: "RDP", detail: "Remote Desktop exposed — common brute-force and BlueKeep exploitation target. Use VPN instead.", severity: 4},
	4444:  {label: "Metasploit default", detail: "Port 4444 is the default Metasploit listener. Investigate for C2 activity immediately.", severity: 5},
	4848:  {label: "GlassFish admin", detail: "GlassFish administration console exposed. Restrict to localhost.", severity: 4},
	5432:  {label: "PostgreSQL", detail: "PostgreSQL database exposed on network. Bind to localhost or restrict via firewall.", severity: 4},
	5900:  {label: "VNC", detail: "VNC remote desktop often has weak or no authentication. Use SSH tunnel instead.", severity: 4},
	5984:  {label: "CouchDB", detail: "CouchDB admin interface — often unauthenticated in default installs.", severity: 4},
	6379:  {label: "Redis", detail: "Redis has no authentication by default. Any client can read/write/delete all data.", severity: 4},
	6443:  {label: "Kubernetes API", detail: "Kubernetes API server exposed. Verify RBAC and authentication are configured.", severity: 4},
	7001:  {label: "WebLogic", detail: "Oracle WebLogic server — frequently targeted by deserialization exploits.", severity: 4},
	8080:  {label: "HTTP (alt)", detail: "Unencrypted HTTP service — credentials and data transmitted in plaintext.", severity: 3},
	8443:  {label: "HTTPS (alt)", detail: "Alternate HTTPS port — verify valid certificate and modern TLS version.", severity: 2},
	8888:  {label: "Jupyter Notebook", detail: "Jupyter Notebook may be exposed without authentication — provides code execution.", severity: 5},
	9000:  {label: "SonarQube / PHP-FPM", detail: "Could be SonarQube admin console or PHP-FPM — restrict to localhost.", severity: 3},
	9090:  {label: "Prometheus", detail: "Prometheus metrics endpoint — exposes internal service metrics. Restrict access.", severity: 3},
	9200:  {label: "Elasticsearch", detail: "Elasticsearch often has no authentication by default. All data readable by anyone.", severity: 4},
	9300:  {label: "Elasticsearch cluster", detail: "Elasticsearch cluster communication port — should never be internet-facing.", severity: 4},
	10250: {label: "Kubernetes kubelet", detail: "Kubernetes kubelet API — can be used to execute commands in pods.", severity: 5},
	11211: {label: "Memcached", detail: "Memcached has no authentication. Data readable by anyone and used in DDoS amplification.", severity: 4},
	15672: {label: "RabbitMQ management", detail: "RabbitMQ management UI — restrict to internal networks.", severity: 3},
	27017: {label: "MongoDB", detail: "MongoDB has no authentication in default installs. All data readable by anyone.", severity: 4},
	50000: {label: "Jenkins", detail: "Jenkins CI/CD — often contains credentials and code. Verify authentication.", severity: 4},
}

func assessPortRisk(r *PortResult) {
	if risk, ok := portRisks[r.Port]; ok {
		r.RiskLabel  = risk.label
		r.RiskDetail = risk.detail
		r.Severity   = risk.severity
	}
	// Elevate severity for known-vulnerable ancient versions
	if r.Version != "" {
		checkVersionRisk(r)
	}
}

// checkVersionRisk flags known-EOL / known-vulnerable versions
func checkVersionRisk(r *PortResult) {
	type vulnVersion struct {
		product  string
		prefix   string // version prefix that indicates vulnerable
		detail   string
		severity int
	}
	checks := []vulnVersion{
		{"OpenSSH", "1.", "OpenSSH 1.x is extremely outdated with many critical CVEs", 5},
		{"OpenSSH", "2.", "OpenSSH 2.x is extremely outdated with many critical CVEs", 5},
		{"OpenSSH", "3.", "OpenSSH 3.x is end-of-life with known critical vulnerabilities", 5},
		{"OpenSSH", "4.", "OpenSSH 4.x is end-of-life — upgrade to 8.x+", 4},
		{"OpenSSH", "5.", "OpenSSH 5.x is end-of-life — upgrade to 8.x+", 4},
		{"OpenSSH", "6.", "OpenSSH 6.x is end-of-life — upgrade to 8.x+", 3},
		{"OpenSSH", "7.", "OpenSSH 7.x may be vulnerable to CVE-2023-38408 and others", 3},
		{"Apache httpd", "1.", "Apache 1.x is end-of-life", 5},
		{"Apache httpd", "2.2", "Apache 2.2 is end-of-life — upgrade to 2.4+", 4},
		{"Apache httpd", "2.4.4", "Apache 2.4.49/50 are vulnerable to path traversal (CVE-2021-41773)", 4},
		{"nginx", "1.1", "nginx 1.1x branch may be outdated — check for CVEs", 3},
		{"MySQL", "5.5", "MySQL 5.5 is end-of-life", 4},
		{"MySQL", "5.6", "MySQL 5.6 is end-of-life", 4},
		{"MySQL", "5.7", "MySQL 5.7 reaches EOL — plan upgrade to 8.0+", 3},
		{"Redis", "2.", "Redis 2.x is end-of-life", 4},
		{"Redis", "3.", "Redis 3.x is end-of-life", 4},
		{"Redis", "4.", "Redis 4.x is end-of-life", 3},
	}
	for _, c := range checks {
		if strings.EqualFold(r.Product, c.product) && strings.HasPrefix(r.Version, c.prefix) {
			if r.Severity < c.severity { r.Severity = c.severity }
			r.RiskDetail = c.detail + " | " + r.RiskDetail
		}
	}
}

// ── Service names ─────────────────────────────────────────────────────────────

// sanitiseBanner strips null bytes and invalid UTF-8 from raw TCP banners
func sanitiseBanner(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c != 0x00 && c >= 0x09 { // keep printable + whitespace, drop nulls and control chars
			out = append(out, c)
		}
	}
	// Replace invalid UTF-8 sequences
	s := strings.ToValidUTF8(strings.TrimSpace(string(out)), "")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func commonServiceName(port int) string {
	names := map[int]string{
		21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
		69: "TFTP", 79: "Finger", 80: "HTTP", 110: "POP3", 111: "RPC",
		119: "NNTP", 123: "NTP", 135: "MSRPC", 137: "NetBIOS-NS",
		139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 179: "BGP",
		389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
		512: "rexec", 513: "rlogin", 514: "rsh", 587: "Submission",
		636: "LDAPS", 873: "rsync", 993: "IMAPS", 995: "POP3S",
		1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle",
		1723: "PPTP", 2049: "NFS", 2375: "Docker", 2376: "Docker-TLS",
		3000: "Grafana/Node", 3306: "MySQL", 3389: "RDP",
		4444: "Metasploit", 4848: "GlassFish", 5432: "PostgreSQL",
		5900: "VNC", 5984: "CouchDB", 6379: "Redis", 6443: "K8s-API",
		7001: "WebLogic", 8000: "HTTP-alt", 8080: "HTTP-alt",
		8443: "HTTPS-alt", 8888: "Jupyter", 9000: "SonarQube",
		9090: "Prometheus", 9200: "Elasticsearch", 9300: "ES-cluster",
		10250: "Kubelet", 11211: "Memcached", 15672: "RabbitMQ-mgmt",
		27017: "MongoDB", 27018: "MongoDB", 50000: "Jenkins",
		50070: "HDFS", 61616: "ActiveMQ",
	}
	if n, ok := names[port]; ok { return n }
	return ""
}
