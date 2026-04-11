//go:build windows

package collector

import (
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

	"obsidianwatch/agent/pkg/schema"
)

type PortResult struct {
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
	State      string `json:"state"`
	Service    string `json:"service,omitempty"`
	Version    string `json:"version,omitempty"`
	Banner     string `json:"banner,omitempty"`
	Product    string `json:"product,omitempty"`
	RiskLabel  string `json:"risk_label,omitempty"`
	RiskDetail string `json:"risk_detail,omitempty"`
	Severity   int    `json:"severity"`
}

type InstalledPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Manager string `json:"manager"`
}

type SystemInfo struct {
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	KernelVersion string `json:"kernel_version"`
	OSRelease     string `json:"os_release"`
	Arch          string `json:"arch"`
}

type RunningService struct {
	Name  string `json:"name"`
	State string `json:"state"`
	PID   string `json:"pid,omitempty"`
}

type SecurityFinding struct {
	Category string `json:"category"`
	Severity int    `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Fix      string `json:"fix,omitempty"`
}

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
	TotalOpen        int                `json:"total_open"`
	CriticalCount    int                `json:"critical_count"`
	HighCount        int                `json:"high_count"`
	MediumCount      int                `json:"medium_count"`
	ScanDurationSecs float64            `json:"scan_duration_secs"`
}

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
		select { case <-ctx.Done(): return; case <-ticker.C: v.scan(ctx) }
	}
}

func (v *VulnScanner) scan(ctx context.Context) {
	v.logger.Info("vuln: starting full host scan")
	start := time.Now()
	result := VulnScanResult{ScannedAt: time.Now().UTC(), Host: v.host, OS: v.os}
	result.System    = collectSystemInfo()
	result.OpenPorts = v.scanTCP(ctx)
	result.Packages  = collectPackages()
	result.Services  = collectServices()
	result.Findings  = collectSecurityFindings()
	result.TotalOpen = len(result.OpenPorts)
	result.ScanDurationSecs = time.Since(start).Seconds()
	for _, p := range result.OpenPorts {
		switch { case p.Severity>=5: result.CriticalCount++; case p.Severity>=4: result.HighCount++; case p.Severity>=3: result.MediumCount++ }
	}
	sev := 1
	if result.CriticalCount > 0 { sev = 5 } else if result.HighCount > 0 { sev = 4 } else if result.MediumCount > 0 { sev = 3 } else if result.TotalOpen > 0 { sev = 2 }
	raw, _ := json.Marshal(result)
	v.logger.Info("vuln: done", "ports", result.TotalOpen, "critical", result.CriticalCount, "high", result.HighCount)
	ev := schema.Event{
		ID: fmt.Sprintf("vuln:%s:%d", v.agentID, time.Now().Unix()),
		Time: time.Now().UTC(), AgentID: v.agentID, Host: v.host, OS: v.os,
		EventType: "vulnerability.scan", Severity: schema.Severity(sev), Source: "vuln-scanner", Raw: raw,
	}
	select {
	case v.out <- ev:
	case <-time.After(30 * time.Second):
		v.logger.Warn("vuln: output channel blocked for 30s, dropping scan result")
	case <-ctx.Done():
	}
}

func (v *VulnScanner) scanTCP(ctx context.Context) []PortResult {
	sem := make(chan struct{}, v.cfg.Concurrency); mu := sync.Mutex{}; var results []PortResult; var wg sync.WaitGroup
	for port := 1; port <= 65535; port++ {
		select { case <-ctx.Done(): goto done; default: }
		wg.Add(1); sem <- struct{}{}
		go func(p int) {
			defer wg.Done(); defer func() { <-sem }()
			if r := v.probeTCP(p); r != nil { mu.Lock(); results = append(results, *r); mu.Unlock() }
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
	conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	buf := make([]byte, 512); n, _ := conn.Read(buf)
	if n > 0 {
		r.Banner = sanitizeBanner(buf[:n])
		r.Product, r.Version = extractProductVersion(r.Banner, port)
		r.Service = r.Product; if r.Service == "" { r.Service = commonServiceName(port) }
	} else { r.Service = commonServiceName(port) }
	assessPortRisk(r)
	return r
}

func collectSystemInfo() SystemInfo {
	h, _ := os.Hostname()
	info := SystemInfo{Hostname: h, OS: "windows"}
	if out, err := exec.Command("cmd", "/c", "ver").Output(); err == nil {
		info.OSRelease = strings.TrimSpace(string(out))
	}
	if out, err := exec.Command("wmic", "os", "get", "BuildNumber", "/value").Output(); err == nil {
		info.KernelVersion = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "BuildNumber="))
	}
	return info
}

func collectPackages() []InstalledPackage {
	var pkgs []InstalledPackage

	// Windows Management Instrumentation — works on all Windows versions
	out, err := exec.Command("wmic", "product", "get", "Name,Version", "/format:csv").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.SplitN(strings.TrimSpace(line), ",", 3)
			if len(parts) == 3 && parts[1] != "" && parts[1] != "Name" {
				pkgs = append(pkgs, InstalledPackage{Name: parts[1], Version: parts[2], Manager: "wmic"})
			}
		}
	}

	// Chocolatey supplement
	if out2, err2 := exec.Command("choco", "list", "--local-only").Output(); err2 == nil {
		for _, line := range strings.Split(string(out2), "\n") {
			parts := strings.Fields(line)
			if len(parts) == 2 {
				pkgs = append(pkgs, InstalledPackage{Name: parts[0], Version: parts[1], Manager: "choco"})
			}
		}
	}

	return pkgs
}


func collectServices() []RunningService {
	var services []RunningService
	out, err := exec.Command("sc", "query", "type=", "service", "state=", "running").Output()
	if err != nil { return services }
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "SERVICE_NAME:") {
			name := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "SERVICE_NAME:"))
			services = append(services, RunningService{Name: name, State: "running"})
		}
	}
	return services
}

func collectSecurityFindings() []SecurityFinding {
	var findings []SecurityFinding

	// 1. Windows Defender real-time protection
	out, err := exec.Command("powershell", "-NonInteractive", "-Command",
		"(Get-MpComputerStatus).RealTimeProtectionEnabled").Output()
	if err == nil {
		val := strings.TrimSpace(string(out))
		if val == "False" {
			findings = append(findings, SecurityFinding{
				Category: "Antivirus", Severity: 5,
				Title:  "Windows Defender real-time protection disabled",
				Detail: "Host is unprotected against malware execution",
				Fix:    "Set-MpPreference -DisableRealtimeMonitoring $false",
			})
		}
	}

	// 2. Windows Firewall
	out2, _ := exec.Command("netsh", "advfirewall", "show", "allprofiles", "state").Output()
	if strings.Contains(string(out2), "OFF") {
		findings = append(findings, SecurityFinding{
			Category: "Firewall", Severity: 4,
			Title:  "Windows Firewall disabled on one or more profiles",
			Detail: "Inbound connections are unrestricted",
			Fix:    "netsh advfirewall set allprofiles state on",
		})
	}

	// 3. RDP enabled
	out3, _ := exec.Command("reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`,
		"/v", "fDenyTSConnections").Output()
	if strings.Contains(string(out3), "0x0") {
		findings = append(findings, SecurityFinding{
			Category: "Remote Access", Severity: 3,
			Title:  "Remote Desktop (RDP) is enabled",
			Detail: "RDP is a common brute-force and exploitation target (BlueKeep, DejaBlue)",
			Fix:    "Disable if not needed or restrict via firewall to trusted IPs only",
		})
	}

	// 4. AutoRun enabled (malware persistence vector)
	out4, _ := exec.Command("reg", "query",
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer`,
		"/v", "NoDriveTypeAutoRun").Output()
	if err := out4; !strings.Contains(string(err), "0xff") {
		findings = append(findings, SecurityFinding{
			Category: "AutoRun", Severity: 3,
			Title:  "AutoRun may be enabled for removable drives",
			Detail: "AutoRun allows malware on USB drives to execute automatically",
			Fix:    `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f`,
		})
	}

	// 5. SMBv1 enabled
	out5, _ := exec.Command("powershell", "-NonInteractive", "-Command",
		"(Get-SmbServerConfiguration).EnableSMB1Protocol").Output()
	if strings.TrimSpace(string(out5)) == "True" {
		findings = append(findings, SecurityFinding{
			Category: "SMB", Severity: 5,
			Title:  "SMBv1 protocol is enabled",
			Detail: "SMBv1 is vulnerable to EternalBlue (MS17-010/WannaCry). Should be disabled on all modern systems.",
			Fix:    "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
		})
	}

	// 6. Guest account enabled
	out6, _ := exec.Command("net", "user", "Guest").Output()
	if strings.Contains(string(out6), "Account active               Yes") {
		findings = append(findings, SecurityFinding{
			Category: "User Accounts", Severity: 3,
			Title:  "Guest account is enabled",
			Detail: "The built-in Guest account provides unauthenticated access",
			Fix:    "net user Guest /active:no",
		})
	}

	// 7. UAC disabled
	out7, _ := exec.Command("reg", "query",
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`,
		"/v", "EnableLUA").Output()
	if strings.Contains(string(out7), "0x0") {
		findings = append(findings, SecurityFinding{
			Category: "UAC", Severity: 4,
			Title:  "User Account Control (UAC) is disabled",
			Detail: "UAC prevents privilege escalation. Disabling it allows any process to run as Administrator.",
			Fix:    `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f`,
		})
	}

	// 8. Audit policy — check if audit logging is configured
	out8, _ := exec.Command("auditpol", "/get", "/category:Logon/Logoff").Output()
	if !strings.Contains(string(out8), "Success and Failure") {
		findings = append(findings, SecurityFinding{
			Category: "Audit Policy", Severity: 2,
			Title:  "Logon/Logoff audit policy not fully configured",
			Detail: "Not all logon events are being audited — reduces forensic visibility",
			Fix:    "auditpol /set /category:\"Logon/Logoff\" /success:enable /failure:enable",
		})
	}

	return findings
}


var versionRe = regexp.MustCompile(`\b(\d+\.\d+[\.\d]*)\b`)
var productPatterns = []struct{ re *regexp.Regexp; name string }{
	{regexp.MustCompile(`(?i)openssh`), "OpenSSH"},
	{regexp.MustCompile(`(?i)apache`), "Apache httpd"},
	{regexp.MustCompile(`(?i)nginx`), "nginx"},
	{regexp.MustCompile(`(?i)mysql`), "MySQL"},
	{regexp.MustCompile(`(?i)redis`), "Redis"},
	{regexp.MustCompile(`(?i)postgresql`), "PostgreSQL"},
	{regexp.MustCompile(`(?i)mongodb`), "MongoDB"},
	{regexp.MustCompile(`(?i)iis`), "IIS"},
}

// sanitizeBanner strips null bytes, control chars, and invalid UTF-8 from banner data.
func sanitizeBanner(b []byte) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0x00 { continue }
		if c < 0x20 && c != 0x09 && c != 0x0a && c != 0x0d { continue }
		out = append(out, c)
	}
	return strings.TrimSpace(strings.ToValidUTF8(string(out), ""))
}

func extractProductVersion(banner string, port int) (product, version string) {
	for _, p := range productPatterns {
		if p.re.MatchString(banner) { product = p.name; break }
	}
	if product == "" { product = commonServiceName(port) }
	if m := versionRe.FindString(banner); m != "" { version = m }
	return
}

type portRisk struct{ label, detail string; severity int }
var portRisks = map[int]portRisk{
	21:    {"FTP",           "FTP transmits credentials in plaintext.", 4},
	23:    {"Telnet",        "Telnet transmits everything in plaintext. Replace with SSH.", 5},
	445:   {"SMB",           "SMB is the primary ransomware vector (EternalBlue/WannaCry).", 4},
	1433:  {"MSSQL",         "SQL Server exposed — restrict to app servers only.", 4},
	2375:  {"Docker API",    "Docker API unauthenticated — full root escape possible.", 5},
	3306:  {"MySQL",         "MySQL exposed — bind to localhost.", 4},
	3389:  {"RDP",           "RDP is a common brute-force and BlueKeep target.", 4},
	4444:  {"Metasploit",    "Metasploit default port — investigate for C2.", 5},
	5432:  {"PostgreSQL",    "PostgreSQL exposed — bind to localhost.", 4},
	5900:  {"VNC",           "VNC often has weak authentication.", 4},
	6379:  {"Redis",         "Redis has no auth by default.", 4},
	8080:  {"HTTP-alt",      "Unencrypted HTTP service.", 3},
	9200:  {"Elasticsearch", "Elasticsearch often unauthenticated.", 4},
	27017: {"MongoDB",       "MongoDB often has no authentication.", 4},
}

func assessPortRisk(r *PortResult) {
	if risk, ok := portRisks[r.Port]; ok { r.RiskLabel = risk.label; r.RiskDetail = risk.detail; r.Severity = risk.severity }
}

func commonServiceName(port int) string {
	names := map[int]string{21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",135:"MSRPC",139:"NetBIOS",143:"IMAP",443:"HTTPS",445:"SMB",1433:"MSSQL",3306:"MySQL",3389:"RDP",4444:"Metasploit",5432:"PostgreSQL",5900:"VNC",6379:"Redis",8080:"HTTP-alt",9200:"Elasticsearch",27017:"MongoDB"}
	return names[port]
}
