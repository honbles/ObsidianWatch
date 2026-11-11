//go:build darwin

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

	"obsidianwatch/macos-agent/pkg/schema"
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
	Posture          []PostureCheck     `json:"posture,omitempty"`
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
	// A-07: posture findings from the previous scan, to detect regressions.
	prevPosture map[string]bool
	postureInit bool
}

// postureCategories are the host-hardening controls whose loss is alertable.
var postureCategories = map[string]bool{
	"System Integrity Protection": true, "Gatekeeper": true, "FileVault": true, "Firewall": true,
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
	for { select { case <-ctx.Done(): return; case <-ticker.C: v.scan(ctx) } }
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
	result.Posture   = collectPosture()
	result.TotalOpen = len(result.OpenPorts)
	result.ScanDurationSecs = time.Since(start).Seconds()
	for _, p := range result.OpenPorts {
		switch { case p.Severity>=5: result.CriticalCount++; case p.Severity>=4: result.HighCount++; case p.Severity>=3: result.MediumCount++ }
	}
	for _, f := range result.Findings {
		switch { case f.Severity>=5: result.CriticalCount++; case f.Severity>=4: result.HighCount++; case f.Severity>=3: result.MediumCount++ }
	}
	sev := 1
	if result.CriticalCount > 0 { sev = 5 } else if result.HighCount > 0 { sev = 4 } else if result.MediumCount > 0 { sev = 3 } else if result.TotalOpen > 0 { sev = 2 }
	v.logger.Info("vuln: done", "ports", result.TotalOpen, "packages", len(result.Packages), "findings", len(result.Findings))
	v.emitPostureRegressions(ctx, result.Findings)
	raw, _ := json.Marshal(result)
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

// emitPostureRegressions emits a high-severity event when a hardening control
// (SIP, Gatekeeper, FileVault, firewall) newly turns off between scans.
func (v *VulnScanner) emitPostureRegressions(ctx context.Context, findings []SecurityFinding) {
	cur := map[string]bool{}
	for _, f := range findings {
		if postureCategories[f.Category] {
			cur[f.Category] = true
		}
	}
	if v.postureInit {
		for cat := range cur {
			if v.prevPosture[cat] {
				continue
			}
			raw, _ := json.Marshal(map[string]interface{}{
				"control": cat, "state": "disabled", "previous": "enabled",
				"message": "macOS security control regressed: " + cat,
			})
			ev := schema.Event{
				ID:   fmt.Sprintf("posture:%s:%s:%d", v.agentID, strings.ReplaceAll(strings.ToLower(cat), " ", "_"), time.Now().Unix()),
				Time: time.Now().UTC(), AgentID: v.agentID, Host: v.host, OS: v.os,
				EventType: "config.posture_regression", Severity: schema.Severity(4),
				Source: "vuln-scanner", Raw: raw,
			}
			select {
			case v.out <- ev:
			case <-time.After(10 * time.Second):
			case <-ctx.Done():
				return
			}
		}
	}
	v.prevPosture = cur
	v.postureInit = true
}

func (v *VulnScanner) scanTCP(ctx context.Context) []PortResult {
	sem := make(chan struct{}, v.cfg.Concurrency); mu := sync.Mutex{}
	var results []PortResult; var wg sync.WaitGroup
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
	} else {
		r.Service = commonServiceName(port)
	}
	assessPortRisk(r)
	return r
}

// ── macOS-specific collectors ─────────────────────────────────────────────────

func collectSystemInfo() SystemInfo {
	h, _ := os.Hostname()
	info := SystemInfo{Hostname: h, OS: "darwin"}
	// sw_vers for macOS version
	if out, err := exec.Command("sw_vers", "-productVersion").Output(); err == nil {
		info.OSRelease = "macOS " + strings.TrimSpace(string(out))
	}
	// uname -r for kernel
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		info.KernelVersion = strings.TrimSpace(string(out))
	}
	// uname -m for arch
	if out, err := exec.Command("uname", "-m").Output(); err == nil {
		info.Arch = strings.TrimSpace(string(out))
	}
	return info
}

func collectPackages() []InstalledPackage {
	var pkgs []InstalledPackage

	// Homebrew (most common macOS package manager)
	if out, err := exec.Command("brew", "list", "--versions").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				pkgs = append(pkgs, InstalledPackage{Name: parts[0], Version: parts[len(parts)-1], Manager: "brew"})
			}
		}
	}

	// MacPorts
	if out, err := exec.Command("port", "installed").Output(); err == nil {
		re := regexp.MustCompile(`\s+(\S+)\s+@([\S]+)`)
		for _, line := range strings.Split(string(out), "\n") {
			if m := re.FindStringSubmatch(line); len(m) >= 3 {
				pkgs = append(pkgs, InstalledPackage{Name: m[1], Version: m[2], Manager: "macports"})
			}
		}
	}

	return pkgs
}

func collectServices() []RunningService {
	var services []RunningService

	// launchctl list — running launch agents/daemons
	out, err := exec.Command("launchctl", "list").Output()
	if err != nil { return services }
	for _, line := range strings.Split(string(out), "\n")[1:] { // skip header
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] != "-" { // PID is non-empty = running
			services = append(services, RunningService{Name: fields[2], State: "running", PID: fields[0]})
		}
	}
	return services
}

func collectSecurityFindings() []SecurityFinding {
	var findings []SecurityFinding

	// Check System Integrity Protection (SIP)
	if out, err := exec.Command("csrutil", "status").Output(); err == nil {
		if strings.Contains(string(out), "disabled") {
			findings = append(findings, SecurityFinding{
				Category: "System Integrity Protection", Severity: 4,
				Title:  "SIP (System Integrity Protection) is disabled",
				Detail: "SIP protects critical system files from modification — disabling it significantly increases attack surface",
				Fix:    "Boot to Recovery Mode and run: csrutil enable",
			})
		}
	}

	// Gatekeeper (A-07)
	if out, err := exec.Command("spctl", "--status").CombinedOutput(); err == nil || len(out) > 0 {
		if strings.Contains(strings.ToLower(string(out)), "disabled") {
			findings = append(findings, SecurityFinding{
				Category: "Gatekeeper", Severity: 4,
				Title:  "Gatekeeper is disabled",
				Detail: "Gatekeeper no longer verifies that downloaded apps are signed/notarized",
				Fix:    "Re-enable: sudo spctl --master-enable",
			})
		}
	}

	// FileVault disk encryption (A-07)
	if out, err := exec.Command("fdesetup", "status").Output(); err == nil {
		if strings.Contains(string(out), "FileVault is Off") {
			findings = append(findings, SecurityFinding{
				Category: "FileVault", Severity: 3,
				Title:  "FileVault disk encryption is off",
				Detail: "The startup disk is not encrypted; data is exposed if the device is lost or stolen",
				Fix:    "System Settings → Privacy & Security → FileVault → Turn On",
			})
		}
	}

	// Check firewall
	if out, err := exec.Command("defaults", "read",
		"/Library/Preferences/com.apple.alf", "globalstate").Output(); err == nil {
		val := strings.TrimSpace(string(out))
		if val == "0" {
			findings = append(findings, SecurityFinding{
				Category: "Firewall", Severity: 4,
				Title:  "macOS Application Firewall is disabled",
				Detail: "The built-in firewall is not blocking incoming connections",
				Fix:    "System Settings → Network → Firewall → Turn On",
			})
		}
	}

	// Check remote login (SSH server)
	if out, err := exec.Command("systemsetup", "-getremotelogin").Output(); err == nil {
		if strings.Contains(string(out), "On") {
			findings = append(findings, SecurityFinding{
				Category: "Remote Access", Severity: 3,
				Title:  "Remote Login (SSH server) is enabled",
				Detail: "SSH server is accepting inbound connections — ensure strong keys and no password auth",
				Fix:    "Disable if not needed: systemsetup -setremotelogin off",
			})
		}
	}

	// Check remote management (Screen Sharing / ARD)
	if out, err := exec.Command("systemsetup", "-getremoteappleevents").Output(); err == nil {
		if strings.Contains(string(out), "On") {
			findings = append(findings, SecurityFinding{
				Category: "Remote Access", Severity: 3,
				Title:  "Remote Apple Events are enabled",
				Detail: "Remote Apple Events allow other computers to control this Mac via AppleScript",
				Fix:    "Disable: systemsetup -setremoteappleevents off",
			})
		}
	}

	// SUID binaries
	if out, err := exec.Command("find", "/usr/bin", "/usr/local/bin", "/bin",
		"-perm", "-4000", "-type", "f").Output(); err == nil {
		suspicious := []string{"python", "perl", "ruby", "bash", "sh", "curl", "wget", "vim", "env"}
		for _, b := range strings.Fields(strings.TrimSpace(string(out))) {
			for _, s := range suspicious {
				if strings.Contains(strings.ToLower(b), s) {
					findings = append(findings, SecurityFinding{
						Category: "SUID Binary", Severity: 4,
						Title:  fmt.Sprintf("Suspicious SUID binary: %s", b),
						Detail: fmt.Sprintf("SUID bit set on %s — can be used for privilege escalation", b),
						Fix:    fmt.Sprintf("chmod u-s %s", b),
					})
				}
			}
		}
	}

	return findings
}

// ── Shared helpers ────────────────────────────────────────────────────────────

var versionRe    = regexp.MustCompile(`\b(\d+\.\d+[\.\d]*)\b`)
var prodPatterns = []struct{ re *regexp.Regexp; name string }{
	{regexp.MustCompile(`(?i)openssh`),      "OpenSSH"},
	{regexp.MustCompile(`(?i)apache`),       "Apache httpd"},
	{regexp.MustCompile(`(?i)nginx`),        "nginx"},
	{regexp.MustCompile(`(?i)mysql`),        "MySQL"},
	{regexp.MustCompile(`(?i)redis`),        "Redis"},
	{regexp.MustCompile(`(?i)postgresql`),   "PostgreSQL"},
	{regexp.MustCompile(`(?i)mongodb`),      "MongoDB"},
	{regexp.MustCompile(`(?i)elasticsearch`),"Elasticsearch"},
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
	for _, p := range prodPatterns {
		if p.re.MatchString(banner) { product = p.name; break }
	}
	if product == "" { product = commonServiceName(port) }
	if m := versionRe.FindString(banner); m != "" { version = m }
	return
}

type portRisk struct{ label, detail string; severity int }
var portRisks = map[int]portRisk{
	21:    {"FTP",           "FTP transmits credentials in plaintext. Use SFTP.", 4},
	23:    {"Telnet",        "Telnet transmits everything in plaintext. Replace with SSH.", 5},
	445:   {"SMB",           "SMB is the primary ransomware vector.", 4},
	1433:  {"MSSQL",         "SQL Server exposed — restrict access.", 4},
	2375:  {"Docker API",    "Docker API unauthenticated — full root escape possible.", 5},
	3306:  {"MySQL",         "MySQL exposed — bind to localhost.", 4},
	3389:  {"RDP",           "RDP is a common brute-force target.", 4},
	4444:  {"Metasploit",    "Metasploit default port — investigate for C2.", 5},
	5432:  {"PostgreSQL",    "PostgreSQL exposed — bind to localhost.", 4},
	5900:  {"VNC",           "VNC often has weak authentication.", 4},
	6379:  {"Redis",         "Redis has no auth by default.", 4},
	8080:  {"HTTP-alt",      "Unencrypted HTTP service.", 3},
	8888:  {"Jupyter",       "Jupyter Notebook provides unauthenticated code execution.", 5},
	9200:  {"Elasticsearch", "Elasticsearch often unauthenticated.", 4},
	27017: {"MongoDB",       "MongoDB often has no authentication.", 4},
}

func assessPortRisk(r *PortResult) {
	if risk, ok := portRisks[r.Port]; ok { r.RiskLabel = risk.label; r.RiskDetail = risk.detail; r.Severity = risk.severity }
}

func commonServiceName(port int) string {
	names := map[int]string{22:"SSH",53:"DNS",80:"HTTP",443:"HTTPS",3306:"MySQL",5432:"PostgreSQL",6379:"Redis",8080:"HTTP-alt",27017:"MongoDB"}
	return names[port]
}
