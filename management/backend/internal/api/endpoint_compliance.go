package api

// P-11 (first slice): CIS-inspired host hygiene checks derived from the data
// the agent already reports in vulnerability.scan (packages, services, ports).
// This is a SUBSET of what a CIS benchmark covers — it cannot see file
// permissions, sysctl or auditd rules — and is labelled as such in the output.

import (
	"encoding/json"
	"net/http"
	"strings"

	"obsidianwatch/management/internal/store"
)

type HostCheck struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Status   string `json:"status"` // pass | fail | unknown
	Severity string `json:"severity"`
	Category string `json:"category,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Fix      string `json:"fix,omitempty"`
}

var insecureServicePkgs = map[string]string{
	"telnet": "telnet client", "telnetd": "telnet server", "telnet-server": "telnet server",
	"rsh-server": "rsh server", "rsh-client": "rsh client", "rsh-redone-server": "rsh server",
	"ypserv": "NIS server", "nis": "NIS", "talk": "talk client", "talkd": "talk server",
	"tftpd": "TFTP server", "tftp-server": "TFTP server", "xinetd": "xinetd", "vsftpd": "FTP server",
}

type hostScan struct {
	Packages []struct{ Name, Version string } `json:"packages"`
	Services []struct{ Name, State string }   `json:"services"`
	Ports    []struct {
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		Service  string `json:"service"`
	} `json:"open_ports"`
	UDP []struct {
		Port int `json:"port"`
	} `json:"udp_ports"`
	Findings []struct {
		Category string `json:"category"`
		Title    string `json:"title"`
	} `json:"findings"`
	System struct {
		OSRelease string `json:"os_release"`
	} `json:"system"`
}

// eolReleases lists OS releases past vendor support. Maintained by hand: add
// entries as releases reach end of life.
var eolReleases = []string{
	"ubuntu 14.04", "ubuntu 16.04", "ubuntu 18.04", "ubuntu 20.04",
	"debian gnu/linux 8", "debian gnu/linux 9", "debian gnu/linux 10", "debian gnu/linux 11",
	"centos linux 6", "centos linux 7", "centos linux 8", "red hat enterprise linux 6",
}

var offensiveToolPkgs = map[string]bool{
	"nmap": true, "netcat": true, "netcat-openbsd": true, "netcat-traditional": true, "ncat": true,
	"hydra": true, "john": true, "aircrack-ng": true, "sqlmap": true, "metasploit-framework": true,
	"nikto": true, "masscan": true, "responder": true,
}

// eolRelease reports whether an os-release string names an EOL release.
func eolRelease(osRelease string) bool {
	l := strings.ToLower(osRelease)
	for _, e := range eolReleases {
		if strings.HasPrefix(l, e) {
			return true
		}
	}
	return false
}

func evalHostChecks(raw json.RawMessage) []HostCheck {
	var s hostScan
	_ = json.Unmarshal(raw, &s)
	pkgs := map[string]bool{}
	for _, p := range s.Packages {
		pkgs[strings.ToLower(p.Name)] = true
	}
	running := map[string]bool{}
	for _, v := range s.Services {
		if strings.EqualFold(v.State, "running") || strings.EqualFold(v.State, "active") {
			running[strings.ToLower(strings.TrimSuffix(v.Name, ".service"))] = true
		}
	}
	open := map[int]bool{}
	for _, p := range s.Ports {
		open[p.Port] = true
	}
	var out []HostCheck
	// HC-001: insecure legacy service packages
	var bad []string
	for name, label := range insecureServicePkgs {
		if pkgs[name] {
			bad = append(bad, name+" ("+label+")")
		}
	}
	c := HostCheck{ID: "HC-001", Title: "No legacy plaintext-protocol packages installed", Severity: "high", Status: "pass",
		Fix: "Remove the packages (apt/yum remove) and use SSH/SFTP instead."}
	if len(bad) > 0 {
		c.Status, c.Detail = "fail", strings.Join(sortedStrings(bad), ", ")
	}
	out = append(out, c)
	// HC-002: plaintext remote-access ports
	c = HostCheck{ID: "HC-002", Title: "Telnet / rsh / TFTP / FTP ports are not listening", Severity: "high", Status: "pass",
		Fix: "Disable the listener and block the port at the host firewall."}
	var ports []string
	for _, p := range []struct {
		n int
		l string
	}{{23, "telnet"}, {513, "rlogin"}, {514, "rsh"}, {69, "tftp"}, {21, "ftp"}} {
		if open[p.n] {
			ports = append(ports, p.l)
		}
	}
	if len(ports) > 0 {
		c.Status, c.Detail = "fail", strings.Join(ports, ", ")
	}
	out = append(out, c)
	// HC-003: audit daemon
	hasAudit := pkgs["auditd"] || pkgs["audit"]
	c = HostCheck{ID: "HC-003", Title: "auditd is installed and running", Severity: "medium", Status: "pass",
		Fix: "Install auditd and enable it so kernel audit events are recorded."}
	if len(s.Packages) > 0 && !hasAudit {
		c.Status, c.Detail = "fail", "auditd package not found"
	} else if hasAudit && len(s.Services) > 0 && !running["auditd"] {
		c.Status, c.Detail = "fail", "auditd installed but not running"
	}
	out = append(out, c)
	// HC-004: host firewall present
	fw := pkgs["ufw"] || pkgs["firewalld"] || pkgs["iptables"] || pkgs["nftables"]
	c = HostCheck{ID: "HC-004", Title: "A host firewall package is installed", Severity: "medium", Status: "pass",
		Fix: "Install and enable ufw, firewalld or nftables."}
	if len(s.Packages) > 0 && !fw {
		c.Status, c.Detail = "fail", "no ufw / firewalld / iptables / nftables found"
	}
	out = append(out, c)
	// HC-005: time sync
	ts := pkgs["chrony"] || pkgs["ntp"] || pkgs["ntpsec"] || pkgs["systemd-timesyncd"]
	c = HostCheck{ID: "HC-005", Title: "Time synchronisation is configured", Severity: "low", Status: "pass",
		Fix: "Install chrony or enable systemd-timesyncd; accurate time is needed for log correlation."}
	if len(s.Packages) > 0 && !ts && !running["systemd-timesyncd"] {
		c.Status, c.Detail = "fail", "no NTP client found"
	}
	out = append(out, c)
	// HC-006: databases exposed on all-interface well-known ports
	var dbs []string
	for _, p := range []struct {
		n int
		l string
	}{{3306, "mysql"}, {5432, "postgres"}, {27017, "mongodb"}, {6379, "redis"}, {9200, "elasticsearch"}, {11211, "memcached"}} {
		if open[p.n] {
			dbs = append(dbs, p.l)
		}
	}
	c = HostCheck{ID: "HC-006", Title: "Database / cache ports are not reachable on the network", Severity: "high", Status: "pass",
		Fix: "Bind the service to 127.0.0.1 or a private interface and restrict with the firewall."}
	if len(dbs) > 0 {
		c.Status, c.Detail = "fail", strings.Join(dbs, ", ")+" (port open to the scanner; confirm binding)"
	}
	out = append(out, c)
	// HC-007: scanner-reported local privilege-escalation risks
	var risky []string
	for _, f := range s.Findings {
		cat := strings.ToLower(f.Category)
		if strings.Contains(cat, "suid") || strings.Contains(strings.ToLower(f.Title), "world-writable") {
			risky = append(risky, f.Title)
		}
	}
	c = HostCheck{ID: "HC-007", Title: "No suspicious SUID binaries or world-writable PATH directories", Severity: "high", Status: "pass",
		Fix: "Remove unneeded SUID bits (chmod u-s) and tighten directory permissions."}
	if len(risky) > 0 {
		c.Status, c.Detail = "fail", strings.Join(sortedStrings(risky), "; ")
	}
	out = append(out, c)
	// HC-008: remote-administration and file-sharing services listening
	var remote []string
	for _, p := range []struct {
		n int
		l string
	}{{3389, "rdp"}, {5900, "vnc"}, {445, "smb"}, {139, "netbios"}, {111, "rpcbind"}, {2049, "nfs"}} {
		if open[p.n] {
			remote = append(remote, p.l)
		}
	}
	for _, u := range s.UDP {
		if u.Port == 161 {
			remote = append(remote, "snmp")
		}
	}
	c = HostCheck{ID: "HC-008", Title: "Remote-administration and file-sharing services are not exposed", Severity: "medium", Status: "pass",
		Fix: "Disable the service or restrict it to management networks with the host firewall."}
	if len(remote) > 0 {
		c.Status, c.Detail = "fail", strings.Join(remote, ", ")
	}
	out = append(out, c)
	// HC-009: offensive / reconnaissance tooling installed
	var tools []string
	for name := range offensiveToolPkgs {
		if pkgs[name] {
			tools = append(tools, name)
		}
	}
	c = HostCheck{ID: "HC-009", Title: "No offensive or reconnaissance tools installed", Severity: "medium", Status: "pass",
		Fix: "Remove tools that are not needed on this host; they are commonly used after compromise."}
	if len(tools) > 0 {
		c.Status, c.Detail = "fail", strings.Join(sortedStrings(tools), ", ")
	}
	out = append(out, c)
	// HC-010: end-of-life operating system
	c = HostCheck{ID: "HC-010", Title: "Operating system release is still supported", Severity: "high", Status: "pass",
		Fix: "Upgrade to a supported release; EOL systems receive no security fixes."}
	if eolRelease(s.System.OSRelease) {
		c.Status, c.Detail = "fail", s.System.OSRelease
	}
	out = append(out, c)
	// HC-011: automatic security updates (Debian/Ubuntu and RPM families)
	auto := pkgs["unattended-upgrades"] || pkgs["dnf-automatic"] || pkgs["yum-cron"]
	c = HostCheck{ID: "HC-011", Title: "Automatic security updates are configured", Severity: "low", Status: "pass",
		Fix: "Install unattended-upgrades (Debian/Ubuntu) or dnf-automatic (RHEL family)."}
	if len(s.Packages) > 0 && !auto {
		c.Status, c.Detail = "fail", "no unattended-upgrades / dnf-automatic / yum-cron package"
	}
	out = append(out, c)
	return out
}

func sortedStrings(in []string) []string {
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && in[j] < in[j-1]; j-- {
			in[j], in[j-1] = in[j-1], in[j]
		}
	}
	return in
}

func handleEndpointCompliance(db, backendDB *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.PathValue("host")
		f := store.EventFilter{HostExact: host, EventType: "vulnerability.scan", Limit: 1}
		events, _, err := db.QueryEvents(r.Context(), f)
		if (err != nil || len(events) == 0) && backendDB != nil {
			events, _, err = backendDB.QueryEvents(r.Context(), f)
		}
		if err != nil || len(events) == 0 {
			writeJSONError(w, http.StatusNotFound, "no vulnerability scan found for this host")
			return
		}
		checks := endpointChecks(events[0].Raw)
		pass, fail, unknown := 0, 0, 0
		for _, c := range checks {
			switch c.Status {
			case "pass":
				pass++
			case "fail":
				fail++
			default:
				unknown++
			}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"host": host, "checks": checks, "passed": pass, "failed": fail, "unknown": unknown, "total": len(checks), "os": hostOSFamily(events[0].Raw),
			"scope": "CIS-inspired host hygiene checks reported by the agent plus package/port analysis; not a full CIS benchmark.",
		})
	}
}
