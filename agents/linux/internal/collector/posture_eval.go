package collector

// posture_eval.go - evaluates Linux endpoint compliance from raw file and
// command output. No OS calls here so it is unit tested directly. Ids match
// the backend catalog (endpoint_posture.go).

import (
	"fmt"
	"regexp"
	"strings"
)

// PostureCheck is one endpoint compliance result sent in the vulnerability scan.
type PostureCheck struct {
	ID     string `json:"id"`
	Status string `json:"status"` // pass | fail | unknown
	Detail string `json:"detail,omitempty"`
}

// linuxPostureRaw holds raw values. Empty strings mean "could not read".
type linuxPostureRaw struct {
	RootDeps        string // lsblk -srno TYPE <root source>: device types under /
	SELinuxEnforce  string // /sys/fs/selinux/enforce
	AppArmorEnabled string // /sys/module/apparmor/parameters/enabled
	AppArmorProfs   string // /sys/kernel/security/apparmor/profiles
	UFWStatus       string // ufw status
	FirewalldState  string // systemctl is-active firewalld
	NftRuleset      string // nft list ruleset
	IptablesRules   string // iptables -S
	SSHDInstalled   bool
	SSHDConfig      string // sshd -T (effective config, lower-case keys)
	ASLR            string // /proc/sys/kernel/randomize_va_space
	Passwd          string // /etc/passwd
	Shadow          string // /etc/shadow
	ShadowReadable  bool
	SecurityAgents  []string // names of AV/EDR products found
	SudoersLines    []string // lines from /etc/sudoers and /etc/sudoers.d/*
	SudoersReadable bool
}

func lp(id, status, detail string) PostureCheck {
	return PostureCheck{ID: id, Status: status, Detail: detail}
}

var nopasswdAll = regexp.MustCompile(`(?i)\bNOPASSWD\s*:\s*ALL\b`)

func evalLinuxPosture(r linuxPostureRaw) []PostureCheck {
	var out []PostureCheck

	// EC-L-001 encrypted root
	switch {
	case strings.TrimSpace(r.RootDeps) == "":
		out = append(out, lp("EC-L-001", "unknown", "could not resolve the root device"))
	case containsWord(r.RootDeps, "crypt"):
		out = append(out, lp("EC-L-001", "pass", ""))
	default:
		out = append(out, lp("EC-L-001", "fail", "no encrypted (LUKS) layer under /"))
	}

	// EC-L-002 SELinux enforcing or AppArmor with loaded profiles
	switch {
	case strings.TrimSpace(r.SELinuxEnforce) == "1":
		out = append(out, lp("EC-L-002", "pass", ""))
	case strings.HasPrefix(strings.ToUpper(strings.TrimSpace(r.AppArmorEnabled)), "Y") && strings.TrimSpace(r.AppArmorProfs) != "":
		out = append(out, lp("EC-L-002", "pass", ""))
	case strings.TrimSpace(r.SELinuxEnforce) == "0":
		out = append(out, lp("EC-L-002", "fail", "SELinux is in permissive mode"))
	default:
		out = append(out, lp("EC-L-002", "fail", "neither SELinux nor AppArmor is enforcing"))
	}

	// EC-L-003 firewall
	fwDetail := ""
	switch {
	case strings.Contains(strings.ToLower(r.UFWStatus), "status: active"):
	case strings.TrimSpace(r.FirewalldState) == "active":
	case strings.Contains(r.NftRuleset, "chain ") && strings.Contains(r.NftRuleset, "hook input"):
	case iptablesActive(r.IptablesRules):
	default:
		fwDetail = "no active ufw, firewalld, nftables input chain or iptables rules"
	}
	switch {
	case fwDetail == "":
		out = append(out, lp("EC-L-003", "pass", ""))
	case r.UFWStatus == "" && r.FirewalldState == "" && r.NftRuleset == "" && r.IptablesRules == "":
		out = append(out, lp("EC-L-003", "unknown", "no firewall tool could be queried (need root?)"))
	default:
		out = append(out, lp("EC-L-003", "fail", fwDetail))
	}

	// EC-L-004 / 005 sshd
	switch {
	case !r.SSHDInstalled:
		out = append(out, lp("EC-L-004", "pass", ""), lp("EC-L-005", "pass", ""))
	case r.SSHDConfig == "":
		out = append(out, lp("EC-L-004", "unknown", "sshd -T unavailable"), lp("EC-L-005", "unknown", "sshd -T unavailable"))
	default:
		cfg := sshdValues(r.SSHDConfig)
		switch v := cfg["permitrootlogin"]; v {
		case "no", "prohibit-password", "without-password", "forced-commands-only":
			if v == "no" {
				out = append(out, lp("EC-L-004", "pass", ""))
			} else {
				out = append(out, lp("EC-L-004", "pass", "root may use keys only"))
			}
		case "":
			out = append(out, lp("EC-L-004", "unknown", "PermitRootLogin not reported"))
		default:
			out = append(out, lp("EC-L-004", "fail", "PermitRootLogin "+v))
		}
		switch cfg["passwordauthentication"] {
		case "no":
			out = append(out, lp("EC-L-005", "pass", ""))
		case "":
			out = append(out, lp("EC-L-005", "unknown", "PasswordAuthentication not reported"))
		default:
			out = append(out, lp("EC-L-005", "fail", "password logins are accepted"))
		}
	}

	// EC-L-006 ASLR
	switch strings.TrimSpace(r.ASLR) {
	case "2":
		out = append(out, lp("EC-L-006", "pass", ""))
	case "":
		out = append(out, lp("EC-L-006", "unknown", "randomize_va_space unreadable"))
	default:
		out = append(out, lp("EC-L-006", "fail", "randomize_va_space = "+strings.TrimSpace(r.ASLR)))
	}

	// EC-L-007 only root has UID 0
	if strings.TrimSpace(r.Passwd) == "" {
		out = append(out, lp("EC-L-007", "unknown", "/etc/passwd unreadable"))
	} else if extra := uidZeroExtras(r.Passwd); len(extra) > 0 {
		out = append(out, lp("EC-L-007", "fail", "extra UID 0 accounts: "+strings.Join(extra, ", ")))
	} else {
		out = append(out, lp("EC-L-007", "pass", ""))
	}

	// EC-L-008 empty passwords
	if !r.ShadowReadable {
		out = append(out, lp("EC-L-008", "unknown", "/etc/shadow unreadable (agent not root?)"))
	} else if e := emptyPasswordAccounts(r.Shadow); len(e) > 0 {
		out = append(out, lp("EC-L-008", "fail", "accounts without a password: "+strings.Join(e, ", ")))
	} else {
		out = append(out, lp("EC-L-008", "pass", ""))
	}

	// EC-L-009 AV / EDR
	if len(r.SecurityAgents) > 0 {
		out = append(out, lp("EC-L-009", "pass", "found: "+strings.Join(r.SecurityAgents, ", ")))
	} else {
		out = append(out, lp("EC-L-009", "fail", "no known antivirus or EDR agent found"))
	}

	// EC-L-010 passwordless sudo for everything
	switch {
	case !r.SudoersReadable:
		out = append(out, lp("EC-L-010", "unknown", "sudoers unreadable"))
	default:
		hits := 0
		for _, l := range r.SudoersLines {
			l = strings.TrimSpace(l)
			if l != "" && !strings.HasPrefix(l, "#") && nopasswdAll.MatchString(l) {
				hits++
			}
		}
		if hits > 0 {
			out = append(out, lp("EC-L-010", "fail", fmt.Sprintf("%d sudoers rule(s) grant NOPASSWD: ALL", hits)))
		} else {
			out = append(out, lp("EC-L-010", "pass", ""))
		}
	}
	return out
}

func containsWord(s, w string) bool {
	for _, f := range strings.Fields(s) {
		if f == w {
			return true
		}
	}
	return false
}

// iptablesActive is true when iptables has any rule or a restrictive default.
func iptablesActive(rules string) bool {
	for _, l := range strings.Split(rules, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "-A ") {
			return true
		}
		if strings.HasPrefix(l, "-P INPUT DROP") || strings.HasPrefix(l, "-P INPUT REJECT") {
			return true
		}
	}
	return false
}

func sshdValues(cfg string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(cfg, "\n") {
		f := strings.Fields(strings.ToLower(l))
		if len(f) >= 2 {
			if _, seen := m[f[0]]; !seen {
				m[f[0]] = f[1]
			}
		}
	}
	return m
}

func uidZeroExtras(passwd string) []string {
	var out []string
	for _, l := range strings.Split(passwd, "\n") {
		f := strings.Split(strings.TrimSpace(l), ":")
		if len(f) >= 3 && f[2] == "0" && f[0] != "root" {
			out = append(out, f[0])
		}
	}
	return out
}

// emptyPasswordAccounts returns accounts whose shadow password field is empty.
// "!" , "*" and "!!" mean locked / no password login and are fine.
func emptyPasswordAccounts(shadow string) []string {
	var out []string
	for _, l := range strings.Split(shadow, "\n") {
		f := strings.Split(strings.TrimSpace(l), ":")
		if len(f) >= 2 && f[0] != "" && f[1] == "" {
			out = append(out, f[0])
		}
	}
	return out
}
