package collector

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func cmdOut(name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// securityAgentMarkers maps a display name to a binary or directory whose
// presence indicates the product is installed.
var securityAgentMarkers = []struct{ name, path string }{
	{"ClamAV", "/usr/bin/clamscan"}, {"ClamAV daemon", "/usr/sbin/clamd"},
	{"CrowdStrike Falcon", "/opt/CrowdStrike/falconctl"}, {"SentinelOne", "/opt/sentinelone"},
	{"Microsoft Defender", "/opt/microsoft/mdatp"}, {"Sophos", "/opt/sophos-spl"},
	{"Trend Micro", "/opt/TrendMicro"}, {"Carbon Black", "/opt/carbonblack"},
	{"Cylance", "/opt/cylance"}, {"ESET", "/opt/eset"}, {"Elastic Defend", "/opt/Elastic/Endpoint"},
	{"Wazuh agent", "/var/ossec/bin/wazuh-control"}, {"Falco", "/usr/bin/falco"},
}

// collectPosture reads the Linux compliance values. Reads that fail give empty
// values, which the evaluator reports as unknown.
func collectPosture() []PostureCheck {
	var r linuxPostureRaw
	if src := cmdOut("findmnt", "-no", "SOURCE", "/"); src != "" {
		r.RootDeps = strings.ReplaceAll(cmdOut("lsblk", "-srno", "TYPE", src), "\n", " ")
	}
	r.SELinuxEnforce = readTrim("/sys/fs/selinux/enforce")
	r.AppArmorEnabled = readTrim("/sys/module/apparmor/parameters/enabled")
	r.AppArmorProfs = readTrim("/sys/kernel/security/apparmor/profiles")
	r.UFWStatus = cmdOut("ufw", "status")
	r.FirewalldState = cmdOut("systemctl", "is-active", "firewalld")
	r.NftRuleset = cmdOut("nft", "list", "ruleset")
	r.IptablesRules = cmdOut("iptables", "-S")
	if _, err := exec.LookPath("sshd"); err == nil {
		r.SSHDInstalled = true
	} else if _, err := os.Stat("/usr/sbin/sshd"); err == nil {
		r.SSHDInstalled = true
	}
	if r.SSHDInstalled {
		bin := "sshd"
		if p, err := exec.LookPath("sshd"); err != nil || p == "" {
			bin = "/usr/sbin/sshd"
		}
		r.SSHDConfig = cmdOut(bin, "-T")
	}
	r.ASLR = readTrim("/proc/sys/kernel/randomize_va_space")
	r.Passwd = readTrim("/etc/passwd")
	if b, err := os.ReadFile("/etc/shadow"); err == nil {
		r.Shadow, r.ShadowReadable = string(b), true
	}
	for _, m := range securityAgentMarkers {
		if _, err := os.Stat(m.path); err == nil {
			r.SecurityAgents = append(r.SecurityAgents, m.name)
		}
	}
	if b, err := os.ReadFile("/etc/sudoers"); err == nil {
		r.SudoersReadable = true
		r.SudoersLines = append(r.SudoersLines, strings.Split(string(b), "\n")...)
		if files, _ := filepath.Glob("/etc/sudoers.d/*"); len(files) > 0 {
			for _, f := range files {
				if fb, err := os.ReadFile(f); err == nil {
					r.SudoersLines = append(r.SudoersLines, strings.Split(string(fb), "\n")...)
				}
			}
		}
	}
	return evalLinuxPosture(r)
}
