package api

// linux_fp_rules.go - Linux/macOS matchers rewritten to cut false positives.
// Command lines here are in agent format (argv joined by spaces, quotes lost),
// so rules look at executables and argv tokens rather than substrings.

import (
	"regexp"
	"strings"

	"obsidianwatch/management/internal/store"
)

func parentBase(ev store.Event) string { return pathBase(rawStringField(ev, "parent_exe")) }

func inSet(s string, set ...string) bool {
	for _, x := range set {
		if s == x {
			return true
		}
	}
	return false
}

// ── kernel modules ───────────────────────────────────────────────────────────

var modprobeSafeParents = []string{"systemd", "systemd-udevd", "udevd", "kmod", "dockerd", "containerd", "networkmanager", "wg-quick"}

func linKernelModule(ev store.Event) bool {
	if ev.EventType != "process" {
		return false
	}
	if exeIn(ev, "modprobe") {
		return !inSet(parentBase(ev), modprobeSafeParents...)
	}
	if exeIn(ev, "insmod") {
		for _, a := range argv(ev) {
			la := strings.ToLower(a)
			if strings.Contains(la, ".ko") {
				return !strings.HasPrefix(la, "/lib/modules/") && !strings.HasPrefix(la, "/usr/lib/modules/")
			}
		}
	}
	return false
}

// ── containers ───────────────────────────────────────────────────────────────

func linContainerTool(ev store.Event) bool {
	return ev.EventType == "process" &&
		(exeIn(ev, "deepce", "amicontained", "cdk") || containsAny(cl(ev), "deepce", "amicontained"))
}

// linContainerIndicator: weak indicators, observe by default. A bare
// docker.sock path is not an indicator (Portainer, Traefik, Watchtower).
// `docker run --privileged` is left to L-CTR-001.
func linContainerIndicator(ev store.Event) bool {
	return ev.EventType == "process" &&
		(exeIn(ev, "nsenter", "pivot_root") || strings.Contains(cl(ev), "cap_sys_admin"))
}

// ── /etc/shadow ──────────────────────────────────────────────────────────────

var shadowSafeExe = []string{"passwd", "chpasswd", "useradd", "usermod", "userdel", "chage", "vipw", "vigr",
	"pwck", "grpck", "adduser", "deluser", "systemd-sysusers", "groupadd", "groupmod", "groupdel", "newusers", "pwconv", "grpconv"}

func linShadowAccess(ev store.Event) bool {
	exe := exeBase(ev)
	switch ev.EventType {
	case "process":
		return containsAny(cl(ev), "/etc/shadow", "/etc/gshadow") && !inSet(exe, shadowSafeExe...)
	case "file":
		// FIM: the writer (raw "exe", from writer_attr.go) must be known and unexpected.
		return containsAny(fp(ev), "/etc/shadow", "/etc/gshadow") && exe != "" && !inSet(exe, shadowSafeExe...)
	}
	return false
}

func linShadowTools(ev store.Event) bool {
	return ev.EventType == "process" && exeIn(ev, "unshadow", "john", "hashcat")
}

// ── credential files ─────────────────────────────────────────────────────────

var sshPrivKeyNames = []string{"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"}
var sshKeyReaders = []string{"cat", "less", "more", "head", "tail", "cp", "base64", "xxd", "tar", "zip", "curl", "nc"}
var sshKeyBenign = []string{"ssh", "ssh-agent", "ssh-add", "ssh-keygen", "scp", "sftp", "git", "rsync"}

func isSSHPrivKeyPath(p string) bool {
	p = strings.Trim(strings.ToLower(p), `"'`)
	return inSet(pathBase(p), sshPrivKeyNames...)
}

func linSSHKeyAccess(ev store.Event) bool {
	switch ev.EventType {
	case "file":
		return isSSHPrivKeyPath(fp(ev)) && !inSet(exeBase(ev), sshKeyBenign...)
	case "process":
		if !inSet(exeBase(ev), sshKeyReaders...) && !procIn(ev, sshKeyReaders...) {
			return false
		}
		for _, a := range argv(ev) {
			if isSSHPrivKeyPath(a) {
				return true
			}
		}
	}
	return false
}

var cloudCredStores = []string{".aws/credentials", ".config/gcloud/credentials.db", ".config/gcloud/legacy_credentials",
	"application_default_credentials.json", ".azure/accesstokens.json", ".azure/msal_token_cache", ".azure/azureprofile.json"}
var cloudCLIs = []string{"aws", "az", "gcloud", "terraform", "kubectl", "aws-vault", "saml2aws"}

// cloudCredFileAccess is shared by L-T1552.005 and M-T1552.005. Config files,
// bare .azure/ or .config/gcloud and terraform.tfstate are ordinary.
func cloudCredFileAccess(ev store.Event) bool {
	if ev.EventType != "file" && ev.EventType != "process" {
		return false
	}
	if exeIn(ev, cloudCLIs...) {
		return false
	}
	return containsAny(fp(ev)+" "+cl(ev), cloudCredStores...)
}

// ── execution from temp dirs ─────────────────────────────────────────────────

var tmpExecExcluded = []string{"/tmp/go-build", "/tmp/.mount_", "/tmp/_mei", "/tmp/pip-", "/tmp/npm-",
	"/var/tmp/go-build", "/private/tmp/go-build", "/private/var/tmp/go-build"}

func execFromTmp(ev store.Event, dirs ...string) bool {
	if ev.EventType != "process" {
		return false
	}
	for _, p := range execPaths(ev) {
		for _, d := range dirs {
			if !strings.HasPrefix(p, d) {
				continue
			}
			excluded := false
			for _, x := range tmpExecExcluded {
				if strings.HasPrefix(p, x) {
					excluded = true
					break
				}
			}
			if !excluded {
				return true
			}
		}
	}
	return false
}

// ── DNS tunnelling ───────────────────────────────────────────────────────────

func dnsTunnelLike(ev store.Event) bool {
	if ev.EventType != "dns" || ev.DstIP == nil {
		return false
	}
	d := strings.ToLower(strings.TrimSuffix(*ev.DstIP, "."))
	if strings.HasSuffix(d, ".in-addr.arpa") || strings.HasSuffix(d, ".ip6.arpa") || strings.Contains(d, "_domainkey") {
		return false
	}
	if len(d) > 100 {
		return true
	}
	for _, l := range strings.Split(d, ".") {
		if len(l) > 52 {
			return true
		}
	}
	return false
}

// ── chmod ────────────────────────────────────────────────────────────────────

var worldWritableMode = regexp.MustCompile(`^(?:0?777|(?:a|o|ugo)[+=][rwxXst]*w[rwxXst]*)$`)

func chmodWorldWritable(ev store.Event) bool {
	if ev.EventType != "process" || !procIn(ev, "chmod") {
		return false
	}
	a := argv(ev)
	for i := 1; i < len(a); i++ {
		if worldWritableMode.MatchString(strings.ToLower(a[i])) {
			return true
		}
	}
	return false
}

// ── macOS ────────────────────────────────────────────────────────────────────

func macSecurityDump(ev store.Event) bool {
	if ev.EventType != "process" || !procIn(ev, "security") {
		return false
	}
	if inSet(parentBase(ev), "git-credential-osxkeychain", "aws-vault") {
		return false
	}
	c := cl(ev)
	if strings.Contains(c, "dump-keychain") {
		return true
	}
	if !containsAny(c, "find-generic-password", "find-internet-password") {
		return false
	}
	for _, a := range argv(ev) { // -w prints the password, -g prints it to stderr
		if len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.ContainsAny(a[1:], "wg") {
			return true
		}
	}
	return false
}
