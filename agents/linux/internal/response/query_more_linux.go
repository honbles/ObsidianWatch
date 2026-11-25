//go:build linux

package response

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func qOSMore(ctx context.Context, p Params) ([]string, [][]string, error) {
	switch p.Kind {
	case "services":
		return qServicesLinux(ctx)
	case "scheduled_tasks":
		return qScheduledLinux(ctx)
	case "sessions":
		return qSessionsUnix(ctx)
	case "firewall_rules":
		return qFirewallLinux(ctx)
	case "shares":
		return qSharesLinux()
	case "certificates":
		return qCertsLinux()
	case "usb_devices":
		return qUSBLinux()
	case "drivers":
		return qModulesLinux()
	case "loaded_modules":
		return qMappedLibsLinux(p.Match)
	case "dns_cache", "named_pipes", "registry", "patches":
		return nil, nil, errKindUnsupported
	}
	return nil, nil, errUnknownKind
}

func qServicesLinux(ctx context.Context) ([]string, [][]string, error) {
	cols := []string{"unit", "load", "active", "sub", "enabled", "description"}
	out, err := sh(ctx, "systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", "--no-pager")
	if err != nil && out == "" {
		// No systemd (containers, SysV hosts): list init scripts instead.
		scripts, _ := os.ReadDir("/etc/init.d")
		var rows [][]string
		for _, sc := range scripts {
			if !sc.IsDir() && sc.Name() != "README" {
				rows = append(rows, []string{sc.Name(), "init.d", "", "", "", "/etc/init.d/" + sc.Name()})
			}
		}
		return cols, rows, nil
	}
	enabled := map[string]string{}
	if uf, _ := sh(ctx, "systemctl", "list-unit-files", "--type=service", "--no-legend", "--plain", "--no-pager"); uf != "" {
		for _, l := range strings.Split(uf, "\n") {
			if f := strings.Fields(l); len(f) >= 2 {
				enabled[f[0]] = f[1]
			}
		}
	}
	var rows [][]string
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(l), "●"))
		if len(f) < 4 {
			continue
		}
		rows = append(rows, []string{f[0], f[1], f[2], f[3], enabled[f[0]], strings.Join(f[4:], " ")})
	}
	return cols, rows, nil
}

func qScheduledLinux(ctx context.Context) ([]string, [][]string, error) {
	cols := []string{"type", "owner", "schedule", "command", "source"}
	var rows [][]string
	addCron := func(path, owner string, hasUser bool) {
		f, err := os.Open(path)
		if err != nil {
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			fl := strings.Fields(l)
			if len(fl) > 0 && strings.Contains(fl[0], "=") { // environment line
				continue
			}
			var sched string
			var rest []string
			if strings.HasPrefix(l, "@") {
				sched, rest = fl[0], fl[1:]
			} else if len(fl) >= 6 {
				sched, rest = strings.Join(fl[:5], " "), fl[5:]
			} else {
				continue
			}
			who := owner
			if hasUser && len(rest) > 1 {
				who, rest = rest[0], rest[1:]
			}
			rows = append(rows, []string{"cron", who, sched, strings.Join(rest, " "), path})
		}
	}
	addCron("/etc/crontab", "", true)
	ds, _ := filepath.Glob("/etc/cron.d/*")
	for _, d := range ds {
		addCron(d, "", true)
	}
	for _, dir := range []string{"/var/spool/cron/crontabs", "/var/spool/cron"} {
		us, _ := os.ReadDir(dir)
		for _, u := range us {
			if !u.IsDir() {
				addCron(filepath.Join(dir, u.Name()), u.Name(), false)
			}
		}
	}
	for _, period := range []string{"hourly", "daily", "weekly", "monthly"} {
		fs, _ := os.ReadDir("/etc/cron." + period)
		for _, f := range fs {
			if !f.IsDir() && !strings.HasPrefix(f.Name(), ".") {
				rows = append(rows, []string{"cron." + period, "root", period, filepath.Join("/etc/cron."+period, f.Name()), "/etc/cron." + period})
			}
		}
	}
	if out, _ := sh(ctx, "systemctl", "list-timers", "--all", "--no-legend", "--plain", "--no-pager"); out != "" {
		for _, l := range strings.Split(out, "\n") {
			f := strings.Fields(l)
			if len(f) < 2 {
				continue
			}
			// The last two fields are the timer and the unit it activates.
			rows = append(rows, []string{"systemd_timer", "", strings.Join(f[:len(f)-2], " "), f[len(f)-1], f[len(f)-2]})
		}
	}
	if out, _ := sh(ctx, "atq"); out != "" {
		for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
			f := strings.Fields(l)
			if len(f) >= 2 {
				rows = append(rows, []string{"at", f[len(f)-1], strings.Join(f[1:len(f)-1], " "), "job " + f[0], "atq"})
			}
		}
	}
	return cols, rows, nil
}

// qSessionsUnix lists logged-in sessions from who(1).
func qSessionsUnix(ctx context.Context) ([]string, [][]string, error) {
	cols := []string{"user", "terminal", "since", "from"}
	out, err := sh(ctx, "who")
	if err != nil && out == "" {
		return nil, nil, err
	}
	var rows [][]string
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 3 {
			continue
		}
		from := ""
		if last := f[len(f)-1]; strings.HasPrefix(last, "(") {
			from = strings.Trim(last, "()")
			f = f[:len(f)-1]
		}
		rows = append(rows, []string{f[0], f[1], strings.Join(f[2:], " "), from})
	}
	return cols, rows, nil
}

func qFirewallLinux(ctx context.Context) ([]string, [][]string, error) {
	cols := []string{"backend", "table", "chain", "rule"}
	var rows [][]string
	if out, err := sh(ctx, "nft", "list", "ruleset"); err == nil && out != "" {
		table, chain := "", ""
		for _, l := range strings.Split(out, "\n") {
			t := strings.TrimSpace(l)
			switch {
			case strings.HasPrefix(t, "table "):
				table, chain = strings.TrimSuffix(strings.TrimPrefix(t, "table "), " {"), ""
			case strings.HasPrefix(t, "chain "):
				chain = strings.TrimSuffix(strings.TrimPrefix(t, "chain "), " {")
			case t == "" || t == "}" || strings.HasPrefix(t, "type ") && strings.Contains(t, "hook"):
				if strings.Contains(t, "hook") {
					rows = append(rows, []string{"nftables", table, chain, t})
				}
			default:
				if chain != "" {
					rows = append(rows, []string{"nftables", table, chain, t})
				}
			}
		}
		return cols, rows, nil
	}
	out, err := sh(ctx, "iptables-save")
	if err != nil && out == "" {
		return nil, nil, err
	}
	table := ""
	for _, l := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(l, "*"):
			table = l[1:]
		case strings.HasPrefix(l, ":"):
			f := strings.Fields(l[1:])
			if len(f) >= 2 {
				rows = append(rows, []string{"iptables", table, f[0], "policy " + f[1]})
			}
		case strings.HasPrefix(l, "-A "):
			f := strings.Fields(l)
			if len(f) >= 2 {
				rows = append(rows, []string{"iptables", table, f[1], strings.Join(f[2:], " ")})
			}
		}
	}
	return cols, rows, nil
}

func qSharesLinux() ([]string, [][]string, error) {
	cols := []string{"type", "name", "path", "options"}
	var rows [][]string
	if f, err := os.Open("/etc/exports"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if l == "" || strings.HasPrefix(l, "#") {
				continue
			}
			fl := strings.Fields(l)
			rows = append(rows, []string{"nfs", fl[0], fl[0], strings.Join(fl[1:], " ")})
		}
		f.Close()
	}
	if f, err := os.Open("/etc/samba/smb.conf"); err == nil {
		section, path, opts := "", "", []string{}
		flush := func() {
			if section != "" && section != "global" {
				rows = append(rows, []string{"smb", section, path, strings.Join(opts, "; ")})
			}
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if l == "" || l[0] == '#' || l[0] == ';' {
				continue
			}
			if strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]") {
				flush()
				section, path, opts = strings.Trim(l, "[]"), "", nil
				continue
			}
			k, v, _ := strings.Cut(l, "=")
			k, v = strings.TrimSpace(strings.ToLower(k)), strings.TrimSpace(v)
			if k == "path" {
				path = v
			} else if k == "guest ok" || k == "public" || k == "writable" || k == "writeable" || k == "read only" || k == "valid users" {
				opts = append(opts, k+"="+v)
			}
		}
		flush()
		f.Close()
	}
	return cols, rows, nil
}

// qCertsLinux lists CA certificates added locally (distribution bundles are
// skipped): the place a rogue root CA for TLS interception would be.
func qCertsLinux() ([]string, [][]string, error) {
	var rows [][]string
	for _, dir := range []string{"/usr/local/share/ca-certificates", "/etc/pki/ca-trust/source/anchors", "/etc/ca-certificates/trust-source/anchors", "/usr/share/pki/trust/anchors"} {
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if b, err := os.ReadFile(path); err == nil {
				rows = append(rows, certRows("system-added", path, b)...)
			}
			return nil
		})
	}
	return certCols, rows, nil
}

func qUSBLinux() ([]string, [][]string, error) {
	cols := []string{"bus_id", "vendor_id", "product_id", "manufacturer", "product", "serial", "class"}
	var rows [][]string
	devs, _ := filepath.Glob("/sys/bus/usb/devices/*")
	rd := func(dir, f string) string {
		b, _ := os.ReadFile(filepath.Join(dir, f))
		return strings.TrimSpace(string(b))
	}
	for _, d := range devs {
		if rd(d, "idVendor") == "" {
			continue
		}
		rows = append(rows, []string{filepath.Base(d), rd(d, "idVendor"), rd(d, "idProduct"), rd(d, "manufacturer"), rd(d, "product"), rd(d, "serial"), rd(d, "bDeviceClass")})
	}
	return cols, rows, nil
}

func qModulesLinux() ([]string, [][]string, error) {
	cols := []string{"name", "size", "used_by", "state", "taint"}
	f, err := os.Open("/proc/modules")
	if err != nil {
		return nil, nil, errors.New("kernel modules are not visible here (/proc/modules missing; a container?)")
	}
	defer f.Close()
	var rows [][]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		x := strings.Fields(sc.Text())
		if len(x) < 5 {
			continue
		}
		taint := ""
		if len(x) >= 7 {
			taint = strings.Trim(x[6], "()")
		}
		rows = append(rows, []string{x[0], x[1], strings.TrimSuffix(x[3], ","), x[4], taint})
	}
	return cols, rows, nil
}

// qMappedLibsLinux lists shared objects mapped into processes whose path
// contains match (required: a full listing would be enormous).
func qMappedLibsLinux(match string) ([]string, [][]string, error) {
	cols := []string{"pid", "process", "module"}
	needle := strings.ToLower(strings.TrimSpace(match))
	if needle == "" {
		return nil, nil, errMatchRequired
	}
	// The filter may name a column ("module:libssl"); only the value is used here.
	if _, v, ok := strings.Cut(needle, ":"); ok && !strings.HasPrefix(needle, "/") {
		needle = v
	}
	maps, _ := filepath.Glob("/proc/[0-9]*/maps")
	var rows [][]string
	for _, m := range maps {
		b, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		pid := filepath.Base(filepath.Dir(m))
		comm, _ := os.ReadFile(filepath.Join(filepath.Dir(m), "comm"))
		seen := map[string]bool{}
		for _, l := range strings.Split(string(b), "\n") {
			i := strings.IndexByte(l, '/')
			if i < 0 {
				continue
			}
			path := l[i:]
			if seen[path] || !strings.Contains(strings.ToLower(path), needle) {
				continue
			}
			seen[path] = true
			rows = append(rows, []string{pid, strings.TrimSpace(string(comm)), path})
		}
	}
	return cols, rows, nil
}
