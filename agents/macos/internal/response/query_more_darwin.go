//go:build darwin

package response

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

func qOSMore(ctx context.Context, p Params) ([]string, [][]string, error) {
	switch p.Kind {
	case "services":
		cols := []string{"label", "pid", "last_exit"}
		out, err := run(ctx, "launchctl", "list")
		if err != nil && out == "" {
			return nil, nil, err
		}
		var rows [][]string
		for i, l := range strings.Split(out, "\n") {
			f := strings.Fields(l)
			if i == 0 || len(f) < 3 {
				continue
			}
			rows = append(rows, []string{f[2], f[0], f[1]})
		}
		return cols, rows, nil
	case "scheduled_tasks":
		cols := []string{"type", "owner", "schedule", "command", "source"}
		var rows [][]string
		if out, _ := run(ctx, "crontab", "-l"); out != "" {
			for _, l := range strings.Split(out, "\n") {
				l = strings.TrimSpace(l)
				if l == "" || strings.HasPrefix(l, "#") {
					continue
				}
				f := strings.Fields(l)
				if len(f) >= 6 {
					rows = append(rows, []string{"cron", "root", strings.Join(f[:5], " "), strings.Join(f[5:], " "), "crontab -l"})
				}
			}
		}
		tabs, _ := filepath.Glob("/usr/lib/cron/tabs/*")
		for _, t := range tabs {
			b, _ := os.ReadFile(t)
			for _, l := range strings.Split(string(b), "\n") {
				f := strings.Fields(l)
				if len(f) >= 6 && !strings.HasPrefix(l, "#") {
					rows = append(rows, []string{"cron", filepath.Base(t), strings.Join(f[:5], " "), strings.Join(f[5:], " "), t})
				}
			}
		}
		// launchd jobs that run on a schedule rather than at load.
		for _, dir := range []string{"/Library/LaunchDaemons", "/Library/LaunchAgents"} {
			plists, _ := filepath.Glob(filepath.Join(dir, "*.plist"))
			for _, pl := range plists {
				b, err := os.ReadFile(pl)
				if err != nil {
					continue
				}
				s := string(b)
				if strings.Contains(s, "StartInterval") || strings.Contains(s, "StartCalendarInterval") {
					rows = append(rows, []string{"launchd", "", "interval/calendar", filepath.Base(pl), pl})
				}
			}
		}
		return cols, rows, nil
	case "sessions":
		cols := []string{"user", "terminal", "since", "from"}
		out, err := run(ctx, "who")
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
				from, f = strings.Trim(last, "()"), f[:len(f)-1]
			}
			rows = append(rows, []string{f[0], f[1], strings.Join(f[2:], " "), from})
		}
		return cols, rows, nil
	case "firewall_rules":
		cols := []string{"backend", "table", "chain", "rule"}
		var rows [][]string
		if out, _ := run(ctx, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"); out != "" {
			rows = append(rows, []string{"application_firewall", "", "global", strings.TrimSpace(out)})
		}
		if out, _ := run(ctx, "pfctl", "-sr"); out != "" {
			for _, l := range strings.Split(out, "\n") {
				if l = strings.TrimSpace(l); l != "" {
					rows = append(rows, []string{"pf", "", "rules", l})
				}
			}
		}
		return cols, rows, nil
	case "shares":
		cols := []string{"type", "name", "path", "options"}
		out, _ := run(ctx, "sharing", "-l")
		var rows [][]string
		name, path := "", ""
		for _, l := range strings.Split(out, "\n") {
			k, v, ok := strings.Cut(l, ":")
			if !ok {
				continue
			}
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			switch k {
			case "name":
				if name != "" {
					rows = append(rows, []string{"share", name, path, ""})
				}
				name, path = v, ""
			case "path":
				path = v
			}
		}
		if name != "" {
			rows = append(rows, []string{"share", name, path, ""})
		}
		return cols, rows, nil
	case "certificates":
		out, err := run(ctx, "security", "find-certificate", "-a", "-p", "/Library/Keychains/System.keychain")
		if err != nil && out == "" {
			return nil, nil, err
		}
		return certCols, certRows("System.keychain", "/Library/Keychains/System.keychain", []byte(out)), nil
	case "usb_devices":
		cols := []string{"name", "vendor_id", "product_id", "serial", "manufacturer"}
		out, err := run(ctx, "system_profiler", "SPUSBDataType")
		if err != nil && out == "" {
			return nil, nil, err
		}
		var rows [][]string
		cur := map[string]string{}
		flush := func() {
			if cur["Product ID"] != "" {
				rows = append(rows, []string{cur["name"], cur["Vendor ID"], cur["Product ID"], cur["Serial Number"], cur["Manufacturer"]})
			}
			cur = map[string]string{}
		}
		for _, l := range strings.Split(out, "\n") {
			t := strings.TrimSpace(l)
			if strings.HasSuffix(t, ":") && !strings.Contains(t[:len(t)-1], ":") {
				flush()
				cur["name"] = strings.TrimSuffix(t, ":")
				continue
			}
			if k, v, ok := strings.Cut(t, ": "); ok {
				cur[k] = v
			}
		}
		flush()
		return cols, rows, nil
	case "drivers":
		cols := []string{"name", "version", "loaded"}
		out, err := run(ctx, "kmutil", "showloaded", "--list-only")
		if err != nil && out == "" {
			out, err = run(ctx, "kextstat", "-l")
			if err != nil && out == "" {
				return nil, nil, err
			}
		}
		var rows [][]string
		for _, l := range strings.Split(out, "\n") {
			f := strings.Fields(l)
			if len(f) >= 7 {
				rows = append(rows, []string{f[5], strings.Trim(f[6], "()"), "yes"})
			}
		}
		return cols, rows, nil
	case "loaded_modules":
		return nil, nil, errKindUnsupported
	case "dns_cache", "named_pipes", "registry", "patches":
		return nil, nil, errKindUnsupported
	}
	return nil, nil, errUnknownKind
}
