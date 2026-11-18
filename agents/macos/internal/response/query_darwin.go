//go:build darwin

package response

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func qProcesses(ctx context.Context) ([]string, [][]string, error) {
	cols := []string{"pid", "ppid", "user", "name", "mem_mb", "path", "cmdline"}
	out, err := run(ctx, "ps", "-axww", "-o", "pid=,ppid=,user=,rss=,comm=")
	if err != nil {
		return nil, nil, err
	}
	args, _ := run(ctx, "ps", "-axww", "-o", "pid=,args=")
	cmd := map[string]string{}
	for _, l := range strings.Split(args, "\n") {
		if f := strings.Fields(l); len(f) > 0 {
			cmd[f[0]] = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), f[0]))
		}
	}
	var rows [][]string
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		path := strings.Join(f[4:], " ")
		rss, _ := strconv.ParseFloat(f[3], 64)
		rows = append(rows, []string{f[0], f[1], f[2], filepath.Base(path), strconv.FormatFloat(rss/1024, 'f', 1, 64), path, cmd[f[0]]})
	}
	return cols, rows, nil
}

func qConnections(ctx context.Context) ([]string, [][]string, error) {
	cols := []string{"proto", "state", "local", "remote", "pid", "process"}
	out, err := run(ctx, "lsof", "-nP", "-iTCP", "-iUDP")
	if err != nil && out == "" {
		return nil, nil, err
	}
	var rows [][]string
	for i, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if i == 0 || len(f) < 9 {
			continue
		}
		proto := strings.ToLower(f[7])
		name := strings.Join(f[8:], " ")
		state := ""
		if j := strings.Index(name, " ("); j > 0 {
			state = strings.Trim(name[j:], " ()")
			name = name[:j]
		}
		local, remote := name, "*"
		if a, b, ok := strings.Cut(name, "->"); ok {
			local, remote = a, b
		}
		if proto == "udp" && state == "" {
			state = "UNCONN"
		}
		rows = append(rows, []string{proto, state, local, remote, f[1], f[0]})
	}
	return cols, rows, nil
}

func plistJSON(ctx context.Context, path string) map[string]any {
	out, err := run(ctx, "plutil", "-convert", "json", "-o", "-", path)
	if err != nil {
		return nil
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(out), &m)
	return m
}

func qPersistence(ctx context.Context) ([]string, [][]string, error) {
	cols := []string{"type", "location", "detail"}
	var rows [][]string
	dirs := []string{"/Library/LaunchDaemons", "/Library/LaunchAgents"}
	homes, _ := filepath.Glob("/Users/*")
	for _, h := range homes {
		dirs = append(dirs, filepath.Join(h, "Library/LaunchAgents"))
	}
	for _, d := range dirs {
		m, _ := filepath.Glob(filepath.Join(d, "*.plist"))
		for _, p := range m {
			detail := ""
			if pl := plistJSON(ctx, p); pl != nil {
				if v, ok := pl["ProgramArguments"].([]any); ok {
					parts := make([]string, 0, len(v))
					for _, x := range v {
						parts = append(parts, strings.TrimSpace(toStr(x)))
					}
					detail = strings.Join(parts, " ")
				} else if v, ok := pl["Program"].(string); ok {
					detail = v
				}
			}
			t := "launch_agent"
			if strings.Contains(d, "Daemons") {
				t = "launch_daemon"
			}
			rows = append(rows, []string{t, p, detail})
		}
	}
	for _, p := range []string{"/etc/crontab", "/var/at/tabs"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			if b, err := os.ReadFile(p); err == nil {
				for _, l := range strings.Split(string(b), "\n") {
					if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
						rows = append(rows, []string{"cron", p, l})
					}
				}
			}
		}
	}
	for _, h := range homes {
		if b, err := os.ReadFile(filepath.Join(h, ".ssh/authorized_keys")); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				if f := strings.Fields(l); len(f) > 0 && !strings.HasPrefix(f[0], "#") {
					rows = append(rows, []string{"ssh_key", filepath.Join(h, ".ssh/authorized_keys"), f[len(f)-1]})
				}
			}
		}
	}
	return cols, rows, nil
}

func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func qSoftware(ctx context.Context) ([]string, [][]string, error) {
	cols := []string{"name", "version", "path"}
	var rows [][]string
	apps, _ := filepath.Glob("/Applications/*.app")
	more, _ := filepath.Glob("/Applications/*/*.app")
	apps = append(apps, more...)
	for _, a := range apps {
		pl := plistJSON(ctx, filepath.Join(a, "Contents/Info.plist"))
		ver, _ := pl["CFBundleShortVersionString"].(string)
		rows = append(rows, []string{strings.TrimSuffix(filepath.Base(a), ".app"), ver, a})
	}
	return cols, rows, nil
}

func qUsers(ctx context.Context) ([]string, [][]string, error) {
	cols := []string{"user", "uid", "admin"}
	out, err := run(ctx, "dscl", ".", "-list", "/Users", "UniqueID")
	if err != nil {
		return nil, nil, err
	}
	adm, _ := run(ctx, "dscl", ".", "-read", "/Groups/admin", "GroupMembership")
	var rows [][]string
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) != 2 || strings.HasPrefix(f[0], "_") {
			continue
		}
		a := "no"
		for _, m := range strings.Fields(adm) {
			if m == f[0] {
				a = "yes"
			}
		}
		rows = append(rows, []string{f[0], f[1], a})
	}
	return cols, rows, nil
}
