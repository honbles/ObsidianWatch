//go:build linux

package response

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func sh(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &out
	err := cmd.Run()
	return out.String(), err
}

func qProcesses(ctx context.Context) ([]string, [][]string, error) {
	cols := []string{"pid", "ppid", "user", "name", "mem_mb", "path", "cmdline"}
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil, nil, err
	}
	var rows [][]string
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := "/proc/" + e.Name()
		comm, _ := os.ReadFile(dir + "/comm")
		exe, _ := os.Readlink(dir + "/exe")
		cmd, _ := os.ReadFile(dir + "/cmdline")
		cmdline := strings.TrimSpace(strings.ReplaceAll(string(cmd), "\x00", " "))
		if cmdline == "" && exe == "" {
			continue // kernel thread
		}
		user := ""
		if st, err := os.Stat(dir); err == nil {
			user = uidName(st)
		}
		rows = append(rows, []string{strconv.Itoa(pid), strconv.Itoa(procPPID(pid)), user, strings.TrimSpace(string(comm)), procMemMB(dir), exe, cmdline})
	}
	sort.Slice(rows, func(i, j int) bool { a, _ := strconv.Atoi(rows[i][0]); b, _ := strconv.Atoi(rows[j][0]); return a < b })
	return cols, rows, nil
}

func qConnections(ctx context.Context) ([]string, [][]string, error) {
	cols := []string{"proto", "state", "local", "remote", "pid", "process"}
	out, err := sh(ctx, "ss", "-H", "-tunap")
	if err != nil && out == "" {
		return nil, nil, fmt.Errorf("ss is not available on this host: %v", err)
	}
	var rows [][]string
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 6 {
			continue
		}
		pid, proc := "", ""
		if len(f) >= 7 {
			// users:(("sshd",pid=812,fd=3))
			u := f[len(f)-1]
			if i := strings.Index(u, `(("`); i >= 0 {
				rest := u[i+3:]
				if j := strings.Index(rest, `"`); j > 0 {
					proc = rest[:j]
				}
			}
			if i := strings.Index(u, "pid="); i >= 0 {
				rest := u[i+4:]
				if j := strings.IndexAny(rest, ",)"); j > 0 {
					pid = rest[:j]
				}
			}
		}
		rows = append(rows, []string{f[0], f[1], f[4], f[5], pid, proc})
	}
	return cols, rows, nil
}

func qPersistence(ctx context.Context) ([]string, [][]string, error) {
	cols := []string{"type", "location", "detail"}
	var rows [][]string
	add := func(t, loc, d string) { rows = append(rows, []string{t, loc, d}) }
	// systemd units in admin/user locations with their ExecStart
	for _, dir := range []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system", "/etc/systemd/user"} {
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), ".service") && !strings.HasSuffix(e.Name(), ".timer") {
				continue
			}
			p := filepath.Join(dir, e.Name())
			exec := ""
			if b, err := os.ReadFile(p); err == nil {
				for _, l := range strings.Split(string(b), "\n") {
					if strings.HasPrefix(l, "ExecStart=") {
						exec = strings.TrimPrefix(l, "ExecStart=")
						break
					}
				}
			}
			if dir != "/etc/systemd/system" && dir != "/etc/systemd/user" && exec == "" {
				continue
			}
			add("systemd", p, exec)
		}
	}
	// cron
	crons := []string{"/etc/crontab"}
	for _, g := range []string{"/etc/cron.d/*", "/etc/cron.hourly/*", "/etc/cron.daily/*", "/etc/cron.weekly/*", "/var/spool/cron/*", "/var/spool/cron/crontabs/*"} {
		m, _ := filepath.Glob(g)
		crons = append(crons, m...)
	}
	for _, p := range crons {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(b), "\n") {
			l = strings.TrimSpace(l)
			if l != "" && !strings.HasPrefix(l, "#") && !strings.Contains(l[:min(len(l), 12)], "=") {
				add("cron", p, l)
			}
		}
	}
	// ssh keys and shell/profile hooks
	homes, _ := filepath.Glob("/home/*")
	homes = append(homes, "/root")
	for _, hm := range homes {
		if b, err := os.ReadFile(filepath.Join(hm, ".ssh/authorized_keys")); err == nil {
			n := 0
			for _, l := range strings.Split(string(b), "\n") {
				if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") {
					n++
					f := strings.Fields(t)
					add("ssh_key", filepath.Join(hm, ".ssh/authorized_keys"), f[len(f)-1])
				}
			}
			_ = n
		}
	}
	for _, p := range []string{"/etc/rc.local", "/etc/ld.so.preload", "/etc/profile.d"} {
		if st, err := os.Stat(p); err == nil {
			if st.IsDir() {
				m, _ := filepath.Glob(p + "/*")
				for _, f := range m {
					add("profile_hook", f, "")
				}
			} else if st.Size() > 0 {
				add("startup_file", p, fmt.Sprintf("%d bytes", st.Size()))
			}
		}
	}
	return cols, rows, nil
}

func qSoftware(ctx context.Context) ([]string, [][]string, error) {
	cols := []string{"name", "version", "manager"}
	var rows [][]string
	if out, err := sh(ctx, "dpkg-query", "-W", "-f=${Package}\t${Version}\n"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			if f := strings.Split(l, "\t"); len(f) == 2 {
				rows = append(rows, []string{f[0], f[1], "dpkg"})
			}
		}
	} else if out, err := sh(ctx, "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			if f := strings.Split(l, "\t"); len(f) == 2 {
				rows = append(rows, []string{f[0], f[1], "rpm"})
			}
		}
	} else if out, err := sh(ctx, "apk", "info", "-v"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			if i := strings.LastIndex(l, "-"); i > 0 {
				j := strings.LastIndex(l[:i], "-")
				if j > 0 {
					rows = append(rows, []string{l[:j], l[j+1:], "apk"})
				}
			}
		}
	}
	return cols, rows, nil
}

func qUsers(ctx context.Context) ([]string, [][]string, error) {
	cols := []string{"user", "uid", "shell", "home", "admin"}
	sudoers := map[string]bool{}
	if b, err := os.ReadFile("/etc/group"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			f := strings.Split(l, ":")
			if len(f) == 4 && (f[0] == "sudo" || f[0] == "wheel" || f[0] == "admin") {
				for _, u := range strings.Split(f[3], ",") {
					sudoers[u] = true
				}
			}
		}
	}
	b, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil, nil, err
	}
	var rows [][]string
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Split(l, ":")
		if len(f) < 7 {
			continue
		}
		admin := "no"
		if f[2] == "0" || sudoers[f[0]] {
			admin = "yes"
		}
		rows = append(rows, []string{f[0], f[2], f[6], f[5], admin})
	}
	return cols, rows, nil
}

// procMemMB returns the resident set size in MB (one decimal), "" when unreadable.
func procMemMB(dir string) string {
	b, err := os.ReadFile(dir + "/statm")
	if err != nil {
		return ""
	}
	f := strings.Fields(string(b))
	if len(f) < 2 {
		return ""
	}
	pages, _ := strconv.ParseInt(f[1], 10, 64)
	return strconv.FormatFloat(float64(pages*int64(os.Getpagesize()))/1048576, 'f', 1, 64)
}
