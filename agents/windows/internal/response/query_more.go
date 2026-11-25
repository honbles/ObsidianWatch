package response

// query_more.go - the wider set of read-only live hunt kinds. Kinds that
// read files the same way on every OS live here; the rest are in
// query_more_<os>.go (qOSMore). Nothing here runs a command chosen by the
// caller: the kind picks a fixed collector, and Match only filters rows.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// MoreQueryKinds are the kinds added after the original seven. Not every
// kind exists on every OS; an unsupported one answers "not available".
var MoreQueryKinds = []string{
	"services", "scheduled_tasks", "sessions", "dns_cache", "browser_extensions",
	"shell_history", "recent_files", "firewall_rules", "shares", "certificates",
	"usb_devices", "drivers", "loaded_modules", "named_pipes", "registry", "patches",
}

var (
	errKindUnsupported = errors.New("not available on this OS")
	errUnknownKind     = errors.New("unknown query kind")
	errMatchRequired   = errors.New("match required for this kind (for example a module name)")
)

func queryMore(ctx context.Context, p Params) ([]string, [][]string, error) {
	switch p.Kind {
	case "browser_extensions":
		return qBrowserExtensions(userHomes())
	case "shell_history":
		return qShellHistory(userHomes())
	case "recent_files":
		return qRecentFiles(ctx, p)
	}
	return qOSMore(ctx, p)
}

// userHomes lists home directories of real users (and root/Administrator).
func userHomes() map[string]string {
	homes := map[string]string{} // user -> home
	switch runtime.GOOS {
	case "windows":
		root := os.Getenv("SystemDrive") + `\Users`
		if root == `\Users` {
			root = `C:\Users`
		}
		ents, _ := os.ReadDir(root)
		for _, e := range ents {
			n := e.Name()
			if !e.IsDir() || n == "Public" || n == "Default" || n == "Default User" || n == "All Users" {
				continue
			}
			homes[n] = filepath.Join(root, n)
		}
	case "darwin":
		ents, _ := os.ReadDir("/Users")
		for _, e := range ents {
			if e.IsDir() && e.Name() != "Shared" && !strings.HasPrefix(e.Name(), ".") {
				homes[e.Name()] = filepath.Join("/Users", e.Name())
			}
		}
		homes["root"] = "/var/root"
	default:
		f, err := os.Open("/etc/passwd")
		if err == nil {
			defer f.Close()
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				x := strings.Split(sc.Text(), ":")
				if len(x) < 7 {
					continue
				}
				uid, _ := strconv.Atoi(x[2])
				shell := x[6]
				if (uid == 0 || uid >= 1000) && !strings.HasSuffix(shell, "nologin") && !strings.HasSuffix(shell, "false") {
					if st, err := os.Stat(x[5]); err == nil && st.IsDir() {
						homes[x[0]] = x[5]
					}
				}
			}
		}
	}
	return homes
}

func sortedUsers(homes map[string]string) []string {
	users := make([]string, 0, len(homes))
	for u := range homes {
		users = append(users, u)
	}
	sort.Strings(users)
	return users
}

// ── browser extensions ───────────────────────────────────────────────────────

func chromiumProfileRoots(home string) map[string]string {
	switch runtime.GOOS {
	case "windows":
		l := filepath.Join(home, "AppData", "Local")
		return map[string]string{
			"chrome": filepath.Join(l, "Google", "Chrome", "User Data"),
			"edge":   filepath.Join(l, "Microsoft", "Edge", "User Data"),
			"brave":  filepath.Join(l, "BraveSoftware", "Brave-Browser", "User Data"),
		}
	case "darwin":
		a := filepath.Join(home, "Library", "Application Support")
		return map[string]string{
			"chrome": filepath.Join(a, "Google", "Chrome"),
			"edge":   filepath.Join(a, "Microsoft Edge"),
			"brave":  filepath.Join(a, "BraveSoftware", "Brave-Browser"),
		}
	default:
		c := filepath.Join(home, ".config")
		return map[string]string{
			"chrome":   filepath.Join(c, "google-chrome"),
			"chromium": filepath.Join(c, "chromium"),
			"edge":     filepath.Join(c, "microsoft-edge"),
			"brave":    filepath.Join(c, "BraveSoftware", "Brave-Browser"),
		}
	}
}

func firefoxProfilesDir(home string) string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(home, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles")
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles")
	default:
		return filepath.Join(home, ".mozilla", "firefox")
	}
}

// manifestName resolves a Chromium manifest name, following __MSG_x__
// references into _locales (en first).
func manifestName(dir string, m map[string]any) string {
	name, _ := m["name"].(string)
	if !strings.HasPrefix(name, "__MSG_") {
		return name
	}
	key := strings.TrimSuffix(strings.TrimPrefix(name, "__MSG_"), "__")
	def, _ := m["default_locale"].(string)
	for _, loc := range []string{"en", "en_US", def} {
		if loc == "" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, "_locales", loc, "messages.json"))
		if err != nil {
			continue
		}
		var msgs map[string]struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(b, &msgs) != nil {
			continue
		}
		for k, v := range msgs {
			if strings.EqualFold(k, key) && v.Message != "" {
				return v.Message
			}
		}
	}
	return name
}

func qBrowserExtensions(homes map[string]string) ([]string, [][]string, error) {
	cols := []string{"user", "browser", "profile", "id", "name", "version", "permissions"}
	var rows [][]string
	for _, user := range sortedUsers(homes) {
		home := homes[user]
		for browser, root := range chromiumProfileRoots(home) {
			profiles, _ := filepath.Glob(filepath.Join(root, "*", "Extensions"))
			for _, extDir := range profiles {
				profile := filepath.Base(filepath.Dir(extDir))
				ids, _ := os.ReadDir(extDir)
				for _, id := range ids {
					vers, _ := os.ReadDir(filepath.Join(extDir, id.Name()))
					for _, v := range vers {
						dir := filepath.Join(extDir, id.Name(), v.Name())
						b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
						if err != nil {
							continue
						}
						var m map[string]any
						if json.Unmarshal(b, &m) != nil {
							continue
						}
						ver, _ := m["version"].(string)
						var perms []string
						for _, k := range []string{"permissions", "host_permissions"} {
							if arr, ok := m[k].([]any); ok {
								for _, p := range arr {
									if s, ok := p.(string); ok {
										perms = append(perms, s)
									}
								}
							}
						}
						rows = append(rows, []string{user, browser, profile, id.Name(), manifestName(dir, m), ver, strings.Join(perms, " ")})
					}
				}
			}
		}
		// Firefox keeps installed add-ons in extensions.json per profile.
		ffs, _ := filepath.Glob(filepath.Join(firefoxProfilesDir(home), "*", "extensions.json"))
		for _, f := range ffs {
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			var doc struct {
				Addons []struct {
					ID         string `json:"id"`
					Version    string `json:"version"`
					Type       string `json:"type"`
					Location   string `json:"location"`
					Active     bool   `json:"active"`
					DefaultLoc struct {
						Name string `json:"name"`
					} `json:"defaultLocale"`
					UserPermissions struct {
						Permissions []string `json:"permissions"`
						Origins     []string `json:"origins"`
					} `json:"userPermissions"`
				} `json:"addons"`
			}
			if json.Unmarshal(b, &doc) != nil {
				continue
			}
			for _, a := range doc.Addons {
				if a.Type != "extension" || a.Location == "app-builtin" || a.Location == "app-system-defaults" {
					continue
				}
				perms := append(append([]string{}, a.UserPermissions.Permissions...), a.UserPermissions.Origins...)
				if !a.Active {
					perms = append([]string{"(disabled)"}, perms...)
				}
				rows = append(rows, []string{user, "firefox", filepath.Base(filepath.Dir(f)), a.ID, a.DefaultLoc.Name, a.Version, strings.Join(perms, " ")})
			}
		}
	}
	return cols, rows, nil
}

// ── shell history ────────────────────────────────────────────────────────────

const historyLinesPerFile = 200

func qShellHistory(homes map[string]string) ([]string, [][]string, error) {
	cols := []string{"user", "file", "line", "command"}
	var rows [][]string
	for _, user := range sortedUsers(homes) {
		home := homes[user]
		var files []string
		if runtime.GOOS == "windows" {
			files = []string{filepath.Join(home, "AppData", "Roaming", "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt")}
		} else {
			files = []string{".bash_history", ".zsh_history", ".sh_history", ".ash_history", ".local/share/fish/fish_history", ".python_history", ".mysql_history", ".psql_history"}
			for i, f := range files {
				files[i] = filepath.Join(home, f)
			}
		}
		for _, f := range files {
			lines := tailLines(f, historyLinesPerFile)
			start := lines.total - len(lines.lines) + 1
			for i, l := range lines.lines {
				// zsh extended history: ": 1700000000:0;command"
				if strings.HasPrefix(l, ": ") {
					if j := strings.IndexByte(l, ';'); j > 0 {
						l = l[j+1:]
					}
				}
				if strings.HasPrefix(l, "- cmd: ") { // fish
					l = strings.TrimPrefix(l, "- cmd: ")
				} else if strings.HasPrefix(l, "  when: ") {
					continue
				}
				if strings.TrimSpace(l) == "" {
					continue
				}
				rows = append(rows, []string{user, f, strconv.Itoa(start + i), l})
			}
		}
	}
	return cols, rows, nil
}

type tail struct {
	lines []string
	total int
}

// tailLines returns the last n lines of a file (and how many it has), reading
// at most the last 1 MiB.
func tailLines(path string, n int) tail {
	f, err := os.Open(path)
	if err != nil {
		return tail{}
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return tail{}
	}
	const window = 1 << 20
	if st.Size() > window {
		f.Seek(st.Size()-window, 0)
	}
	var all []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		all = append(all, sc.Text())
	}
	t := tail{total: len(all)}
	if len(all) > n {
		all = all[len(all)-n:]
	}
	t.lines = all
	return t
}

// ── recently changed files ───────────────────────────────────────────────────

func recentRoots(homes map[string]string) []string {
	var roots []string
	for _, user := range sortedUsers(homes) {
		h := homes[user]
		for _, d := range []string{"Downloads", "Desktop", "Documents"} {
			roots = append(roots, filepath.Join(h, d))
		}
		if runtime.GOOS == "windows" {
			roots = append(roots, filepath.Join(h, "AppData", "Local", "Temp"), filepath.Join(h, "AppData", "Roaming"))
		}
	}
	switch runtime.GOOS {
	case "windows":
		roots = append(roots, os.Getenv("SystemRoot")+`\Temp`, `C:\ProgramData`)
	default:
		roots = append(roots, "/tmp", "/var/tmp", "/dev/shm")
	}
	return roots
}

// qRecentFiles lists files changed in the last Hours (default 24, at most
// 720) under user folders and temp directories, or under Path when given.
func qRecentFiles(ctx context.Context, p Params) ([]string, [][]string, error) {
	hours := p.Hours
	if hours <= 0 {
		hours = 24
	}
	if hours > 720 {
		hours = 720
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	roots := recentRoots(userHomes())
	if p.Path != "" {
		if !filepath.IsAbs(p.Path) {
			return nil, nil, fmt.Errorf("path must be absolute")
		}
		roots = []string{p.Path}
	}
	cols := []string{"path", "size", "modified", "sha256"}
	var rows [][]string
	deadline := time.Now().Add(fileWalkBudget)
	seen, hashed := 0, 0
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if ctx.Err() != nil || time.Now().After(deadline) || seen > fileWalkMax {
				return fs.SkipAll
			}
			seen++
			if d.IsDir() {
				if skipDirs[path] || d.Name() == "node_modules" || d.Name() == ".git" {
					return fs.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.ModTime().Before(since) {
				return nil
			}
			sum := ""
			if hashed < 200 && info.Size() <= hashMaxBytes {
				sum, _, _ = hashFile(path)
				hashed++
			}
			rows = append(rows, []string{path, strconv.FormatInt(info.Size(), 10), info.ModTime().UTC().Format(time.RFC3339), sum})
			return nil
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i][2] > rows[j][2] })
	return cols, rows, nil
}

// ── certificates (shared helper) ─────────────────────────────────────────────

// certRows parses PEM or DER certificates from data into rows of
// store, subject, issuer, sha1-less fingerprint (sha256), not_after.
func certRows(store, source string, data []byte) [][]string {
	var rows [][]string
	add := func(c *x509.Certificate) {
		self := ""
		if c.Subject.String() == c.Issuer.String() {
			self = "yes"
		}
		rows = append(rows, []string{store, source, c.Subject.String(), c.Issuer.String(), self,
			c.NotAfter.UTC().Format("2006-01-02"), fmt.Sprintf("%x", sha256Sum(c.Raw))})
	}
	rest := data
	found := false
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if c, err := x509.ParseCertificate(b.Bytes); err == nil {
			add(c)
			found = true
		}
	}
	if !found {
		if c, err := x509.ParseCertificate(data); err == nil {
			add(c)
		}
	}
	return rows
}

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }

var certCols = []string{"store", "source", "subject", "issuer", "self_signed", "not_after", "sha256"}
