// Package runtimeinv lists the third-party packages a running service process
// actually has, for runtime reachability of dependency vulnerabilities
// (Code step 4).
//
// Evidence levels, strongest first:
//
//	loaded   - the package's code is in the process: compiled into a Go binary
//	           (build info), or a file of the package is memory-mapped (a Java
//	           jar, a Python or Node native extension, a .NET assembly).
//	deployed - the package is installed where the process loads code from (the
//	           interpreter's site-packages, node_modules of the working
//	           directory, the .NET app's deps.json, jars nested in a Spring
//	           Boot fat jar) but nothing proves it was imported.
//
// Everything is read through /proc/<pid>/root, so it works for containers.
// Nothing is executed and no package file is written.
package runtimeinv

import (
	"archive/zip"
	"bufio"
	"bytes"
	"debug/buildinfo"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Package is one dependency seen in a process.
type Package struct {
	Ecosystem string `json:"e"` // Go | Maven | PyPI | npm | NuGet
	Name      string `json:"n"`
	Version   string `json:"v"`
	Evidence  string `json:"ev"` // loaded | deployed
}

// Result is the inventory of one process.
type Result struct {
	Language  string    `json:"language,omitempty"`
	Packages  []Package `json:"packages"`
	Truncated bool      `json:"truncated,omitempty"`
}

const maxPackages = 5000

type collector struct {
	root  string // /proc/<pid>/root
	pkgs  map[string]Package
	trunc bool
	lang  map[string]bool
}

func (c *collector) add(eco, name, version, evidence string) {
	name, version = strings.TrimSpace(name), strings.TrimSpace(version)
	if name == "" || version == "" {
		return
	}
	key := eco + "\x00" + strings.ToLower(name) + "\x00" + version
	if old, ok := c.pkgs[key]; ok {
		if old.Evidence == "deployed" && evidence == "loaded" {
			old.Evidence = "loaded"
			c.pkgs[key] = old
		}
		return
	}
	if len(c.pkgs) >= maxPackages {
		c.trunc = true
		return
	}
	c.pkgs[key] = Package{Ecosystem: eco, Name: name, Version: version, Evidence: evidence}
}

// in maps a path seen inside the process to the agent's view of it.
func (c *collector) in(p string) string { return filepath.Join(c.root, p) }

// Inventory builds the package list of pid under procRoot ("/proc").
func Inventory(procRoot string, pid int) (Result, error) {
	base := filepath.Join(procRoot, itoa(pid))
	c := &collector{root: filepath.Join(base, "root"), pkgs: map[string]Package{}, lang: map[string]bool{}}

	// Go: the module list is compiled into the binary.
	if bi, err := buildinfo.ReadFile(filepath.Join(base, "exe")); err == nil {
		c.lang["go"] = true
		for _, d := range bi.Deps {
			m := d
			if d.Replace != nil {
				m = d.Replace
			}
			c.add("Go", m.Path, strings.TrimPrefix(m.Version, "v"), "loaded")
		}
	}

	maps := mappedFiles(filepath.Join(base, "maps"))
	sitePkgs := map[string]bool{}
	for _, p := range maps {
		switch {
		case strings.HasSuffix(p, ".jar"):
			c.lang["java"] = true
			c.jar(p)
		case strings.Contains(p, "/site-packages/") || strings.Contains(p, "/dist-packages/"):
			c.lang["python"] = true
			dir, top := sitePackagesOf(p)
			sitePkgs[dir] = true
			c.pythonLoaded(dir, top)
		case strings.Contains(p, "/node_modules/") && strings.HasSuffix(p, ".node"):
			c.lang["node"] = true
			c.nodeLoaded(p)
		case strings.HasSuffix(strings.ToLower(p), ".dll"):
			c.lang["dotnet"] = true
			c.nugetLoaded(p)
		}
	}
	exe, _ := os.Readlink(filepath.Join(base, "exe"))
	cwd, _ := os.Readlink(filepath.Join(base, "cwd"))
	exeBase := filepath.Base(exe)
	// Python: every distribution in the site-packages the process uses.
	if strings.HasPrefix(exeBase, "python") {
		c.lang["python"] = true
		for _, d := range pythonSiteDirs(c, exe) {
			sitePkgs[d] = true
		}
	}
	for d := range sitePkgs {
		c.pythonDeployed(d)
	}
	// Node: the working directory's dependency tree.
	if exeBase == "node" || exeBase == "nodejs" || exeBase == "bun" {
		c.lang["node"] = true
		if cwd != "" {
			c.nodeDeployed(cwd)
		}
	}
	// .NET: the app's deps.json, next to the main assembly (working directory).
	if exeBase == "dotnet" || c.lang["dotnet"] {
		if cwd != "" {
			c.dotnetDeployed(cwd, maps)
		}
	}

	out := Result{Truncated: c.trunc}
	for l := range c.lang {
		if out.Language == "" || l == "go" {
			out.Language = l
		}
	}
	for _, p := range c.pkgs {
		out.Packages = append(out.Packages, p)
	}
	sort.Slice(out.Packages, func(i, j int) bool {
		a, b := out.Packages[i], out.Packages[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		return a.Name < b.Name
	})
	return out, nil
}

func itoa(n int) string {
	var b [20]byte
	i := len(b)
	if n == 0 {
		return "0"
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// mappedFiles returns the distinct file paths mapped into the process.
func mappedFiles(mapsPath string) []string {
	f, err := os.Open(mapsPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 {
			continue
		}
		p := strings.Join(fields[5:], " ")
		p = strings.TrimSuffix(p, " (deleted)")
		if !strings.HasPrefix(p, "/") || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// ── Java ──────────────────────────────────────────────────────────────────────

var jarNameRe = regexp.MustCompile(`^(.+?)-(\d[\w.\-+]*)\.jar$`)

// jar records the Maven coordinates inside a mapped jar (several for shaded
// jars). Jars nested in a Spring Boot fat jar are "deployed".
func (c *collector) jar(p string) {
	zr, err := zip.OpenReader(c.in(p))
	if err != nil {
		return
	}
	defer zr.Close()
	found := c.pomProps(&zr.Reader, "loaded")
	nested := 0
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".jar") || !(strings.HasPrefix(f.Name, "BOOT-INF/lib/") || strings.HasPrefix(f.Name, "WEB-INF/lib/")) {
			continue
		}
		nested++
		if nested > 1000 {
			break
		}
		if f.UncompressedSize64 > 0 && f.UncompressedSize64 < 64<<20 {
			if rc, err := f.Open(); err == nil {
				b, _ := io.ReadAll(io.LimitReader(rc, 64<<20))
				rc.Close()
				if inner, err := zip.NewReader(bytes.NewReader(b), int64(len(b))); err == nil && c.pomProps(inner, "deployed") > 0 {
					continue
				}
			}
		}
		// No pom.properties: fall back to the file name (artifact only).
		if m := jarNameRe.FindStringSubmatch(filepath.Base(f.Name)); m != nil {
			c.add("Maven", m[1], m[2], "deployed")
		}
	}
	if found == 0 {
		if m := jarNameRe.FindStringSubmatch(filepath.Base(p)); m != nil {
			c.add("Maven", m[1], m[2], "loaded")
		}
	}
}

func (c *collector) pomProps(zr *zip.Reader, evidence string) int {
	n := 0
	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, "META-INF/maven/") || !strings.HasSuffix(f.Name, "/pom.properties") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		props := map[string]string{}
		sc := bufio.NewScanner(io.LimitReader(rc, 64<<10))
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), "=")
			if ok {
				props[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
		rc.Close()
		if props["groupId"] != "" && props["artifactId"] != "" {
			c.add("Maven", props["groupId"]+":"+props["artifactId"], props["version"], evidence)
			n++
		}
	}
	return n
}

// ── Python ────────────────────────────────────────────────────────────────────

// sitePackagesOf splits /x/site-packages/pkg/mod.so into the directory and
// the top-level package name.
func sitePackagesOf(p string) (dir, top string) {
	for _, marker := range []string{"/site-packages/", "/dist-packages/"} {
		if i := strings.Index(p, marker); i >= 0 {
			dir = p[:i+len(marker)-1]
			rest := p[i+len(marker):]
			top, _, _ = strings.Cut(rest, "/")
			top = strings.SplitN(top, ".", 2)[0] // module.cpython-311.so -> module
			return dir, top
		}
	}
	return "", ""
}

func pythonSiteDirs(c *collector, exe string) []string {
	var out []string
	// venv: <venv>/bin/python -> <venv>/lib/python3.*/site-packages
	prefix := filepath.Dir(filepath.Dir(exe))
	for _, pat := range []string{"lib/python3*/site-packages", "lib/python3*/dist-packages", "local/lib/python3*/dist-packages", "lib/python3/dist-packages"} {
		matches, _ := filepath.Glob(c.in(filepath.Join(prefix, pat)))
		for _, m := range matches {
			out = append(out, strings.TrimPrefix(m, c.root))
		}
	}
	return out
}

var distInfoRe = regexp.MustCompile(`^(.+?)-([^-]+?)\.(dist-info|egg-info)$`)

// pythonDists maps each top-level import name in a site-packages directory
// to its distribution (name, version).
func (c *collector) pythonDists(dir string) map[string][2]string {
	out := map[string][2]string{}
	ents, err := os.ReadDir(c.in(dir))
	if err != nil {
		return out
	}
	for _, e := range ents {
		m := distInfoRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		name, ver := m[1], m[2]
		if b, err := os.ReadFile(filepath.Join(c.in(dir), e.Name(), "METADATA")); err == nil {
			for _, line := range strings.SplitN(string(b), "\n", 40) {
				if v, ok := strings.CutPrefix(line, "Name: "); ok {
					name = strings.TrimSpace(v)
				} else if v, ok := strings.CutPrefix(line, "Version: "); ok {
					ver = strings.TrimSpace(v)
				}
			}
		}
		tops := []string{strings.ToLower(strings.ReplaceAll(name, "-", "_"))}
		if b, err := os.ReadFile(filepath.Join(c.in(dir), e.Name(), "top_level.txt")); err == nil {
			for _, t := range strings.Fields(string(b)) {
				tops = append(tops, strings.ToLower(t))
			}
		}
		for _, t := range tops {
			out[t] = [2]string{name, ver}
		}
	}
	return out
}

func (c *collector) pythonLoaded(dir, top string) {
	if dir == "" || top == "" {
		return
	}
	if d, ok := c.pythonDists(dir)[strings.ToLower(top)]; ok {
		c.add("PyPI", d[0], d[1], "loaded")
	}
}

func (c *collector) pythonDeployed(dir string) {
	seen := map[[2]string]bool{}
	for _, d := range c.pythonDists(dir) {
		if !seen[d] {
			seen[d] = true
			c.add("PyPI", d[0], d[1], "deployed")
		}
	}
}

// ── Node ──────────────────────────────────────────────────────────────────────

// nodeLoaded: a native addon .../node_modules/<pkg>/build/x.node.
func (c *collector) nodeLoaded(p string) {
	i := strings.LastIndex(p, "/node_modules/")
	rest := p[i+len("/node_modules/"):]
	parts := strings.Split(rest, "/")
	name := parts[0]
	if strings.HasPrefix(name, "@") && len(parts) > 1 {
		name += "/" + parts[1]
	}
	var pj struct {
		Name, Version string
	}
	if b, err := os.ReadFile(c.in(p[:i] + "/node_modules/" + name + "/package.json")); err == nil && json.Unmarshal(b, &pj) == nil {
		c.add("npm", pj.Name, pj.Version, "loaded")
	}
}

// nodeDeployed reads node_modules/.package-lock.json (npm 7+), else the
// package.json of each top-level package.
func (c *collector) nodeDeployed(cwd string) {
	nm := filepath.Join(cwd, "node_modules")
	if b, err := os.ReadFile(c.in(filepath.Join(nm, ".package-lock.json"))); err == nil {
		var lock struct {
			Packages map[string]struct {
				Name, Version string
			} `json:"packages"`
		}
		if json.Unmarshal(b, &lock) == nil && len(lock.Packages) > 0 {
			for k, v := range lock.Packages {
				i := strings.LastIndex(k, "node_modules/")
				if i < 0 {
					continue
				}
				name := v.Name
				if name == "" {
					name = k[i+len("node_modules/"):]
				}
				c.add("npm", name, v.Version, "deployed")
			}
			return
		}
	}
	ents, err := os.ReadDir(c.in(nm))
	if err != nil {
		return
	}
	read := func(dir string) {
		var pj struct{ Name, Version string }
		if b, err := os.ReadFile(c.in(filepath.Join(dir, "package.json"))); err == nil && json.Unmarshal(b, &pj) == nil {
			c.add("npm", pj.Name, pj.Version, "deployed")
		}
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "@") {
			sub, _ := os.ReadDir(c.in(filepath.Join(nm, e.Name())))
			for _, s := range sub {
				read(filepath.Join(nm, e.Name(), s.Name()))
			}
			continue
		}
		read(filepath.Join(nm, e.Name()))
	}
}

// ── .NET ──────────────────────────────────────────────────────────────────────

var nugetPathRe = regexp.MustCompile(`(?i)/\.nuget/packages/([^/]+)/([^/]+)/`)

func (c *collector) nugetLoaded(p string) {
	if m := nugetPathRe.FindStringSubmatch(p); m != nil {
		c.add("NuGet", m[1], m[2], "loaded")
	}
}

// dotnetDeployed reads *.deps.json in the app directory. Packages whose
// runtime assembly is mapped into the process are "loaded".
func (c *collector) dotnetDeployed(cwd string, maps []string) {
	mapped := map[string]bool{}
	for _, p := range maps {
		mapped[strings.ToLower(filepath.Base(p))] = true
	}
	files, _ := filepath.Glob(c.in(filepath.Join(cwd, "*.deps.json")))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var deps struct {
			Targets map[string]map[string]struct {
				Runtime map[string]json.RawMessage `json:"runtime"`
			} `json:"targets"`
			Libraries map[string]struct {
				Type string `json:"type"`
			} `json:"libraries"`
		}
		if json.Unmarshal(b, &deps) != nil {
			continue
		}
		for key, lib := range deps.Libraries {
			if lib.Type != "package" {
				continue
			}
			name, ver, ok := strings.Cut(key, "/")
			if !ok {
				continue
			}
			ev := "deployed"
			for _, t := range deps.Targets {
				for asm := range t[key].Runtime {
					if mapped[strings.ToLower(filepath.Base(asm))] {
						ev = "loaded"
					}
				}
			}
			c.add("NuGet", name, ver, ev)
		}
	}
}
