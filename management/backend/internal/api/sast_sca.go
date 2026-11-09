package api

// SA-06: software composition analysis. Manifests/lockfiles in the scanned
// repo are parsed, and exact name+version pairs are checked against OSV
// (osv.dev), which aggregates GitHub advisories, PyPI, Go, RustSec etc.
// Network failure never fails the scan: SCA findings are simply absent.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var osvBaseURL = "https://api.osv.dev"

const (
	scaMaxPackages = 2000
	scaMaxVulnGets = 150
	scaBatchSize   = 500
)

type scaPkg struct {
	Ecosystem, Name, Version, File string
}

func scaFileBase(p string) string { return strings.ToLower(filepath.Base(p)) }

// parseManifest returns the pinned dependencies of a manifest or lockfile.
func parseManifest(rel string, data []byte) []scaPkg {
	var out []scaPkg
	switch scaFileBase(rel) {
	case "package-lock.json":
		var m struct {
			Packages map[string]struct {
				Version string `json:"version"`
			} `json:"packages"`
			Dependencies map[string]struct {
				Version string `json:"version"`
			} `json:"dependencies"`
		}
		if json.Unmarshal(data, &m) != nil {
			return nil
		}
		for k, v := range m.Packages {
			i := strings.LastIndex(k, "node_modules/")
			if i < 0 || v.Version == "" {
				continue
			}
			out = append(out, scaPkg{"npm", k[i+len("node_modules/"):], v.Version, rel})
		}
		if len(m.Packages) == 0 {
			for k, v := range m.Dependencies {
				if v.Version != "" {
					out = append(out, scaPkg{"npm", k, v.Version, rel})
				}
			}
		}
	case "requirements.txt":
		re := regexp.MustCompile(`^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-+!]+)`)
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			if m := re.FindStringSubmatch(strings.TrimSpace(sc.Text())); m != nil {
				out = append(out, scaPkg{"PyPI", m[1], m[2], rel})
			}
		}
	case "go.mod":
		sc := bufio.NewScanner(bytes.NewReader(data))
		in := false
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if i := strings.Index(l, "//"); i >= 0 {
				l = strings.TrimSpace(l[:i])
			}
			switch {
			case strings.HasPrefix(l, "require ("):
				in = true
			case l == ")":
				in = false
			case in || strings.HasPrefix(l, "require "):
				f := strings.Fields(strings.TrimPrefix(l, "require "))
				if len(f) >= 2 && strings.HasPrefix(f[1], "v") {
					out = append(out, scaPkg{"Go", f[0], strings.TrimPrefix(f[1], "v"), rel})
				}
			}
		}
	case "pipfile.lock":
		var m struct {
			Default map[string]struct {
				Version string `json:"version"`
			} `json:"default"`
			Develop map[string]struct {
				Version string `json:"version"`
			} `json:"develop"`
		}
		if json.Unmarshal(data, &m) != nil {
			return nil
		}
		for _, grp := range []map[string]struct {
			Version string `json:"version"`
		}{m.Default, m.Develop} {
			for name, v := range grp {
				if ver := strings.TrimPrefix(v.Version, "=="); ver != "" && ver != v.Version {
					out = append(out, scaPkg{"PyPI", name, ver, rel})
				}
			}
		}
	case "poetry.lock":
		var name string
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(l, "name = ") {
				name = strings.Trim(strings.TrimPrefix(l, "name = "), `"`)
			} else if strings.HasPrefix(l, "version = ") && name != "" {
				out = append(out, scaPkg{"PyPI", name, strings.Trim(strings.TrimPrefix(l, "version = "), `"`), rel})
				name = ""
			}
		}
	case "yarn.lock":
		// yarn v1: `"name@range", name@range2:` header then `  version "x.y.z"`.
		var name string
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			raw := sc.Text()
			l := strings.TrimSpace(raw)
			if raw != "" && raw[0] != ' ' && raw[0] != '#' && strings.HasSuffix(l, ":") {
				first := strings.Trim(strings.SplitN(strings.TrimSuffix(l, ":"), ",", 2)[0], `" `)
				if i := strings.LastIndex(first, "@"); i > 0 {
					name = first[:i]
				}
			} else if strings.HasPrefix(l, "version ") && name != "" {
				out = append(out, scaPkg{"npm", name, strings.Trim(strings.TrimPrefix(l, "version "), `" `), rel})
				name = ""
			}
		}
	case "cargo.lock":
		var name string
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(l, "name = ") {
				name = strings.Trim(strings.TrimPrefix(l, "name = "), `"`)
			} else if strings.HasPrefix(l, "version = ") && name != "" {
				out = append(out, scaPkg{"crates.io", name, strings.Trim(strings.TrimPrefix(l, "version = "), `"`), rel})
				name = ""
			}
		}
	case "composer.lock":
		var m struct {
			Packages []struct{ Name, Version string } `json:"packages"`
		}
		if json.Unmarshal(data, &m) == nil {
			for _, p := range m.Packages {
				out = append(out, scaPkg{"Packagist", p.Name, strings.TrimPrefix(p.Version, "v"), rel})
			}
		}
	}
	return out
}

var scaManifests = map[string]bool{"package-lock.json": true, "requirements.txt": true, "go.mod": true, "cargo.lock": true, "composer.lock": true,
	"pipfile.lock": true, "poetry.lock": true, "yarn.lock": true}

func isScaManifest(path string) bool { return scaManifests[scaFileBase(path)] }

type osvVuln struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Aliases  []string `json:"aliases"`
	Affected []struct {
		Ranges []struct {
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

func osvSeverity(v osvVuln) string {
	switch strings.ToUpper(v.DatabaseSpecific.Severity) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "LOW":
		return "low"
	}
	return "medium"
}

func osvFixed(v osvVuln) string {
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if f := e["fixed"]; f != "" {
					return f
				}
			}
		}
	}
	return ""
}

func osvPost(ctx context.Context, path string, body interface{}, out interface{}) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, "POST", osvBaseURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("osv %s: HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out)
}

func osvGetVuln(ctx context.Context, id string) (osvVuln, error) {
	var v osvVuln
	req, err := http.NewRequestWithContext(ctx, "GET", osvBaseURL+"/v1/vulns/"+id, nil)
	if err != nil {
		return v, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return v, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return v, fmt.Errorf("osv vuln %s: HTTP %d", id, resp.StatusCode)
	}
	return v, json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&v)
}

// scaFindings checks pkgs against OSV and returns one finding per
// (package, vulnerability).
func scaFindings(ctx context.Context, repo string, pkgs []scaPkg) ([]SASTFinding, error) {
	seen := map[string]bool{}
	var uniq []scaPkg
	for _, p := range pkgs {
		k := p.Ecosystem + "|" + p.Name + "|" + p.Version
		if !seen[k] {
			seen[k] = true
			uniq = append(uniq, p)
		}
	}
	if len(uniq) > scaMaxPackages {
		uniq = uniq[:scaMaxPackages]
	}
	type hit struct {
		pkg scaPkg
		id  string
	}
	var hits []hit
	for start := 0; start < len(uniq); start += scaBatchSize {
		end := start + scaBatchSize
		if end > len(uniq) {
			end = len(uniq)
		}
		chunk := uniq[start:end]
		type pk struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		}
		type q struct {
			Package pk     `json:"package"`
			Version string `json:"version"`
		}
		var qs []q
		for _, p := range chunk {
			qs = append(qs, q{pk{p.Name, p.Ecosystem}, p.Version})
		}
		var resp struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			} `json:"results"`
		}
		if err := osvPost(ctx, "/v1/querybatch", map[string]interface{}{"queries": qs}, &resp); err != nil {
			return nil, err
		}
		for i, r := range resp.Results {
			if i >= len(chunk) {
				break
			}
			for _, v := range r.Vulns {
				hits = append(hits, hit{chunk[i], v.ID})
			}
		}
	}
	details := map[string]osvVuln{}
	ids := map[string]bool{}
	for _, h := range hits {
		ids[h.id] = true
	}
	var idList []string
	for id := range ids {
		idList = append(idList, id)
	}
	sort.Strings(idList)
	for i, id := range idList {
		if i >= scaMaxVulnGets {
			break
		}
		if v, err := osvGetVuln(ctx, id); err == nil {
			details[id] = v
		}
	}
	var out []SASTFinding
	for _, h := range hits {
		v := details[h.id]
		sev := osvSeverity(v)
		title := fmt.Sprintf("Vulnerable dependency: %s %s (%s)", h.pkg.Name, h.pkg.Version, h.id)
		detail := v.Summary
		if detail == "" {
			detail = "Known vulnerability reported in the OSV database."
		}
		if len(v.Aliases) > 0 {
			detail += " Aliases: " + strings.Join(v.Aliases, ", ") + "."
		}
		fix := "Upgrade " + h.pkg.Name
		if f := osvFixed(v); f != "" {
			fix += " to " + f + " or later."
		} else {
			fix += " to a patched version if one exists, or remove the dependency."
		}
		out = append(out, SASTFinding{
			RuleID: "SCA-" + h.id, Severity: sev, CWE: "CWE-1104", OWASP: "A06:2021 Vulnerable and Outdated Components",
			Title: title, Detail: detail, Fix: fix, Repo: repo, File: h.pkg.File, Line: 0, Engine: "osv",
		})
	}
	return out, nil
}

// runSCAOnDir walks dir for manifests (bounded) and checks them against OSV.
func runSCAOnDir(ctx context.Context, repo, dir string) ([]SASTFinding, error) {
	var pkgs []scaPkg
	files := 0
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || files >= 50 || !isScaManifest(p) {
			return nil
		}
		fi, e := d.Info()
		if e != nil || fi.Size() > 8<<20 {
			return nil
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return nil
		}
		files++
		rel, _ := filepath.Rel(dir, p)
		pkgs = append(pkgs, parseManifest(filepath.ToSlash(rel), b)...)
		return nil
	})
	if len(pkgs) == 0 {
		return nil, nil
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	return scaFindings(cctx, repo, pkgs)
}
