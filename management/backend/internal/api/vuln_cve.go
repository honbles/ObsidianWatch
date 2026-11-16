package api

// vuln_cve.go - CVE matching for hosts that have no distro advisory feed
// (Windows, macOS, RPM-based Linux): installed software is mapped to a CPE and
// checked against NVD on the EXACT installed version.
//
// Why CPE and not keyword search: a keyword search for "Google Chrome 126" returns
// whichever CVEs mention those words in any version, so it both misses real
// ones and reports CVEs that do not apply. A CPE query with a version asks NVD
// "which CVEs affect this version", and NVD answers using the affected
// version ranges.
//
// Honest limits, shown in the UI: only products with a known CPE mapping can be
// checked (the rest are listed as not checked), and "no CVEs found" for a
// product means none in NVD for that exact version, not that it is safe.
//
// NVD allows 5 requests / 30 s without an API key (50 with one), so lookups
// run in the background, are paced process-wide, and every (cpe, version)
// answer is cached for 24 h in the database.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"obsidianwatch/management/internal/store"
)

// ---- product -> CPE ----------------------------------------------------------

type cpeRule struct {
	re       *regexp.Regexp // against the lower-cased display name
	vendor   string
	product  string
	nameVer  *regexp.Regexp // take the version from the display name instead
	trimZero bool           // 1.2.0.0 -> 1.2 (some installers pad the version)
}

func cr(re, vendor, product string) cpeRule {
	return cpeRule{re: regexp.MustCompile(re), vendor: vendor, product: product}
}

// The catalog is deliberately limited to products whose NVD vendor/product
// names are well established. Extending it is a one-line change.
var cpeCatalog = []cpeRule{
	cr(`^google chrome`, "google", "chrome"),
	cr(`^mozilla firefox esr`, "mozilla", "firefox_esr"),
	cr(`^mozilla firefox`, "mozilla", "firefox"),
	cr(`^mozilla thunderbird`, "mozilla", "thunderbird"),
	cr(`^microsoft edge$`, "microsoft", "edge_chromium"),
	cr(`^7-zip`, "7-zip", "7-zip"),
	cr(`^vlc media player`, "videolan", "vlc_media_player"),
	cr(`^notepad\+\+`, "notepad-plus-plus", "notepad\\+\\+"),
	cr(`^git$|^git version`, "git-scm", "git"),
	{re: regexp.MustCompile(`^python \d`), vendor: "python", product: "python", nameVer: regexp.MustCompile(`(?i)python (\d+\.\d+\.\d+)`)},
	cr(`^node\.?js`, "nodejs", "node.js"),
	{re: regexp.MustCompile(`^putty`), vendor: "putty", product: "putty", trimZero: true},
	cr(`^winscp`, "winscp", "winscp"),
	cr(`^filezilla`, "filezilla-project", "filezilla_client"),
	cr(`^microsoft visual studio code`, "microsoft", "visual_studio_code"),
	cr(`^openssl`, "openssl", "openssl"),
	{re: regexp.MustCompile(`^winrar`), vendor: "rarlab", product: "winrar", trimZero: true},
	cr(`^wireshark`, "wireshark", "wireshark"),
	cr(`^docker desktop`, "docker", "desktop"),
	cr(`^teamviewer`, "teamviewer", "teamviewer"),
	cr(`^anydesk`, "anydesk", "anydesk"),
	cr(`^oracle vm virtualbox`, "oracle", "vm_virtualbox"),
	cr(`^vmware workstation`, "vmware", "workstation"),
	cr(`^gimp`, "gimp", "gimp"),
	cr(`^openvpn`, "openvpn", "openvpn"),
	cr(`^go programming language`, "golang", "go"),
	cr(`^obs studio`, "obsproject", "obs_studio"),
	cr(`^mysql server`, "oracle", "mysql"),
	cr(`^postgresql \d`, "postgresql", "postgresql"),
	cr(`^cmake`, "kitware", "cmake"),
}

var leadingVersion = regexp.MustCompile(`^\d+(?:\.\d+)*`)

// cpeFor maps an installed package to a CPE 2.3 name with its exact version.
func cpeFor(name, version string) (cpe string, ok bool) {
	l := strings.ToLower(strings.TrimSpace(name))
	for _, r := range cpeCatalog {
		if !r.re.MatchString(l) {
			continue
		}
		v := strings.TrimSpace(version)
		if r.nameVer != nil {
			if m := r.nameVer.FindStringSubmatch(name); m != nil {
				v = m[1]
			}
		}
		v = leadingVersion.FindString(strings.TrimPrefix(v, "v"))
		if v == "" {
			return "", false
		}
		if r.trimZero {
			for strings.Count(v, ".") >= 2 && strings.HasSuffix(v, ".0") {
				v = strings.TrimSuffix(v, ".0")
			}
		}
		return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", r.vendor, r.product, v), true
	}
	return "", false
}

// ---- NVD, paced ----------------------------------------------------------------

var nvdPace struct {
	mu   sync.Mutex
	next time.Time
}

// nvdWait reserves the next request slot. One pacer for the whole process, so
// concurrent hosts and the AI path share NVD's rate limit instead of each
// tripping it.
func nvdWait(ctx context.Context, keyed bool) error {
	interval := 6500 * time.Millisecond // 5 requests / 30 s
	if keyed {
		interval = 700 * time.Millisecond // 50 requests / 30 s
	}
	nvdPace.mu.Lock()
	slot := time.Now()
	if nvdPace.next.After(slot) {
		slot = nvdPace.next
	}
	nvdPace.next = slot.Add(interval)
	nvdPace.mu.Unlock()
	d := time.Until(slot)
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

type cpeCVE struct {
	ID          string  `json:"id"`
	CVSS        float64 `json:"cvss"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	Published   string  `json:"published"`
}

const (
	cveMinScore    = 4.0
	cveMaxPerCPE   = 25
	cpeCacheMaxAge = 24 * time.Hour
)

// nvdCVEURL is a variable so tests can point it at a local server.
var nvdCVEURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

var nvdHTTP = &http.Client{Timeout: 40 * time.Second}

// nvdQueryCPE asks NVD for CVEs affecting this exact CPE (version-range aware).
func nvdQueryCPE(ctx context.Context, apiKey, cpe string) (rows []cpeCVE, total int, err error) {
	q := url.Values{}
	q.Set("virtualMatchString", cpe)
	q.Set("resultsPerPage", "200")
	reqURL := nvdCVEURL + "?" + q.Encode() + "&noRejected"
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if err := nvdWait(ctx, apiKey != ""); err != nil {
			return nil, 0, err
		}
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if e != nil {
			return nil, 0, e
		}
		if apiKey != "" {
			req.Header.Set("apiKey", apiKey)
		}
		req.Header.Set("User-Agent", "ObsidianWatch-SIEM/1.0")
		resp, e := nvdHTTP.Do(req)
		if e != nil {
			lastErr = e
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		switch {
		case resp.StatusCode == 200:
			var nr nvdResponse
			if e := json.Unmarshal(body, &nr); e != nil {
				return nil, 0, e
			}
			for _, it := range nr.Vulnerabilities {
				score, sev := extractCVSS(it.CVE.Metrics)
				if score < cveMinScore {
					continue
				}
				desc := ""
				for _, d := range it.CVE.Descriptions {
					if d.Lang == "en" {
						desc = d.Value
						break
					}
				}
				if len(desc) > 240 {
					desc = desc[:240] + "…"
				}
				pub := it.CVE.Published
				if len(pub) >= 10 {
					pub = pub[:10]
				}
				rows = append(rows, cpeCVE{ID: it.CVE.ID, CVSS: score, Severity: sev, Description: desc, Published: pub})
			}
			sort.Slice(rows, func(i, j int) bool {
				if rows[i].CVSS != rows[j].CVSS {
					return rows[i].CVSS > rows[j].CVSS
				}
				return rows[i].ID < rows[j].ID
			})
			if len(rows) > cveMaxPerCPE {
				rows = rows[:cveMaxPerCPE]
			}
			return rows, nr.TotalResults, nil
		case resp.StatusCode == 429 || resp.StatusCode == 503 || resp.StatusCode == 403:
			lastErr = fmt.Errorf("NVD %s (rate limited; an API key in Settings raises the limit 10x)", resp.Status)
			select { // back off before retrying
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			case <-time.After(time.Duration(10*(attempt+1)) * time.Second):
			}
		default:
			return nil, 0, fmt.Errorf("NVD API error: %s", resp.Status)
		}
	}
	return nil, 0, lastErr
}

// ---- host result ---------------------------------------------------------------

type HostCVE struct {
	Package     string  `json:"package"`
	Version     string  `json:"version"`
	CPE         string  `json:"cpe"`
	CVEID       string  `json:"cve_id"`
	CVSS        float64 `json:"cvss"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	Published   string  `json:"published"`
	URL         string  `json:"url"`
}

type HostCVEChecked struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	CPE     string `json:"cpe"`
	CVEs    int    `json:"cves"`         // after the score filter
	Total   int    `json:"total_in_nvd"` // before it
	Failed  bool   `json:"failed,omitempty"`
}

type HostCVEResult struct {
	Status        string           `json:"status"` // running | done | partial | no_packages
	Method        string           `json:"method"`
	PackagesTotal int              `json:"packages_total"`
	Checked       []HostCVEChecked `json:"checked"`
	Unmapped      int              `json:"unmapped"`
	Failed        int              `json:"failed"`
	Progress      int              `json:"progress"`
	ToCheck       int              `json:"to_check"`
	Findings      []HostCVE        `json:"findings"`
	HasKey        bool             `json:"has_api_key"`
	Note          string           `json:"note"`
	ComputedAt    time.Time        `json:"computed_at"`
}

const hostCVEMethod = "NVD, matched by CPE on the exact installed version"
const hostCVENote = "Only products with a known CPE mapping are checked; the rest are not assessed. " +
	"No CVEs for a product means none in NVD for that exact version, not that it is secure. CVSS 4.0+ only."

type scanPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// scanFacts pulls what CVE matching needs out of a vulnerability.scan payload.
func scanFacts(raw json.RawMessage) (osRelease, osName string, pkgs []scanPkg) {
	var m struct {
		OS     string `json:"os"`
		System struct {
			OSRelease string `json:"os_release"`
		} `json:"system"`
		Packages []scanPkg `json:"packages"`
	}
	if json.Unmarshal(raw, &m) != nil {
		return "", "", nil
	}
	return m.System.OSRelease, m.OS, m.Packages
}

// hostUsesCPEPath reports whether a host's CVEs come from the CPE/NVD path:
// anything without a distro feed, and at least one recognised product.
func hostUsesCPEPath(osRelease string, pkgs []scanPkg) bool {
	if osvEcosystemFor(osRelease) != "" {
		return false
	}
	for _, p := range pkgs {
		if _, ok := cpeFor(p.Name, p.Version); ok {
			return true
		}
	}
	return false
}

type cveTarget struct{ name, version, cpe string }

func cveTargets(pkgs []scanPkg) (targets []cveTarget, unmapped int) {
	seen := map[string]bool{}
	for _, p := range pkgs {
		cpe, ok := cpeFor(p.Name, p.Version)
		if !ok {
			unmapped++
			continue
		}
		if seen[cpe] {
			continue
		}
		seen[cpe] = true
		targets = append(targets, cveTarget{p.Name, p.Version, cpe})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].cpe < targets[j].cpe })
	return
}

// computeHostCVE checks every recognised product, using the database cache so
// repeated runs and the AI path are fast. progress is called after each product.
func computeHostCVE(ctx context.Context, db *store.DB, apiKey string, pkgs []scanPkg, progress func(done, total int)) *HostCVEResult {
	targets, unmapped := cveTargets(pkgs)
	res := &HostCVEResult{Method: hostCVEMethod, PackagesTotal: len(pkgs), Unmapped: unmapped, ToCheck: len(targets),
		HasKey: apiKey != "", Note: hostCVENote, Findings: []HostCVE{}, Checked: []HostCVEChecked{}}
	for i, t := range targets {
		if ctx.Err() != nil {
			break
		}
		var rows []cpeCVE
		total := 0
		ok := false
		if raw, tot, hit := db.CPECacheGet(ctx, t.cpe, cpeCacheMaxAge); hit {
			if json.Unmarshal(raw, &rows) == nil {
				total, ok = tot, true
			}
		}
		if !ok {
			r, tot, err := nvdQueryCPE(ctx, apiKey, t.cpe)
			if err != nil {
				res.Failed++
				res.Checked = append(res.Checked, HostCVEChecked{Name: t.name, Version: t.version, CPE: t.cpe, Failed: true})
				if progress != nil {
					progress(i+1, len(targets))
				}
				continue
			}
			rows, total = r, tot
			if b, e := json.Marshal(rows); e == nil {
				_ = db.CPECachePut(ctx, t.cpe, total, b)
			}
		}
		res.Checked = append(res.Checked, HostCVEChecked{Name: t.name, Version: t.version, CPE: t.cpe, CVEs: len(rows), Total: total})
		for _, c := range rows {
			res.Findings = append(res.Findings, HostCVE{Package: t.name, Version: t.version, CPE: t.cpe, CVEID: c.ID, CVSS: c.CVSS,
				Severity: c.Severity, Description: c.Description, Published: c.Published, URL: "https://nvd.nist.gov/vuln/detail/" + c.ID})
		}
		if progress != nil {
			progress(i+1, len(targets))
		}
	}
	sort.SliceStable(res.Findings, func(i, j int) bool { return res.Findings[i].CVSS > res.Findings[j].CVSS })
	res.Progress = len(res.Checked)
	res.Status = "done"
	if res.Failed > 0 || res.Progress < res.ToCheck {
		res.Status = "partial"
	}
	res.ComputedAt = time.Now().UTC()
	return res
}

// findings in the shape the AI path already consumes
func (r *HostCVEResult) asCVEFindings() []CVEFinding {
	out := make([]CVEFinding, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, CVEFinding{PackageName: f.Package, InstalledVersion: f.Version, CVEID: f.CVEID, CVSSScore: f.CVSS,
			Severity: f.Severity, Description: f.Description, Published: f.Published, URL: f.URL})
	}
	return out
}

// ---- background jobs -------------------------------------------------------------

type hostCVEJob struct {
	done, total int
}

var hostCVEJobs = struct {
	sync.Mutex
	m map[string]*hostCVEJob
}{m: map[string]*hostCVEJob{}}

func hostCVERunning(host string) (*hostCVEJob, bool) {
	hostCVEJobs.Lock()
	defer hostCVEJobs.Unlock()
	j, ok := hostCVEJobs.m[host]
	if !ok {
		return nil, false
	}
	c := *j
	return &c, true
}

// startHostCVE runs the lookup in the background (one per host at a time).
func startHostCVE(db *store.DB, apiKey, host string, scanAt time.Time, pkgs []scanPkg) {
	hostCVEJobs.Lock()
	if _, running := hostCVEJobs.m[host]; running {
		hostCVEJobs.Unlock()
		return
	}
	targets, _ := cveTargets(pkgs)
	hostCVEJobs.m[host] = &hostCVEJob{total: len(targets)}
	hostCVEJobs.Unlock()
	go func() {
		defer func() {
			hostCVEJobs.Lock()
			delete(hostCVEJobs.m, host)
			hostCVEJobs.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		res := computeHostCVE(ctx, db, apiKey, pkgs, func(done, total int) {
			hostCVEJobs.Lock()
			if j := hostCVEJobs.m[host]; j != nil {
				j.done, j.total = done, total
			}
			hostCVEJobs.Unlock()
		})
		if b, err := json.Marshal(res); err == nil {
			_ = db.HostCVEPut(context.Background(), host, scanAt, b)
		}
	}()
}

// hostCVEView is what the Vulnerability page receives alongside the scan.
// It never blocks: a missing or outdated result starts a background run and
// reports "running" with progress; the page polls until it is done.
func hostCVEView(ctx context.Context, db *store.DB, apiKey, host string, scanAt time.Time, raw json.RawMessage) *HostCVEResult {
	osRelease, _, pkgs := scanFacts(raw)
	if len(pkgs) == 0 {
		return &HostCVEResult{Status: "no_packages", Method: hostCVEMethod, Findings: []HostCVE{}, Checked: []HostCVEChecked{}}
	}
	if !hostUsesCPEPath(osRelease, pkgs) {
		return nil
	}
	var stored *HostCVEResult
	storedScan, fresh := time.Time{}, false
	if b, sa, at, ok := db.HostCVEGet(ctx, host); ok {
		var r HostCVEResult
		if json.Unmarshal(b, &r) == nil {
			stored, storedScan = &r, sa
			age := time.Since(at)
			fresh = sa.Equal(scanAt.UTC().Truncate(time.Microsecond)) && age < cpeCacheMaxAge
			if r.Status == "partial" && age > 10*time.Minute {
				fresh = false // retry failed lookups, but not on every page load
			}
		}
	}
	if j, running := hostCVERunning(host); running {
		v := &HostCVEResult{Status: "running", Method: hostCVEMethod, Progress: j.done, ToCheck: j.total, PackagesTotal: len(pkgs), HasKey: apiKey != "",
			Findings: []HostCVE{}, Checked: []HostCVEChecked{}, Note: hostCVENote}
		if stored != nil && storedScan.Equal(scanAt.UTC().Truncate(time.Microsecond)) {
			v.Findings, v.Checked = stored.Findings, stored.Checked // show what we have meanwhile
		}
		return v
	}
	if !fresh {
		startHostCVE(db, apiKey, host, scanAt, pkgs)
		targets, unmapped := cveTargets(pkgs)
		return &HostCVEResult{Status: "running", Method: hostCVEMethod, ToCheck: len(targets), Unmapped: unmapped, PackagesTotal: len(pkgs),
			HasKey: apiKey != "", Findings: []HostCVE{}, Checked: []HostCVEChecked{}, Note: hostCVENote}
	}
	stored.HasKey = apiKey != ""
	return stored
}

// nvdKey resolves the NVD API key: the Settings value first, then config.
func nvdKey(ctx context.Context, db *store.DB, cfgKey string) string {
	if s, err := db.GetSetting(ctx, "nvd_api_key"); err == nil && s != "" {
		return s
	}
	return cfgKey
}
