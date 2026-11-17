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
	part     string         // "a" (application, default) or "o" (operating system)
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
	// .NET: the runtime/SDK/ASP.NET Core are separate NVD products.
	// The display name carries the real 3-part version (8.0.31); the installer's
	// 4-part number (8.0.31.36421) is a build id NVD does not use.
	{re: regexp.MustCompile(`^microsoft \.net (runtime|sdk|desktop runtime)|^microsoft windows desktop runtime`), vendor: "microsoft", product: ".net", nameVer: regexp.MustCompile(`(\d+\.\d+\.\d+)`)},
	{re: regexp.MustCompile(`^microsoft asp\.net core`), vendor: "microsoft", product: "asp.net_core", nameVer: regexp.MustCompile(`(\d+\.\d+\.\d+)`)},
	cr(`^microsoft azure cli`, "microsoft", "azure_cli"),
	cr(`^github cli$`, "github", "cli"),
	cr(`^powershell \d`, "microsoft", "powershell"),
	cr(`^microsoft threat modeling tool`, "microsoft", "threat_modeling_tool"),
	cr(`^dell command \| update|^dell command update`, "dell", "command_update"),
	cr(`^dell optimizer`, "dell", "optimizer"),
	cr(`^dell trusted device`, "dell", "trusted_device"),
	cr(`^dell supportassist os recovery`, "dell", "supportassist_os_recovery"),
	cr(`^sophos connect`, "sophos", "connect_client"),
	cr(`^zoom( workplace| meetings)?$|^zoom \(`, "zoom", "zoom"),
	cr(`^slack$`, "slack", "slack"),
	cr(`^adobe acrobat reader|^adobe reader`, "adobe", "acrobat_reader_dc"),
	cr(`^citrix workspace`, "citrix", "workspace"),
	cr(`^nmap`, "nmap", "nmap"),
	cr(`^curl \d`, "haxx", "curl"),
	cr(`^kubectl|^kubernetes cli`, "kubernetes", "kubernetes"),
	cr(`^terraform \d`, "hashicorp", "terraform"),
	cr(`^microsoft visual studio (community|professional|enterprise) 2022`, "microsoft", "visual_studio_2022"),
	cr(`^java\(tm\) se runtime|^java \d|^oracle java`, "oracle", "jre"),
	// Windows itself, from the build number (see windowsOSName in scanFacts).
	{re: regexp.MustCompile(`^os: windows 10 22h2$`), vendor: "microsoft", product: "windows_10_22h2", part: "o"},
	{re: regexp.MustCompile(`^os: windows 11 21h2$`), vendor: "microsoft", product: "windows_11_21h2", part: "o"},
	{re: regexp.MustCompile(`^os: windows 11 22h2$`), vendor: "microsoft", product: "windows_11_22h2", part: "o"},
	{re: regexp.MustCompile(`^os: windows 11 23h2$`), vendor: "microsoft", product: "windows_11_23h2", part: "o"},
	{re: regexp.MustCompile(`^os: windows 11 24h2$`), vendor: "microsoft", product: "windows_11_24h2", part: "o"},
	{re: regexp.MustCompile(`^os: windows 11 25h2$`), vendor: "microsoft", product: "windows_11_25h2", part: "o"},
}

// osPkgPrefix marks a synthetic "package" that stands for the operating system.
const osPkgPrefix = "OS: "

var winVerRe = regexp.MustCompile(`10\.0\.(\d{4,6})\.(\d+)`)

// windowsOSPkg turns "Microsoft Windows [Version 10.0.26100.7171]" into a
// synthetic package so the OS build is matched against NVD like any product.
// Only client builds that map one-to-one to an NVD product are returned.
func windowsOSPkg(osRelease string) (scanPkg, bool) {
	m := winVerRe.FindStringSubmatch(osRelease)
	if m == nil {
		return scanPkg{}, false
	}
	name := map[string]string{
		"19045": "Windows 10 22H2", "22000": "Windows 11 21H2", "22621": "Windows 11 22H2",
		"22631": "Windows 11 23H2", "26100": "Windows 11 24H2", "26200": "Windows 11 25H2",
	}[m[1]]
	if name == "" {
		return scanPkg{}, false
	}
	return scanPkg{Name: osPkgPrefix + name, Version: "10.0." + m[1] + "." + m[2]}, true
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
		part := r.part
		if part == "" {
			part = "a"
		}
		return fmt.Sprintf("cpe:2.3:%s:%s:%s:%s:*:*:*:*:*:*:*", part, r.vendor, r.product, v), true
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

const (
	nvdPageSize = 200
	nvdMaxPages = 6 // up to 1200 CVEs per product; enough to include every high-severity one for a patched-late build
)

// nvdQueryCPE asks NVD for CVEs affecting this exact CPE (version-range aware),
// following pages so a product with many CVEs is not cut off before the severe
// ones are seen.
func nvdQueryCPE(ctx context.Context, apiKey, cpe string) (rows []cpeCVE, total int, err error) {
	for page := 0; page < nvdMaxPages; page++ {
		pr, tot, e := nvdQueryPage(ctx, apiKey, cpe, page*nvdPageSize)
		if e != nil {
			if page > 0 && len(rows) > 0 {
				break // keep what we have rather than lose the whole product
			}
			return nil, 0, e
		}
		rows = append(rows, pr...)
		total = tot
		if (page+1)*nvdPageSize >= tot {
			break
		}
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
	return rows, total, nil
}

func nvdQueryPage(ctx context.Context, apiKey, cpe string, start int) (rows []cpeCVE, total int, err error) {
	q := url.Values{}
	q.Set("virtualMatchString", cpe)
	q.Set("resultsPerPage", fmt.Sprint(nvdPageSize))
	q.Set("startIndex", fmt.Sprint(start))
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

// nvdCPEURL is the NVD product dictionary endpoint (variable for tests).
var nvdCPEURL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

// nvdProductKnown reports whether NVD's product dictionary has any CPE under
// this vendor and product. It separates "no CVEs for this version" from "NVD
// does not know this product by this name, so nothing was really checked".
func nvdProductKnown(ctx context.Context, apiKey, cpe string) (known bool, err error) {
	parts := strings.Split(cpe, ":")
	if len(parts) < 5 {
		return false, fmt.Errorf("bad cpe")
	}
	match := strings.Join(parts[:5], ":")
	q := url.Values{}
	q.Set("cpeMatchString", match)
	q.Set("resultsPerPage", "1")
	if err := nvdWait(ctx, apiKey != ""); err != nil {
		return false, err
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, nvdCPEURL+"?"+q.Encode(), nil)
	if e != nil {
		return false, e
	}
	if apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}
	req.Header.Set("User-Agent", "ObsidianWatch-SIEM/1.0")
	resp, e := nvdHTTP.Do(req)
	if e != nil {
		return false, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("NVD CPE API: %s", resp.Status)
	}
	var r struct {
		TotalResults int `json:"totalResults"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r) != nil {
		return false, fmt.Errorf("unreadable NVD CPE response")
	}
	return r.TotalResults > 0, nil
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
	// NotInNVD: NVD's product dictionary has nothing under this name, so a
	// result of zero means "not assessed", not "no vulnerabilities".
	NotInNVD bool `json:"not_in_nvd,omitempty"`
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
	pkgs = m.Packages
	if strings.EqualFold(m.OS, "windows") {
		if p, ok := windowsOSPkg(m.System.OSRelease); ok {
			pkgs = append(append([]scanPkg{}, pkgs...), p)
		}
	}
	return m.System.OSRelease, m.OS, pkgs
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
	pt := 0
	for _, p := range pkgs {
		if !strings.HasPrefix(p.Name, osPkgPrefix) {
			pt++
		}
	}
	res := &HostCVEResult{Method: hostCVEMethod, PackagesTotal: pt, Unmapped: unmapped, ToCheck: len(targets),
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
		chk := HostCVEChecked{Name: t.name, Version: t.version, CPE: t.cpe, CVEs: len(rows), Total: total}
		if total == 0 {
			dkey := "dict:" + strings.Join(strings.Split(t.cpe, ":")[:5], ":")
			if _, _, hit := db.CPECacheGet(ctx, dkey, 30*24*time.Hour); !hit {
				if known, err := nvdProductKnown(ctx, apiKey, t.cpe); err == nil {
					n := 0
					if known {
						n = 1
					}
					_ = db.CPECachePut(ctx, dkey, n, json.RawMessage(`[]`))
				}
			}
			if _, n, hit := db.CPECacheGet(ctx, dkey, 30*24*time.Hour); hit && n == 0 {
				chk.NotInNVD = true
			}
		}
		res.Checked = append(res.Checked, chk)
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
