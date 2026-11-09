package api

// vuln_osv.go — F-21: match a host's installed packages against OSV using the
// distro's own ecosystem (Debian, Ubuntu, Alpine) and the exact installed
// version, instead of NVD keyword search. OSV's distro feeds carry the
// distro's fixed versions, so back-ported fixes are respected.
//
// Limits: OSV indexes distro SOURCE package names; a binary package whose name
// differs from its source (e.g. libssl3 vs openssl) can be missed. RPM-based
// distributions are not covered. Callers fall back to NVD when this returns an
// error or the distro is unsupported.

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	osrUbuntu = regexp.MustCompile(`(?i)^ubuntu\s+(\d+)\.(\d+)`)
	osrDebian = regexp.MustCompile(`(?i)^debian\b.*?\b(\d+)(?:\.\d+)?\b`)
	osrAlpine = regexp.MustCompile(`(?i)^alpine\b.*?v?(\d+\.\d+)`)
)

// osvEcosystemFor maps an os-release PRETTY_NAME to an OSV ecosystem, or "".
func osvEcosystemFor(osRelease string) string {
	s := strings.TrimSpace(osRelease)
	if m := osrUbuntu.FindStringSubmatch(s); m != nil {
		year, _ := strconv.Atoi(m[1])
		eco := "Ubuntu:" + m[1] + "." + m[2]
		if m[2] == "04" && year%2 == 0 {
			eco += ":LTS"
		}
		return eco
	}
	if m := osrDebian.FindStringSubmatch(s); m != nil {
		return "Debian:" + m[1]
	}
	if m := osrAlpine.FindStringSubmatch(s); m != nil {
		return "Alpine:v" + m[1]
	}
	return ""
}

const hostOSVMaxPackages = 1500

// osvHostFindings queries OSV for the given packages (maps with name, version,
// manager) and returns one finding per (package, vulnerability).
func osvHostFindings(ctx context.Context, ecosystem string, pkgs []map[string]interface{}) ([]CVEFinding, error) {
	type pk struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	}
	type q struct {
		Package pk     `json:"package"`
		Version string `json:"version"`
	}
	type ref struct{ name, version string }
	var qs []q
	var refs []ref
	seen := map[string]bool{}
	for _, p := range pkgs {
		name, _ := p["name"].(string)
		ver, _ := p["version"].(string)
		mgr, _ := p["manager"].(string)
		if name == "" || ver == "" || (mgr != "" && mgr != "dpkg" && mgr != "apk") || seen[name+"|"+ver] {
			continue
		}
		seen[name+"|"+ver] = true
		qs = append(qs, q{pk{name, ecosystem}, ver})
		refs = append(refs, ref{name, ver})
		if len(qs) >= hostOSVMaxPackages {
			break
		}
	}
	type hit struct {
		r  ref
		id string
	}
	var hits []hit
	for start := 0; start < len(qs); start += scaBatchSize {
		end := start + scaBatchSize
		if end > len(qs) {
			end = len(qs)
		}
		var resp struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			} `json:"results"`
		}
		if err := osvPost(ctx, "/v1/querybatch", map[string]interface{}{"queries": qs[start:end]}, &resp); err != nil {
			return nil, err
		}
		for i, r := range resp.Results {
			if start+i >= len(refs) {
				break
			}
			for _, v := range r.Vulns {
				hits = append(hits, hit{refs[start+i], v.ID})
			}
		}
	}
	ids := map[string]bool{}
	for _, h := range hits {
		ids[h.id] = true
	}
	var idList []string
	for id := range ids {
		idList = append(idList, id)
	}
	sort.Strings(idList)
	details := map[string]osvVuln{}
	for i, id := range idList {
		if i >= scaMaxVulnGets {
			break
		}
		if v, err := osvGetVuln(ctx, id); err == nil {
			details[id] = v
		}
	}
	var out []CVEFinding
	for _, h := range hits {
		v := details[h.id]
		cve := h.id
		for _, a := range v.Aliases {
			if strings.HasPrefix(a, "CVE-") {
				cve = a
				break
			}
		}
		desc := v.Summary
		if desc == "" {
			desc = "Known vulnerability reported in the OSV distro database."
		}
		if f := osvFixed(v); f != "" {
			desc += " Fixed in " + f + "."
		}
		sev := osvSeverity(v)
		out = append(out, CVEFinding{
			PackageName: h.r.name, InstalledVersion: h.r.version, CVEID: cve, Severity: sev,
			CVSSScore:   map[string]float64{"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5}[sev],
			Description: desc, URL: fmt.Sprintf("https://osv.dev/vulnerability/%s", h.id),
		})
	}
	return out, nil
}
