package api

// sast_sbom_view.go - the SBOM as a page: GET .../sast/sbom?repo=&view=1
// returns the stored CycloneDX document flattened into components, each with
// its vulnerabilities (from the same scan) and where it runs now (runtime
// inventory). Without view=1 the endpoint still returns the CycloneDX file.

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"obsidianwatch/management/internal/store"
)

// purlEcosystem maps a purl type to the ecosystem names used by the runtime
// inventory and the scanners.
var purlEcosystem = map[string]string{
	"npm": "npm", "pypi": "PyPI", "golang": "Go", "maven": "Maven", "nuget": "NuGet",
	"gem": "RubyGems", "cargo": "crates.io", "composer": "Packagist", "pub": "Pub", "hex": "Hex",
}

type sbomVuln struct {
	ID       string   `json:"id"`
	Severity string   `json:"severity"`
	Title    string   `json:"title,omitempty"`  // detail without the advisory URL
	Detail   string   `json:"detail,omitempty"` // as the scanner gave it
	URL      string   `json:"url,omitempty"`    // advisory (scanner link)
	DBURL    string   `json:"db_url,omitempty"` // NVD / GitHub advisory / OSV page for the ID
	Fix      string   `json:"fix,omitempty"`
	Files    []string `json:"files,omitempty"` // manifests that declare the affected version
	Triage   string   `json:"triage,omitempty"`
	IssueURL string   `json:"issue_url,omitempty"`
}

type sbomViewComponent struct {
	Name       string     `json:"name"`
	Version    string     `json:"version"`
	Ecosystem  string     `json:"ecosystem"`
	PURL       string     `json:"purl,omitempty"`
	Licenses   []string   `json:"licenses,omitempty"`
	Transitive bool       `json:"transitive"`
	File       string     `json:"file,omitempty"`
	Files      []string   `json:"files,omitempty"` // every manifest that declares this version (from the scan findings)
	Vulns      []sbomVuln `json:"vulns,omitempty"`
	Runtime    string     `json:"runtime"` // loaded | deployed | not_running | unknown
	Hosts      []string   `json:"hosts,omitempty"`
	Services   []string   `json:"services,omitempty"`
}

type cdxDoc struct {
	Metadata struct {
		Timestamp string `json:"timestamp"`
	} `json:"metadata"`
	Components []struct {
		BOMRef   string `json:"bom-ref"`
		Name     string `json:"name"`
		Version  string `json:"version"`
		PURL     string `json:"purl"`
		Licenses []struct {
			License map[string]string `json:"license"`
		} `json:"licenses"`
		Properties []map[string]string `json:"properties"`
	} `json:"components"`
	Vulnerabilities []struct {
		ID             string              `json:"id"`
		Detail         string              `json:"detail"`
		Recommendation string              `json:"recommendation"`
		Advisories     []map[string]string `json:"advisories"`
		Ratings        []map[string]string `json:"ratings"`
		Affects        []map[string]string `json:"affects"`
	} `json:"vulnerabilities"`
}

func ecosystemOfPURL(purl string) string {
	t := strings.TrimPrefix(purl, "pkg:")
	if i := strings.Index(t, "/"); i > 0 {
		if e, ok := purlEcosystem[t[:i]]; ok {
			return e
		}
		return t[:i]
	}
	return ""
}

// buildSBOMView flattens a CycloneDX document and adds runtime status.
func buildSBOMView(ctx context.Context, db *store.DB, raw []byte) ([]sbomViewComponent, error) {
	var doc cdxDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	vulnsByRef := map[string][]sbomVuln{}
	for _, v := range doc.Vulnerabilities {
		sev := ""
		if len(v.Ratings) > 0 {
			sev = v.Ratings[0]["severity"]
		}
		url := ""
		if len(v.Advisories) > 0 {
			url = v.Advisories[0]["url"]
		}
		if url == "" {
			url = advisoryURL(v.ID, v.Detail)
		}
		title := strings.TrimSpace(strings.Replace(v.Detail, url, "", 1))
		for _, a := range v.Affects {
			dup := false // SBOMs written before de-duplication list a vulnerability once per manifest
			for _, x := range vulnsByRef[a["ref"]] {
				dup = dup || x.ID == v.ID
			}
			if dup {
				continue
			}
			vulnsByRef[a["ref"]] = append(vulnsByRef[a["ref"]], sbomVuln{ID: v.ID, Severity: sev, Detail: truncate(v.Detail, 600),
				Title: truncate(title, 400), URL: url, DBURL: vulnDBURL(v.ID), Fix: v.Recommendation})
		}
	}
	out := make([]sbomViewComponent, 0, len(doc.Components))
	ecos := map[string]bool{}
	for _, c := range doc.Components {
		vc := sbomViewComponent{Name: c.Name, Version: c.Version, PURL: c.PURL, Ecosystem: ecosystemOfPURL(c.PURL), Vulns: vulnsByRef[c.BOMRef]}
		for _, l := range c.Licenses {
			if v := l.License["id"]; v != "" {
				vc.Licenses = append(vc.Licenses, v)
			} else if v := l.License["name"]; v != "" {
				vc.Licenses = append(vc.Licenses, v)
			}
		}
		for _, p := range c.Properties {
			switch p["name"] {
			case "obsidianwatch:dependency":
				vc.Transitive = p["value"] == "transitive"
			case "obsidianwatch:source-file":
				vc.File = p["value"]
			}
		}
		sort.Slice(vc.Vulns, func(i, j int) bool { return sevRank(vc.Vulns[i].Severity) > sevRank(vc.Vulns[j].Severity) })
		if vc.Ecosystem != "" {
			ecos[vc.Ecosystem] = true
		}
		out = append(out, vc)
	}
	since := time.Now().Add(-runtimeFresh)
	coverage := 0
	if db != nil {
		coverage = db.RuntimeInventoryCoverage(ctx, since)
	}
	var index map[string]store.RuntimeIndexEntry
	if coverage > 0 && len(ecos) > 0 {
		list := make([]string, 0, len(ecos))
		for e := range ecos {
			list = append(list, e)
		}
		index, _ = db.RuntimePackageIndex(ctx, list, since)
	}
	for i := range out {
		c := &out[i]
		switch {
		case coverage == 0 || c.Ecosystem == "":
			c.Runtime = "unknown"
		default:
			e, ok := index[c.Ecosystem+"\x00"+store.PackageNameKey(c.Ecosystem, c.Name)+"\x00"+normVersion(c.Ecosystem, c.Version)]
			switch {
			case !ok:
				c.Runtime = "not_running"
			case e.Loaded:
				c.Runtime, c.Hosts, c.Services = "loaded", e.Hosts, e.Services
			default:
				c.Runtime, c.Hosts, c.Services = "deployed", e.Hosts, e.Services
			}
		}
	}
	return out, nil
}

// sbomAddFindings fills fix, manifests, triage and issue links from the scan's
// dependency findings (the SBOM holds one manifest per component).
func sbomAddFindings(comps []sbomViewComponent, findings []SASTFinding) {
	type info struct {
		files    []string
		fix      string
		triage   string
		issueURL string
	}
	byVuln := map[string]*info{}
	filesByPkg := map[string][]string{}
	add := func(list []string, f string) []string {
		for _, x := range list {
			if x == f {
				return list
			}
		}
		return append(list, f)
	}
	for _, f := range findings {
		if f.Package == "" || !strings.HasPrefix(f.RuleID, "SCA-") {
			continue
		}
		pk := strings.ToLower(f.Package) + "@" + strings.TrimPrefix(f.Version, "v")
		if f.File != "" {
			filesByPkg[pk] = add(filesByPkg[pk], f.File)
		}
		k := strings.TrimPrefix(f.RuleID, "SCA-") + "\x00" + pk
		x := byVuln[k]
		if x == nil {
			x = &info{fix: f.Fix}
			byVuln[k] = x
		}
		if f.File != "" {
			x.files = add(x.files, f.File)
		}
		if f.Triage != nil && x.triage == "" {
			x.triage = f.Triage.Status
		}
		if f.IssueURL != "" {
			x.issueURL = f.IssueURL
		}
	}
	for i := range comps {
		c := &comps[i]
		pk := strings.ToLower(c.Name) + "@" + strings.TrimPrefix(c.Version, "v")
		c.Files = filesByPkg[pk]
		for j := range c.Vulns {
			v := &c.Vulns[j]
			if x := byVuln[v.ID+"\x00"+pk]; x != nil {
				v.Files, v.Triage, v.IssueURL = x.files, x.triage, x.issueURL
				if v.Fix == "" {
					v.Fix = x.fix
				}
			}
		}
	}
}

func writeSBOMView(w http.ResponseWriter, r *http.Request, db *store.DB, connID int64, repo, branch string, scannedAt time.Time, raw, findingsRaw []byte) {
	comps, err := buildSBOMView(r.Context(), db, raw)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "stored SBOM could not be read: " + err.Error()})
		return
	}
	var findings []SASTFinding
	if json.Unmarshal(findingsRaw, &findings) == nil && len(findings) > 0 {
		if db != nil {
			ix := loadTriageIndex(r.Context(), db, connID)
			issues := issueLinksByFingerprint(r.Context(), db, connID)
			for i := range findings {
				ix.apply(&findings[i])
				findings[i].IssueURL = issues[findings[i].Repo+"\x00"+findings[i].Fingerprint]
			}
		}
		sbomAddFindings(comps, findings)
	}
	summary := map[string]int{"components": len(comps)}
	for _, c := range comps {
		if c.Transitive {
			summary["transitive"]++
		}
		if len(c.Vulns) > 0 {
			summary["vulnerable"]++
		}
		summary["runtime_"+c.Runtime]++
	}
	writeJSON(w, 200, map[string]interface{}{"repo": repo, "branch": branch, "scanned_at": scannedAt,
		"summary": summary, "components": comps})
}
