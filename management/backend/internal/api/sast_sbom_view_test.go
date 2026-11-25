package api

import (
	"context"
	"testing"
)

func TestSBOMViewFlatten(t *testing.T) {
	res, err := parseTrivy([]byte(trivySample), "acme/web", true)
	if err != nil {
		t.Fatal(err)
	}
	comps, err := buildSBOMView(context.Background(), nil, res.SBOM)
	if err != nil || len(comps) != 2 {
		t.Fatalf("%v %+v", err, comps)
	}
	by := map[string]sbomViewComponent{}
	for _, c := range comps {
		by[c.Name] = c
	}
	l := by["lodash"]
	if l.Ecosystem != "npm" || len(l.Vulns) != 1 || l.Vulns[0].ID != "CVE-2020-8203" || l.Vulns[0].Severity != "high" ||
		len(l.Licenses) != 1 || l.Licenses[0] != "MIT" || l.File != "package-lock.json" || l.Runtime != "unknown" {
		t.Fatalf("lodash: %+v", l)
	}
	if !by["left-pad"].Transitive || len(by["left-pad"].Vulns) != 0 {
		t.Fatalf("left-pad: %+v", by["left-pad"])
	}
	if ecosystemOfPURL("pkg:maven/org.apache/x@1") != "Maven" || ecosystemOfPURL("pkg:golang/github.com/a/b@v1") != "Go" {
		t.Fatal("purl ecosystems")
	}
}

// A package declared in several manifests must list each vulnerability once,
// both in new SBOMs and in SBOMs stored before de-duplication.
func TestSBOMVulnsDeduplicated(t *testing.T) {
	comps := []sbomComponent{{Name: "golang.org/x/crypto", Version: "v0.49.0", PURL: "pkg:golang/golang.org/x/crypto@v0.49.0", Ecosystem: "gomod", File: "a/go.mod"}}
	var findings []SASTFinding
	for _, file := range []string{"a/go.mod", "b/go.mod", "c/go.mod"} {
		findings = append(findings, SASTFinding{RuleID: "SCA-CVE-2026-39828", Severity: "high", Title: "CVE-2026-39828 in golang.org/x/crypto v0.49.0",
			Detail: "ssh: unauthorized command execution https://avd.aquasec.com/nvd/cve-2026-39828", Fix: "Upgrade golang.org/x/crypto to v0.50.0 or later.",
			File: file, Package: "golang.org/x/crypto", Version: "v0.49.0", Ecosystem: "Go"})
	}
	doc := buildCycloneDX("o/r", comps, findings)
	view, err := buildSBOMView(context.Background(), nil, doc)
	if err != nil || len(view) != 1 || len(view[0].Vulns) != 1 {
		t.Fatalf("%v %+v", err, view)
	}
	v := view[0].Vulns[0]
	if v.URL != "https://avd.aquasec.com/nvd/cve-2026-39828" || v.DBURL != "https://nvd.nist.gov/vuln/detail/CVE-2026-39828" ||
		v.Title != "ssh: unauthorized command execution" || v.Fix == "" {
		t.Fatalf("vuln: %+v", v)
	}
	sbomAddFindings(view, findings)
	if len(view[0].Files) != 3 || len(view[0].Vulns[0].Files) != 3 {
		t.Fatalf("files: %+v", view[0])
	}
	// an old SBOM with the vulnerability repeated per manifest
	old := []byte(`{"components":[{"bom-ref":"r1","name":"x","version":"1","purl":"pkg:npm/x@1"}],"vulnerabilities":[
	 {"id":"GO-2026-1","ratings":[{"severity":"low"}],"affects":[{"ref":"r1"}]},
	 {"id":"GO-2026-1","ratings":[{"severity":"low"}],"affects":[{"ref":"r1"}]}]}`)
	view, _ = buildSBOMView(context.Background(), nil, old)
	if len(view[0].Vulns) != 1 || view[0].Vulns[0].DBURL != "https://osv.dev/vulnerability/GO-2026-1" {
		t.Fatalf("old: %+v", view[0].Vulns)
	}
}
