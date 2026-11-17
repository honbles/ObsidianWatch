package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCPEFor(t *testing.T) {
	cases := []struct{ name, ver, want string }{
		{"Google Chrome", "126.0.6478.127", "cpe:2.3:a:google:chrome:126.0.6478.127:*:*:*:*:*:*:*"},
		{"Mozilla Firefox (x64 en-US)", "125.0.1", "cpe:2.3:a:mozilla:firefox:125.0.1:*:*:*:*:*:*:*"},
		{"Microsoft Edge", "126.0.2592.87", "cpe:2.3:a:microsoft:edge_chromium:126.0.2592.87:*:*:*:*:*:*:*"},
		{"Python 3.12.1 (64-bit)", "3.12.1150.0", "cpe:2.3:a:python:python:3.12.1:*:*:*:*:*:*:*"},
		{"PuTTY release 0.80 (64-bit)", "0.80.0.0", "cpe:2.3:a:putty:putty:0.80:*:*:*:*:*:*:*"},
		{"Notepad++ (64-bit x64)", "8.6.2", `cpe:2.3:a:notepad-plus-plus:notepad\+\+:8.6.2:*:*:*:*:*:*:*`},
		{"7-Zip 23.01 (x64)", "23.01", "cpe:2.3:a:7-zip:7-zip:23.01:*:*:*:*:*:*:*"},
		{"PostgreSQL 16", "16.1-1", "cpe:2.3:a:postgresql:postgresql:16.1:*:*:*:*:*:*:*"},
		{"Git", "2.43.0", "cpe:2.3:a:git-scm:git:2.43.0:*:*:*:*:*:*:*"},
	}
	for _, c := range cases {
		got, ok := cpeFor(c.name, c.ver)
		if !ok || got != c.want {
			t.Errorf("%q %q -> %q (%v), want %q", c.name, c.ver, got, ok, c.want)
		}
	}
	for _, n := range []string{"Microsoft Visual C++ 2015-2022 Redistributable", "Realtek Audio", "Some Unknown App"} {
		if _, ok := cpeFor(n, "1.2.3"); ok {
			t.Errorf("%q must not be mapped", n)
		}
	}
	if _, ok := cpeFor("Google Chrome", "unknown"); ok {
		t.Errorf("a non-numeric version must not produce a CPE")
	}
}

func TestHostUsesCPEPath(t *testing.T) {
	win := []scanPkg{{"Google Chrome", "126.0.1"}, {"Realtek", "1.0"}}
	if !hostUsesCPEPath("Microsoft Windows [Version 10.0.26100]", win) {
		t.Errorf("windows with a known product uses the CPE path")
	}
	if hostUsesCPEPath("Ubuntu 22.04.3 LTS", win) {
		t.Errorf("distro-feed hosts keep the OSV path")
	}
	if hostUsesCPEPath("Microsoft Windows", []scanPkg{{"Realtek", "1.0"}}) {
		t.Errorf("no recognised product -> no CPE path")
	}
	targets, unmapped := cveTargets(append(win, scanPkg{"Google Chrome", "126.0.1"}))
	if len(targets) != 1 || unmapped != 1 {
		t.Errorf("targets %d unmapped %d", len(targets), unmapped)
	}
}

func TestNVDQueryCPE(t *testing.T) {
	var hits int
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		gotQuery = r.URL.RawQuery
		fmt.Fprint(w, `{"totalResults":3,"vulnerabilities":[
		 {"cve":{"id":"CVE-2024-0001","published":"2024-01-02T00:00:00.000","descriptions":[{"lang":"en","value":"low one"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":3.1},"baseSeverity":"LOW"}]}}},
		 {"cve":{"id":"CVE-2024-0002","published":"2024-02-03T00:00:00.000","descriptions":[{"lang":"en","value":"bad"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":8.8},"baseSeverity":"HIGH"}]}}},
		 {"cve":{"id":"CVE-2024-0003","published":"2024-03-04T00:00:00.000","descriptions":[{"lang":"en","value":"worse"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8},"baseSeverity":"CRITICAL"}]}}}]}`)
	}))
	defer srv.Close()
	old := nvdCVEURL
	nvdCVEURL = srv.URL
	defer func() { nvdCVEURL = old }()
	nvdPace.next = time.Time{}

	rows, total, err := nvdQueryCPE(context.Background(), "key", "cpe:2.3:a:google:chrome:126.0.1:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(rows) != 2 {
		t.Fatalf("total %d rows %d (CVSS<4 must be dropped)", total, len(rows))
	}
	if rows[0].ID != "CVE-2024-0003" || rows[1].ID != "CVE-2024-0002" || rows[0].Published != "2024-03-04" {
		t.Errorf("sorted by score desc: %+v", rows)
	}
	if !strings.Contains(gotQuery, "virtualMatchString=cpe") || !strings.Contains(gotQuery, "noRejected") {
		t.Errorf("query: %s", gotQuery)
	}
	if hits != 1 {
		t.Errorf("hits %d", hits)
	}
}

func TestNVDPacerSpacing(t *testing.T) {
	nvdPace.next = time.Time{}
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := nvdWait(ctx, true); err != nil { // keyed: 700ms apart
			t.Fatal(err)
		}
	}
	if el := time.Since(start); el < 1300*time.Millisecond {
		t.Errorf("3 keyed requests took %v; slots must be ~700ms apart", el)
	}
	nvdPace.next = time.Now().Add(time.Hour)
	cctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if err := nvdWait(cctx, false); err == nil {
		t.Errorf("a cancelled context must abort the wait")
	}
	nvdPace.next = time.Time{}
}

func TestCPEForExpandedCatalog(t *testing.T) {
	cases := []struct{ name, ver, want string }{
		{"Microsoft Windows Desktop Runtime - 8.0.31 (x64)", "8.0.31.36421", "cpe:2.3:a:microsoft:.net:8.0.31:*:*:*:*:*:*:*"},
		{"Microsoft Windows Desktop Runtime 10.0.12 (x64)", "10.0.12.50000", "cpe:2.3:a:microsoft:.net:10.0.12:*:*:*:*:*:*:*"},
		{"Microsoft ASP.NET Core 8.0.31 - Shared Framework (x64)", "8.0.31.26421", "cpe:2.3:a:microsoft:asp.net_core:8.0.31:*:*:*:*:*:*:*"},
		{"Microsoft Azure CLI (64-bit)", "2.92.0", "cpe:2.3:a:microsoft:azure_cli:2.92.0:*:*:*:*:*:*:*"},
		{"GitHub CLI", "2.103.3", "cpe:2.3:a:github:cli:2.103.3:*:*:*:*:*:*:*"},
		{"Dell Command | Update for Windows Universal", "5.4.1", "cpe:2.3:a:dell:command_update:5.4.1:*:*:*:*:*:*:*"},
		{"Dell Optimizer", "6.3.4.0", "cpe:2.3:a:dell:optimizer:6.3.4.0:*:*:*:*:*:*:*"},
		{"Sophos Connect", "2.5.1025.0607", "cpe:2.3:a:sophos:connect_client:2.5.1025.0607:*:*:*:*:*:*:*"},
		{"OS: Windows 11 24H2", "10.0.26100.7171", "cpe:2.3:o:microsoft:windows_11_24h2:10.0.26100.7171:*:*:*:*:*:*:*"},
	}
	for _, c := range cases {
		got, ok := cpeFor(c.name, c.ver)
		if !ok || got != c.want {
			t.Errorf("cpeFor(%q,%q) = %q,%v want %q", c.name, c.ver, got, ok, c.want)
		}
	}
	// versionless / channel-based products must NOT be guessed
	for _, n := range []string{"Microsoft 365 - en-us", "Microsoft OneNote - en-us", "Copilot", "Microsoft Intune Management Extension", "UltraViewer version 6.6.124", "Cirrus Audio Driver", "Block 64 Discovery Agent", "Microsoft Visual C++ v14 Redistributable (x64) - 14.50.35719"} {
		if c, ok := cpeFor(n, "1.2.3"); ok {
			t.Errorf("%q must not be mapped, got %s", n, c)
		}
	}
}

func TestWindowsOSPkg(t *testing.T) {
	p, ok := windowsOSPkg("Microsoft Windows [Version 10.0.26100.7171]")
	if !ok || p.Name != "OS: Windows 11 24H2" || p.Version != "10.0.26100.7171" {
		t.Fatalf("%+v %v", p, ok)
	}
	if p, ok := windowsOSPkg("Microsoft Windows [Version 10.0.19045.5555]"); !ok || p.Name != "OS: Windows 10 22H2" {
		t.Fatalf("%+v", p)
	}
	for _, s := range []string{"", "Linux 6.1", "Microsoft Windows [Version 10.0.17763.1]", "Microsoft Windows [Version 6.3.9600]"} {
		if _, ok := windowsOSPkg(s); ok {
			t.Errorf("%q must not map", s)
		}
	}
	raw := []byte(`{"os":"windows","system":{"os_release":"Microsoft Windows [Version 10.0.26100.7171]"},"packages":[{"name":"Git","version":"2.56.0.2"}]}`)
	_, _, pkgs := scanFacts(raw)
	if len(pkgs) != 2 || pkgs[1].Name != "OS: Windows 11 24H2" {
		t.Fatalf("scanFacts must add the OS entry: %+v", pkgs)
	}
}

func TestNVDQueryFollowsPages(t *testing.T) {
	var starts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := r.URL.Query().Get("startIndex")
		starts = append(starts, st)
		// 450 results in total: pages at 0, 200, 400. The critical one is only on the last page.
		id, score := "CVE-2024-1000", "5.0"
		if st == "400" {
			id, score = "CVE-2024-9999", "9.8"
		}
		fmt.Fprintf(w, `{"totalResults":450,"vulnerabilities":[{"cve":{"id":"%s","published":"2024-01-01T00:00:00.000","descriptions":[{"lang":"en","value":"x"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":%s},"baseSeverity":"HIGH"}]}}}]}`, id, score)
	}))
	defer srv.Close()
	old := nvdCVEURL
	nvdCVEURL = srv.URL
	defer func() { nvdCVEURL = old }()
	nvdPace.next = time.Time{}
	rows, total, err := nvdQueryCPE(context.Background(), "key", "cpe:2.3:o:microsoft:windows_11_24h2:10.0.26100.1:*:*:*:*:*:*:*")
	if err != nil || total != 450 {
		t.Fatalf("%v total=%d", err, total)
	}
	if strings.Join(starts, ",") != "0,200,400" {
		t.Errorf("pages requested: %v", starts)
	}
	if len(rows) == 0 || rows[0].ID != "CVE-2024-9999" {
		t.Errorf("the critical CVE on the last page must surface first: %+v", rows)
	}
}

func TestNVDProductKnown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("cpeMatchString"), "real_product") {
			fmt.Fprint(w, `{"totalResults":12}`)
			return
		}
		fmt.Fprint(w, `{"totalResults":0}`)
	}))
	defer srv.Close()
	old := nvdCPEURL
	nvdCPEURL = srv.URL
	defer func() { nvdCPEURL = old }()
	nvdPace.next = time.Time{}
	if k, err := nvdProductKnown(context.Background(), "k", "cpe:2.3:a:acme:real_product:1.0:*:*:*:*:*:*:*"); err != nil || !k {
		t.Fatalf("known: %v %v", k, err)
	}
	nvdPace.next = time.Time{}
	if k, err := nvdProductKnown(context.Background(), "k", "cpe:2.3:a:acme:made_up:1.0:*:*:*:*:*:*:*"); err != nil || k {
		t.Fatalf("unknown: %v %v", k, err)
	}
}
