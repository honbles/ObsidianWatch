package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOSVEcosystemFor(t *testing.T) {
	cases := map[string]string{
		"Ubuntu 22.04.3 LTS":             "Ubuntu:22.04:LTS",
		"Ubuntu 23.10":                   "Ubuntu:23.10",
		"Debian GNU/Linux 12 (bookworm)": "Debian:12",
		"Alpine Linux v3.19":             "Alpine:v3.19",
		"Red Hat Enterprise Linux 9.2":   "",
		"":                               "",
	}
	for in, want := range cases {
		if got := osvEcosystemFor(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestOSVHostFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			w.Write([]byte(`{"results":[{"vulns":[{"id":"DSA-1"}]},{}]}`))
		case "/v1/vulns/DSA-1":
			w.Write([]byte(`{"id":"DSA-1","summary":"bad bug","aliases":["CVE-2024-1"],"database_specific":{"severity":"HIGH"},"affected":[{"ranges":[{"events":[{"fixed":"1.2-3"}]}]}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	old := osvBaseURL
	osvBaseURL = srv.URL
	defer func() { osvBaseURL = old }()
	pkgs := []map[string]interface{}{
		{"name": "openssl", "version": "1.0", "manager": "dpkg"},
		{"name": "curl", "version": "7", "manager": "dpkg"},
		{"name": "rpmpkg", "version": "1", "manager": "rpm"},
	}
	f, err := osvHostFindings(context.Background(), "Debian:12", pkgs)
	if err != nil || len(f) != 1 {
		t.Fatalf("%v %+v", err, f)
	}
	if f[0].PackageName != "openssl" || f[0].CVEID != "CVE-2024-1" || f[0].Severity != "high" || f[0].InstalledVersion != "1.0" {
		t.Fatalf("%+v", f[0])
	}
}
