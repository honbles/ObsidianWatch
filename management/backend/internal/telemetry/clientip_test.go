package telemetry

import (
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	cases := []struct{ peer, xff, real, want string }{
		{"172.22.0.5:4431", "", "", "172.22.0.5"},                    // no header: the peer
		{"172.22.0.5:4431", "41.58.12.9", "", "41.58.12.9"},          // console nginx
		{"172.22.0.5:4431", "", "41.58.12.9", "41.58.12.9"},          // X-Real-IP only (older proxy config)
		{"172.22.0.5:4431", "6.6.6.6, 41.58.12.9", "", "41.58.12.9"}, // forged left entry ignored
		{"172.22.0.5:4431", "10.1.2.3", "", "10.1.2.3"},              // internal client
		{"41.58.12.9:5000", "1.2.3.4", "9.9.9.9", "41.58.12.9"},      // public peer: headers not trusted
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.peer
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if c.real != "" {
			r.Header.Set("X-Real-IP", c.real)
		}
		if got := ClientIP(r); got != c.want {
			t.Errorf("peer %s xff %q real %q: got %s want %s", c.peer, c.xff, c.real, got, c.want)
		}
	}
}

func TestArchiveCommit(t *testing.T) {
	old := buildCommitFile
	defer func() { buildCommitFile = old }()
	for in, want := range map[string]string{
		"$Format:%H$\n": "", // a git checkout: the placeholder
		"5f1c0de3a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4\n": "5f1c0de3a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4",
		"not a commit": "",
	} {
		buildCommitFile = in
		if got := archiveCommit(); got != want {
			t.Errorf("%q: got %q", in, got)
		}
	}
}
