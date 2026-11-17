package api

import (
	"strings"
	"testing"
)

func TestParseIPFeed(t *testing.T) {
	in := "# Feodo\n; comment\n\nip_address,port,status\n203.0.113.7\n198.51.100.9:443\n198.51.100.10,8080,online\n\"192.0.2.44\",x\n2001:db8::5\n203.0.113.7\n10.0.0.1\n127.0.0.1\n0.0.0.0\nnot-an-ip\n"
	got := parseIPFeed(strings.NewReader(in))
	want := []string{"203.0.113.7", "198.51.100.9", "198.51.100.10", "192.0.2.44", "2001:db8::5"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestFetchFeedRejectsBadURLs(t *testing.T) {
	for _, u := range []string{"http://example.com/f.txt", "ftp://x/y", "", "not a url", "https://"} {
		if _, err := fetchFeed(t.Context(), u); err == nil {
			t.Errorf("%q must be rejected", u)
		}
	}
}
