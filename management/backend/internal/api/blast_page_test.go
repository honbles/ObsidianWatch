package api

import "testing"

func TestGCPPageURL(t *testing.T) {
	if gcpPageURL("https://x/y?a=1", "pageToken", "") != "https://x/y?a=1" {
		t.Fatal("empty token must not change url")
	}
	if got := gcpPageURL("https://x/y?a=1", "pageToken", "a b"); got != "https://x/y?a=1&pageToken=a+b" {
		t.Fatal(got)
	}
	if got := gcpPageURL("https://x/y", "pageToken", "t"); got != "https://x/y?pageToken=t" {
		t.Fatal(got)
	}
}
