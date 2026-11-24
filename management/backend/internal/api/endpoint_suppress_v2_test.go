package api

import (
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func TestSuppressionMatching(t *testing.T) {
	now := time.Now()
	ev := fxProcRaw("modprobe", "modprobe -b usb", `{"exe":"/usr/sbin/modprobe","parent_exe":"/usr/lib/systemd/systemd-udevd"}`)
	ev.Host = "web01"
	user := "root"
	ev.UserName = &user

	base := EndpointSuppression{RuleID: "L-T1547.006", MatchMode: suppModeExact, Reason: "udev"}
	if !suppressionMatches(base, "L-T1547.006", ev, now) {
		t.Error("exact rule id should match")
	}
	if suppressionMatches(base, "L-T1547.006b", ev, now) {
		t.Error("exact mode must not prefix-match")
	}
	pre := EndpointSuppression{RuleID: "L-T1547.", MatchMode: suppModePrefix}
	if !suppressionMatches(pre, "L-T1547.006", ev, now) {
		t.Error("prefix mode should match")
	}

	// matchers AND together
	full := base
	full.Host, full.ProcessName, full.ImagePathGlob = "WEB01", "modprobe", "/usr/sbin/*"
	full.ParentProcess, full.UserName, full.CmdlineContain = "systemd-udevd", "r*", "-B USB"
	if !suppressionMatches(full, "L-T1547.006", ev, now) {
		t.Error("all matchers satisfied should match")
	}
	for name, mut := range map[string]func(*EndpointSuppression){
		"host":    func(r *EndpointSuppression) { r.Host = "web02" },
		"process": func(r *EndpointSuppression) { r.ProcessName = "insmod" },
		"image":   func(r *EndpointSuppression) { r.ImagePathGlob = "/opt/*" },
		"parent":  func(r *EndpointSuppression) { r.ParentProcess = "dockerd" },
		"user":    func(r *EndpointSuppression) { r.UserName = "alice" },
		"cmdline": func(r *EndpointSuppression) { r.CmdlineContain = "overlay" },
	} {
		r := full
		mut(&r)
		if suppressionMatches(r, "L-T1547.006", ev, now) {
			t.Errorf("a failing %s matcher must stop the match", name)
		}
	}

	// expiry and rule-less
	past := now.Add(-time.Hour)
	exp := base
	exp.ExpiresAt = &past
	if suppressionMatches(exp, "L-T1547.006", ev, now) {
		t.Error("expired suppression must not match")
	}
	if suppressionMatches(EndpointSuppression{}, "L-T1547.006", ev, now) {
		t.Error("rule-less suppression must not match")
	}

	// Windows parent from Sysmon event_data, and file path globs
	w := fxProcParent("powershell.exe", "powershell -enc AAAA", `C:\\Windows\\CCM\\CcmExec.exe`)
	if !suppressionMatches(EndpointSuppression{RuleID: "W-T1059.001a", ParentProcess: "ccmexec.exe"}, "W-T1059.001a", w, now) {
		t.Error("Sysmon ParentImage should satisfy parent_process")
	}
	f := fxFile(`C:\\Users\\a\\AppData\\Local\\Temp\\x.dll`)
	if !suppressionMatches(EndpointSuppression{RuleID: "W-T1574.002", FilePathGlob: `c:\\users\\*\\appdata\\local\\temp\\*.dll`}, "W-T1574.002", f, now) {
		t.Error("file_path_glob should match across separators")
	}
}

func TestEndpointSuppressedCountsHits(t *testing.T) {
	endpointSupp.mu.Lock()
	endpointSupp.rules = []EndpointSuppression{{ID: 42, RuleID: "IOC:otx:hash", MatchMode: suppModeExact}}
	endpointSupp.mu.Unlock()
	defer func() {
		endpointSupp.mu.Lock()
		endpointSupp.rules = nil
		endpointSupp.mu.Unlock()
		endpointSupp.hmu.Lock()
		endpointSupp.hits = map[suppHitKey]int64{}
		endpointSupp.hmu.Unlock()
	}()
	ev := store.Event{Host: "h1"}
	if !endpointSuppressed("IOC:otx:hash", ev) || !endpointSuppressed("IOC:otx:hash", ev) {
		t.Fatal("IOC suppression should apply")
	}
	if endpointSuppressed("IOC:otx:ip", ev) {
		t.Error("exact mode must not cover IOC:otx:ip")
	}
	endpointSupp.hmu.Lock()
	var total int64
	for k, n := range endpointSupp.hits {
		if k.id == 42 {
			total += n
		}
	}
	endpointSupp.hmu.Unlock()
	if total != 2 {
		t.Errorf("hits=%d want 2", total)
	}
}

func TestValidateSuppression(t *testing.T) {
	now := time.Now()
	ok := func(r EndpointSuppression) string { return validateSuppression(&r, now) }
	good := EndpointSuppression{RuleID: "L-T1547.006", Reason: "udev", ExpiresInDays: 30}
	if m := ok(good); m != "" {
		t.Errorf("valid rule rejected: %s", m)
	}
	cases := map[string]EndpointSuppression{
		"no reason":          {RuleID: "L-T1547.006", ExpiresInDays: 30},
		"no rule":            {Reason: "x", ExpiresInDays: 30},
		"unknown exact id":   {RuleID: "L-NOPE-999", Reason: "x", ExpiresInDays: 30},
		"short prefix":       {RuleID: "L-T15", MatchMode: suppModePrefix, Reason: "x", ExpiresInDays: 30},
		"prefix no rule":     {RuleID: "ZZZZZZZZ", MatchMode: suppModePrefix, Reason: "x", ExpiresInDays: 30},
		"no expiry":          {RuleID: "L-T1547.006", Reason: "x"},
		"expiry over a year": {RuleID: "L-T1547.006", Reason: "x", ExpiresInDays: 400},
		"bad mode":           {RuleID: "L-T1547.006", MatchMode: "regex", Reason: "x", ExpiresInDays: 30},
		"bad glob":           {RuleID: "L-T1547.006", ImagePathGlob: "[", Reason: "x", ExpiresInDays: 30},
	}
	for name, r := range cases {
		if ok(r) == "" {
			t.Errorf("%s: should be rejected", name)
		}
	}
	// permanent needs no expiry; IOC and Sigma namespaces are accepted
	if m := ok(EndpointSuppression{RuleID: "IOC:otx:hash", Reason: "x", Permanent: true}); m != "" {
		t.Errorf("permanent IOC rule rejected: %s", m)
	}
	if m := ok(EndpointSuppression{RuleID: "SIGMA:abc-123", Reason: "x", ExpiresInDays: 10}); m != "" {
		t.Errorf("sigma rule rejected: %s", m)
	}
	if m := ok(EndpointSuppression{RuleID: "L-T1547.", MatchMode: suppModePrefix, Reason: "x", ExpiresInDays: 10}); m != "" {
		t.Errorf("valid prefix rejected: %s", m)
	}
}
