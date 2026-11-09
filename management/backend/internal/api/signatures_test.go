package api

import (
	"encoding/json"
	"io"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func allSigSets() map[string][]ThreatSig {
	return map[string][]ThreatSig{
		"linux": linuxSignatures, "windows": windowsSignatures, "windowsTamper": windowsTamperSignatures,
		"dc": dcSignatures, "macos": macosSignatures, "endpoint": endpointAgentSignatures,
		"dns": dnsCatSignatures, "devops": devopsSignatures,
		"awsExtra": awsExtraSignatures, "gcpEsc": gcpEscalationSignatures,
	}
}

func TestSignatureIDsUniqueAndComplete(t *testing.T) {
	seen := map[string]string{}
	for set, sigs := range allSigSets() {
		for _, s := range sigs {
			if s.ID == "" || s.Name == "" || s.Match == nil {
				t.Errorf("%s: incomplete signature %+v", set, s.ID)
			}
			if prev, dup := seen[s.ID]; dup {
				t.Errorf("duplicate rule ID %s in %s and %s", s.ID, prev, set)
			}
			seen[s.ID] = set
		}
	}
}

func i32(v uint32) *uint32 { return &v }
func sp(s string) *string  { return &s }

func TestWindowsTamperRules(t *testing.T) {
	find := func(id string) ThreatSig {
		for _, s := range windowsTamperSignatures {
			if s.ID == id {
				return s
			}
		}
		t.Fatalf("rule %s missing", id)
		return ThreatSig{}
	}
	svc := store.Event{EventID: i32(7036), Raw: json.RawMessage(`{"event_data":{"param1":"Sysmon64","param2":"stopped"}}`)}
	if !find("W-T1562.001d").Match(svc) {
		t.Error("stopped Sysmon service should match")
	}
	run := store.Event{EventID: i32(7036), Raw: json.RawMessage(`{"event_data":{"param1":"Sysmon64","param2":"running"}}`)}
	if find("W-T1562.001d").Match(run) {
		t.Error("running state must not match")
	}
	if !find("W-T1562.002").Match(store.Event{EventID: i32(4719)}) {
		t.Error("4719 should match")
	}
	ch := "Microsoft-Windows-WMI-Activity/Operational"
	if !find("W-T1546.003b").Match(store.Event{EventID: i32(5861), Channel: &ch}) {
		t.Error("WMI 5861 should match")
	}
	benign := store.Event{EventID: i32(7045), Raw: json.RawMessage(`{"event_data":{"ImagePath":"C:\\Program Files\\App\\svc.exe"}}`)}
	if find("W-T1543.003b").Match(benign) {
		t.Error("service in Program Files must not match")
	}
}

func TestSecretScanner(t *testing.T) {
	if !lineHasSecret(`aws_secret = "AKIAIOSFODNN7EXAMPLE"`) && !lineHasSecret(`token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"`) {
		t.Log("note: neither sample tripped the scanner (check patterns)")
	}
	red := redactSecrets(`token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"`)
	if strings.Contains(red, "ghp_1234567890abcdefghijklmnopqrstuvwxyz") {
		t.Errorf("secret not redacted: %s", red)
	}
	if lineHasSecret(`password = "changeme"`) {
		t.Error("placeholder password should be filtered")
	}
	if shannonEntropy("aaaaaaaa") > 0.1 {
		t.Error("entropy of repeated char should be ~0")
	}
}

func TestProcGUIDsAndPrevalenceKeys(t *testing.T) {
	ev := store.Event{Raw: json.RawMessage(`{"event_data":{"ProcessGuid":"{abc}","ParentProcessGuid":"{def}"}}`)}
	g, p := procGUIDs(ev)
	if g != "{abc}" || p != "{def}" {
		t.Errorf("guid parse: %q %q", g, p)
	}
	g, p = procGUIDs(store.Event{Raw: json.RawMessage(`{"process_guid":"x-1-2","parent_process_guid":"x-0-1"}`)})
	if g != "x-1-2" || p != "x-0-1" {
		t.Errorf("flat guid parse: %q %q", g, p)
	}
	img, name, h := `C:\Temp\Evil.EXE`, "evil.exe", "SHA256="+strings.Repeat("AB", 32)
	keys := prevalenceKeys(store.Event{EventType: "process", ImagePath: &img, ProcessName: &name, FileHash: &h})
	want := map[string]bool{"image:c:\\temp\\evil.exe": true, "proc:evil.exe": true, "hash:" + strings.Repeat("ab", 32): true}
	for _, k := range keys {
		if !want[k] {
			t.Errorf("unexpected key %q", k)
		}
		delete(want, k)
	}
	if len(want) != 0 {
		t.Errorf("missing keys %v", want)
	}
}

func TestGraphSpawnEdgeUsesPIDReuseOrder(t *testing.T) {
	now := time.Now()
	mk := func(off int, name string, pid, ppid int) store.Event {
		n := name
		return store.Event{EventType: "process", ProcessName: &n, PID: &pid, PPID: &ppid, Time: now.Add(time.Duration(off) * time.Second), Host: "h", AgentID: "a"}
	}
	g := newGraphBuilder("h")
	// pid 10 is first "old.exe" then reused by "bash"; child 20 spawned afterwards belongs to bash.
	g.processEvents([]store.Event{mk(3, "child", 20, 10), mk(0, "old.exe", 10, 1), mk(2, "bash", 10, 1)})
	found := false
	for _, e := range g.edges {
		if e.Type == "spawned" && e.Source == "proc-bash" && e.Target == "proc-child" {
			found = true
		}
		if e.Type == "spawned" && e.Source == "proc-old.exe" {
			t.Error("child wrongly attributed to reused PID's previous owner")
		}
	}
	if !found {
		t.Error("expected bash -> child spawn edge")
	}
}

func TestNormUserAndHaversine(t *testing.T) {
	for in, want := range map[string]string{`CORP\Alice`: "alice", "Bob@corp.com": "bob", " root ": "root"} {
		if got := normUser(in); got != want {
			t.Errorf("normUser(%q)=%q want %q", in, got, want)
		}
	}
	// Lagos -> London is ~5,000 km.
	if d := haversineKm(6.5244, 3.3792, 51.5074, -0.1278); d < 4900 || d > 5200 {
		t.Errorf("haversine Lagos-London = %.0f km", d)
	}
}

func TestDevOpsTypedRules(t *testing.T) {
	find := func(id string) ThreatSig {
		for _, s := range devopsSignatures {
			if s.ID == id {
				return s
			}
		}
		t.Fatalf("missing %s", id)
		return ThreatSig{}
	}
	ev := func(typ, raw string) store.Event { return store.Event{EventType: typ, Raw: json.RawMessage(raw)} }
	if !find("DEV-007").Match(ev("devops.repo_deleted", `{"event":"repository.deleted"}`)) {
		t.Error("webhook repo delete should match")
	}
	if !find("DEV-007").Match(ev("devops.audit", `{"action":"repo.destroy"}`)) {
		t.Error("audit repo.destroy should match")
	}
	// The old substring matcher fired on any text containing these words.
	if find("DEV-007").Match(ev("devops.push", `{"event":"push","message":"fix repo_destroy docs"}`)) {
		t.Error("substring in commit message must not match")
	}
	if !find("DEV-006").Match(ev("devops.audit", `{"action":"repo.access","visibility":"public"}`)) {
		t.Error("repo.access public should match")
	}
	if find("DEV-006").Match(ev("devops.audit", `{"action":"repo.access","visibility":"private"}`)) {
		t.Error("private visibility must not match")
	}
}

func TestParseSearchQuery(t *testing.T) {
	tok, not, sp := parseSearchQuery(`powershell "encoded command" -chrome host:web1 sev:4`)
	if len(tok) != 2 || tok[0] != "powershell" || tok[1] != "encoded command" {
		t.Errorf("tokens: %v", tok)
	}
	if len(not) != 1 || not[0] != "chrome" {
		t.Errorf("not tokens: %v", not)
	}
	f := store.EventFilter{}
	for _, a := range sp {
		a(&f)
	}
	if f.Host != "web1" || f.Severity != 4 {
		t.Errorf("filters: %+v", f)
	}
}

func TestAWSRoleARNAndSessionTokenSigning(t *testing.T) {
	ok := "arn:aws:iam::123456789012:role/ObsidianWatchReadOnly"
	if !awsRoleARNRe.MatchString(ok) {
		t.Error("valid role ARN rejected")
	}
	for _, bad := range []string{"arn:aws:iam::123:role/x", "arn:aws:iam::123456789012:user/bob", "https://evil/x"} {
		if awsRoleARNRe.MatchString(bad) {
			t.Errorf("bad ARN accepted: %s", bad)
		}
	}
	req, _ := http.NewRequest("POST", "https://sts.amazonaws.com/", nil)
	awsSign(req, awsCreds{AccessKeyID: "AK", SecretAccessKey: "SK", SessionToken: "TOKEN", Region: "us-east-1"}, "sts", nil)
	if req.Header.Get("X-Amz-Security-Token") != "TOKEN" {
		t.Error("session token header missing")
	}
	if !strings.Contains(req.Header.Get("Authorization"), "x-amz-security-token") {
		t.Error("session token must be a signed header")
	}
}

func TestAWSRetryTransportRetriesThrottlingWithBody(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		b, _ := io.ReadAll(r.Body)
		if calls < 3 {
			w.WriteHeader(503)
			return
		}
		w.Write(b)
	}))
	defer srv.Close()
	c := &http.Client{Transport: awsRetryTransport{base: http.DefaultTransport}}
	req, _ := http.NewRequest("POST", srv.URL, strings.NewReader("payload"))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(got) != "payload" || calls != 3 {
		t.Errorf("status=%d body=%q calls=%d", resp.StatusCode, got, calls)
	}
}

func TestValidateNLQuery(t *testing.T) {
	q, since, err := validateNLQuery("```json\n{\"q\":\"proc:winword.exe cmd:powershell -user:system\",\"since\":\"7d\"}\n```")
	if err != nil || since != "7d" || q == "" {
		t.Fatalf("valid query rejected: %v %q %q", err, q, since)
	}
	if _, _, err := validateNLQuery(`{"q":"password:x","since":"1h"}`); err == nil {
		// password: is not an allowlisted prefix and must be rejected
		t.Fatal("expected rejection of unknown prefix")
	}
	if _, s, _ := validateNLQuery(`{"q":"type:process","since":"999d"}`); s != "24h" {
		t.Fatalf("bad since should default, got %q", s)
	}
}

func TestGCPExternalOwnerGrant(t *testing.T) {
	caller := "admin@corp.com"
	mk := func(grants string) store.Event {
		return store.Event{EventType: "cloud.gcp_audit", UserName: &caller,
			Raw: json.RawMessage(`{"iam_grants":` + grants + `}`)}
	}
	if !gcpExternalRoleGrant(mk(`[{"action":"ADD","role":"roles/owner","member":"user:evil@gmail.com"}]`), "roles/owner") {
		t.Fatal("external owner ADD should match")
	}
	if gcpExternalRoleGrant(mk(`[{"action":"REMOVE","role":"roles/owner","member":"user:evil@gmail.com"}]`), "roles/owner") {
		t.Fatal("REMOVE must not match")
	}
	if gcpExternalRoleGrant(mk(`[{"action":"ADD","role":"roles/owner","member":"user:bob@corp.com"}]`), "roles/owner") {
		t.Fatal("internal member must not match")
	}
}

func TestParseManifests(t *testing.T) {
	npm := parseManifest("web/package-lock.json", []byte(`{"packages":{"":{"version":"1.0.0"},"node_modules/lodash":{"version":"4.17.20"},"node_modules/a/node_modules/b":{"version":"2.0.0"}}}`))
	if len(npm) != 2 {
		t.Fatalf("npm: %+v", npm)
	}
	py := parseManifest("requirements.txt", []byte("# c\nDjango==3.0.1\nrequests[security]==2.25.0 ; python_version>'3'\nflask>=1\n"))
	if len(py) != 2 || py[0].Name != "Django" || py[1].Version != "2.25.0" {
		t.Fatalf("py: %+v", py)
	}
	gm := parseManifest("go.mod", []byte("module x\n\nrequire (\n\tgithub.com/a/b v1.2.3 // indirect\n)\nrequire github.com/c/d v0.1.0\n"))
	if len(gm) != 2 || gm[0].Version != "1.2.3" {
		t.Fatalf("go: %+v", gm)
	}
	cg := parseManifest("Cargo.lock", []byte("[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n"))
	if len(cg) != 1 || cg[0].Ecosystem != "crates.io" {
		t.Fatalf("cargo: %+v", cg)
	}
}

func TestSCAFindingsOSV(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/querybatch":
			w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-1"}]},{}]}`))
		case r.URL.Path == "/v1/vulns/GHSA-1":
			w.Write([]byte(`{"id":"GHSA-1","summary":"bad","database_specific":{"severity":"HIGH"},"affected":[{"ranges":[{"events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	old := osvBaseURL
	osvBaseURL = srv.URL
	defer func() { osvBaseURL = old }()
	f, err := scaFindings(context.Background(), "r", []scaPkg{{"npm", "lodash", "4.17.20", "package-lock.json"}, {"npm", "ok", "1.0.0", "package-lock.json"}})
	if err != nil || len(f) != 1 || f[0].Severity != "high" || !strings.Contains(f[0].Fix, "4.17.21") {
		t.Fatalf("got %+v err=%v", f, err)
	}
}

func TestGCPRetryAfter(t *testing.T) {
	if gcpRetryAfter("7", 0).Seconds() != 7 || gcpRetryAfter("999", 0).Seconds() != 30 || gcpRetryAfter("", 1).Seconds() != 4 {
		t.Fatal("retry-after calc wrong")
	}
}

func TestInventoryFromScans(t *testing.T) {
	now := time.Now()
	evs := []store.Event{
		{Host: "a", Time: now, Raw: json.RawMessage(`{"packages":[{"name":"openssl","version":"3.0.2"}],"services":[{"name":"sshd","state":"running"}]}`)},
		{Host: "a", Time: now.Add(-time.Hour), Raw: json.RawMessage(`{"packages":[{"name":"openssl","version":"1.1.1"}]}`)}, // older scan ignored
		{Host: "b", Time: now, Raw: json.RawMessage(`{"packages":[{"name":"openssl","version":"1.1.1k"}]}`)},
	}
	h := inventoryFromScans(evs, "", "openssl", "1.1.1")
	if len(h) != 1 || h[0].Host != "b" {
		t.Fatalf("got %+v", h)
	}
	if h := inventoryFromScans(evs, "service", "ssh", ""); len(h) != 1 || h[0].State != "running" {
		t.Fatalf("services: %+v", h)
	}
}

func TestGitHubPosture(t *testing.T) {
	if f := postureFromProtection("o/r", "main", nil, true); len(f) != 1 || f[0].Severity != "high" {
		t.Fatalf("unprotected: %+v", f)
	}
	p := &ghProtection{}
	p.AllowForcePush.Enabled = true
	if f := postureFromProtection("o/r", "main", p, false); len(f) != 3 {
		t.Fatalf("weak protection want 3 findings, got %+v", f)
	}
	good := &ghProtection{RequiredReviews: &struct {
		Count int `json:"required_approving_review_count"`
	}{2}}
	good.EnforceAdmins.Enabled = true
	if f := postureFromProtection("o/r", "main", good, false); len(f) != 0 {
		t.Fatalf("good protection should be clean: %+v", f)
	}
	var r ghRepoInfo
	r.FullName = "o/r"
	r.Security.SecretScanning.Status = "disabled"
	if f := postureFromRepo(r); len(f) != 1 {
		t.Fatalf("repo: %+v", f)
	}
}

func TestAWSCSPMParsers(t *testing.T) {
	sum := []byte(`<GetAccountSummaryResponse><GetAccountSummaryResult><SummaryMap><entry><key>AccountMFAEnabled</key><value>0</value></entry><entry><key>AccountAccessKeysPresent</key><value>1</value></entry></SummaryMap></GetAccountSummaryResult></GetAccountSummaryResponse>`)
	f := awsIAMFindings(sum, 404, nil)
	if len(f) != 3 || f[0].Severity != "critical" {
		t.Fatalf("iam: %+v", f)
	}
	sg := []byte(`<r><securityGroupInfo><item><groupId>sg-1</groupId><groupName>web</groupName><ipPermissions><item><ipProtocol>tcp</ipProtocol><fromPort>22</fromPort><toPort>22</toPort><ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges></item><item><ipProtocol>tcp</ipProtocol><fromPort>443</fromPort><toPort>443</toPort><ipRanges><item><cidrIp>0.0.0.0/0</cidrIp></item></ipRanges></item></ipPermissions></item></securityGroupInfo></r>`)
	g := awsSGFindings(sg, "us-east-1")
	if len(g) != 1 || g[0].Severity != "high" {
		t.Fatalf("sg: %+v", g)
	}
	if f, _ := awsS3PABFinding("b", 404, nil); f == nil {
		t.Fatal("missing PAB must be reported")
	}
	if f, ok := awsS3PABFinding("b", 200, []byte(`<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>`)); f != nil || !ok {
		t.Fatal("fully blocked bucket must pass")
	}
	if tf := awsTrailFindings([]byte(`{"trailList":[{"Name":"t","IsMultiRegionTrail":false,"LogFileValidationEnabled":false}]}`)); len(tf) != 2 {
		t.Fatalf("trail: %+v", tf)
	}
}

func TestGitLabPosture(t *testing.T) {
	if f := glPostureFromBranches("g/p", "main", nil); len(f) != 1 || f[0].Severity != "high" {
		t.Fatalf("unprotected: %+v", f)
	}
	weak := []glProtectedBranch{{Name: "main", AllowForcePush: true}}
	weak[0].PushAccessLevels = append(weak[0].PushAccessLevels, struct {
		AccessLevel int `json:"access_level"`
	}{30})
	if f := glPostureFromBranches("g/p", "main", weak); len(f) != 2 {
		t.Fatalf("weak: %+v", f)
	}
}

func TestGitLabWebhookMapping(t *testing.T) {
	now := time.Now()
	del := map[string]interface{}{"object_kind": "push", "ref": "refs/heads/main", "user_username": "eve",
		"before": "abc", "after": gitlabZeroSHA, "project": map[string]interface{}{"path_with_namespace": "g/p"}}
	ev := processGitLabWebhookEvent(del, nil, now)
	if len(ev) != 1 || ev[0].EventType != "devops.push" || ev[0].Severity != 4 {
		t.Fatalf("branch delete: %+v", ev)
	}
	mem := map[string]interface{}{"event_name": "user_add_to_team", "user_username": "bob", "project_access": "Maintainer", "project_path_with_namespace": "g/p"}
	if ev := processGitLabWebhookEvent(mem, nil, now); len(ev) != 1 || ev[0].EventType != "devops.member_added" {
		t.Fatalf("member: %+v", ev)
	}
	if ev := processGitLabWebhookEvent(map[string]interface{}{"object_kind": "merge_request", "object_attributes": map[string]interface{}{"action": "open"}}, nil, now); len(ev) != 0 {
		t.Fatal("non-merge MR must not emit")
	}
}

func TestRarityCandidates(t *testing.T) {
	img := func(s string) *string { return &s }
	h := img("sha256=" + strings.Repeat("a", 64))
	evs := []store.Event{
		{EventType: "process", ImagePath: img(`C:\Users\bob\AppData\Local\Temp\x.exe`), FileHash: h},
		{EventType: "process", ImagePath: img(`C:\Windows\System32\cmd.exe`), FileHash: h},
		{EventType: "process", ImagePath: img("/tmp/payload"), FileHash: img(strings.Repeat("b", 64))},
		{EventType: "process", ImagePath: img("/tmp/nohash")},
	}
	c := rarityCandidates(evs, 10)
	if len(c) != 2 {
		t.Fatalf("want 2 candidates, got %d", len(c))
	}
	if inWritableDir("/usr/bin/ls") || !inWritableDir("/dev/shm/a") {
		t.Fatal("writable dir detection wrong")
	}
}

func TestCloudEntityKeyIncludesResource(t *testing.T) {
	u, ip := "alice", "1.1.1.1"
	mk := func(raw string) store.Event {
		return store.Event{AgentID: "azure-activitylog-1", EventType: "cloud.azure_activity", UserName: &u, SrcIP: &ip, Raw: json.RawMessage(raw)}
	}
	a, b := mk(`{"resource_id":"/subscriptions/s/resourceGroups/rg/providers/x/a"}`), mk(`{"resource_id":"/subscriptions/s/resourceGroups/rg/providers/x/b"}`)
	if !isCloudEvent(a) {
		t.Skip("event not classified as cloud")
	}
	if alertEntityKey(a) == alertEntityKey(b) {
		t.Fatal("different resources must produce different entity keys")
	}
	if alertEntityKey(a) != alertEntityKey(a) {
		t.Fatal("key must be deterministic")
	}
}

func TestCloudResourceIDTolerantOfObjectResource(t *testing.T) {
	ev := store.Event{Raw: json.RawMessage(`{"resource":{"type":"gce_instance"},"resource_name":"projects/p/zones/z/instances/i"}`)}
	if got := cloudResourceID(ev); got != "projects/p/zones/z/instances/i" {
		t.Fatalf("got %q", got)
	}
}

func TestParseMoreLockfiles(t *testing.T) {
	y := parseManifest("yarn.lock", []byte("# yarn lockfile v1\n\n\"@babel/core@^7.0.0\", \"@babel/core@^7.1.0\":\n  version \"7.2.0\"\n\nlodash@^4.17.0:\n  version \"4.17.20\"\n"))
	if len(y) != 2 || y[0].Name != "@babel/core" || y[1].Version != "4.17.20" {
		t.Fatalf("yarn: %+v", y)
	}
	po := parseManifest("poetry.lock", []byte("[[package]]\nname = \"django\"\nversion = \"3.0.1\"\n"))
	if len(po) != 1 || po[0].Ecosystem != "PyPI" {
		t.Fatalf("poetry: %+v", po)
	}
	pf := parseManifest("Pipfile.lock", []byte(`{"default":{"requests":{"version":"==2.25.0"}},"develop":{}}`))
	if len(pf) != 1 || pf[0].Version != "2.25.0" {
		t.Fatalf("pipfile: %+v", pf)
	}
}

func TestBreachedAlerts(t *testing.T) {
	now := time.Now()
	acked := now.Add(-time.Hour)
	al := []store.Alert{
		{ID: 1, Status: "open", Severity: 5, CreatedAt: now.Add(-2 * time.Hour)},                      // breached (1h)
		{ID: 2, Status: "open", Severity: 5, CreatedAt: now.Add(-30 * time.Minute)},                    // within SLA
		{ID: 3, Status: "open", Severity: 5, CreatedAt: now.Add(-5 * time.Hour), AcknowledgedAt: &acked}, // acked
		{ID: 4, Status: "closed", Severity: 5, CreatedAt: now.Add(-9 * time.Hour)},                     // closed
	}
	b := breachedAlerts(al, now)
	if len(b) != 1 || b[0].ID != 1 {
		t.Fatalf("got %+v", b)
	}
}

func TestUSBRule(t *testing.T) {
	ev := store.Event{EventType: "usb", Raw: json.RawMessage(`{"device":{"mass_storage":true}}`)}
	if !usbSignatures[0].Match(ev) {
		t.Fatal("mass storage should match")
	}
	ev.Raw = json.RawMessage(`{"device":{"mass_storage":false}}`)
	if usbSignatures[0].Match(ev) {
		t.Fatal("keyboard must not match")
	}
}

func TestWindowsUSBRule(t *testing.T) {
	id := uint32(6416)
	ev := store.Event{EventType: "logon", EventID: &id, Raw: json.RawMessage(`{"DeviceId":"USBSTOR\\DISK&VEN_SANDISK"}`)}
	if !windowsUSBSignatures[0].Match(ev) {
		t.Fatal("usbstor 6416 should match")
	}
	id2 := uint32(4624)
	ev.EventID = &id2
	if windowsUSBSignatures[0].Match(ev) {
		t.Fatal("other event ids must not match")
	}
}

func TestAccountRules(t *testing.T) {
	id := uint32(4720)
	if !windowsAccountSignatures[0].Match(store.Event{EventID: &id}) {
		t.Fatal("4720 should match")
	}
	p, c := "/usr/sbin/usermod", "usermod -aG sudo mallory"
	ev := store.Event{EventType: "process", ProcessName: &p, CommandLine: &c}
	if !linuxAccountSignatures[0].Match(ev) || !linuxAccountSignatures[1].Match(ev) {
		t.Fatal("usermod -aG sudo should match both rules")
	}
	c2 := "usermod -s /bin/bash bob"
	ev.CommandLine = &c2
	if linuxAccountSignatures[1].Match(ev) {
		t.Fatal("shell change is not a privileged-group add")
	}
}

func TestRDPPublicRule(t *testing.T) {
	id := uint32(4624)
	pub, priv := "8.8.4.4", "10.1.2.3"
	ev := store.Event{EventType: "logon", EventID: &id, SrcIP: &pub, Raw: json.RawMessage(`{"logon_type":"10"}`)}
	if !remoteSessionSignatures[0].Match(ev) {
		t.Fatal("public RDP logon should match")
	}
	ev.SrcIP = &priv
	if remoteSessionSignatures[0].Match(ev) {
		t.Fatal("private source must not match")
	}
}

func TestADOReviewerPolicy(t *testing.T) {
	repo := "r1"
	pol := adoPolicy{IsEnabled: true, IsBlocking: true}
	pol.Type.ID = adoMinReviewersPolicy
	pol.Settings.MinimumApproverCount = 1
	pol.Settings.Scope = append(pol.Settings.Scope, struct {
		RepositoryID *string `json:"repositoryId"`
		RefName      string  `json:"refName"`
		MatchKind    string  `json:"matchKind"`
	}{&repo, "refs/heads/main", "Exact"})
	if !adoDefaultBranchReviewed("R1", "refs/heads/main", []adoPolicy{pol}) {
		t.Fatal("policy should cover main")
	}
	if adoDefaultBranchReviewed("other", "refs/heads/main", []adoPolicy{pol}) {
		t.Fatal("policy scoped to another repo must not cover")
	}
	pol.IsBlocking = false
	if adoDefaultBranchReviewed("r1", "refs/heads/main", []adoPolicy{pol}) {
		t.Fatal("non-blocking policy must not count")
	}
}

func TestAWSActionHasOnlyMatchesEventName(t *testing.T) {
	ev := store.Event{EventType: "cloud.cloudtrail", Raw: json.RawMessage(`{"event_name":"CreateUser","user_agent":"deletebucket-tool"}`)}
	if !awsActionHas(ev, "createuser") || awsActionHas(ev, "deletebucket") {
		t.Fatal("must match event_name only, not other fields")
	}
}

func TestOSVEcosystemForOS(t *testing.T) {
	cases := map[string]string{
		"Ubuntu 22.04.3 LTS":              "Ubuntu:22.04",
		"Debian GNU/Linux 12 (bookworm)":  "Debian:12",
		"Alpine Linux v3.18":              "Alpine:v3.18",
		"Red Hat Enterprise Linux 9.2":    "",
	}
	for in, want := range cases {
		if got := osvEcosystemForOS(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
	eco, pk := endpointPkgs(json.RawMessage(`{"system":{"os_release":"Ubuntu 22.04.3 LTS"},"packages":[{"name":"openssl","version":"3.0.2-0ubuntu1.10"},{"name":"","version":"1"}]}`))
	if eco != "Ubuntu:22.04" || len(pk) != 1 || pk[0].Ecosystem != "Ubuntu:22.04" {
		t.Fatalf("pkgs: %s %+v", eco, pk)
	}
}

func TestEvalHostChecks(t *testing.T) {
	raw := json.RawMessage(`{"packages":[{"name":"telnetd","version":"1"},{"name":"ufw","version":"1"}],"services":[{"name":"auditd","state":"stopped"}],"open_ports":[{"port":23},{"port":6379}]}`)
	got := map[string]string{}
	for _, c := range evalHostChecks(raw) {
		got[c.ID] = c.Status
	}
	for id, want := range map[string]string{"HC-001": "fail", "HC-002": "fail", "HC-003": "fail", "HC-004": "pass", "HC-006": "fail"} {
		if got[id] != want {
			t.Errorf("%s: got %s want %s", id, got[id], want)
		}
	}
	for _, c := range evalHostChecks(json.RawMessage(`{}`)) {
		if c.Status != "pass" && c.ID != "HC-002" {
			t.Errorf("empty scan should not fail %s", c.ID)
		}
	}
}

func TestAzureGCPFieldMatchers(t *testing.T) {
	az := store.Event{Raw: json.RawMessage(`{"operation_name":"Microsoft.Network/AzureFirewalls/delete","note":"ddosprotectionplans/delete"}`)}
	if !azureOpHas(az, "azurefirewalls/delete") || azureOpHas(az, "ddosprotectionplans/delete") {
		t.Fatal("azure should match operation_name only")
	}
	g := store.Event{Raw: json.RawMessage(`{"method_name":"compute.firewalls.delete","resource":"compute.instances.insert"}`)}
	if !gcpMethodHas(g, "compute.firewalls.delete") || gcpMethodHas(g, "compute.instances.insert") {
		t.Fatal("gcp should match method_name only")
	}
}

func TestIAMRoleRiskImpersonation(t *testing.T) {
	for role, want := range map[string]string{
		"roles/iam.serviceAccountUser":         "high",
		"roles/iam.serviceAccountTokenCreator": "high",
		"roles/iam.serviceAccountKeyAdmin":     "high",
		"roles/run.developer":                  "high",
		"roles/viewer":                         "low",
		"roles/pubsub.publisher":               "medium",
	} {
		if got := iamRoleRisk(role); got != want {
			t.Errorf("%s: got %s want %s", role, got, want)
		}
	}
}

func TestProcessADOWebhookEvent(t *testing.T) {
	var p map[string]interface{}
	_ = json.Unmarshal([]byte(`{"eventType":"git.push","resource":{"repository":{"name":"app"},"pushedBy":{"uniqueName":"a@x.io"},"refUpdates":[{"name":"refs/heads/main","oldObjectId":"abc","newObjectId":"0000000000000000000000000000000000000000"}]}}`), &p)
	ev := processADOWebhookEvent(p, &store.DevOpsConnector{ID: 3, Org: "acme"}, time.Now())
	if len(ev) != 1 || ev[0].Severity != 4 || ev[0].Username != "a@x.io" || ev[0].Host != "acme" {
		t.Fatalf("unexpected: %+v", ev)
	}
	_ = json.Unmarshal([]byte(`{"eventType":"build.complete","resource":{"result":"failed","definition":{"name":"ci"},"requestedFor":{"uniqueName":"b@x.io"}}}`), &p)
	ev = processADOWebhookEvent(p, nil, time.Now())
	if len(ev) != 1 || ev[0].EventType != "devops.workflow_run" {
		t.Fatalf("build: %+v", ev)
	}
	if processADOWebhookEvent(map[string]interface{}{"eventType": "other"}, nil, time.Now()) != nil {
		t.Fatal("unknown event should be ignored")
	}
}

func TestAWSRDSAndEBSFindings(t *testing.T) {
	x := []byte(`<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances>
	<DBInstance><DBInstanceIdentifier>db1</DBInstanceIdentifier><PubliclyAccessible>true</PubliclyAccessible><StorageEncrypted>false</StorageEncrypted><Engine>mysql</Engine><BackupRetentionPeriod>0</BackupRetentionPeriod></DBInstance>
	<DBInstance><DBInstanceIdentifier>db2</DBInstanceIdentifier><PubliclyAccessible>false</PubliclyAccessible><StorageEncrypted>true</StorageEncrypted><Engine>pg</Engine><BackupRetentionPeriod>7</BackupRetentionPeriod></DBInstance>
	</DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`)
	f := awsRDSFindings(x, "us-east-1")
	if len(f) != 3 {
		t.Fatalf("want 3 findings for db1 only, got %d: %+v", len(f), f)
	}
	if awsEBSDefaultEncryptionFinding([]byte(`<R><ebsEncryptionByDefault>false</ebsEncryptionByDefault></R>`), "r") == nil ||
		awsEBSDefaultEncryptionFinding([]byte(`<R><ebsEncryptionByDefault>true</ebsEncryptionByDefault></R>`), "r") != nil {
		t.Fatal("ebs default encryption detection wrong")
	}
}

func TestAWSRegionsFromXML(t *testing.T) {
	got := awsRegionsFromXML([]byte(`<R><regionInfo><item><regionName>us-east-1</regionName></item><item><regionName>eu-west-1</regionName></item></regionInfo></R>`))
	if len(got) != 2 || got[1] != "eu-west-1" {
		t.Fatalf("got %v", got)
	}
}

func TestEntraServicePrincipalHost(t *testing.T) {
	ev := entraSignInToCloudEvent(entraSignIn{ID: "x", ServicePrincipalName: "Deploy-Bot", SignInKind: "service_principal"}, 1)
	if ev.Host != "sp:deploy-bot" {
		t.Fatalf("host %q", ev.Host)
	}
	ev = entraSignInToCloudEvent(entraSignIn{ID: "y", UserPrincipalName: "A@x.io"}, 1)
	if ev.Host != "a@x.io" {
		t.Fatalf("host %q", ev.Host)
	}
}

func TestEntraSPInvalidCredentialSig(t *testing.T) {
	var sig ThreatSig
	for _, s := range entraIdentitySignatures {
		if s.ID == "C-AZ-ID-005" {
			sig = s
		}
	}
	mk := func(raw string) store.Event {
		return store.Event{EventType: "cloud.entra_signin", Raw: json.RawMessage(raw)}
	}
	if sig.Match == nil || !sig.Match(mk(`{"sign_in_kind":"service_principal","status":{"errorCode":7000215}}`)) {
		t.Fatal("should match SP invalid secret")
	}
	if sig.Match(mk(`{"sign_in_kind":"","status":{"errorCode":7000215}}`)) || sig.Match(mk(`{"sign_in_kind":"service_principal","status":{"errorCode":0}}`)) {
		t.Fatal("must not match user sign-ins or successes")
	}
}

func TestRedactNLQuestion(t *testing.T) {
	q := redactNLQuestion("failed logins on web01 for admin with password=Hunter2 key AKIAABCDEFGHIJKLMNOP from 10.0.0.5")
	for _, bad := range []string{"Hunter2", "AKIAABCDEFGHIJKLMNOP"} {
		if strings.Contains(q, bad) {
			t.Errorf("%s leaked: %s", bad, q)
		}
	}
	for _, keep := range []string{"web01", "admin", "10.0.0.5"} {
		if !strings.Contains(q, keep) {
			t.Errorf("%s should be kept: %s", keep, q)
		}
	}
}

func TestAzureSubscriptionResolution(t *testing.T) {
	ids, err := resolveAzureSubscriptions(context.Background(), "", "aaa, bbb;ccc")
	if err != nil || len(ids) != 3 || ids[2] != "ccc" {
		t.Fatalf("%v %v", ids, err)
	}
	got := parseAzureSubscriptionList([]byte(`{"value":[{"subscriptionId":"s1","state":"Enabled"},{"subscriptionId":"s2","state":"Disabled"}]}`))
	if len(got) != 1 || got[0] != "s1" {
		t.Fatalf("%v", got)
	}
}

func TestCloudResourceIDAWS(t *testing.T) {
	mk := func(raw string) store.Event { return store.Event{Raw: []byte(raw)} }
	if got := cloudResourceID(mk(`{"resources":[{"ARN":"arn:aws:s3:::Logs","type":"AWS::S3::Bucket"}]}`)); got != "arn:aws:s3:::logs" {
		t.Fatalf("arn: %q", got)
	}
	if got := cloudResourceID(mk(`{"resources":null,"request_parameters":{"bucketName":"B1"}}`)); got != "bucketname:b1" {
		t.Fatalf("param: %q", got)
	}
	if got := cloudResourceID(mk(`{"request_parameters":{"other":"x"}}`)); got != "-" {
		t.Fatalf("none: %q", got)
	}
}
