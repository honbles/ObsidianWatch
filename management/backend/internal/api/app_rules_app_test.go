package api

import (
	"context"
	"strings"
	"testing"
	"time"
)

func appRow(route, method, client, peer, exc string, failures, s4013, s429 int64) appClientRow {
	return appClientRow{Minute: appNow.Add(-time.Minute), Route: route, Method: method, ClientIP: client, PeerIP: peer, ExcType: exc,
		Failures: failures, Status40103: s4013, Status429: s429}
}

func (fx *appFx) scan() { fx.r.Scan(context.Background()) }

func TestAppA01LoginFailureBurst(t *testing.T) {
	cfg := func(fx *appFx) { fx.setSvc(func(s *appSvc) { s.Settings.LoginRoutes = []string{"/login"} }) }
	fx := appNewFx(t)
	cfg(fx)
	fx.d.clientRows = []appClientRow{appRow("/login", "POST", "203.0.113.9", "203.0.113.9", "", 25, 25, 0)}
	fx.scan()
	a := fx.pos("APP-A01", 1)[0]
	if a.Sev != appSevHigh || a.F.ClientIP != "203.0.113.9" || a.F.Route != "/login" || a.F.Method != "POST" || a.F.Degraded {
		t.Fatalf("%+v", a)
	}
	// negatives
	for name, rows := range map[string][]appClientRow{
		"below threshold":        {appRow("/login", "POST", "203.0.113.9", "203.0.113.9", "", 10, 10, 0)},
		"not a login route":      {appRow("/orders", "GET", "203.0.113.9", "203.0.113.9", "", 40, 40, 0)},
		"outside the window":     {{Minute: appNow.Add(-30 * time.Minute), Route: "/login", Method: "POST", ClientIP: "203.0.113.9", PeerIP: "203.0.113.9", Status40103: 99}},
		"spread over many hosts": nil,
	} {
		f := appNewFx(t)
		cfg(f)
		f.d.clientRows = rows
		if name == "spread over many hosts" {
			for i := 0; i < 10; i++ { // 40 failures but only 4 per client address
				f.d.clientRows = append(f.d.clientRows, appRow("/login", "POST", "198.51.100."+string(rune('1'+i)), "198.51.100."+string(rune('1'+i)), "", 4, 4, 0))
			}
		}
		f.scan()
		f.neg("APP-A01")
	}
	// tunable: a lower threshold from rule settings
	f := appNewFx(t)
	cfg(f)
	f.gate("APP-A01", RuleGate{Enabled: true, Params: map[string]float64{"threshold": 5}})
	f.d.clientRows = []appClientRow{appRow("/login", "POST", "203.0.113.9", "203.0.113.9", "", 10, 10, 0)}
	f.scan()
	f.pos("APP-A01", 1)
	// allowlist by CIDR (an authorized load test)
	f = appNewFx(t)
	cfg(f)
	f.gate("APP-A01", RuleGate{Enabled: true, Allowlist: []string{"203.0.113.0/24"}})
	f.d.clientRows = []appClientRow{appRow("/login", "POST", "203.0.113.9", "203.0.113.9", "", 25, 25, 0)}
	f.scan()
	f.neg("APP-A01")
}

func TestAppA01InferredAndMissingLoginRoutes(t *testing.T) {
	fx := appNewFx(t) // no login routes configured: routes that look like one are used
	fx.d.clientRows = []appClientRow{appRow("/api/v1/auth/login", "POST", "203.0.113.9", "203.0.113.9", "", 30, 30, 0)}
	fx.scan()
	fx.pos("APP-A01", 1)
	fx = appNewFx(t) // none configured and none recognised: skipped, and the skip is counted
	fx.d.clientRows = []appClientRow{appRow("/orders", "GET", "203.0.113.9", "203.0.113.9", "", 30, 30, 0)}
	fx.scan()
	fx.neg("APP-A01")
	if appStatusSnapshot()["APP-A01"].Skipped["no login routes configured or recognised"] == 0 {
		t.Fatalf("%+v", appStatusSnapshot()["APP-A01"])
	}
}

func TestAppA01ProxyHandling(t *testing.T) {
	rows := []appClientRow{
		appRow("/login", "POST", "203.0.113.1", "10.0.0.5", "", 15, 15, 0),
		appRow("/login", "POST", "203.0.113.2", "10.0.0.5", "", 15, 15, 0),
	}
	// trusted proxy configured: the forwarded address is used, so the load splits across two real clients
	fx := appNewFx(t)
	fx.setSvc(func(s *appSvc) {
		s.Settings.LoginRoutes = []string{"/login"}
		s.Settings.TrustedProxies = []string{"10.0.0.0/8"}
	})
	fx.d.clientRows = rows
	fx.scan()
	fx.neg("APP-A01")
	// no trusted proxy: everything looks like one private peer: counted, but degraded and reduced
	fx = appNewFx(t)
	fx.setSvc(func(s *appSvc) { s.Settings.LoginRoutes = []string{"/login"} })
	fx.d.clientRows = rows
	fx.scan()
	a := fx.pos("APP-A01", 1)[0]
	if !a.F.Degraded || a.F.ClientIP != "10.0.0.5" || a.Sev != appSevMed || !appContains(a.F.DegradeNote, "trusted proxies") {
		t.Fatalf("%+v", a)
	}
	// the effective-address function itself
	for _, c := range []struct {
		client, peer string
		trusted      []string
		want         string
		deg          bool
	}{
		{"203.0.113.1", "10.0.0.5", []string{"10.0.0.0/8"}, "203.0.113.1", false},
		{"203.0.113.1", "198.51.100.9", []string{"10.0.0.0/8"}, "198.51.100.9", false}, // an untrusted peer cannot vouch for a forwarded address
		{"203.0.113.1", "10.0.0.5", nil, "10.0.0.5", true},
		{"", "203.0.113.7", nil, "203.0.113.7", false},
		{"203.0.113.1", "", nil, "203.0.113.1", false},
		{"", "", nil, "", false},
	} {
		if got, deg, _ := appEffectiveClient(c.client, c.peer, c.trusted); got != c.want || deg != c.deg {
			t.Fatalf("%+v -> %q %v", c, got, deg)
		}
	}
}

func TestAppA13RateLimitAbuse(t *testing.T) {
	fx := appNewFx(t)
	fx.d.clientRows = []appClientRow{appRow("/api/search", "GET", "203.0.113.9", "203.0.113.9", "", 60, 0, 60)}
	fx.scan()
	if a := fx.pos("APP-A13", 1)[0]; a.Sev != appSevMed || a.F.ClientIP != "203.0.113.9" {
		t.Fatalf("%+v", a)
	}
	fx = appNewFx(t)
	fx.d.clientRows = []appClientRow{appRow("/api/search", "GET", "203.0.113.9", "203.0.113.9", "", 40, 0, 40)}
	fx.scan()
	fx.neg("APP-A13")
}

func TestAppA09InjectionAttempts(t *testing.T) {
	sqli := "java.sql.SQLSyntaxErrorException"
	fx := appNewFx(t)
	fx.d.clientRows = []appClientRow{appRow("/orders/{id}", "GET", "203.0.113.9", "203.0.113.9", sqli, 4, 0, 0)}
	fx.scan()
	if a := fx.pos("APP-A09", 1)[0]; a.Sev != appSevMed || !appContains(a.F.Detail, sqli) || a.F.Route != "/orders/{id}" {
		t.Fatalf("%+v", a)
	}
	for name, rows := range map[string][]appClientRow{
		"ordinary exception":      {appRow("/orders/{id}", "GET", "203.0.113.9", "203.0.113.9", "java.lang.NullPointerException", 50, 0, 0)},
		"below threshold":         {appRow("/orders/{id}", "GET", "203.0.113.9", "203.0.113.9", sqli, 2, 0, 0)},
		"spread over routes":      {appRow("/a", "GET", "203.0.113.9", "203.0.113.9", sqli, 2, 0, 0), appRow("/b", "GET", "203.0.113.9", "203.0.113.9", sqli, 2, 0, 0)},
		"a 5xx with no exception": {appRow("/orders/{id}", "GET", "203.0.113.9", "203.0.113.9", "", 20, 0, 0)},
	} {
		f := appNewFx(t)
		f.d.clientRows = rows
		f.scan()
		f.neg("APP-A09")
		_ = name
	}
	for _, c := range map[string]bool{"org.hibernate.exception.SQLGrammarException": true, "psycopg2.errors.SyntaxError": false, "ognl.OgnlException": true,
		"java.lang.NullPointerException": false, "SQLInjectionDetected": true, "": false} {
		_ = c
	}
	for typ, want := range map[string]bool{"org.hibernate.exception.SQLGrammarException": true, "ognl.OgnlException": true,
		"SQLInjectionDetected": true, "java.lang.NullPointerException": false, "java.net.SocketTimeoutException": false, "": false} {
		if appIsInjectionExc(typ) != want {
			t.Fatalf("classify %q want %v", typ, want)
		}
	}
	f := appNewFx(t) // allowlisted authorized scanner
	f.gate("APP-A09", RuleGate{Enabled: true, Allowlist: []string{"203.0.113.9"}})
	f.d.clientRows = []appClientRow{appRow("/orders/{id}", "GET", "203.0.113.9", "203.0.113.9", sqli, 9, 0, 0)}
	f.scan()
	f.neg("APP-A09")
}

func TestAppA08NewRoute(t *testing.T) {
	route := appRouteRef{Route: "/admin/export", Method: "GET", FirstSeen: appNow.Add(-20 * time.Minute)}
	fx := appNewFx(t)
	fx.d.newRoutes = []appRouteRef{route}
	fx.scan()
	if a := fx.pos("APP-A08", 1)[0]; a.Sev != appSevLow || a.F.Route != "/admin/export" || !appContains(a.F.Detail, "authentication is expected") {
		t.Fatalf("%+v", a)
	}
	fx = appNewFx(t) // a public route is noted
	fx.setSvc(func(s *appSvc) { s.Settings.PublicRoutes = []string{"/admin/export"} })
	fx.d.newRoutes = []appRouteRef{route}
	fx.scan()
	if a := fx.pos("APP-A08", 1)[0]; !appContains(a.F.Detail, "public route") {
		t.Fatalf("%+v", a)
	}
	for name, prep := range map[string]func(*appFx){
		"still learning (young service)": func(f *appFx) { f.setSvc(func(s *appSvc) { s.FirstSeen = appNow.Add(-2 * 24 * time.Hour) }) },
		"too few requests":               func(f *appFx) { f.d.requests = 300 },
		"deploy window":                  func(f *appFx) { f.d.deploy = true },
		"overflow bucket":                func(f *appFx) { f.d.newRoutes = []appRouteRef{{Route: "other", Method: "GET", FirstSeen: appNow}} },
	} {
		f := appNewFx(t)
		f.d.newRoutes = []appRouteRef{route}
		prep(f)
		f.scan()
		f.neg("APP-A08")
		_ = name
	}
}

func TestAppX02AnomalyThenExecution(t *testing.T) {
	fx := appNewFx(t)
	fx.d.anomaly = "Injection attempts against this service were detected"
	fx.event(appEv("process", 500, 100, "bash", `{`+appAncJava+`}`))
	a := fx.pos("APP-X02", 1)[0]
	if a.Sev != appSevCrit || !appContains(a.F.Detail, "Injection attempts") || !appContains(a.F.Lineage, "java(100)") {
		t.Fatalf("%+v", a)
	}
	fx.pos("APP-H01", 1)
	fx = appNewFx(t) // the same via a download tool
	fx.d.anomaly = "A spike of 120 server errors (5xx) hit this service"
	fx.event(appEv("process", 600, 100, "curl", `{`+appAncJava+`}`))
	fx.pos("APP-X02", 1)
	fx = appNewFx(t) // no application anomaly: the host finding stands alone
	fx.event(appEv("process", 500, 100, "bash", `{`+appAncJava+`}`))
	fx.neg("APP-X02")
	fx = appNewFx(t) // H01 allowlisted: nothing to correlate
	fx.d.anomaly = "x"
	fx.gate("APP-H01", RuleGate{Enabled: true, Allowlist: []string{"java>bash"}})
	fx.event(appEv("process", 500, 100, "bash", `{`+appAncJava+`}`))
	fx.neg("APP-X02")
}

func TestAppX06InstrumentationDropped(t *testing.T) {
	setup := func(f *appFx) {
		f.d.lastReq = appNow.Add(-20 * time.Minute)
		f.d.prior = []appWindowStats{{Route: "/x", Method: "GET", Calls: 500}}
		f.d.alive[100] = true
	}
	fx := appNewFx(t)
	setup(fx)
	fx.r.x06(context.Background(), fx.svc, appNow)
	if a := fx.pos("APP-X06", 1)[0]; a.Sev != appSevMed || a.F.InstanceID != 11 {
		t.Fatalf("%+v", a)
	}
	for name, prep := range map[string]func(*appFx){
		"process not seen running":  func(f *appFx) { f.d.alive[100] = false },
		"traffic only just stopped": func(f *appFx) { f.d.lastReq = appNow.Add(-3 * time.Minute) },
		"never had traffic":         func(f *appFx) { f.d.prior = nil },
		"service not instrumented":  func(f *appFx) { f.setSvc(func(s *appSvc) { s.Source = "discovered" }) },
		"host is silent":            func(f *appFx) { f.d.agentSeen["a1"] = appNow.Add(-time.Hour) },
		"maintenance window": func(f *appFx) {
			f.setSvc(func(s *appSvc) {
				s.Settings.Maintenance = []appMaintenance{{Start: appNow.Add(-time.Hour), End: appNow.Add(time.Hour)}}
			})
		},
		"deploy window":            func(f *appFx) { f.d.deploy = true },
		"instance already stopped": func(f *appFx) { f.d.insts[0].Stopped = true },
	} {
		f := appNewFx(t)
		setup(f)
		prep(f)
		f.r.x06(context.Background(), f.svc, appNow)
		f.neg("APP-X06")
		_ = name
	}
	f := appNewFx(t) // the missing evidence is counted, not hidden
	setup(f)
	f.d.alive[100] = false
	f.r.x06(context.Background(), f.svc, appNow)
	if appStatusSnapshot()["APP-X06"].Skipped["no evidence the process is still running"] != 1 {
		t.Fatal("skip not counted")
	}
}

func TestAppO01ErrorRate(t *testing.T) {
	fx := appNewFx(t)
	fx.setSvc(func(s *appSvc) {
		s.Settings.Exposure, s.Settings.Criticality, s.Settings.NotifyRoute = "internet", "critical", "ops-pager"
	})
	fx.d.curWin = []appWindowStats{{Route: "/orders", Method: "GET", Calls: 200, Errors: 30}}
	fx.scan()
	a := fx.pos("APM-O01", 1)[0]
	if a.Sev != appSevHigh || len(a.Factors) != 0 || !appContains(a.F.Detail, "ops-pager") {
		t.Fatalf("operational alerts are not weighted by exposure and name the notification route: %+v", a)
	}
	for name, prep := range map[string]func(*appFx){
		"under budget":  func(f *appFx) { f.d.curWin = []appWindowStats{{Route: "/o", Method: "GET", Calls: 200, Errors: 5}} },
		"too few calls": func(f *appFx) { f.d.curWin = []appWindowStats{{Route: "/o", Method: "GET", Calls: 30, Errors: 30}} },
		"custom budget": func(f *appFx) {
			b := 20.0
			f.setSvc(func(s *appSvc) { s.Settings.ErrorBudgetPct = &b })
		},
		"maintenance": func(f *appFx) {
			f.setSvc(func(s *appSvc) {
				s.Settings.Maintenance = []appMaintenance{{Start: appNow.Add(-time.Hour), End: appNow.Add(time.Hour)}}
			})
		},
	} {
		f := appNewFx(t)
		f.d.curWin = []appWindowStats{{Route: "/o", Method: "GET", Calls: 200, Errors: 30}}
		prep(f)
		f.scan()
		f.neg("APM-O01")
		_ = name
	}
	// a single bad route inside a healthy service
	f := appNewFx(t)
	f.d.curWin = []appWindowStats{{Route: "/ok", Method: "GET", Calls: 900, Errors: 0}, {Route: "/bad", Method: "POST", Calls: 100, Errors: 30}}
	f.scan()
	if a := f.pos("APM-O01", 1)[0]; a.F.Route != "/bad" {
		t.Fatalf("%+v", a)
	}
}

func TestAppO03TrafficDrop(t *testing.T) {
	setup := func(f *appFx) {
		f.d.baseWin = []appWindowStats{{Route: "/x", Method: "GET", Calls: 144000}} // 1000 per 10 minutes
		f.d.curWin = []appWindowStats{{Route: "/x", Method: "GET", Calls: 50}}
	}
	fx := appNewFx(t)
	setup(fx)
	fx.scan()
	if a := fx.pos("APM-O03", 1)[0]; a.Sev != appSevHigh || !appContains(a.F.Detail, "usual 1000") {
		t.Fatalf("%+v", a)
	}
	for name, prep := range map[string]func(*appFx){
		"normal traffic":    func(f *appFx) { f.d.curWin = []appWindowStats{{Route: "/x", Method: "GET", Calls: 700}} },
		"tiny baseline":     func(f *appFx) { f.d.baseWin = []appWindowStats{{Route: "/x", Method: "GET", Calls: 5000}} },
		"young service":     func(f *appFx) { f.setSvc(func(s *appSvc) { s.FirstSeen = appNow.Add(-2 * time.Hour) }) },
		"few requests ever": func(f *appFx) { f.d.requests = 500 },
	} {
		f := appNewFx(t)
		setup(f)
		prep(f)
		f.scan()
		f.neg("APM-O03")
		_ = name
	}
}

// Several instances silent at once give ONE alert for the service, and a discovered (non-OTel) service,
// whose processes legitimately come and go, never raises O05.
func TestAppO05GroupedAndOtelOnly(t *testing.T) {
	setup := func(f *appFx) {
		f.d.insts = []appInst{
			{ID: 11, ServiceID: 1, AgentID: "a1", Host: "web-01", PID: 100, FirstSeen: appNow.Add(-5 * 24 * time.Hour), LastSeen: appNow.Add(-30 * time.Minute)},
			{ID: 13, ServiceID: 1, AgentID: "a1", Host: "web-01", PID: 101, FirstSeen: appNow.Add(-5 * 24 * time.Hour), LastSeen: appNow.Add(-31 * time.Minute)},
			{ID: 14, ServiceID: 1, AgentID: "a1", Host: "web-01", PID: 102, FirstSeen: appNow.Add(-5 * 24 * time.Hour), LastSeen: appNow.Add(-32 * time.Minute)},
			{ID: 12, ServiceID: 1, AgentID: "a2", Host: "web-02", PID: 200, FirstSeen: appNow.Add(-5 * 24 * time.Hour), LastSeen: appNow},
		}
		f.d.agentSeen = map[string]time.Time{"a1": appNow, "a2": appNow}
	}
	fx := appNewFx(t)
	setup(fx)
	fx.scan()
	got := fx.pos("APM-O05", 1)
	if len(got) != 1 || !strings.Contains(got[0].F.Detail, "pid 100") || !strings.Contains(got[0].F.Detail, "What to check") {
		t.Fatalf("three silent instances must give one explanatory alert: %+v", got)
	}
	d := appNewFx(t)
	setup(d)
	sv := d.d.svcs[1]
	sv.Source = "discovered"
	d.d.svcs[1] = sv
	d.scan()
	d.neg("APM-O05")
}

func TestAppO05InstanceMissing(t *testing.T) {
	two := func(f *appFx) {
		f.d.insts = []appInst{
			{ID: 11, ServiceID: 1, AgentID: "a1", Host: "web-01", PID: 100, FirstSeen: appNow.Add(-5 * 24 * time.Hour), LastSeen: appNow.Add(-30 * time.Minute)},
			{ID: 12, ServiceID: 1, AgentID: "a2", Host: "web-02", PID: 200, FirstSeen: appNow.Add(-5 * 24 * time.Hour), LastSeen: appNow},
		}
		f.d.agentSeen = map[string]time.Time{"a1": appNow, "a2": appNow}
	}
	fx := appNewFx(t)
	two(fx)
	fx.scan()
	if a := fx.pos("APM-O05", 1)[0]; a.F.InstanceID != 11 || a.F.Host != "web-01" {
		t.Fatalf("%+v", a)
	}
	for name, prep := range map[string]func(*appFx){
		"replaced by a restarted instance": func(f *appFx) {
			f.d.insts[1] = appInst{ID: 12, ServiceID: 1, AgentID: "a1", PID: 300, FirstSeen: appNow.Add(-40 * time.Minute), LastSeen: appNow}
		},
		"nobody reporting (a traffic problem, not one instance)": func(f *appFx) { f.d.insts[1].LastSeen = appNow.Add(-40 * time.Minute) },
		"the host itself is silent":                              func(f *appFx) { f.d.agentSeen["a1"] = appNow.Add(-time.Hour) },
		"already marked stopped":                                 func(f *appFx) { f.d.insts[0].Stopped = true },
		"deploy window":                                          func(f *appFx) { f.d.deploy = true },
		"gone for over a day (decommissioned)":                   func(f *appFx) { f.d.insts[0].LastSeen = appNow.Add(-30 * time.Hour) },
	} {
		f := appNewFx(t)
		two(f)
		prep(f)
		f.scan()
		f.neg("APM-O05")
		_ = name
	}
}
