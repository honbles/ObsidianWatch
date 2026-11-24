package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAppWeigh(t *testing.T) {
	st := func(exp, crit string) appServiceSettings {
		s := appDefaultSettings()
		s.Exposure, s.Criticality = exp, crit
		return s
	}
	for _, c := range []struct {
		name     string
		base     int
		set      appServiceSettings
		identity string
		degraded bool
		oper     bool
		want     int
	}{
		{"no factors", appSevMed, st("unknown", "normal"), "", false, false, appSevMed},
		{"internet-facing raises one level", appSevMed, st("internet", "normal"), "", false, false, appSevHigh},
		{"high criticality raises one level", appSevMed, st("internal", "high"), "", false, false, appSevHigh},
		{"both raise two levels", appSevMed, st("internet", "critical"), "", false, false, appSevCrit},
		{"capped at Critical", appSevHigh, st("internet", "critical"), "", false, false, appSevCrit},
		{"low criticality does not raise", appSevMed, st("internal", "low"), "", false, false, appSevMed},
		{"degraded input lowers one level", appSevHigh, st("unknown", "normal"), "", true, false, appSevMed},
		{"degraded after weighting", appSevHigh, st("internet", "normal"), "", true, false, appSevHigh},
		{"asserted identity caps at Medium", appSevCrit, st("internet", "critical"), "asserted", false, false, appSevMed},
		{"asserted below the cap is unchanged", appSevLow, st("unknown", "normal"), "asserted", false, false, appSevLow},
		{"verified identity is not capped", appSevCrit, st("unknown", "normal"), "verified", false, false, appSevCrit},
		{"operational rules are not weighted", appSevHigh, st("internet", "critical"), "", false, true, appSevHigh},
		{"never below Info", appSevInfo, st("unknown", "normal"), "", true, false, appSevInfo},
	} {
		if got, _ := appWeigh(c.base, c.set, c.identity, c.degraded, c.oper); got != c.want {
			t.Fatalf("%s: got %d want %d", c.name, got, c.want)
		}
	}
	if _, factors := appWeigh(appSevMed, st("internet", "critical"), "", false, false); len(factors) != 2 {
		t.Fatalf("factors must be listed for the alert text: %v", factors)
	}
}

func TestAppGateObserveDisabledAllowlist(t *testing.T) {
	meta, _ := RuleMetaFor("APP-H01")
	f := appFinding{RuleID: "APP-H01", BaseSev: appSevHigh, AllowVals: []string{"java>bash", "bash"}}
	// observe mode: shows as Info whatever the weighting says
	if sev, _, skip := appFinalSeverity(RuleGate{Enabled: true, Observe: true}, f, meta); skip || sev != appSevInfo {
		t.Fatalf("observe: %d %v", sev, skip)
	}
	if sev, _, skip := appFinalSeverity(RuleGate{Enabled: true}, f, meta); skip || sev != appSevHigh {
		t.Fatalf("promoted: %d %v", sev, skip)
	}
	if _, _, skip := appFinalSeverity(RuleGate{Enabled: false}, f, meta); !skip {
		t.Fatal("a disabled rule must not alert")
	}
	if _, _, skip := appFinalSeverity(RuleGate{Enabled: true, Allowlist: []string{"JAVA>BASH"}}, f, meta); !skip {
		t.Fatal("allowlist is case-insensitive")
	}
	for entry, val := range map[string]string{"10.0.0.0/8": "10.9.8.7", "203.0.113.0/24": "203.0.113.200", "curl": "CURL"} {
		if !appAllowMatch(entry, val) {
			t.Fatalf("%s should match %s", entry, val)
		}
	}
	for entry, val := range map[string]string{"10.0.0.0/8": "11.0.0.1", "curl": "wget", "": "x", "x": ""} {
		if appAllowMatch(entry, val) {
			t.Fatalf("%q must not match %q", entry, val)
		}
	}
}

func TestAppDefaultsToObserveThroughTheEmitterPath(t *testing.T) {
	fx := appNewFx(t)
	delete(fx.em.gates, "APP-H01")
	fx.em.gates["APP-H01"] = RuleGate{Enabled: true, Observe: true}
	fx.event(appEv("process", 500, 100, "bash", `{`+appAncJava+`}`))
	a := fx.pos("APP-H01", 1)[0]
	if a.Sev != appSevInfo || !a.Observe {
		t.Fatalf("%+v", a)
	}
}

func TestAppAlertText(t *testing.T) {
	meta, _ := RuleMetaFor("APP-A09")
	svc := appSvc{ID: 1, Name: "checkout", Env: "prod", Source: "otel", Settings: appDefaultSettings()}
	svc.Settings.Exposure, svc.Settings.Criticality = "internet", "critical"
	f := appFinding{RuleID: "APP-A09", Svc: svc, BaseSev: appSevMed, Summary: "Injection attempts", Detail: "4 failures", InstanceID: 11, Host: "web-01",
		Route: "/orders/{id}", Method: "GET", ClientIP: "203.0.113.9", TraceID: "abc123", Lineage: "java(1) > bash(2)", Identity: "asserted", Degraded: true, DegradeNote: "proxy"}
	sev, factors := appWeigh(f.BaseSev, svc.Settings, f.Identity, f.Degraded, false)
	body := appAlertBody(f, meta, true, sev, factors)
	title := appAlertTitle(f)
	if title != "[APP-A09] Injection attempts - checkout (prod)" {
		t.Fatal(title)
	}
	for _, want := range []string{"Service: checkout", "Environment: prod", "Instance: 11", "Host: web-01", "Route: GET /orders/{id}", "Client address: 203.0.113.9",
		"Trace: abc123", "Process lineage: java(1) > bash(2)", "Telemetry tier: T1", "Identity: asserted", "internet-facing +1", "critical criticality +1",
		"asserted identity", "Degraded input: proxy", "Mode: observe", "MITRE ATT&CK: T1190", "What to check:", "Likely false positives:"} {
		if !strings.Contains(body, want) {
			t.Fatalf("alert body lacks %q:\n%s", want, body)
		}
	}
}

func TestAppScanRunsEveryDataDrivenRule(t *testing.T) {
	fx := appNewFx(t)
	fx.setSvc(func(s *appSvc) { s.Settings.LoginRoutes = []string{"/login"} })
	fx.d.clientRows = []appClientRow{appRow("/login", "POST", "203.0.113.9", "203.0.113.9", "", 25, 25, 60)}
	fx.d.curWin = []appWindowStats{{Route: "/o", Method: "GET", Calls: 200, Errors: 30}}
	fx.r.Scan(context.Background())
	fx.pos("APP-A01", 1)
	fx.pos("APP-A13", 1)
	fx.pos("APM-O01", 1)
}

func TestAppRuleMetaContract(t *testing.T) {
	ids := []string{"APP-H01", "APP-H02", "APP-H03", "APP-H04", "APP-H05", "APP-H06", "APP-H07", "APP-H08", "APP-H11",
		"APP-A01", "APP-A08", "APP-A09", "APP-A13", "APP-X02", "APP-X06", "APM-O01", "APM-O03", "APM-O05", "APM-O06", "APM-O07", "APM-O08", "APM-O09", "APM-O10", "APM-O11", "APM-O12", "APM-O13", "APM-O14"}
	for _, id := range ids {
		m, ok := RuleMetaFor(id)
		if !ok {
			t.Fatalf("%s has no RuleMeta", id)
		}
		wantFamily := map[string]string{"APP-H": "app-h", "APP-A": "app-a", "APP-X": "app-x", "APM-O": "apm-o"}[id[:5]]
		if m.Family != wantFamily {
			t.Fatalf("%s: family %q want %q", id, m.Family, wantFamily)
		}
		if !m.DefaultObserve {
			t.Fatalf("%s must start in observe mode", id)
		}
		if m.Operational != strings.HasPrefix(id, "APM-") {
			t.Fatalf("%s: Operational must be set exactly for APM rules", id)
		}
		if m.WhatToCheck == "" {
			t.Fatalf("%s: WhatToCheck is required", id)
		}
		if strings.HasPrefix(id, "APP-H") && m.Tier != 0 || strings.HasPrefix(id, "APP-A") && m.Tier != 1 {
			t.Fatalf("%s: wrong tier %d", id, m.Tier)
		}
		for _, tu := range m.Tunables {
			if tu.Key == "" || tu.Label == "" {
				t.Fatalf("%s: incomplete tunable %+v", id, tu)
			}
		}
	}
	// no other Application rule is registered without being tested here
	for _, m := range AllRuleMeta() {
		if (strings.HasPrefix(m.ID, "APP-") || strings.HasPrefix(m.ID, "APM-")) && !appContainsStr(ids, m.ID) {
			t.Fatalf("%s is registered but not covered by the contract test", m.ID)
		}
	}
}

func appContainsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// Contract: every v1 rule ships positive and negative fixtures. The tests above record them;
// this one (kept in the last file alphabetically) fails if a rule lacks either.
func TestAppRuleFixtureCoverage(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	appFixtureSeen.Lock()
	defer appFixtureSeen.Unlock()
	for _, id := range []string{"APP-H01", "APP-H02", "APP-H03", "APP-H04", "APP-H05", "APP-H06", "APP-H07", "APP-H08", "APP-H11",
		"APP-A01", "APP-A08", "APP-A09", "APP-A13", "APP-X02", "APP-X06", "APM-O01", "APM-O03", "APM-O05", "APM-O06", "APM-O07", "APM-O08", "APM-O09", "APM-O10", "APM-O11", "APM-O12", "APM-O13", "APM-O14"} {
		if !appFixtureSeen.pos[id] {
			t.Errorf("%s: no positive fixture ran", id)
		}
		if !appFixtureSeen.neg[id] {
			t.Errorf("%s: no negative fixture ran", id)
		}
	}
}

func TestAppRulesStatusEndpoint(t *testing.T) {
	appStatusReset()
	appSkip("APP-A01", "no login routes configured or recognised")
	rec := httptest.NewRecorder()
	appHandleRulesStatus()(rec, httptest.NewRequest("GET", "/api/v1/app/rules/status", nil))
	var out struct {
		Rules []struct {
			ID      string           `json:"id"`
			Skipped map[string]int64 `json:"skipped"`
			Observe bool             `json:"default_observe"`
		} `json:"rules"`
	}
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Rules) != 27 {
		t.Fatalf("all 27 rules must be listed even before they run: %d", len(out.Rules))
	}
	for _, r := range out.Rules {
		if !r.Observe {
			t.Fatalf("%s must start in observe", r.ID)
		}
		if r.ID == "APP-A01" && r.Skipped["no login routes configured or recognised"] != 1 {
			t.Fatalf("skip counter: %+v", r)
		}
	}
}
