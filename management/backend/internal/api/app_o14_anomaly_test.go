package api

import (
	"strings"
	"testing"
	"time"
)

// A service whose same window in each of the last weeks looked like base, and whose current window is cur.
func seasonalFx(t *testing.T, base, cur appWindowTotals) *appFx {
	fx := appNewFx(t)
	fx.d.totals = func(from, to time.Time) appWindowTotals {
		if appNow.Sub(to) < 6*24*time.Hour { // the current window
			return cur
		}
		return base
	}
	return fx
}

func TestAppO14SeasonalAnomaly(t *testing.T) {
	base := appWindowTotals{Calls: 1000, Errors: 10, P95Ms: 120} // 1 %
	fx := seasonalFx(t, base, appWindowTotals{Calls: 1000, Errors: 100, P95Ms: 130})
	fx.scan()
	got := fx.pos("APM-O14", 1)
	if !strings.Contains(got[0].F.Detail, "Error rate is 10.0% against a usual 1.0%") {
		t.Fatal(got[0].F.Detail)
	}
	lat := seasonalFx(t, base, appWindowTotals{Calls: 1000, Errors: 10, P95Ms: 400})
	lat.scan()
	if g := lat.fired("APM-O14"); len(g) != 1 || !strings.Contains(g[0].F.Detail, "p95 is 400 ms against a usual 120 ms") {
		t.Fatalf("%+v", g)
	}
	spike := seasonalFx(t, base, appWindowTotals{Calls: 5000, Errors: 50, P95Ms: 120})
	spike.scan()
	if g := spike.fired("APM-O14"); len(g) != 1 || !strings.Contains(g[0].F.Detail, "5000 requests against a usual 1000") {
		t.Fatalf("%+v", g)
	}
}

func TestAppO14Quiet(t *testing.T) {
	base := appWindowTotals{Calls: 1000, Errors: 10, P95Ms: 120}
	normal := seasonalFx(t, base, appWindowTotals{Calls: 1200, Errors: 15, P95Ms: 150})
	normal.scan()
	normal.neg("APM-O14")
	young := seasonalFx(t, base, appWindowTotals{Calls: 1000, Errors: 500, P95Ms: 900}) // no three weeks of history yet
	young.setSvc(func(s *appSvc) { s.FirstSeen = appNow.Add(-10 * 24 * time.Hour) })
	young.scan()
	young.neg("APM-O14")
	quiet := seasonalFx(t, base, appWindowTotals{Calls: 20, Errors: 20, P95Ms: 900}) // too little traffic to judge
	quiet.scan()
	quiet.neg("APM-O14")
}

func TestAppO03UsesSeasonalBaseline(t *testing.T) {
	// Yesterday's traffic at this hour was low, but at this hour of the week it is normally high: a drop to the
	// low figure is a drop. The previous-day baseline alone would not have noticed.
	fx := appNewFx(t)
	fx.d.requests = 100000
	fx.d.curWin = []appWindowStats{{Route: "/o", Method: "GET", Calls: 100}}
	fx.d.baseWin = []appWindowStats{{Route: "/o", Method: "GET", Calls: 14400}} // a day averages 100 per 10 min
	fx.d.totals = func(from, to time.Time) appWindowTotals { return appWindowTotals{Calls: 2000} }
	fx.scan()
	got := fx.pos("APM-O03", 1)
	if !strings.Contains(got[0].F.Detail, "usual for this time of the week 2000") {
		t.Fatal(got[0].F.Detail)
	}
}
