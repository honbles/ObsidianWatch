package api

import (
	"encoding/json"
	"testing"
)

func TestEvalGCPWorkbench(t *testing.T) {
	var l []gcpWorkbenchInstance
	js := `[{"name":"projects/p/locations/z/instances/a","gceSetup":{"serviceAccounts":[{"email":"1-compute@developer.gserviceaccount.com"}]}},
	        {"name":"projects/p/locations/z/instances/b","gceSetup":{"disablePublicIp":true,"serviceAccounts":[{"email":"nb@p.iam.gserviceaccount.com"}]}}]`
	if err := json.Unmarshal([]byte(js), &l); err != nil {
		t.Fatal(err)
	}
	f, passed := evalGCPWorkbench(l)
	if len(f) != 2 || passed != 1 {
		t.Fatalf("f=%d passed=%d", len(f), passed)
	}
}

func TestArmorToCloudEvent(t *testing.T) {
	var e gcpLogEntry
	js := `{"insertId":"i1","timestamp":"2026-11-05T01:00:00Z","resource":{"type":"http_load_balancer","labels":{"url_map_name":"um"}},
	 "jsonPayload":{"enforcedSecurityPolicy":{"name":"waf","outcome":"DENY","configuredAction":"DENY"}},
	 "httpRequest":{"remoteIp":"9.9.9.9","requestUrl":"https://x/a","requestMethod":"GET","status":403}}`
	if err := json.Unmarshal([]byte(js), &e); err != nil {
		t.Fatal(err)
	}
	ev := armorToCloudEvent(e, 1)
	if ev.SrcIP != "9.9.9.9" || ev.Host != "um" || ev.Severity != cloudSevMedium || ev.EventType != "cloud.gcp_lb_armor" {
		t.Fatalf("%+v", ev)
	}
}
