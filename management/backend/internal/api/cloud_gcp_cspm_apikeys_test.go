package api

import (
	"encoding/json"
	"testing"
	"time"
)

func TestEvalGCPAPIKeys(t *testing.T) {
	now := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	var keys []gcpAPIKey
	js := `[
	 {"name":"projects/1/locations/global/keys/a","displayName":"open","createTime":"2026-10-30T00:00:00Z"},
	 {"name":"projects/1/locations/global/keys/b","displayName":"appOnly","createTime":"2026-10-30T00:00:00Z","restrictions":{"browserKeyRestrictions":{}}},
	 {"name":"projects/1/locations/global/keys/c","displayName":"good","createTime":"2026-10-30T00:00:00Z","restrictions":{"serverKeyRestrictions":{},"apiTargets":[{"service":"maps.googleapis.com"}]}},
	 {"name":"projects/1/locations/global/keys/d","displayName":"old","createTime":"2025-01-01T00:00:00Z","restrictions":{"apiTargets":[{"service":"x"}]}}]`
	if err := json.Unmarshal([]byte(js), &keys); err != nil {
		t.Fatal(err)
	}
	f, passed := evalGCPAPIKeys(keys, now)
	if len(f) != 3 || passed != 1 {
		t.Fatalf("findings=%d passed=%d: %+v", len(f), passed, f)
	}
	if f[0].Severity != "high" || f[1].Severity != "medium" || f[2].Severity != "low" {
		t.Fatalf("severities %v %v %v", f[0].Severity, f[1].Severity, f[2].Severity)
	}
}
