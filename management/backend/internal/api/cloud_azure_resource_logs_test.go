package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"obsidianwatch/management/internal/store"
)

const laSample = `{"tables":[{"name":"PrimaryResult","columns":[{"name":"TimeGenerated"},{"name":"ResourceId"},{"name":"ResourceType"},{"name":"Category"},{"name":"OperationName"},{"name":"ResultType"},{"name":"ResultSignature"},{"name":"CallerIPAddress"},{"name":"requestUri_s"},{"name":"identity_claim_upn_s"}],"rows":[["2026-11-05T10:00:00.5Z","/subscriptions/s/resourceGroups/rg/providers/MICROSOFT.KEYVAULT/VAULTS/kv1","VAULTS","AuditEvent","SecretGet","Forbidden","403","1.2.3.4","https://kv1.vault.azure.net/secrets/x","a@b.c"],["bad-time","x","VAULTS","AuditEvent","","","","","",""]]}]}`

func TestAzureResourceKQLShape(t *testing.T) {
	q := azureResourceKQL(time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC))
	for _, w := range []string{"AzureDiagnostics", "VAULTS", "kube-audit-admin", "column_ifexists", "take 5000", "2026-11-05T00:00:00"} {
		if !strings.Contains(q, w) {
			t.Errorf("missing %q in query", w)
		}
	}
}

func TestParseAndConvertAzureResourceRows(t *testing.T) {
	rows, err := parseAzureLAResponse([]byte(laSample))
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	ev, ok := azureResourceRowToEvent(rows[0], "ws1")
	if !ok || ev.Host != "kv1" || ev.Severity != cloudSevMedium || ev.SrcIP != "1.2.3.4" || ev.Username != "a@b.c" {
		t.Fatalf("bad event %+v ok=%v", ev, ok)
	}
	if _, ok := azureResourceRowToEvent(rows[1], "ws1"); ok {
		t.Fatal("bad timestamp should be skipped")
	}
	ev2, _ := azureResourceRowToEvent(rows[0], "ws1")
	if ev.ID != ev2.ID {
		t.Fatal("id must be deterministic for dedup")
	}
	se := store.Event{EventType: ev.EventType, Raw: ev.Raw}
	if !azureResourceSignatures[0].Match(se) {
		t.Fatal("key vault denied sig should match")
	}
	if azureResourceSignatures[1].Match(se) {
		t.Fatal("anonymous sig should not match")
	}
}

func TestPullAzureResourceLogsHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || !strings.HasSuffix(r.URL.Path, "/workspaces/ws1/query") || r.Header.Get("Authorization") != "Bearer t" {
			w.WriteHeader(400)
			return
		}
		w.Write([]byte(laSample))
	}))
	defer srv.Close()
	old := azureLogAnalyticsBase
	azureLogAnalyticsBase = srv.URL
	defer func() { azureLogAnalyticsBase = old }()
	evs, err := pullAzureResourceLogs(context.Background(), "t", "ws1", time.Now())
	if err != nil || len(evs) != 1 {
		t.Fatalf("evs=%d err=%v", len(evs), err)
	}
}
