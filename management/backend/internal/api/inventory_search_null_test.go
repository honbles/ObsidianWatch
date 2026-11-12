package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestInventoryNoHitsIsEmptyArrayNotNull(t *testing.T) {
	b, _ := json.Marshal(map[string]interface{}{"hits": inventoryFromScans(nil, "", "nginx", "")})
	if !strings.Contains(string(b), `"hits":[]`) {
		t.Fatalf("hits must serialise as [], got %s", b)
	}
}

func TestAzureAuthHint(t *testing.T) {
	if !strings.Contains(azureAuthHint("AADSTS7000215: Invalid client secret"), "VALUE") {
		t.Error("expected secret-value hint")
	}
	if azureAuthHint("something else") != "" {
		t.Error("unknown errors get no hint")
	}
}
