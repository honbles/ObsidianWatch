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

func TestAzureSecretGUIDRejectedLocally(t *testing.T) {
	_, err := getAzureToken(nil, "t", "c", " 98ee1c4d-0000-4000-a6b9-4ba4de2c4aaa ", "r")
	if err == nil || !strings.Contains(err.Error(), "secret's ID") {
		t.Fatalf("expected local GUID rejection, got %v", err)
	}
}
