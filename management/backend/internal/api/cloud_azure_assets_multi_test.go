package api

import (
	"context"
	"strings"
	"testing"
)

func TestAzureInventorySubs(t *testing.T) {
	inv := &AzureAssetInventory{}
	got := azureInventorySubs(context.Background(), "", "sub-a, sub-b;sub-c", "", inv)
	if len(got) != 3 || got[2] != "sub-c" {
		t.Fatalf("%v", got)
	}
	if got = azureInventorySubs(context.Background(), "", "", "fallback", inv); len(got) != 1 || got[0] != "fallback" {
		t.Fatalf("fallback: %v", got)
	}
	var many []string
	for i := 0; i < 120; i++ {
		many = append(many, "s"+strings.Repeat("x", i%3)+string(rune('a'+i%26)))
	}
	inv = &AzureAssetInventory{}
	got = azureInventorySubs(context.Background(), "", strings.Join(many, ","), "", inv)
	if len(got) != azureInventoryMaxSubs || len(inv.Errors) != 1 {
		t.Fatalf("cap: %d %v", len(got), inv.Errors)
	}
}
