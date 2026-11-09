package store

import (
	"strings"
	"testing"
)

func TestSecretsRoundTrip(t *testing.T) {
	t.Setenv("OW_SECRET_KEY", "unit-test-key")
	if !SecretsEnabled() {
		t.Fatal("secrets should be enabled with OW_SECRET_KEY set")
	}
	sealed := sealString("hunter2")
	if !strings.HasPrefix(sealed, encPrefix) || strings.Contains(sealed, "hunter2") {
		t.Fatalf("not sealed: %q", sealed)
	}
	if sealString(sealed) != sealed {
		t.Fatal("sealing twice must be a no-op")
	}
	if openString(sealed) != "hunter2" {
		t.Fatal("round trip failed")
	}
	if openString("plain") != "plain" {
		t.Fatal("plaintext must pass through")
	}
	if openString(encPrefix+"!!notbase64") != "" {
		t.Fatal("corrupt ciphertext must not be returned as a credential")
	}
}

func TestSealCredsOnlySensitiveKeys(t *testing.T) {
	t.Setenv("OW_SECRET_KEY", "unit-test-key")
	out := sealCreds(map[string]string{"client_id": "abc", "client_secret": "s3cr3t", "External_ID": "ext"})
	if out["client_id"] != "abc" {
		t.Fatal("non-secret key must stay plaintext")
	}
	if !strings.HasPrefix(out["client_secret"], encPrefix) || !strings.HasPrefix(out["External_ID"], encPrefix) {
		t.Fatalf("secret keys not sealed: %+v", out)
	}
	openCreds(out)
	if out["client_secret"] != "s3cr3t" || out["External_ID"] != "ext" {
		t.Fatalf("openCreds failed: %+v", out)
	}
}

func TestHashInstallKey(t *testing.T) {
	a, b := hashInstallKey("k1"), hashInstallKey("k1")
	if a != b || a == hashInstallKey("k2") || len(a) != 64 || a == "k1" {
		t.Fatal("hash must be deterministic, distinct, hex sha256")
	}
}
