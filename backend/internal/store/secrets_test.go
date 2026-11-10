package store

import "testing"

// Ciphertext produced by the management service's sealString with
// OW_SECRET_KEY="unit-test-key". Guards against key-derivation drift.
const mgmtSealedVector = "enc:v1:4icmxjDLqSFK/vmmcR5AiSg4Gxpuuqg4ji1enSgzG7IzDsiWtr9z+ks="

func TestOpenStringDecryptsManagementCiphertext(t *testing.T) {
	t.Setenv("OW_SECRET_KEY", "unit-test-key")
	if got := openString(mgmtSealedVector); got != "agent-key-123" {
		t.Fatalf("got %q, want agent-key-123", got)
	}
	if openString("plain-key") != "plain-key" {
		t.Fatal("plaintext must pass through")
	}
}
