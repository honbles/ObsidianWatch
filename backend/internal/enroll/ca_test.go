package enroll

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateCA(t *testing.T) {
	dir := t.TempDir()
	cf, kf := filepath.Join(dir, "ca", "agent-ca.crt"), filepath.Join(dir, "ca", "agent-ca.key")
	ca, created, err := LoadOrCreateCA(cf, kf)
	if err != nil || !created || !ca.Cert.IsCA {
		t.Fatalf("create: %v created=%v", err, created)
	}
	st, _ := os.Stat(kf)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("CA key mode %v, want 0600", st.Mode().Perm())
	}
	again, created, err := LoadOrCreateCA(cf, kf)
	if err != nil || created || !again.Cert.Equal(ca.Cert) {
		t.Fatalf("reload: %v created=%v", err, created)
	}
	// Losing one half must not silently mint a new CA (it would orphan every agent).
	os.Remove(kf)
	if _, _, err := LoadOrCreateCA(cf, kf); err == nil {
		t.Error("half-present CA was accepted")
	}
}
