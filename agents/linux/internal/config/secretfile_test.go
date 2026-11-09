package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteSecretFileTightensExistingMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writeSecretFile(p, []byte("new")); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0600 {
		t.Fatalf("mode = %v, want 0600", st.Mode().Perm())
	}
	if b, _ := os.ReadFile(p); string(b) != "new" {
		t.Fatalf("content = %q", b)
	}
}
