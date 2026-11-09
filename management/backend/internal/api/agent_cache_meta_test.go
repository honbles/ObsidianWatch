package api

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAgentCacheValid(t *testing.T) {
	z := filepath.Join(t.TempDir(), "a.zip")
	_ = os.WriteFile(z, []byte("zipdata"), 0o600)
	if agentCacheValid(z, "", time.Now()) {
		t.Fatal("no meta must be invalid")
	}
	if err := writeAgentCacheMeta(z, "cfg1"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if !agentCacheValid(z, "cfg1", now) || !agentCacheValid(z, "", now) {
		t.Fatal("fresh cache should be valid")
	}
	if agentCacheValid(z, "cfg2", now) {
		t.Fatal("different config must invalidate")
	}
	if agentCacheValid(z, "cfg1", now.Add(agentCacheMaxAge+time.Hour)) {
		t.Fatal("expired cache must be invalid")
	}
	_ = os.WriteFile(z, []byte("tampered"), 0o600)
	if agentCacheValid(z, "cfg1", now) {
		t.Fatal("tampered zip must be invalid")
	}
}
