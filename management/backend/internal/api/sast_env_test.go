package api

import (
	"strings"
	"testing"
)

func TestScannerEnvScrubsSecrets(t *testing.T) {
	t.Setenv("OW_SECRET_KEY", "s3cret")
	t.Setenv("AGENT_API_KEY", "k")
	t.Setenv("JWT_SECRET", "j")
	t.Setenv("DB_PASSWORD", "p")
	t.Setenv("PATH", "/usr/bin")
	joined := strings.Join(scannerEnv(), "\n")
	for _, bad := range []string{"OW_SECRET_KEY", "AGENT_API_KEY", "JWT_SECRET", "DB_PASSWORD"} {
		if strings.Contains(joined, bad) {
			t.Errorf("%s leaked to scanner env", bad)
		}
	}
	if !strings.Contains(joined, "PATH=/usr/bin") {
		t.Error("PATH must be preserved")
	}
}
