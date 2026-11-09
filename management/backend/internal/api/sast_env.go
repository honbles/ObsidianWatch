package api

import (
	"os"
	"strings"
)

// scannerEnv returns a minimal environment for SAST tools that parse
// untrusted repositories (H-4). Application secrets (OW_SECRET_KEY, the agent
// API key, JWT secret, DB password, ...) are never passed to them.
func scannerEnv() []string {
	allow := map[string]bool{
		"PATH": true, "HOME": true, "LANG": true, "LC_ALL": true, "TMPDIR": true, "TZ": true,
		"JAVA_HOME": true, "HTTPS_PROXY": true, "HTTP_PROXY": true, "NO_PROXY": true,
		"https_proxy": true, "http_proxy": true, "no_proxy": true,
		"SSL_CERT_FILE": true, "REQUESTS_CA_BUNDLE": true,
	}
	var out []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if allow[k] || strings.HasPrefix(k, "SEMGREP_") || strings.HasPrefix(k, "CODEQL_") {
			out = append(out, kv)
		}
	}
	return out
}
