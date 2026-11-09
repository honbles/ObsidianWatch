package api

// F-25: integrity, config-binding and expiry for cached agent build zips.
// A sidecar <zip>.meta records the zip's SHA-256, a hash of the configuration
// baked into the build (URLs and API key, never stored in clear), and the build
// time. A cached zip is reused only if it still matches the requested config,
// is unmodified, and is younger than agentCacheMaxAge.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"time"
)

const agentCacheMaxAge = 14 * 24 * time.Hour

type agentCacheMeta struct {
	ZipSHA256  string    `json:"zip_sha256"`
	ConfigHash string    `json:"config_hash"`
	BuiltAt    time.Time `json:"built_at"`
}

func agentConfigHash(cfg AgentBuilderConfig) string {
	h := sha256.Sum256([]byte(buildAgentYAML(cfg)))
	return hex.EncodeToString(h[:])
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeAgentCacheMeta(zipPath, cfgHash string) error {
	sum, err := fileSHA256(zipPath)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(agentCacheMeta{ZipSHA256: sum, ConfigHash: cfgHash, BuiltAt: time.Now().UTC()})
	return os.WriteFile(zipPath+".meta", b, 0o600)
}

// agentCacheValid reports whether the cached zip may be served. wantCfgHash == ""
// skips the config-binding check (used by the config-less dashboard download).
func agentCacheValid(zipPath, wantCfgHash string, now time.Time) bool {
	raw, err := os.ReadFile(zipPath + ".meta")
	if err != nil {
		return false
	}
	var m agentCacheMeta
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	if now.Sub(m.BuiltAt) > agentCacheMaxAge {
		return false
	}
	if wantCfgHash != "" && m.ConfigHash != wantCfgHash {
		return false
	}
	sum, err := fileSHA256(zipPath)
	return err == nil && sum == m.ZipSHA256
}
