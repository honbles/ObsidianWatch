package store

// secrets.go — read side of the at-rest encryption used by the management
// service. The management API seals sensitive settings (including
// setup.agent_api_key) as "enc:v1:<base64(nonce|ciphertext)>" with AES-256-GCM
// keyed from OW_SECRET_KEY. The ingest backend reads that setting to
// authenticate agents, so it must open the value the same way. The key
// derivation MUST stay identical to management/backend/internal/store/secrets.go.

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"log/slog"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

const encPrefix = "enc:v1:"

var (
	secretOnce sync.Once
	secretGCM  cipher.AEAD
)

func loadSecretKey() {
	raw := strings.TrimSpace(os.Getenv("OW_SECRET_KEY"))
	if raw == "" {
		if f := strings.TrimSpace(os.Getenv("OW_SECRET_KEY_FILE")); f != "" {
			if b, err := os.ReadFile(f); err == nil {
				raw = strings.TrimSpace(string(b))
			} else {
				slog.Error("secrets: cannot read OW_SECRET_KEY_FILE", "err", err)
			}
		}
	}
	if raw == "" {
		return
	}
	var key []byte
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil && len(b) == 32 {
		key = b
	} else {
		key = argon2.IDKey([]byte(raw), []byte("obsidianwatch/secrets/v1"), 2, 32*1024, 2, 32)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		slog.Error("secrets: bad key", "err", err)
		return
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		slog.Error("secrets: gcm init failed", "err", err)
		return
	}
	secretGCM = g
}

// openString decrypts a sealed value; plaintext passes through unchanged.
// A sealed value that cannot be opened returns "" so ciphertext is never used
// as a credential.
func openString(s string) string {
	if !strings.HasPrefix(s, encPrefix) {
		return s
	}
	secretOnce.Do(loadSecretKey)
	if secretGCM == nil {
		slog.Error("secrets: setting is encrypted but OW_SECRET_KEY is not set on the ingest backend")
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, encPrefix))
	if err != nil || len(raw) < secretGCM.NonceSize() {
		return ""
	}
	n := secretGCM.NonceSize()
	pt, err := secretGCM.Open(nil, raw[:n], raw[n:], nil)
	if err != nil {
		slog.Error("secrets: decrypt failed (OW_SECRET_KEY differs from the management service?)")
		return ""
	}
	return string(pt)
}
