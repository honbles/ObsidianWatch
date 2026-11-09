package store

// secrets.go — encryption at rest for stored credentials (M-12, G-17,
// CC-07, AW-03, AZ-10). Cloud/DevOps connector secrets and sensitive
// settings (API keys, SMTP password) used to be stored as plaintext JSON.
//
// Values are sealed with AES-256-GCM and stored as "enc:v1:<base64(nonce|ct)>".
// The key comes from OW_SECRET_KEY (any passphrase or 32-byte base64 key) or
// the file named by OW_SECRET_KEY_FILE. Reads are backward compatible:
// a value without the prefix is plaintext (pre-existing rows) and is returned
// as-is, then re-encrypted the next time it is written. With no key
// configured the server refuses to start (RequireSecretsKey) unless
// OW_ALLOW_PLAINTEXT_SECRETS=true.
//
// IMPORTANT: losing the key makes encrypted credentials unrecoverable
// (re-enter them in the UI). Back it up separately from the database.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
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
		slog.Warn("secrets: OW_SECRET_KEY not set — connector credentials and API keys are stored UNENCRYPTED")
		return
	}
	var key []byte
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil && len(b) == 32 {
		key = b
	} else {
		// H-5: passphrases go through a memory-hard KDF, not a bare hash.
		// The salt is a fixed application constant (the passphrase is a
		// deployment secret, not a per-user password).
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

// RequireSecretsKey is the fail-closed startup check (H-5). It returns an
// error when no at-rest key is configured, unless the operator explicitly
// opts into plaintext storage with OW_ALLOW_PLAINTEXT_SECRETS=true.
func RequireSecretsKey() error {
	if SecretsEnabled() {
		return nil
	}
	if strings.EqualFold(os.Getenv("OW_ALLOW_PLAINTEXT_SECRETS"), "true") {
		slog.Warn("secrets: running with plaintext credential storage (OW_ALLOW_PLAINTEXT_SECRETS=true)")
		return nil
	}
	return errors.New("OW_SECRET_KEY (or OW_SECRET_KEY_FILE) is not set; refusing to store credentials in plaintext. " +
		"Set a key, or set OW_ALLOW_PLAINTEXT_SECRETS=true to override")
}

// SecretsEnabled reports whether at-rest encryption is active.
func SecretsEnabled() bool {
	secretOnce.Do(loadSecretKey)
	return secretGCM != nil
}

// sealString encrypts s (no-op if disabled, empty, or already sealed).
func sealString(s string) string {
	if s == "" || strings.HasPrefix(s, encPrefix) || !SecretsEnabled() {
		return s
	}
	nonce := make([]byte, secretGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return s
	}
	ct := secretGCM.Seal(nonce, nonce, []byte(s), nil)
	return encPrefix + base64.StdEncoding.EncodeToString(ct)
}

// openString decrypts a sealed value; plaintext passes through unchanged.
// If the value is sealed but cannot be opened (wrong/missing key) it is
// returned as "" so a ciphertext is never used as a credential.
func openString(s string) string {
	if !strings.HasPrefix(s, encPrefix) {
		return s
	}
	if !SecretsEnabled() {
		slog.Error("secrets: encrypted value present but OW_SECRET_KEY is not set")
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, encPrefix))
	if err != nil || len(raw) < secretGCM.NonceSize() {
		return ""
	}
	n := secretGCM.NonceSize()
	pt, err := secretGCM.Open(nil, raw[:n], raw[n:], nil)
	if err != nil {
		slog.Error("secrets: decrypt failed (wrong OW_SECRET_KEY?)")
		return ""
	}
	return string(pt)
}

var secretCredKeys = map[string]bool{
	"secret_access_key": true, "session_token": true, "external_id": true, "client_secret": true,
	"service_account": true, "token": true, "pat": true, "password": true,
	"api_key": true, "private_key": true,
}

// sealCreds returns a copy of creds with sensitive values encrypted.
func sealCreds(creds map[string]string) map[string]string {
	out := make(map[string]string, len(creds))
	for k, v := range creds {
		if secretCredKeys[strings.ToLower(k)] {
			v = sealString(v)
		}
		out[k] = v
	}
	return out
}

// openCreds decrypts any sealed values in place.
func openCreds(creds map[string]string) {
	for k, v := range creds {
		if strings.HasPrefix(v, encPrefix) {
			creds[k] = openString(v)
		}
	}
}

// isSecretSettingKey marks settings whose values must be sealed.
func isSecretSettingKey(k string) bool {
	k = strings.ToLower(k)
	for _, s := range []string{"api_key", "password", "secret", "token", "webhooks"} {
		if strings.Contains(k, s) {
			return !strings.HasPrefix(k, "cspm:") // scan results, not secrets
		}
	}
	return false
}
