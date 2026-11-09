package store

import "strings"

const maskedSecret = "••••••••"

// isSecretCredKey reports whether a connector credential field holds a secret
// and must not be returned to the browser. It matches by name pattern rather
// than a fixed list, so a credential field added later (session_token,
// webhook_secret, api_key, ...) is masked by default instead of leaking until
// someone remembers to extend a list. Identifier fields (…_id, …_key_id) and
// plain settings are left visible.
func isSecretCredKey(k string) bool {
	k = strings.ToLower(k)
	if strings.HasSuffix(k, "_id") || k == "id" {
		return false
	}
	if k == "pat" { // exact only: "path", "patch" etc. are not secrets
		return true
	}
	for _, p := range []string{"secret", "token", "password", "passwd", "private", "credential", "service_account", "api_key", "apikey", "access_key", "client_key", "key_json", "certificate"} {
		if strings.Contains(k, p) {
			return true
		}
	}
	return false
}

// maskCreds returns a copy of creds with secret fields replaced by a fixed
// placeholder (omitted if empty). The input is not modified.
func maskCreds(creds map[string]string) map[string]string {
	safe := make(map[string]string, len(creds))
	for k, v := range creds {
		if isSecretCredKey(k) {
			if v != "" {
				safe[k] = maskedSecret
			}
			continue
		}
		safe[k] = v
	}
	return safe
}
