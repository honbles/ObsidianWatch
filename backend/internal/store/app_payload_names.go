package store

// app_payload_names.go - the always-masked parameter names and credential-looking values of the payload capture design.
// This is a copy of the agent's list (agents/*/internal/otel/model.go); the three must stay identical, and
// each side enforces it independently so no single component has to be trusted.

import "strings"

// Parameter names that are never forwarded, whatever an admin chooses. Matching works on the whole name with
// separators removed (apiKey, api_key, API-KEY) and on the words inside it (user_password, authToken).
var deniedCompact = []string{"password", "passwd", "passphrase", "secret", "token", "apikey", "authorization", "cookie",
	"creditcard", "cardnumber", "cvv", "cvc", "sessionid", "privatekey", "accesskey", "clientsecret", "refreshtoken"}

var deniedWords = map[string]bool{"pwd": true, "pass": true, "jwt": true, "bearer": true, "auth": true, "sid": true, "otp": true,
	"pin": true, "ssn": true, "card": true, "pan": true, "iban": true, "cvv": true, "cvc": true, "signature": true, "sig": true,
	"credential": true, "credentials": true, "session": true, "sess": true, "csrf": true, "xsrf": true, "secret": true, "token": true,
	"password": true, "passwd": true, "cookie": true}

// PayloadNameDenied reports whether a parameter name belongs to the always-masked set.
func PayloadNameDenied(name string) bool {
	var compact strings.Builder
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	var prev rune
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			compact.WriteRune(r)
			cur = append(cur, r)
		case r >= 'A' && r <= 'Z':
			compact.WriteRune(r + 32)
			if prev >= 'a' && prev <= 'z' { // camelCase boundary
				flush()
			}
			cur = append(cur, r)
		default:
			flush()
		}
		prev = r
	}
	flush()
	c := compact.String()
	for _, d := range deniedCompact {
		if strings.Contains(c, d) {
			return true
		}
	}
	for _, w := range words {
		if deniedWords[w] {
			return true
		}
	}
	return false
}

// PayloadValueMasked reports whether a value looks like a credential or a card number and must not be
// forwarded even from an allowed parameter: JWTs, bearer or basic credentials, private keys, long opaque
// tokens, and card numbers (Luhn).
func PayloadValueMasked(v string) bool {
	t := strings.TrimSpace(v)
	if t == "" {
		return false
	}
	l := strings.ToLower(t)
	if strings.HasPrefix(l, "bearer ") || strings.HasPrefix(l, "basic ") || strings.Contains(t, "-----BEGIN") {
		return true
	}
	if strings.HasPrefix(t, "eyJ") && strings.Count(t, ".") == 2 {
		return true
	}
	digits, ok := 0, true
	for _, r := range t {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r == ' ' || r == '-':
		default:
			ok = false
		}
	}
	if ok && digits >= 13 && digits <= 19 && luhn(t) {
		return true
	}
	if len(t) >= 32 && !strings.ContainsAny(t, " \t") {
		hasD, hasL, clean := false, false, true
		for _, r := range t {
			switch {
			case r >= '0' && r <= '9':
				hasD = true
			case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z':
				hasL = true
			case r == '+' || r == '/' || r == '_' || r == '=' || r == '-' || r == '.':
			default:
				clean = false
			}
		}
		if clean && hasD && hasL {
			return true
		}
	}
	return false
}

func luhn(s string) bool {
	sum, alt := 0, false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c < '0' || c > '9' {
			continue
		}
		n := int(c - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}
