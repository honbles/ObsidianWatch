package api

import "testing"

func TestPayloadNameAndValueRules(t *testing.T) {
	for _, n := range []string{"password", "user_password", "apiKey", "API-KEY", "auth_token", "client_secret", "cookie", "Authorization", "cardNumber", "cvv", "ssn", "otp", "sessionId", "jwt", "refresh_token"} {
		if !PayloadNameDenied(n) {
			t.Errorf("%q must be denied", n)
		}
	}
	for _, n := range []string{"q", "sort", "page", "id", "keyword", "monkey", "bypass", "passenger", "compass", "email"} {
		if PayloadNameDenied(n) {
			t.Errorf("%q must not be denied", n)
		}
	}
	for _, v := range []string{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123", "Bearer abcdef", "4111 1111 1111 1111", "-----BEGIN PRIVATE KEY-----", "3f9a8c1b2d4e5f60718293a4b5c6d7e8f9a0b1c2"} {
		if !PayloadValueMasked(v) {
			t.Errorf("%q must be masked", v)
		}
	}
	for _, v := range []string{"apple", "asc", "2026-11-20", "1234567890123", "hello world this is a long search phrase", ""} {
		if PayloadValueMasked(v) {
			t.Errorf("%q must not be masked", v)
		}
	}
}
