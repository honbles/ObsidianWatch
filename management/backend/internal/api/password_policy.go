package api

import (
	"errors"
	"fmt"
	"strings"
)

// validatePassword enforces the console password policy: 10+ characters,
// at most 72 bytes (bcrypt silently ignores or rejects anything longer), not a
// well-known password, not the username, and not unchanged from the current one.
func validatePassword(pw, username, current string) error {
	if len(pw) < 10 {
		return fmt.Errorf("password must be at least 10 characters")
	}
	if len(pw) > 72 {
		return fmt.Errorf("password must be at most 72 bytes")
	}
	lp := strings.ToLower(pw)
	if commonPasswords[lp] {
		return fmt.Errorf("that password is too common")
	}
	if u := strings.ToLower(strings.TrimSpace(username)); u != "" && (lp == u || strings.Contains(lp, u) && len(u) >= 4) {
		return fmt.Errorf("password must not contain the username")
	}
	if current != "" && pw == current {
		return fmt.Errorf("new password must differ from the current password")
	}
	return nil
}

var commonPasswords = map[string]bool{
	"password123": true, "password1234": true, "1234567890": true, "qwertyuiop": true, "0123456789": true,
	"administrator": true, "admin12345": true, "letmein123": true, "welcome123": true, "changeme123": true,
	"obsidianwatch": true, "passw0rd123": true, "iloveyou123": true, "abcdefghij": true, "11111111111": true,
}

// validateUsername restricts new usernames to a safe, unambiguous charset so
// they can't carry control characters into audit/log lines or look-alike
// whitespace/unicode into the admin UI. Applies to creation only; existing
// accounts are not renamed.
func validateUsername(u string) error {
	if len(u) < 3 || len(u) > 64 {
		return errors.New("username must be 3 to 64 characters")
	}
	for _, r := range u {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '.' || r == '_' || r == '-' || r == '@'
		if !ok {
			return errors.New("username may only contain letters, digits and . _ - @")
		}
	}
	return nil
}
