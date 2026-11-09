package api

import "testing"

func TestValidatePassword(t *testing.T) {
	long := ""
	for i := 0; i < 80; i++ {
		long += "a1"
	}
	cases := []struct {
		name, pw, user, cur string
		ok                  bool
	}{
		{"good", "correct-horse-battery", "alice", "", true},
		{"too short", "short1!", "alice", "", false},
		{"nine chars", "abcdefgh1", "alice", "", false},
		{"too long for bcrypt", long, "alice", "", false},
		{"common", "Password123", "alice", "", false},
		{"is username", "administrator", "administrator", "", false},
		{"contains username", "xx-alice-secret-xx", "alice", "", false},
		{"same as current", "correct-horse-battery", "alice", "correct-horse-battery", false},
		{"short username not a substring ban", "abcd-efgh-ijkl", "ab", "", true},
	}
	for _, c := range cases {
		if err := validatePassword(c.pw, c.user, c.cur); (err == nil) != c.ok {
			t.Errorf("%s: ok=%v err=%v", c.name, c.ok, err)
		}
	}
}
