package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"obsidianwatch/management/internal/auth"
)

func TestDeleteUserRejectsSelfAndNonAdmin(t *testing.T) {
	h := handleDeleteUser(nil, nil) // both rejections happen before any DB/JWT use
	do := func(role string, uid int64) int {
		r := httptest.NewRequest(http.MethodDelete, "/api/v1/users/7", nil)
		r.SetPathValue("id", "7")
		r = r.WithContext(context.WithValue(r.Context(), auth.ClaimsKey, &auth.Claims{UserID: uid, Username: "u", Role: role}))
		w := httptest.NewRecorder()
		h(w, r)
		return w.Code
	}
	if c := do("admin", 7); c != 400 {
		t.Fatalf("self-delete: got %d, want 400", c)
	}
	if c := do("analyst", 1); c != 403 {
		t.Fatalf("non-admin: got %d, want 403", c)
	}
}

func TestValidateUsername(t *testing.T) {
	for _, ok := range []string{"alice", "a.b-c_d", "bob@corp.example", "Adm123"} {
		if err := validateUsername(ok); err != nil {
			t.Errorf("%q should be valid: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "ab", "has space", "new\nline", "tab\t", "ünï", "semi;colon", string(make([]byte, 65))} {
		if validateUsername(bad) == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestParseJWTCutoffs(t *testing.T) {
	m := parseJWTCutoffs(map[string]string{"5": "1700000000", "x": "1", "6": "abc", "7": "-3"})
	if len(m) != 1 || m[5].Unix() != 1700000000 {
		t.Fatalf("unexpected: %v", m)
	}
}
