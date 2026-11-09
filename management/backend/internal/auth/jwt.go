package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

type JWTService struct {
	secret   []byte
	duration time.Duration

	// M-07: logout support. JWTs are stateless by design, so "logout"
	// needs an explicit revocation list keyed by JTI, checked on Verify
	// and swept once expired tokens age out.
	mu      sync.Mutex
	revoked map[string]time.Time // jti -> expiry (for sweep)
	// notBefore invalidates every token issued to a user before the given
	// instant (password change, account deletion). Held in memory like the JTI
	// list, so it is lost on restart; tokens are short-lived (hours).
	notBefore map[int64]time.Time
	// OnUserRevoked, when set, is called after RevokeUser so the cutoff can be
	// persisted and survive a restart (see RestoreUserCutoffs).
	OnUserRevoked func(userID int64, cutoff time.Time)
	// OnRevoked, when set, is called after Revoke so a logout survives a restart.
	OnRevoked func(jti string, expires time.Time)
}

func NewJWTService(secret string, duration time.Duration) *JWTService {
	j := &JWTService{secret: []byte(secret), duration: duration, revoked: make(map[string]time.Time), notBefore: make(map[int64]time.Time)}
	go j.sweepRevokedLoop()
	return j
}

func newJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (j *JWTService) Sign(userID int64, username, role string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID:   userID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(j.duration)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        newJTI(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secret)
}

func (j *JWTService) Verify(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return j.secret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	if j.isRevoked(claims.ID) {
		return nil, errors.New("token has been revoked")
	}
	if j.issuedBeforeUserCutoff(claims) {
		return nil, errors.New("token has been revoked")
	}
	return claims, nil
}

// Revoke marks a token's JTI as invalid immediately (used by logout).
func (j *JWTService) Revoke(claims *Claims) {
	j.mu.Lock()
	exp := time.Now().Add(j.duration)
	if claims.ExpiresAt != nil {
		exp = claims.ExpiresAt.Time
	}
	j.revoked[claims.ID] = exp
	cb := j.OnRevoked
	j.mu.Unlock()
	if cb != nil && claims.ID != "" {
		cb(claims.ID, exp)
	}
}

// RestoreRevoked reloads revoked JTIs saved via OnRevoked, skipping expired ones.
func (j *JWTService) RestoreRevoked(m map[string]time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()
	for jti, exp := range m {
		if exp.After(now) {
			j.revoked[jti] = exp
		}
	}
}

// RevokeUser invalidates all tokens issued to userID up to now. Tokens issued in
// the same second or later (e.g. the fresh one handed out after a password
// change) stay valid, because JWT iat has one-second resolution.
func (j *JWTService) RevokeUser(userID int64) {
	cut := time.Now().Truncate(time.Second)
	j.mu.Lock()
	j.notBefore[userID] = cut
	cb := j.OnUserRevoked
	j.mu.Unlock()
	if cb != nil {
		cb(userID, cut)
	}
}

// RestoreUserCutoffs reloads per-user cutoffs saved by OnUserRevoked, so a
// restart does not re-validate tokens that were revoked (password change,
// account deletion). A later cutoff already held in memory wins.
func (j *JWTService) RestoreUserCutoffs(m map[int64]time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for id, t := range m {
		if cur, ok := j.notBefore[id]; !ok || t.After(cur) {
			j.notBefore[id] = t
		}
	}
}

func (j *JWTService) issuedBeforeUserCutoff(c *Claims) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	cut, ok := j.notBefore[c.UserID]
	if !ok {
		return false
	}
	return c.IssuedAt == nil || c.IssuedAt.Time.Before(cut)
}

func (j *JWTService) isRevoked(jti string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	_, ok := j.revoked[jti]
	return ok
}

func (j *JWTService) sweepRevokedLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		j.mu.Lock()
		now := time.Now()
		for jti, exp := range j.revoked {
			if now.After(exp) {
				delete(j.revoked, jti)
			}
		}
		j.mu.Unlock()
	}
}
