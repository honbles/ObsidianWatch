package api

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

const jwtCutoffPrefix = "auth.cutoff" // settings key: auth.cutoff.<userID> = unix seconds
const jwtJTIPrefix = "auth.jti"       // settings key: auth.jti.<jti> = expiry unix seconds

// parseJWTCutoffs turns the stored settings map (userID -> unix seconds) into
// cutoffs, skipping malformed entries.
func parseJWTCutoffs(m map[string]string) map[int64]time.Time {
	out := make(map[int64]time.Time, len(m))
	for k, v := range m {
		id, err1 := strconv.ParseInt(k, 10, 64)
		sec, err2 := strconv.ParseInt(v, 10, 64)
		if err1 != nil || err2 != nil || sec <= 0 {
			continue
		}
		out[id] = time.Unix(sec, 0)
	}
	return out
}

// persistJWTRevocations makes user-level token revocation (password change,
// account deletion) survive a restart by mirroring cutoffs into the settings table.
func persistJWTRevocations(ctx context.Context, db *store.DB, jwt *auth.JWTService, logger *slog.Logger) {
	if m, err := db.GetSettingsPrefix(ctx, jwtCutoffPrefix); err == nil {
		jwt.RestoreUserCutoffs(parseJWTCutoffs(m))
	} else {
		logger.Warn("auth: could not restore token cutoffs", "err", err)
	}
	// Individual logouts (JTI revocations).
	if m, err := db.GetSettingsPrefix(ctx, jwtJTIPrefix); err == nil {
		jwt.RestoreRevoked(parseJWTCutoffs2(m))
	} else {
		logger.Warn("auth: could not restore revoked tokens", "err", err)
	}
	_ = db.DeleteSettingsPrefixOlder(ctx, jwtJTIPrefix, time.Now().Add(-48*time.Hour))
	jwt.OnRevoked = func(jti string, exp time.Time) {
		if err := db.SetSetting(context.Background(), jwtJTIPrefix+"."+jti, strconv.FormatInt(exp.Unix(), 10)); err != nil {
			logger.Error("auth: failed to persist token revocation", "err", err)
		}
	}
	jwt.OnUserRevoked = func(id int64, cut time.Time) {
		key := jwtCutoffPrefix + "." + strconv.FormatInt(id, 10)
		if err := db.SetSetting(context.Background(), key, strconv.FormatInt(cut.Unix(), 10)); err != nil {
			logger.Error("auth: failed to persist token cutoff", "user", id, "err", err)
		}
	}
}

// parseJWTCutoffs2 parses jti -> unix-expiry settings, skipping bad entries.
func parseJWTCutoffs2(m map[string]string) map[string]time.Time {
	out := make(map[string]time.Time, len(m))
	for jti, v := range m {
		sec, err := strconv.ParseInt(v, 10, 64)
		if err != nil || sec <= 0 || jti == "" {
			continue
		}
		out[jti] = time.Unix(sec, 0)
	}
	return out
}
