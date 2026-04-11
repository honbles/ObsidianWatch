package store

import (
	"context"
	"strings"
)

// GetSetting returns a single setting value by key.
func (db *DB) GetSetting(ctx context.Context, key string) (string, error) {
	var value string
	err := db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = $1`, key).Scan(&value)
	return value, err
}

// SetSetting upserts a setting value.
func (db *DB) SetSetting(ctx context.Context, key, value string) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO settings (key, value, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()
	`, key, value)
	return err
}

// GetSettingsPrefix returns all settings whose key starts with prefix as a map.
func (db *DB) GetSettingsPrefix(ctx context.Context, prefix string) (map[string]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT key, value FROM settings WHERE key LIKE $1`, prefix+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			continue
		}
		// Strip prefix from key for cleaner map
		result[strings.TrimPrefix(k, prefix+".")] = v
	}
	return result, rows.Err()
}

// SetSettingsPrefix upserts multiple settings with a shared prefix.
func (db *DB) SetSettingsPrefix(ctx context.Context, prefix string, values map[string]string) error {
	for k, v := range values {
		if err := db.SetSetting(ctx, prefix+"."+k, v); err != nil {
			return err
		}
	}
	return nil
}

// SetSettingsMap upserts multiple settings using the full key as-is (no prefix added).
func (db *DB) SetSettingsMap(ctx context.Context, values map[string]string) error {
	for k, v := range values {
		if err := db.SetSetting(ctx, k, v); err != nil {
			return err
		}
	}
	return nil
}
