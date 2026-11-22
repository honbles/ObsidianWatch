package store

// app_retention.go - Application Monitoring purge functions. Owned by the
// Application build; the integration owner wires AppPurge into the scheduler.
//
// Retention is configurable through settings keys app.retention_stats_days
// (default 90) and app.retention_trace_days (default 7).

import (
	"context"
	"strconv"
	"strings"
	"time"
)

const (
	AppDefaultStatsDays   = 90
	AppDefaultTraceDays   = 7
	AppDefaultClientDays  = 7
	AppDefaultPayloadDays = 7
)

// AppRetentionDays reads the configured retention, falling back to the defaults
// for missing, non-numeric or non-positive values.
func (db *DB) AppRetentionDays(ctx context.Context) (statsDays, traceDays int) {
	statsDays, traceDays = AppDefaultStatsDays, AppDefaultTraceDays
	read := func(key string, def int) int {
		var v string
		if err := db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = $1`, key).Scan(&v); err != nil {
			return def
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || n <= 0 {
			return def
		}
		return n
	}
	return read("app.retention_stats_days", AppDefaultStatsDays), read("app.retention_trace_days", AppDefaultTraceDays)
}

// AppPurgeResult counts the rows AppPurge removed from each table.
type AppPurgeResult struct {
	Stats, Traces, EdgeStats, ClientStats, Payloads int64
}

// AppPurge deletes data older than the configured retention: route and dependency statistics
// (app.retention_stats_days, 90), traces (app.retention_trace_days, 7) and per-client failure
// counters (app.retention_client_days, 7).
func (db *DB) AppPurge(ctx context.Context, now time.Time) (AppPurgeResult, error) {
	var out AppPurgeResult
	sd, td := db.AppRetentionDays(ctx)
	cd := db.appSettingDays(ctx, "app.retention_client_days", AppDefaultClientDays)
	exec := func(dst *int64, q string, cutoff time.Time) error {
		res, err := db.ExecContext(ctx, q, cutoff)
		if err != nil {
			return err
		}
		*dst, _ = res.RowsAffected()
		return nil
	}
	if err := exec(&out.Stats, `DELETE FROM app_route_stats WHERE minute < $1`, now.AddDate(0, 0, -sd)); err != nil {
		return out, err
	}
	if err := exec(&out.EdgeStats, `DELETE FROM app_edge_stats WHERE hour < $1`, now.AddDate(0, 0, -sd)); err != nil {
		return out, err
	}
	if err := exec(&out.Traces, `DELETE FROM app_traces WHERE started < $1`, now.AddDate(0, 0, -td)); err != nil {
		return out, err
	}
	if err := exec(&out.ClientStats, `DELETE FROM app_client_stats WHERE minute < $1`, now.AddDate(0, 0, -cd)); err != nil {
		return out, err
	}
	// Diagnosis aggregates (slowest children, database calls, N+1) are short-lived; the tables exist once the
	// ingest migration that creates them has run.
	var haveDiag bool
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('app_db_stats') IS NOT NULL`).Scan(&haveDiag); err == nil && haveDiag {
		for _, t := range []string{"app_route_children", "app_db_stats", "app_route_n1"} {
			var n int64
			if err := exec(&n, `DELETE FROM `+t+` WHERE minute < $1`, now.AddDate(0, 0, -sd)); err != nil {
				return out, err
			}
		}
	}
	// Sampled request parameters (payload capture) are short-lived; the table exists only once the ingest
	// migration that creates it has run.
	var have bool
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('app_payloads') IS NOT NULL`).Scan(&have); err == nil && have {
		pd := db.appSettingDays(ctx, "app.retention_payload_days", AppDefaultPayloadDays)
		if err := exec(&out.Payloads, `DELETE FROM app_payloads WHERE time < $1`, now.AddDate(0, 0, -pd)); err != nil {
			return out, err
		}
	}
	return out, nil
}

func (db *DB) appSettingDays(ctx context.Context, key string, def int) int {
	var v string
	if err := db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = $1`, key).Scan(&v); err != nil {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return def
	}
	return n
}
