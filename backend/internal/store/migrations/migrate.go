package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"
	"strings"
)

//go:embed *.sql
var sqlFiles embed.FS

// Run applies all *.sql migration files in order.
// Migrations are tracked in a simple schema_migrations table so
// each file is only ever applied once.
func Run(ctx context.Context, db *sql.DB, logger *slog.Logger) error {
	// Ensure tracking table exists.
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			filename   TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`); err != nil {
		return fmt.Errorf("migrations: create tracking table: %w", err)
	}

	// Collect already-applied migrations.
	rows, err := db.QueryContext(ctx, `SELECT filename FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("migrations: query applied: %w", err)
	}
	applied := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		applied[name] = true
	}
	rows.Close()

	// Collect all SQL files and sort them.
	entries, err := fs.ReadDir(sqlFiles, ".")
	if err != nil {
		return fmt.Errorf("migrations: read embedded files: %w", err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	// Apply new migrations in a transaction each.
	for _, name := range files {
		if applied[name] {
			logger.Debug("migration already applied", "file", name)
			continue
		}

		content, err := sqlFiles.ReadFile(name)
		if err != nil {
			return fmt.Errorf("migrations: read %s: %w", name, err)
		}

		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("migrations: begin tx: %w", err)
		}

		if _, err := tx.ExecContext(ctx, string(content)); err != nil {
			tx.Rollback()
			return fmt.Errorf("migrations: apply %s: %w", name, err)
		}

		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (filename) VALUES ($1)`, name,
		); err != nil {
			tx.Rollback()
			return fmt.Errorf("migrations: record %s: %w", name, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migrations: commit %s: %w", name, err)
		}

		logger.Info("migration applied", "file", name)
	}

	return nil
}
