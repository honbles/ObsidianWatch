package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"obsidianwatch/management/internal/store"
)

// CloudConnectorEngine polls cloud providers every 5 minutes.
type CloudConnectorEngine struct {
	db      *store.DB
	eventDB *store.DB
	logger  *slog.Logger
}

func NewCloudConnectorEngine(db *store.DB, eventDB *store.DB, logger *slog.Logger) *CloudConnectorEngine {
	return &CloudConnectorEngine{db: db, eventDB: eventDB, logger: logger}
}

func (e *CloudConnectorEngine) Run(ctx context.Context) {
	e.logger.Info("cloud connector engine started")
	e.syncAll(ctx)
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.syncAll(ctx)
		}
	}
}

func (e *CloudConnectorEngine) SyncOne(ctx context.Context, id int64) error {
	conn, err := e.db.GetCloudConnectorRaw(ctx, id)
	if err != nil {
		return err
	}
	return e.syncConnector(ctx, conn)
}

func (e *CloudConnectorEngine) syncAll(ctx context.Context) {
	connectors, err := e.db.ListCloudConnectors(ctx)
	if err != nil {
		return
	}
	for _, c := range connectors {
		// Retry errored connectors after 30 min cooldown
		if c.Status == "error" && c.LastSync != nil {
			if time.Since(*c.LastSync) < 30*time.Minute {
				continue
			}
		}
		conn, err := e.db.GetCloudConnectorRaw(ctx, c.ID)
		if err != nil {
			continue
		}
		go e.syncConnector(ctx, conn)
	}
}

func (e *CloudConnectorEngine) syncConnector(ctx context.Context, conn *store.CloudConnector) error {
	// Retry up to 3 times with exponential backoff
	var ingested int
	var cursor string
	var syncErr error
	backoff := 5 * time.Second

	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
			}
		}

		syncCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		ingested, cursor, syncErr = e.doSync(syncCtx, conn)
		cancel()

		if syncErr == nil {
			break
		}
		// Don't retry auth errors — they won't fix themselves
		if isAuthError(syncErr) {
			break
		}
		e.logger.Warn("cloud sync attempt failed, retrying",
			"provider", conn.Provider, "attempt", attempt+1, "err", syncErr)
	}

	status := "connected"
	errMsg := ""
	if syncErr != nil {
		status = "error"
		errMsg = syncErr.Error()
		e.logger.Warn("cloud sync failed", "provider", conn.Provider, "id", conn.ID, "err", syncErr)
	} else if ingested > 0 {
		e.logger.Info("cloud sync complete", "provider", conn.Provider, "id", conn.ID, "ingested", ingested)
	}

	e.db.UpdateCloudConnectorStatus(ctx, conn.ID, status, errMsg, int64(ingested), cursor)
	return syncErr
}

func (e *CloudConnectorEngine) doSync(ctx context.Context, conn *store.CloudConnector) (int, string, error) {
	switch conn.Provider {
	case "aws":
		return syncAWS(ctx, conn, e.db, e.eventDB, e.logger)
	case "azure":
		return syncAzure(ctx, conn, e.db, e.eventDB, e.logger)
	case "gcp":
		return syncGCP(ctx, conn, e.db, e.eventDB, e.logger)
	default:
		return 0, "", fmt.Errorf("unknown provider: %s", conn.Provider)
	}
}

func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return contains(msg, "invalid credentials") ||
		contains(msg, "auth failed") ||
		contains(msg, "401") ||
		contains(msg, "403") ||
		contains(msg, "Unauthorized") ||
		contains(msg, "Forbidden")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}

// CloudEvent is a normalized cloud event for insertion into the backend events table.
type CloudEvent struct {
	ID        string
	Time      time.Time
	AgentID   string
	Host      string
	OS        string
	EventType string
	Severity  int
	Source    string
	Username  string
	SrcIP     string
	Raw       json.RawMessage
}

// ingestCloudEvents bulk-inserts cloud events into the backend events table.
func ingestCloudEvents(ctx context.Context, db *store.DB, events []CloudEvent) (int, error) {
	if db == nil || len(events) == 0 {
		return 0, nil
	}
	inserted := 0
	for _, ev := range events {
		var srcIP interface{}
		if ev.SrcIP != "" {
			srcIP = ev.SrcIP
		}
		var username interface{}
		if ev.Username != "" {
			username = ev.Username
		}
		_, err := db.ExecContext(ctx, `
			INSERT INTO events (id, time, agent_id, host, os, event_type, severity, source, raw, user_name, src_ip)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
			ON CONFLICT (id, time) DO NOTHING`,
			ev.ID, ev.Time, ev.AgentID, ev.Host, ev.OS,
			ev.EventType, ev.Severity, ev.Source, ev.Raw,
			username, srcIP,
		)
		if err != nil {
			continue
		}
		inserted++
	}
	return inserted, nil
}
