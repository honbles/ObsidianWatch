package store

import (
	"context"
	"time"

	"github.com/lib/pq"
)

// EventsChannel matches the channel the ingest backend notifies after each
// inserted batch (backend/internal/store/events.go).
const EventsChannel = "ow_events"

// ListenEvents calls wake (without blocking) whenever the ingest backend
// reports new events, until ctx ends. It reconnects on its own; a lost
// notification only means the caller's poll picks the events up instead.
func (db *DB) ListenEvents(ctx context.Context, wake chan<- struct{}) error {
	if db.dsn == "" {
		return nil
	}
	l := pq.NewListener(db.dsn, time.Second, time.Minute, func(ev pq.ListenerEventType, err error) {
		if err != nil && db.logger != nil {
			db.logger.Debug("events listener", "event", ev, "err", err)
		}
	})
	defer l.Close()
	if err := l.Listen(EventsChannel); err != nil {
		return err
	}
	ping := time.NewTicker(90 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-l.Notify: // nil after a reconnect: wake anyway, events may have arrived
			select {
			case wake <- struct{}{}:
			default:
			}
		case <-ping.C:
			go l.Ping()
		}
	}
}

// NotifyEventsInserted wakes the detection engine after the management server
// itself writes events (cloud and DevOps connectors, webhooks), so they are
// evaluated as quickly as agent events instead of on the next poll.
func (db *DB) NotifyEventsInserted(ctx context.Context) {
	_, _ = db.ExecContext(ctx, `SELECT pg_notify($1, '')`, EventsChannel)
}
