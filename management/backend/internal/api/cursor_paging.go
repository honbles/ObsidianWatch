package api

import (
	"context"
	"time"

	"obsidianwatch/management/internal/store"
)

// cursorSafetyMargin accounts for events whose INSERT started before this
// poll's query ran but committed after it — without a small margin, a
// cursor advanced all the way to "now" on an empty poll could jump past
// such a row and it would never be picked up by a later poll either.
const cursorSafetyMargin = 2 * time.Second

// pageEventCursor (D-01/D-02) is the shared replacement for the old
// "evaluateSince(ctx, time.Now().Add(-N))" wall-clock polling pattern used
// by most engines. It pages events.ingested_at forward from a persisted
// per-engine cursor instead of a fixed lookback window, so a burst of
// events, a slow processing pass, or an agent that reconnects and flushes
// a backlog can never fall outside the window and get silently skipped —
// every row is seen by exactly one poll, in ingested_at order.
//
// On an engine's first-ever run (no cursor row yet), it falls back to
// initialLookback so there's still a bounded catch-up rather than
// replaying the entire table. The cursor advances even when zero events
// are found, so AdvanceEngineCursor's updated_at also works as a
// liveness heartbeat (used by the D-11 agent/engine health check to
// detect a stalled engine).
func pageEventCursor(ctx context.Context, db *store.DB, engineName string, base store.EventFilter, initialLookback time.Duration, pageLimit int) ([]store.Event, error) {
	cursor, err := db.GetEngineCursor(ctx, engineName)
	if err != nil {
		return nil, err
	}
	if cursor.IsZero() {
		cursor = time.Now().Add(-initialLookback)
	}

	f := base
	f.IngestedAfter = cursor
	f.SkipCount = true
	// D-08: these are freshly-ingested events the normalizer already
	// populated structured columns for — the per-row raw-JSON unmarshal
	// in enrichFromRaw is wasted work for every engine that pages through
	// here on every tick.
	f.SkipEnrich = true
	if pageLimit <= 0 {
		pageLimit = 5000
	}
	f.Limit = pageLimit

	events, _, err := db.QueryEvents(ctx, f)
	if err != nil {
		return nil, err
	}

	var newCursor time.Time
	pageFull := len(events) >= pageLimit
	if pageFull {
		// There may be more rows past this page — advance only to the
		// last row we actually saw, never past it, so the next poll
		// picks up exactly where this one stopped.
		newCursor = events[len(events)-1].IngestedAt
	} else {
		// We drained everything currently available. It's safe to advance
		// up to "now minus a small safety margin" — the margin covers a
		// transaction that started before our query ran but hadn't
		// committed (and so wasn't visible) yet.
		newCursor = time.Now().Add(-cursorSafetyMargin)
		if len(events) > 0 {
			if last := events[len(events)-1].IngestedAt; last.After(newCursor) {
				newCursor = last
			}
		}
	}
	if newCursor.After(cursor) {
		if err := db.AdvanceEngineCursor(ctx, engineName, newCursor); err != nil {
			return events, err
		}
	}
	return events, nil
}
