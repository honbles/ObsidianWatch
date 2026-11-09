package forwarder

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"obsidianwatch/network-probe/pkg/schema"
)

func testFwd() *Forwarder {
	return &Forwarder{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func mkEvents(n int) []schema.ProbeEvent { return make([]schema.ProbeEvent, n) }

func TestFlushChunksBoundsBatchSize(t *testing.T) {
	var sizes []int
	rest := testFwd().flushChunks(context.Background(), mkEvents(1234), func(_ context.Context, b []schema.ProbeEvent) error {
		sizes = append(sizes, len(b))
		return nil
	})
	if len(rest) != 0 || len(sizes) != 3 || sizes[0] != 500 || sizes[2] != 234 {
		t.Fatalf("rest=%d sizes=%v", len(rest), sizes)
	}
}

func TestFlushChunksRetriesTransientKeepsUnsent(t *testing.T) {
	calls := 0
	rest := testFwd().flushChunks(context.Background(), mkEvents(1200), func(context.Context, []schema.ProbeEvent) error {
		calls++
		if calls == 2 {
			return errors.New("backend returned 503")
		}
		return nil
	})
	if len(rest) != 700 { // first 500 sent, 700 left to retry
		t.Fatalf("rest = %d, want 700", len(rest))
	}
}

func TestFlushChunksDropsPermanentRejection(t *testing.T) {
	calls := 0
	rest := testFwd().flushChunks(context.Background(), mkEvents(1000), func(context.Context, []schema.ProbeEvent) error {
		calls++
		if calls == 1 {
			return errPermanent{code: 413}
		}
		return nil
	})
	if len(rest) != 0 || calls != 2 {
		t.Fatalf("rest=%d calls=%d", len(rest), calls)
	}
}
