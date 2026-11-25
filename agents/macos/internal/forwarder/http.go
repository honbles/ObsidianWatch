package forwarder

// http.go - batched HTTP/2 forwarder authenticated by the agent certificate.
// Events are read from the local Queue and POSTed to the backend ingest API.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"obsidianwatch/macos-agent/pkg/schema"

	"obsidianwatch/macos-agent/internal/identity"
)

// HTTPForwarder reads from the Queue and delivers batches to the backend.
type HTTPForwarder struct {
	cfg      ForwarderConfig
	queue    *Queue
	client   *http.Client
	retry    RetryPolicy
	logger   *slog.Logger
	agentID  string
	hostname string
	mu       sync.Mutex
	cur      int // current batch size; halves on 413 and grows back
	// DepthSink, when set, receives the queue depth every 30 s (health events).
	DepthSink func(int64)
	ver       string
}

// ForwarderConfig holds transport configuration.
type ForwarderConfig struct {
	InstallKey    string
	BackendURL    string
	BatchSize     int
	FlushInterval time.Duration
	// mTLS
	CertFile  string
	KeyFile   string
	CAFile    string
	CACertPEM string
}

// NewHTTPForwarder creates the forwarder and builds the TLS-aware HTTP client.
func NewHTTPForwarder(cfg ForwarderConfig, queue *Queue, agentID, hostname, ver string, logger *slog.Logger) (*HTTPForwarder, error) {
	client, err := buildHTTPClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("forwarder: build client: %w", err)
	}

	return &HTTPForwarder{
		cfg:      cfg,
		queue:    queue,
		client:   client,
		retry:    DefaultRetryPolicy(),
		logger:   logger,
		agentID:  agentID,
		hostname: hostname,
		ver:      ver,
	}, nil
}

// Run starts the flush loop until ctx is cancelled.
func (f *HTTPForwarder) Run(ctx context.Context) error {
	ticker := time.NewTicker(f.cfg.FlushInterval)
	defer ticker.Stop()

	f.logger.Info("forwarder: started", "url", f.cfg.BackendURL)
	depth := time.NewTicker(30 * time.Second)
	defer depth.Stop()
	if f.DepthSink != nil {
		f.DepthSink(f.QueueDepth())
	}

	for {
		select {
		case <-ctx.Done():
			// Drain remaining events before shutting down.
			f.flush(context.Background())
			return nil
		case <-ticker.C:
			f.flush(ctx)
		case <-depth.C:
			if f.DepthSink != nil {
				f.DepthSink(f.QueueDepth())
			}
		}
	}
}

// SendFinal (D-12) transmits one last event synchronously as the agent shuts
// down - typically "agent.tamper" (stop requested / signal received) - so the
// server sees a stop/uninstall attempt before the agent dies. It bypasses the
// queue ordering, waits at most 5 seconds, and falls back to the local queue
// if the backend is unreachable.
func (f *HTTPForwarder) SendFinal(ev schema.Event) {
	ev.AgentID = f.agentID
	ev.Host = f.hostname
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	batch := schema.Batch{
		AgentID:    f.agentID,
		Hostname:   f.hostname,
		AgentVer:   f.ver,
		InstallKey: f.cfg.InstallKey,
		SentAt:     time.Now().UTC(),
		Events:     []schema.Event{ev},
	}
	if err := f.send(ctx, batch); err != nil {
		f.logger.Warn("forwarder: final event send failed, queued locally", "err", err)
		f.Enqueue([]schema.Event{ev})
	}
}

// Enqueue pushes events into the local queue (non-blocking path from collectors).
func (f *HTTPForwarder) Enqueue(events []schema.Event) {
	if err := f.queue.Push(events); err != nil {
		f.logger.Error("forwarder: enqueue failed", "err", err)
	}
}

// maxBatchesPerTick bounds one flush so a large backlog drains steadily
// without starving shutdown.
const maxBatchesPerTick = 50

// flush sends queued batches until the queue is empty, a send fails, or
// maxBatchesPerTick batches went out. Events leave the queue only after the
// backend accepted them.
func (f *HTTPForwarder) flush(ctx context.Context) {
	for i := 0; i < maxBatchesPerTick; i++ {
		if !f.flushOne(ctx) {
			return
		}
	}
}

// flushOne sends one batch and reports whether to keep going.
func (f *HTTPForwarder) flushOne(ctx context.Context) bool {
	size := f.batchSize()
	events, rc, err := f.queue.Peek(size)
	if err != nil {
		f.logger.Error("forwarder: queue read failed", "err", err)
		return false
	}
	if len(events) == 0 {
		if len(rc.takes) > 0 { // only unreadable lines: drop them
			_ = f.queue.Ack(rc)
			return true
		}
		return false
	}
	// Everything in this queue was collected on this host. Events queued
	// under an earlier identity (before a reinstall or re-enrollment) are
	// sent under the current one.
	for i := range events {
		events[i].AgentID = f.agentID
	}
	batch := schema.Batch{
		AgentID:    f.agentID,
		Hostname:   f.hostname,
		AgentVer:   f.ver,
		InstallKey: f.cfg.InstallKey,
		SentAt:     time.Now().UTC(),
		Events:     events,
	}
	err = f.retry.Do(ctx, func() error { return f.send(ctx, batch) })
	var he *httpStatusError
	switch {
	case err == nil:
		if aerr := f.queue.Ack(rc); aerr != nil {
			// The batch was delivered; it will be sent again and the
			// backend drops the duplicates by event id.
			f.logger.Error("forwarder: ack failed", "err", aerr)
			return false
		}
		f.grow()
		f.logger.Debug("forwarder: sent batch", "count", len(events))
		return true
	case errors.As(err, &he) && len(events) > 1 && (he.code == http.StatusRequestEntityTooLarge ||
		he.code == http.StatusBadRequest || he.code == http.StatusUnprocessableEntity):
		// Too large, or one bad event spoils the batch: halve until the bad
		// event is alone, so only it is dropped.
		f.shrink(len(events))
		f.logger.Warn("forwarder: batch refused, sending smaller batches", "events", len(events), "status", he.code)
		return true
	case errors.As(err, &he) && (he.code == http.StatusBadRequest || he.code == http.StatusUnprocessableEntity ||
		he.code == http.StatusRequestEntityTooLarge):
		// The backend will never accept this event: keeping it would block
		// every event behind it.
		f.logger.Error("forwarder: backend refused an event permanently, dropping it",
			"id", events[0].ID, "type", events[0].EventType, "status", he.code)
		_ = f.queue.Ack(rc)
		return true
	default:
		// Network errors, 5xx and 429 after retries, and 401/403 (identity
		// not yet renewed or revoked) leave the batch queued for next time.
		f.logger.Error("forwarder: send failed; events stay queued",
			"events", len(events), "err", err)
		return false
	}
}

func (f *HTTPForwarder) batchSize() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cur <= 0 || f.cur > f.cfg.BatchSize {
		f.cur = f.cfg.BatchSize
	}
	if f.cur <= 0 {
		f.cur = 500
	}
	return f.cur
}

func (f *HTTPForwarder) shrink(n int) {
	f.mu.Lock()
	f.cur = max(1, n/2)
	f.mu.Unlock()
}

func (f *HTTPForwarder) grow() {
	f.mu.Lock()
	if f.cur < f.cfg.BatchSize {
		f.cur = min(f.cfg.BatchSize, f.cur*2)
	}
	f.mu.Unlock()
}

// QueueDepth is the number of events waiting to be sent.
func (f *HTTPForwarder) QueueDepth() int64 {
	n, _ := f.queue.Len()
	return n
}

// httpStatusError is a non-2xx answer from the backend.
type httpStatusError struct{ code int }

func (e *httpStatusError) Error() string { return fmt.Sprintf("HTTP %d", e.code) }

// Retryable lets RetryPolicy stop early on answers retrying cannot fix.
func (e *httpStatusError) Retryable() bool { return IsRetryable(e.code) }

// send serialises the batch and POSTs it to the backend.
func (f *HTTPForwarder) send(ctx context.Context, batch schema.Batch) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		f.cfg.BackendURL+"/api/v1/events", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "obsidianwatch-agent/"+f.ver)

	resp, err := f.client.Do(req)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated ||
		resp.StatusCode == http.StatusNoContent {
		return nil
	}

	return &httpStatusError{code: resp.StatusCode}
}

// ---------------------------------------------------------------------------
// TLS helpers
// ---------------------------------------------------------------------------

func buildHTTPClient(cfg ForwarderConfig) (*http.Client, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	// Load client certificate for mTLS.
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	// Load CA cert - prefer inline PEM (embedded binary), fall back to file path.
	var caPEM []byte
	switch {
	case cfg.CACertPEM != "":
		caPEM = []byte(cfg.CACertPEM)
	case cfg.CAFile != "":
		var err error
		caPEM, err = os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
	}
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("parse CA cert: invalid PEM")
		}
		tlsCfg.RootCAs = pool
	}

	// Every connection presents the agent's enrolled certificate.
	identity.ApplyActive(tlsCfg)
	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
		// HTTP/2 is automatically negotiated via ALPN when TLS is present.
		ForceAttemptHTTP2: true,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}, nil
}
