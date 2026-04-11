package forwarder

// http.go — forwards probe events to the management backend
// Uses the same batch format as endpoint agents so the backend needs
// zero changes to receive network probe data.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"obsidianwatch/network-probe/internal/config"
	"obsidianwatch/network-probe/pkg/schema"
)

type Forwarder struct {
	cfg     config.ForwarderConfig
	probeID string
	host    string
	ver     string
	client  *http.Client
	logger  *slog.Logger

	mu     sync.Mutex
	buffer []schema.ProbeEvent
}

func New(cfg config.ForwarderConfig, probeID, host, ver string, logger *slog.Logger) (*Forwarder, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}

	if cfg.CACertPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.CACertPEM)) {
			return nil, fmt.Errorf("forwarder: invalid CA cert PEM")
		}
		tlsCfg.RootCAs = pool
	}

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   30 * time.Second,
	}

	return &Forwarder{
		cfg: cfg, probeID: probeID, host: host, ver: ver,
		client: client, logger: logger,
		buffer: make([]schema.ProbeEvent, 0, cfg.BatchSize),
	}, nil
}

func (f *Forwarder) Enqueue(ev schema.ProbeEvent) {
	f.mu.Lock()
	f.buffer = append(f.buffer, ev)
	shouldFlush := len(f.buffer) >= f.cfg.BatchSize
	f.mu.Unlock()
	if shouldFlush {
		go f.Flush(context.Background())
	}
}

func (f *Forwarder) Run(ctx context.Context, in <-chan schema.ProbeEvent) {
	interval, err := time.ParseDuration(f.cfg.FlushInterval)
	if err != nil {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			f.Flush(context.Background())
			return
		case ev, ok := <-in:
			if !ok {
				return
			}
			f.Enqueue(ev)
		case <-ticker.C:
			if f.pending() > 0 {
				f.Flush(ctx)
			}
		}
	}
}

func (f *Forwarder) pending() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.buffer)
}

func (f *Forwarder) Flush(ctx context.Context) {
	f.mu.Lock()
	if len(f.buffer) == 0 {
		f.mu.Unlock()
		return
	}
	batch := make([]schema.ProbeEvent, len(f.buffer))
	copy(batch, f.buffer)
	f.buffer = f.buffer[:0]
	f.mu.Unlock()

	if err := f.send(ctx, batch); err != nil {
		f.logger.Warn("forwarder: send failed", "events", len(batch), "err", err)
		// Re-queue on failure (simple retry)
		f.mu.Lock()
		f.buffer = append(batch, f.buffer...)
		if len(f.buffer) > 50000 {
			f.buffer = f.buffer[len(f.buffer)-50000:] // cap buffer
		}
		f.mu.Unlock()
	} else {
		f.logger.Debug("forwarder: sent", "events", len(batch))
	}
}

func (f *Forwarder) send(ctx context.Context, events []schema.ProbeEvent) error {
	batch := schema.EventBatch{
		AgentID:  f.probeID,
		Hostname: f.host,
		AgentVer: f.ver,
		Events:   events,
	}
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}

	url := f.cfg.BackendURL + "/api/v1/ingest"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Key", f.cfg.APIKey)

	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("backend returned %d", resp.StatusCode)
	}
	return nil
}

// SendDeviceInventory sends all known devices as a summary event
func (f *Forwarder) SendDeviceInventory(ctx context.Context, devices interface{}) {
	raw, _ := json.Marshal(devices)
	f.Enqueue(schema.ProbeEvent{
		ID:        fmt.Sprintf("inv:%s:%d", f.probeID, time.Now().Unix()),
		Time:      time.Now().UTC(),
		AgentID:   f.probeID,
		Host:      f.host,
		OS:        "network-probe",
		EventType: schema.EventDeviceSeen,
		Severity:  schema.SevInfo,
		Source:    "inventory",
		Raw:       raw,
	})
}

// SendInventory sends device inventory + ARP table + topology as a single event
func (f *Forwarder) SendInventory(ctx context.Context, devices interface{}, arp interface{}, topology interface{}) {
	raw, _ := json.Marshal(map[string]interface{}{
		"devices":  devices,
		"arp":      arp,
		"topology": topology,
		"ts":       time.Now().UTC(),
	})
	f.Enqueue(schema.ProbeEvent{
		ID:        fmt.Sprintf("inventory:%s:%d", f.probeID, time.Now().Unix()),
		Time:      time.Now().UTC(),
		AgentID:   f.probeID,
		Host:      f.host,
		OS:        "network-probe",
		EventType: "net.inventory",
		Severity:  1,
		Source:    "probe",
		Raw:       raw,
	})
}
