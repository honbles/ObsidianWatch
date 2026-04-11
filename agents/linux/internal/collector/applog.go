//go:build linux

package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"time"

	"obsidianwatch/linux-agent/pkg/schema"
)

type AppLogConfig struct {
	Name      string
	Path      string
	Format    string // json | text
	EventType string
	Severity  int
}

type AppLogCollector struct {
	cfgs     []AppLogConfig
	stateDir string
	agentID  string
	hostname string
	out      chan<- schema.Event
	logger   *slog.Logger
}

func NewAppLogCollector(cfgs []AppLogConfig, stateDir, agentID, hostname string, out chan<- schema.Event, logger *slog.Logger) *AppLogCollector {
	return &AppLogCollector{cfgs: cfgs, stateDir: stateDir, agentID: agentID, hostname: hostname, out: out, logger: logger}
}

func (c *AppLogCollector) Run(ctx context.Context) error {
	for _, cfg := range c.cfgs {
		go c.tailFile(ctx, cfg)
	}
	<-ctx.Done()
	return nil
}

func (c *AppLogCollector) tailFile(ctx context.Context, cfg AppLogConfig) {
	f, err := os.Open(cfg.Path)
	if err != nil {
		c.logger.Warn("applog: cannot open", "path", cfg.Path, "err", err)
		return
	}
	defer f.Close()

	// Seek to end
	f.Seek(0, io.SeekEnd)

	c.logger.Info("applog: tailing", "name", cfg.Name, "path", cfg.Path)
	reader := bufio.NewReader(f)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				time.Sleep(250 * time.Millisecond)
				continue
			}
			return
		}

		c.emitLine(cfg, line)
	}
}

func (c *AppLogCollector) emitLine(cfg AppLogConfig, line string) {
	evType := schema.EventTypeAppLog
	if cfg.EventType != "" {
		evType = schema.EventType(cfg.EventType)
	}
	sev := schema.Severity(cfg.Severity)
	if sev == 0 {
		sev = schema.SeverityInfo
	}

	var raw json.RawMessage
	if cfg.Format == "json" {
		raw = json.RawMessage(line)
	} else {
		b, _ := json.Marshal(map[string]string{"message": line, "source": cfg.Name})
		raw = b
	}

	ev := schema.Event{
		ID:        newID(),
		Time:      time.Now().UTC(),
		AgentID:   c.agentID,
		Host:      c.hostname,
		OS:        "linux",
		EventType: evType,
		Severity:  sev,
		Source:    "applog/" + cfg.Name,
		Raw:       raw,
		Channel:   cfg.Name,
	}
	select {
	case c.out <- ev:
	default:
	}
}
