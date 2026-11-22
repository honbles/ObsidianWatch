package otel

// service.go - wires receiver, aggregator, binder and sender together.

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"obsidianwatch/macos-agent/pkg/schema"
)

// Options is everything the service needs; main maps agent config onto it.
type Options struct {
	AgentID  string
	Hostname string

	Receiver ReceiverOptions
	Sender   SenderOptions
	Agg      AggOptions

	UserHashKey       string
	CleartextServices []string          // "name|env" (or "name") that opted into cleartext user ids
	ClientIPDefault   string            // full | truncated | off
	ClientIPByService map[string]string // "name|env" (or "name") overrides

	FlushInterval  time.Duration
	ConfigInterval time.Duration // how often per-service settings are pulled (default 5 minutes)
	Resolver       PeerResolver
	// Emit hands an event to the agent's NORMAL event channel. Required.
	Emit   func(schema.Event) bool
	Logger *slog.Logger
}

// Service is the running application-monitoring OTLP path.
type Service struct {
	opt  Options
	Recv *Receiver
	Agg  *Aggregator
	Send *Sender
	Live *liveSettings
}

func lookupMode(m map[string]string, def, svc, env string) string {
	if v, ok := m[svc+"|"+env]; ok {
		return v
	}
	if v, ok := m[svc]; ok {
		return v
	}
	return def
}

// New builds the service; it does not start listening until Run.
func New(opt Options) (*Service, error) {
	if opt.Emit == nil {
		return nil, errors.New("otel: Emit is required (events must use the agent's normal channel)")
	}
	if opt.Logger == nil {
		opt.Logger = slog.Default()
	}
	if opt.FlushInterval <= 0 {
		opt.FlushInterval = 30 * time.Second
	}
	if opt.ClientIPDefault == "" {
		opt.ClientIPDefault = ClientIPFull
	}
	if opt.Resolver == nil {
		opt.Resolver = NewPeerResolver()
	}
	hasher := NewHasher(opt.UserHashKey)
	if !hasher.Enabled() {
		opt.Logger.Warn("app monitoring: no user_hash_key configured; user identifiers will not be sent")
	}
	if opt.ConfigInterval <= 0 {
		opt.ConfigInterval = 5 * time.Minute
	}
	clear := map[string]bool{}
	for _, s := range opt.CleartextServices {
		clear[s] = true
	}
	live := newLiveSettings()
	// The build configuration is a floor: the stricter client-address mode wins (see remoteconfig.go).
	ipMode := func(svc, env string) string {
		build := lookupMode(opt.ClientIPByService, opt.ClientIPDefault, svc, env)
		if rs, ok := live.get(svc, env); ok && rs.StoreClientIP != "" {
			return stricterMode(build, rs.StoreClientIP)
		}
		return build
	}
	ec := EventContext{
		AgentID: opt.AgentID, Host: opt.Hostname, Hasher: hasher, IPMode: ipMode,
		ClearTxt: func(svc, env string) bool {
			if rs, ok := live.get(svc, env); ok {
				return rs.CleartextUsers // pulled settings are authoritative when present
			}
			return clear[svc+"|"+env] || clear[svc]
		},
	}
	opt.Agg.IPMode = ipMode
	opt.Agg.PayloadFn = live.payloadFor
	opt.Agg.SlowFn = func(svc, env string) int {
		if rs, ok := live.get(svc, env); ok && rs.LatencyTargetMs > 0 {
			return rs.LatencyTargetMs
		}
		return 0
	}
	opt.Agg.DBStmtFn = func(svc, env string) string {
		if rs, ok := live.get(svc, env); ok && !rs.PolicyOnly {
			return rs.DBStatementMode
		}
		return "off"
	}
	agg := NewAggregator(opt.Agg, nil)
	snd, err := NewSender(opt.Sender, agg.Requeue, opt.Logger)
	if err != nil {
		return nil, err
	}
	recv := NewReceiver(opt.Receiver, agg, NewBinder(), opt.Resolver, ec, opt.Emit, opt.Logger)
	return &Service{opt: opt, Recv: recv, Agg: agg, Send: snd, Live: live}, nil
}

// Run starts the receiver and the flush loop and blocks until ctx is cancelled.
func (s *Service) Run(ctx context.Context) error {
	if err := s.Recv.Start(ctx); err != nil {
		return err
	}
	if !s.Recv.OnlyLocal() {
		return errors.New("otel: receiver is reachable beyond loopback; refusing to run")
	}
	go s.pollConfig(ctx)
	sendCtx, stopSend := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Send.Run(sendCtx); close(done) }()

	t := time.NewTicker(s.opt.FlushInterval)
	defer t.Stop()
	flush := func(final bool) {
		b := s.Agg.Flush(s.opt.AgentID, final)
		if b == nil {
			return
		}
		for _, part := range b.Split() {
			s.Send.Send(part)
		}
	}
	for {
		select {
		case <-t.C:
			flush(false)
		case <-ctx.Done():
			flush(true)
			stopSend() // Sender drains its queue with short timeouts
			<-done
			return nil
		}
	}
}

// pollConfig pulls per-service settings: soon after start, then periodically; a failure is
// retried sooner. Until the first success the build configuration alone applies.
func (s *Service) pollConfig(ctx context.Context) {
	wait := 2 * time.Second
	failing := false
	for {
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return
		}
		fctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		list, err := s.Send.FetchConfig(fctx, s.opt.AgentID)
		cancel()
		if err != nil {
			if !failing {
				s.opt.Logger.Warn("app monitoring: could not pull service settings; using build configuration", "err", err)
			}
			failing, wait = true, 30*time.Second
			continue
		}
		if failing {
			s.opt.Logger.Info("app monitoring: service settings pulled again")
		}
		failing, wait = false, s.opt.ConfigInterval
		s.Live.set(list, time.Now())
	}
}

// AddDiscovered feeds host-discovered instances (from the host sensor) into the next batch.
func (s *Service) AddDiscovered(list []BatchInstance) { s.Agg.AddDiscovered(list) }

// InstrumentedPIDs returns the pids of instrumented services (for the host sensor's watch set).
func (s *Service) InstrumentedPIDs() []int { return s.Agg.PIDs() }
