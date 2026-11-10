// obsidianwatch-agent — Windows security event collection agent.
//
// Usage:
//   agent.exe install    # install as Windows service (config embedded in binary)
//   agent.exe uninstall  # remove service
//   agent.exe            # run interactively (dev/debug)

//go:build windows

package main

import (
	"crypto/subtle"
	"encoding/json"
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"obsidianwatch/agent/internal/collector"
	"obsidianwatch/agent/internal/config"
	"obsidianwatch/agent/internal/forwarder"
	"obsidianwatch/agent/internal/ownproc"
	"obsidianwatch/agent/internal/parser"
	sysmonpkg "obsidianwatch/agent/internal/sysmon"
	"obsidianwatch/agent/pkg/schema"
)

const (
	serviceName        = "ObsidianWatchAgent"
	serviceDisplayName = "ObsidianWatch Security Agent"
	serviceDescription = "Collects Windows security events and forwards them to the ObsidianWatch backend."
)

func main() {
	// Config is embedded in the binary at compile time by the Agent Builder.
	// Just run: agent.exe install   or   agent.exe uninstall
	flag.Parse()

	isService, err := svc.IsWindowsService()
	if err != nil {
		fmt.Fprintf(os.Stderr, "svc.IsWindowsService: %v\n", err)
		os.Exit(1)
	}

	// Handle install / uninstall verbs — always in interactive context.
	if flag.NArg() > 0 {
		if err := handleCommand(flag.Arg(0)); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	cfg, err := config.LoadEmbedded("agent.yaml")
	if err != nil {
		msg := fmt.Sprintf("ObsidianWatch agent: config load failed: %v\n", err)
		fmt.Fprint(os.Stderr, msg)
		if exeDir, e2 := filepath.Abs(filepath.Dir(os.Args[0])); e2 == nil {
			_ = os.WriteFile(filepath.Join(exeDir, "agent-error.log"), []byte(msg), 0644)
		}
		os.Exit(1)
	}

	logger := buildLogger(cfg.Log.Level, cfg.Log.Format)

	if isService {
		os.MkdirAll(`C:\ProgramData\ObsidianWatch`, 0700)
		hardenDataDir()
		if f, err := os.OpenFile(`C:\ProgramData\ObsidianWatch\agent.log`,
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
			fmt.Fprintf(f, `{"time":"%s","level":"INFO","msg":"main: starting as Windows service"}`+"\n",
				time.Now().Format(time.RFC3339))
			f.Close()
		}
		if err := svc.Run(serviceName, &agentService{cfg: cfg, logger: logger}); err != nil {
			logger.Error("service run failed", "err", err)
			os.Exit(1)
		}
		return
	}

	enableAuditPolicies(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger.Info("obsidianwatch-agent starting (interactive)", "version", cfg.Agent.Version)
	if err := run(ctx, cfg, logger); err != nil {
		logger.Error("agent exited with error", "err", err)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// agentService implements svc.Handler for the Windows service manager.
// ---------------------------------------------------------------------------

type agentService struct {
	cfg    *config.Config
	logger *slog.Logger
}

func (s *agentService) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	status <- svc.Status{State: svc.StartPending}

	// Write startup marker directly to log file — before anything else
	// so we know Execute() was reached even if run() panics.
	os.MkdirAll(`C:\ProgramData\ObsidianWatch`, 0700)
	hardenDataDir()
	if f, err := os.OpenFile(`C:\ProgramData\ObsidianWatch\agent.log`,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
		fmt.Fprintf(f, `{"time":"%s","level":"INFO","msg":"service Execute() started"}`+"\n",
			time.Now().Format(time.RFC3339))
		f.Close()
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		defer func() {
			if r := recover(); r != nil {
				msg := fmt.Sprintf(`{"time":"%s","level":"ERROR","msg":"agent panic","err":"%v"}`+"\n",
					time.Now().Format(time.RFC3339), r)
				if f, err := os.OpenFile(`C:\ProgramData\ObsidianWatch\agent.log`,
					os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
					f.WriteString(msg)
					f.Close()
				}
			}
		}()
		// Write pre-run marker directly to file
		if f, err := os.OpenFile(`C:\ProgramData\ObsidianWatch\agent.log`,
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
			fmt.Fprintf(f, `{"time":"%s","level":"INFO","msg":"goroutine: calling run()"}`+"\n",
				time.Now().Format(time.RFC3339))
			f.Close()
		}
		if err := run(ctx, s.cfg, s.logger); err != nil {
			msg := fmt.Sprintf(`{"time":"%s","level":"ERROR","msg":"run() returned error","err":"%v"}`+"\n",
				time.Now().Format(time.RFC3339), err)
			if f, ferr := os.OpenFile(`C:\ProgramData\ObsidianWatch\agent.log`,
				os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); ferr == nil {
				f.WriteString(msg)
				f.Close()
			}
			s.logger.Error("agent run error", "err", err)
		} else {
			if f, err := os.OpenFile(`C:\ProgramData\ObsidianWatch\agent.log`,
				os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
				fmt.Fprintf(f, `{"time":"%s","level":"INFO","msg":"run() returned nil (clean exit)"}`+"\n",
					time.Now().Format(time.RFC3339))
				f.Close()
			}
		}
	}()

	status <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			status <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			cancel()
			// Give collectors up to 10 s to flush.
			time.Sleep(10 * time.Second)
			return false, 0
		}
	}

	cancel()
	return false, 0
}

// ---------------------------------------------------------------------------
// run wires up all subsystems and runs until ctx is cancelled.
// ---------------------------------------------------------------------------

func run(ctx context.Context, cfg *config.Config, logger *slog.Logger) error {
	// Write directly to log file first — before anything else in run()
	logStep := func(msg string) {
		if f, err := os.OpenFile(`C:\ProgramData\ObsidianWatch\agent.log`,
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
			fmt.Fprintf(f, `{"time":"%s","level":"INFO","msg":"step: %s"}`+"\n",
				time.Now().Format(time.RFC3339), msg)
			f.Close()
		}
	}
	if f, err := os.OpenFile(`C:\ProgramData\ObsidianWatch\agent.log`,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
		fmt.Fprintf(f, `{"time":"%s","level":"INFO","msg":"run() entered","version":"%s"}`+"\n",
			time.Now().Format(time.RFC3339), cfg.Agent.Version)
		f.Close()
	}

	// Ensure required directories exist before any subsystem tries to use them.
	// This means the user never has to create folders manually.
	dirsToCreate := []string{
		`C:\Program Files\ObsidianWatch\Agent\certs`,
		`C:\ProgramData\ObsidianWatch`,
	}
	if cfg.Queue.DBPath != "" {
		dirsToCreate = append(dirsToCreate, filepath.Dir(cfg.Queue.DBPath))
	}
	for _, d := range dirsToCreate {
		if err := os.MkdirAll(d, 0755); err != nil {
			logger.Warn("could not create directory", "path", d, "err", err)
		}
	}
	logStep("dirs created")

	// Ensure required Windows services are running before starting collectors.
	ensureWindowsServices(logger)
	logStep("windows services checked")

	// Resolve host metadata once.
	agentID := cfg.Agent.ID
	if agentID == "" {
		h, _ := os.Hostname()
		agentID = h
	}
	hostInfo := parser.ResolveHostInfo(agentID, cfg.Agent.Version)
	logStep("host info resolved: " + agentID)

	// Pipeline channel: collectors → normaliser/enricher → forwarder
	eventCh := make(chan schema.Event, 4096)

	// --- Queue (offline buffer) ---
	q, err := forwarder.NewQueue(cfg.Queue.DBPath, cfg.Queue.MaxRows, logger)
	if err != nil {
		logStep("queue init FAILED: " + err.Error())
		return fmt.Errorf("queue init: %w", err)
	}
	logStep("queue init OK: " + cfg.Queue.DBPath)
	defer q.Close()

	// --- Forwarder ---
	// Cert paths in the embedded config are relative to the executable location.
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	resolveRelative := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(exeDir, p)
	}
	fwdCfg := forwarder.ForwarderConfig{
		InstallKey:    cfg.Forwarder.InstallKey,
		BackendURL:    cfg.Forwarder.BackendURL,
		BatchSize:     cfg.Forwarder.BatchSize,
		FlushInterval: cfg.Forwarder.FlushInterval,
		CertFile:      resolveRelative(cfg.Forwarder.CertFile),
		KeyFile:       resolveRelative(cfg.Forwarder.KeyFile),
		CAFile:        resolveRelative(cfg.Forwarder.CAFile),
		CACertPEM:     cfg.Forwarder.CACertPEM,
		APIKey:        cfg.Forwarder.APIKey,
	}
	caInfo := fwdCfg.CAFile
	if caInfo == "" && fwdCfg.CACertPEM != "" {
		caInfo = "(embedded PEM, " + fmt.Sprintf("%d", len(fwdCfg.CACertPEM)) + " bytes)"
	}
	logStep("forwarder config built: backend=" + fwdCfg.BackendURL + " ca=" + caInfo)
	fwd, err := forwarder.NewHTTPForwarder(fwdCfg, q, agentID, hostInfo.Hostname, cfg.Agent.Version, logger)
	if err != nil {
		logStep("forwarder init FAILED: " + err.Error())
		return fmt.Errorf("forwarder init: %w", err)
	}
	logStep("forwarder init OK")

	// --- Normaliser + Enricher ---
	norm := parser.NewNormalizer(logger)
	enrch := parser.NewEnricher(hostInfo, logger)

	// Dispatcher goroutine: reads from eventCh, normalises, enriches, enqueues.
	go func() {
		buf := make([]schema.Event, 0, cfg.Forwarder.BatchSize)
		flush := func() {
			if len(buf) == 0 {
				return
			}
			buf = norm.NormalizeBatch(buf)
			enrch.EnrichBatch(buf)
			fwd.Enqueue(buf)
			buf = buf[:0]
		}
		ticker := time.NewTicker(cfg.Forwarder.FlushInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				flush()
				return
			case ev := <-eventCh:
				if ownproc.IsOwn(ev.PID, ev.PPID) {
					ev.Raw = ownproc.TagRaw(ev.Raw)
					ev.Severity = schema.SeverityInfo
				}
				buf = append(buf, ev)
				if len(buf) >= cfg.Forwarder.BatchSize {
					flush()
				}
			case <-ticker.C:
				flush()
			}
		}
	}()

	// --- Collectors ---
	logStep("starting collectors")
	errCh := make(chan error, 8)

	startCollector := func(name string, fn func(context.Context) error) {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					msg := fmt.Sprintf("collector PANIC: %s: %v", name, r)
					logStep(msg)
					logger.Error("collector: panic", "name", name, "err", r)
				}
			}()
			logger.Info("collector: starting", "name", name)
			logStep("collector starting: " + name)
			if err := fn(ctx); err != nil {
				logStep("collector error: " + name + ": " + err.Error())
				logger.Error("collector: error", "name", name, "err", err)
				errCh <- fmt.Errorf("%s: %w", name, err)
			} else {
				logStep("collector exited cleanly: " + name)
			}
		}()
	}

	// ── Rate limiter ─────────────────────────────────────────────────────
	// Sits between collectors and the dispatcher — wraps eventCh.
	var dispatchCh chan schema.Event
	if cfg.Collector.RateLimit.Enabled {
		rawCh := make(chan schema.Event, 4096)
		dispatchCh = rawCh
		// Replace eventCh with rawCh for all collectors below.
		// The rate limiter will forward allowed events into the original eventCh.
		rlCfg := collector.RateLimitConfig{
			MaxPerSecond: cfg.Collector.RateLimit.MaxPerSecond,
			DedupeWindow: cfg.Collector.RateLimit.DedupeWindow,
		}
		limiter := collector.NewRateLimiter(rlCfg)
		go collector.FilteredChannel(rawCh, eventCh, limiter)
		logger.Info("ratelimit: enabled", "max_per_sec", rlCfg.MaxPerSecond, "dedupe_window", rlCfg.DedupeWindow)
	} else {
		dispatchCh = eventCh
	}

	// Track active collector names for health reporting
	activeCollectors := []string{}

	if cfg.Collector.EventLog.Enabled {
		c := collector.NewEventLogCollector(
			cfg.Collector.EventLog.Channels,
			agentID, hostInfo.Hostname, dispatchCh, logger,
		)
		startCollector("eventlog", c.Run)
		activeCollectors = append(activeCollectors, "eventlog")
	}

	if cfg.Collector.Sysmon.Enabled {
		c := collector.NewSysmonCollector(agentID, hostInfo.Hostname, dispatchCh, logger)
		startCollector("sysmon", c.Run)
		activeCollectors = append(activeCollectors, "sysmon")
	}

	if cfg.Collector.Network.Enabled {
		c := collector.NewNetworkCollector(
			cfg.Collector.Network.PollInterval,
			agentID, hostInfo.Hostname, dispatchCh, logger,
		)
		startCollector("network", c.Run)
		activeCollectors = append(activeCollectors, "network")
	}

	if cfg.Collector.Process.Enabled {
		c := collector.NewProcessCollector(agentID, hostInfo.Hostname, dispatchCh, logger)
		startCollector("process", c.Run)
		activeCollectors = append(activeCollectors, "process")
	}

	if cfg.Collector.Registry.Enabled {
		c := collector.NewRegistryCollector(
			cfg.Collector.Registry.Keys,
			agentID, hostInfo.Hostname, dispatchCh, logger,
		)
		startCollector("registry", c.Run)
		activeCollectors = append(activeCollectors, "registry")
	}

	if cfg.Collector.DNS.Enabled {
		c := collector.NewDNSCollector(agentID, hostInfo.Hostname, dispatchCh, logger)
		startCollector("dns", c.Run)
		activeCollectors = append(activeCollectors, "dns")
	}

	if cfg.Collector.FIM.Enabled && len(cfg.Collector.FIM.Dirs) > 0 {
		fimDirs := make([]collector.FIMConfig, len(cfg.Collector.FIM.Dirs))
		for i, d := range cfg.Collector.FIM.Dirs {
			fimDirs[i] = collector.FIMConfig{
				Path:      d.Path,
				Recursive: d.Recursive,
				Exclude:   d.Exclude,
			}
		}
		c := collector.NewFIMCollector(fimDirs, agentID, hostInfo.Hostname, dispatchCh, logger)
		startCollector("fim", c.Run)
		activeCollectors = append(activeCollectors, "fim")
	}

	if len(cfg.Collector.AppLogs) > 0 {
		stateDir := filepath.Join(filepath.Dir(cfg.Queue.DBPath), "applog_state")
		if err := os.MkdirAll(stateDir, 0700); err != nil {
			logger.Warn("applog: could not create state dir", "dir", stateDir, "err", err)
		}
		appCfgs := make([]collector.AppLogConfig, len(cfg.Collector.AppLogs))
		for i, a := range cfg.Collector.AppLogs {
			appCfgs[i] = collector.AppLogConfig{
				Name:      a.Name,
				Path:      a.Path,
				Format:    a.Format,
				EventType: a.EventType,
				Severity:  a.Severity,
			}
		}
		c := collector.NewAppLogCollector(appCfgs, stateDir, agentID, hostInfo.Hostname, dispatchCh, logger)
		startCollector("applog", c.Run)
		activeCollectors = append(activeCollectors, "applog")
		logger.Info("applog: collector started", "files", len(appCfgs))
	}

	if cfg.Collector.Health.Enabled {
		c := collector.NewHealthReporter(
			cfg.Collector.Health.Interval,
			agentID, hostInfo.Hostname, cfg.Agent.Version,
			activeCollectors,
			eventCh, // health bypasses rate limiter — always send
			logger,
		)
		startCollector("health", c.Run)
	}

	// Vulnerability scanner — full TCP port scan every 5 days
	{
		vs := collector.NewVulnScanner(collector.VulnScannerConfig{
			Enabled:      true,
			ScanInterval: 5 * 24 * time.Hour,
			Concurrency:  50,
		}, agentID, hostInfo.Hostname, "windows", dispatchCh, logger)
		startCollector("vuln", func(c context.Context) error {
			vs.Run(c)
			return nil
		})
	}

	// ── Location collector ───────────────────────────────────────────────
	// Uses Windows Location API (GPS → WiFi → IP fallback), posts to backend.
	{
		c := collector.NewLocationCollector(
			30*time.Minute,
			agentID, hostInfo.Hostname,
			cfg.Forwarder.BackendURL, cfg.Forwarder.APIKey,
			resolveRelative(cfg.Forwarder.CAFile), cfg.Forwarder.CACertPEM,
			cfg.Forwarder.AllowInsecureTLS, cfg.Collector.LocationPrecisePositioning,
			eventCh, // bypasses rate limiter — location is low frequency
			logger,
		)
		startCollector("location", c.Run)
		activeCollectors = append(activeCollectors, "location")
	}

	// Live Response — analyst terminal access. H-2: opt-in only.
	if cfg.LiveResponse.Enabled {
		lr := collector.NewLiveResponseCollector(
			agentID, hostInfo.Hostname,
			cfg.Forwarder.ManagementURL,
			cfg.Forwarder.APIKey,
			cfg.Forwarder.CAFile,
			cfg.Forwarder.CAFile,
			cfg.Forwarder.AllowInsecureTLS,
			logger,
		)
		caPEM := cfg.Forwarder.ManagementCACertPEM
		if caPEM == "" {
			caPEM = cfg.Forwarder.CACertPEM
		}
		if caPEM != "" {
			lr.SetCAPEM(caPEM)
		}
		go func() { lr.Run(ctx) }()
		activeCollectors = append(activeCollectors, "live-response")
	}

	// [APP-COLLECTORS-BEGIN]
	// [APP-COLLECTORS-END]

	// Start the HTTP forwarder (reads from queue, not eventCh).
	go func() { errCh <- fwd.Run(ctx) }()

	logStep("all collectors launched — waiting for shutdown")
	<-ctx.Done()
	logger.Info("agent shutting down")
	// D-12: report the stop to the server before exiting (service stop,
	// uninstall, or an attempt to blind the host).
	{
		raw, _ := json.Marshal(map[string]interface{}{
			"reason": "service stop / shutdown requested", "pid": os.Getpid(),
		})
		fwd.SendFinal(schema.Event{
			ID:        fmt.Sprintf("agent-tamper:%s:%d", agentID, time.Now().UnixNano()),
			OS:        "windows",
			EventType: "agent.tamper",
			Severity:  schema.Severity(4),
			Source:    "agent",
			Raw:       raw,
		})
	}
	return nil
}

// ---------------------------------------------------------------------------
// Windows service management verbs
// ---------------------------------------------------------------------------

func handleCommand(cmd string) error {
	switch cmd {
	case "install":
		return installService()
	case "uninstall":
		return uninstallService()
	default:
		return fmt.Errorf("unknown command %q (valid: install, uninstall)", cmd)
	}
}

func installService() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return fmt.Errorf("abs exe path: %w", err)
	}

	// C-3: the binary embeds the fleet API key and CA, so restrict it to
	// SYSTEM and Administrators (best effort; warn if it fails).
	if out, aerr := exec.Command("icacls", exePath, "/inheritance:r",
		"/grant:r", "*S-1-5-18:(RX)", "*S-1-5-32-544:(F)").CombinedOutput(); aerr != nil {
		fmt.Printf("  Warning: could not restrict binary ACL: %v %s\n", aerr, strings.TrimSpace(string(out)))
	}

	// Load the embedded config — no yaml file needed.
	cfg, err := config.LoadEmbedded("agent.yaml")
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Auto-generate install key.
	installKey, err := generateInstallKey()
	if err != nil {
		return fmt.Errorf("generate install key: %w", err)
	}
	fmt.Printf("  Generated install key: %s\n", installKey)
	fmt.Println("  This key will appear on the ObsidianWatch dashboard (Agents → shield icon).")

	agentInstallID := cfg.Agent.ID
	if agentInstallID == "" {
		if h, err2 := os.Hostname(); err2 == nil {
			agentInstallID = h
		}
	}

	// Register key with management server.
	if cfg.Forwarder.ManagementURL != "" {
		fmt.Println("  Registering with management server...")
		// Use management CA if provided, fall back to backend CA.
		mgmtCA := cfg.Forwarder.ManagementCACertPEM
		if mgmtCA == "" {
			mgmtCA = cfg.Forwarder.CACertPEM
		}
		if err := registerInstallKey(cfg.Forwarder.ManagementURL, cfg.Forwarder.APIKey, mgmtCA, agentInstallID, installKey); err != nil {
			fmt.Printf("  Warning: could not register with server: %v\n", err)
			fmt.Println("  The key is saved locally and will sync on first connection.")
		} else {
			fmt.Println("  Registered on dashboard OK.")
		}
	}

	// Persist key to state file (no config yaml to patch).
	if err := config.PersistInstallKey(installKey); err != nil {
		fmt.Printf("  Warning: could not persist install key: %v\n", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to SCM: %w", err)
	}
	// Disconnect before removing the existing service — Windows will not fully
	// purge a deleted service entry while any SCM handle is open in this process.
	m.Disconnect()

	removeExistingService(serviceName)

	// Reconnect to SCM for CreateService.
	m, err = mgr.Connect()
	if err != nil {
		return fmt.Errorf("reconnect to SCM: %w", err)
	}
	defer m.Disconnect()

	// Copy binary to Program Files — no config file or certs to copy,
	// everything is embedded in the binary.
	installDir := `C:\Program Files\ObsidianWatch\Agent`
	if err := os.MkdirAll(installDir, 0755); err != nil {
		return fmt.Errorf("create install dir: %w", err)
	}

	installedExe := filepath.Join(installDir, "agent.exe")
	if err := copyFile(exePath, installedExe); err != nil {
		return fmt.Errorf("copy binary: %w", err)
	}
	fmt.Printf("  Installed to %s\n", installDir)

	// Register service — no -config flag needed.
	s, err := m.CreateService(serviceName, installedExe, mgr.Config{
		StartType:   mgr.StartAutomatic,
		DisplayName: serviceDisplayName,
		Description: serviceDescription,
	})
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	if err := applyTamperDACL(s); err != nil {
		fmt.Printf("Warning: could not apply tamper DACL: %v\n", err)
	}

	fmt.Printf("Service %q installed with tamper protection.\n", serviceName)
	fmt.Println("Starting service...")
	if err := s.Start(); err != nil {
		fmt.Printf("Warning: service installed but could not auto-start: %v\n", err)
		fmt.Println("Start it manually: Start-Service ObsidianWatchAgent")
	} else {
		fmt.Println("Service started. Agent should appear online on the dashboard within seconds.")
	}
	return nil
}

// enablePrivilege enables a named privilege in the current process token.
// Required before SetServiceObjectSecurity with DACL/OWNER flags.
func enablePrivilege(name string) {
	var token windows.Token
	proc, _ := windows.GetCurrentProcess()
	_ = windows.OpenProcessToken(proc, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	defer token.Close()
	var luid windows.LUID
	namep, _ := windows.UTF16PtrFromString(name)
	advapi32p := windows.NewLazySystemDLL("advapi32.dll")
	lookupPriv := advapi32p.NewProc("LookupPrivilegeValueW")
	lookupPriv.Call(0, uintptr(unsafe.Pointer(namep)), uintptr(unsafe.Pointer(&luid)))
	privs := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{{
			Luid:       luid,
			Attributes: windows.SE_PRIVILEGE_ENABLED,
		}},
	}
	windows.AdjustTokenPrivileges(token, false, &privs, 0, nil, nil)
}

// deleteServiceViaSYSTEM is the last-resort fallback when WRITE_DAC is blocked.
// Creates a temporary one-shot service running as LocalSystem that resets the DACL
// and deletes the target service. This is more reliable than a scheduled task
// because it avoids temp file path issues and task scheduler timing problems.
func deleteServiceViaSYSTEM(svcName string) error {
	fmt.Println("  Direct DACL unlock blocked — using LocalSystem service to remove...")

	cleanerName := "OW_Cleaner_" + svcName
	script := fmt.Sprintf(
		`sc.exe sdset %s D:P(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA) && sc.exe stop %s && sc.exe delete %s`,
		svcName, svcName, svcName)

	// Create a one-shot service running as LocalSystem.
	// cmd.exe is not a real service so sc.exe start returns 1053 (timeout),
	// but the sdset/stop/delete commands execute before the timeout fires.
	createOut, createErr := exec.Command("sc.exe", "create", cleanerName,
		"binPath=", `cmd.exe /c `+script,
		"type=", "own",
		"start=", "demand").CombinedOutput()
	if createErr != nil {
		return fmt.Errorf("create cleaner service failed: %v: %s", createErr, createOut)
	}

	exec.Command("sc.exe", "start", cleanerName).Run() // expected to fail with 1053
	exec.Command("sc.exe", "delete", cleanerName).Run()

	fmt.Println("  Waiting for service removal to complete...")
	waitForServiceGone(svcName)
	fmt.Println("  Service removed via LocalSystem service.")
	return nil
}

// waitForServiceGone polls sc.exe query every 500ms until the service entry
// is fully removed from the SCM (sc.exe returns error 1060 or "does not exist").
// Waits up to 30 seconds. This is necessary because both DeleteService and
// sc.exe delete are asynchronous — the SCM only removes the entry once all
// open handles are closed and the service process has fully exited.
func waitForServiceGone(svcName string) {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		out, _ := exec.Command("sc.exe", "query", svcName).CombinedOutput()
		lower := strings.ToLower(string(out))
		// sc.exe prints "[SC] EnumQueryServicesStatus: OpenService FAILED 1060:"
		// or "The specified service does not exist as an installed service."
		if strings.Contains(lower, "1060") ||
			strings.Contains(lower, "does not exist") ||
			strings.Contains(lower, "openservice failed") {
			return
		}
	}
}

// removeExistingService removes a previous installation using raw Win32 calls
// so it works even when the service has a tamper-protection DACL that blocks
// the high-level mgr.OpenService (which requests SERVICE_ALL_ACCESS).
func removeExistingService(name string) {
	const (
		SC_MANAGER_CONNECT = 0x0001
		SERVICE_WRITE_DAC  = 0x00040000
		SERVICE_ALL_ACCESS = 0x000F01FF
	)
	advapi32r := windows.NewLazySystemDLL("advapi32.dll")
	openSCMr := advapi32r.NewProc("OpenSCManagerW")
	openSvcR := advapi32r.NewProc("OpenServiceW")
	closeHndR := advapi32r.NewProc("CloseServiceHandle")
	setSecR := advapi32r.NewProc("SetServiceObjectSecurity")
	controlR := advapi32r.NewProc("ControlService")
	deleteR := advapi32r.NewProc("DeleteService")

	scmName, _ := windows.UTF16PtrFromString("")
	scmDB, _ := windows.UTF16PtrFromString("ServicesActive")
	scm, _, _ := openSCMr.Call(
		uintptr(unsafe.Pointer(scmName)),
		uintptr(unsafe.Pointer(scmDB)),
		SC_MANAGER_CONNECT,
	)
	if scm == 0 {
		return
	}
	defer closeHndR.Call(scm)

	svcName, _ := windows.UTF16PtrFromString(name)

	// First open with WRITE_DAC to reset DACL
	hDac, _, _ := openSvcR.Call(scm, uintptr(unsafe.Pointer(svcName)), SERVICE_WRITE_DAC)
	if hDac == 0 {
		// WRITE_DAC denied — service exists but tamper DACL is still active.
		// Fall back to SYSTEM task which can bypass it.
		deleteServiceViaSYSTEM(name) //nolint
		return
	}

	unlockSddl := "D:P(A;;0x000F01FF;;;SY)(A;;0x000F01FF;;;BA)"
	if sd, err := windows.SecurityDescriptorFromString(unlockSddl); err == nil {
		setSecR.Call(hDac, 4, uintptr(unsafe.Pointer(sd)))
	}
	closeHndR.Call(hDac)

	// Now open with full access to stop and delete
	hFull, _, _ := openSvcR.Call(scm, uintptr(unsafe.Pointer(svcName)), SERVICE_ALL_ACCESS)
	if hFull == 0 {
		return
	}

	var status windows.SERVICE_STATUS
	controlR.Call(hFull, windows.SERVICE_CONTROL_STOP, uintptr(unsafe.Pointer(&status)))
	time.Sleep(2 * time.Second)
	deleteR.Call(hFull)
	closeHndR.Call(hFull)

	// DeleteService is asynchronous — poll sc.exe query until the service
	// entry is fully gone from the SCM database.
	waitForServiceGone(name)
	fmt.Println("  Removed existing service installation.")
}

// applyTamperDACL sets a restrictive security descriptor on the service that
// prevents stop/delete by non-SYSTEM accounts.
//
// Service-specific hex rights used in SDDL:
//
//	0x000F01FF = SERVICE_ALL_ACCESS  (SYSTEM gets everything)
//	0x0002019D = query/start/pause/read but NOT stop/delete (Administrators)
//	0x00010020 = SERVICE_STOP | DELETE  (denied for Everyone)
func applyTamperDACL(s *mgr.Service) error {
	// Hex masks avoid the invalid generic-rights keywords that caused parse errors.
	sddl := "D:P(A;;0x000F01FF;;;SY)(A;;0x0002019D;;;BA)(D;;0x00010020;;;WD)"
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("parse SDDL: %w", err)
	}
	advapi32 := windows.NewLazySystemDLL("advapi32.dll")
	setSec := advapi32.NewProc("SetServiceObjectSecurity")
	// DACL_SECURITY_INFORMATION = 0x4
	ret, _, err2 := setSec.Call(uintptr(s.Handle), 4, uintptr(unsafe.Pointer(sd)))
	if ret == 0 {
		return fmt.Errorf("SetServiceObjectSecurity: %w", err2)
	}
	return nil
}

// registerInstallKey registers a chosen password as the agent's install key
// on the management server. The key is stored in the DB and shown on the dashboard.
// generateInstallKey returns a 32-character cryptographically random hex string.
func generateInstallKey() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func registerInstallKey(mgmtURL, apiKey, mgmtCACertPEM, agentID, password string) error {
	mgmtURL = strings.TrimRight(mgmtURL, "/")
	body := fmt.Sprintf(`{"agent_id":%q,"install_key":%q,"os":"windows"}`, agentID, password)

	// W-05: fail closed — no silent InsecureSkipVerify fallback.
	tlsCfg, err := config.BuildTLSConfig([]byte(mgmtCACertPEM), false)
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	req, err := http.NewRequest(http.MethodPost, mgmtURL+"/api/v1/agent/register-key",
		strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}

// verifyInstallKey (F-02/W-05) asks the management server to verify the key.
// The key goes in a POST body (never the URL) with the fleet API key header.
// The server rotates the key on success, so each key is single-use.
// Returns (accepted, reachable): reachable=false means the server could not be
// contacted at all (as opposed to contacted-and-rejected).
func verifyInstallKey(key, mgmtURL, apiKey string) (bool, bool) {
	if mgmtURL == "" {
		return false, false
	}
	mgmtURL = strings.TrimRight(mgmtURL, "/")

	cfg, err := config.LoadEmbedded("agent.yaml")
	if err != nil {
		return false, false
	}
	mgmtCA := cfg.Forwarder.ManagementCACertPEM
	if mgmtCA == "" {
		mgmtCA = cfg.Forwarder.CACertPEM
	}
	tlsCfg, err := config.BuildTLSConfig([]byte(mgmtCA), cfg.Forwarder.AllowInsecureTLS)
	if err != nil {
		fmt.Printf("Warning: TLS setup failed: %v\n", err)
		return false, false
	}
	if apiKey == "" {
		apiKey = cfg.Forwarder.APIKey
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	body := fmt.Sprintf(`{"key":%q}`, key)
	req, err := http.NewRequest(http.MethodPost, mgmtURL+"/api/v1/verify-install-key", strings.NewReader(body))
	if err != nil {
		return false, false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Warning: could not reach management server at %s: %v\n", mgmtURL, err)
		return false, false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200, true
}

func uninstallService() error {
	// Read install key from state file
	installKey, err := config.ReadInstallKey()
	if err != nil || installKey == "" {
		return fmt.Errorf("could not read install key — was this agent installed with this tool?\n(expected at %s)", config.InstallKeyFile())
	}

	// ── Tamper protection: require the admin to enter the key ────────────────
	fmt.Println()
	fmt.Println("  ╔══════════════════════════════════════════════════════╗")
	fmt.Println("  ║          ObsidianWatch Tamper Protection             ║")
	fmt.Println("  ╚══════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("  To uninstall, enter the install key shown on the dashboard.")
	fmt.Println("  (Agents → select agent → shield icon)")
	fmt.Println()
	fmt.Print("  Enter install key: ")

	var inputKey string
	fmt.Scanln(&inputKey)
	inputKey = strings.TrimSpace(inputKey)

	// F-02: the management server is the authority — it verifies the key and
	// rotates it, so a key is single-use and "Regenerate key" on the dashboard
	// actually works. The local copy is consulted only when the server cannot
	// be reached at all; a server rejection is final.
	mgmtURL := ""
	if ecfg, cerr := config.LoadEmbedded("agent.yaml"); cerr == nil {
		mgmtURL = ecfg.Forwarder.ManagementURL
	}
	accepted, reachable := verifyInstallKey(inputKey, mgmtURL, "")
	if reachable {
		if !accepted {
			fmt.Println()
			fmt.Println("  ✗ Incorrect key. Uninstall blocked.")
			return fmt.Errorf("tamper protection: incorrect install key")
		}
	} else if subtle.ConstantTimeCompare([]byte(inputKey), []byte(installKey)) != 1 {
		fmt.Println()
		fmt.Println("  ✗ Incorrect key (management server unreachable; checked against local copy). Uninstall blocked.")
		return fmt.Errorf("tamper protection: incorrect install key")
	}
	fmt.Println("  ✓ Key accepted.")
	fmt.Println()

	// ── Raw Win32 uninstall with DACL bypass ────────────────────────────────
	// Our tamper DACL denies SERVICE_STOP and DELETE for everyone except SYSTEM.
	// mgr.OpenService requests SERVICE_ALL_ACCESS which includes those rights
	// and gets Access Denied before we can even unlock the DACL.
	//
	// Fix: open the service with only WRITE_DAC (0x00040000) which IS allowed
	// by our DACL, reset the security descriptor to allow full admin access,
	// then stop and delete using a fresh handle with full rights.

	const (
		SC_MANAGER_CONNECT = 0x0001     // always granted to any user
		SERVICE_WRITE_DAC  = 0x00040000 // not in our deny list — should be allowed
		SERVICE_ALL_ACCESS = 0x000F01FF
	)

	// Enable SE_TAKE_OWNERSHIP_NAME so we can take ownership of the service
	// object and then reset its DACL regardless of existing restrictions.
	enablePrivilege("SeTakeOwnershipPrivilege")
	enablePrivilege("SeSecurityPrivilege")

	advapi32u := windows.NewLazySystemDLL("advapi32.dll")
	openSCM := advapi32u.NewProc("OpenSCManagerW")
	openSvc := advapi32u.NewProc("OpenServiceW")
	closeHnd := advapi32u.NewProc("CloseServiceHandle")
	setSec2 := advapi32u.NewProc("SetServiceObjectSecurity")

	// Open SCM with CONNECT only — always succeeds for any local user
	scmName, _ := windows.UTF16PtrFromString("")
	scmDB, _ := windows.UTF16PtrFromString("ServicesActive")
	scmHandle, _, _ := openSCM.Call(
		uintptr(unsafe.Pointer(scmName)),
		uintptr(unsafe.Pointer(scmDB)),
		SC_MANAGER_CONNECT,
	)
	if scmHandle == 0 {
		return fmt.Errorf("OpenSCManager failed: %w", windows.GetLastError())
	}
	defer closeHnd.Call(scmHandle)

	svcName, _ := windows.UTF16PtrFromString(serviceName)

	// Step 1: Open with WRITE_DAC|WRITE_OWNER — our deny ACE only blocks
	// SERVICE_STOP (0x20) and DELETE (0x10000), not DAC/owner writes.
	hDac, _, _ := openSvc.Call(scmHandle, uintptr(unsafe.Pointer(svcName)), SERVICE_WRITE_DAC)
	if hDac == 0 {
		// Last resort: use a scheduled task running as SYSTEM to delete
		return deleteServiceViaSYSTEM(serviceName)
	}

	// Step 2: Reset DACL to allow admins full access
	unlockSddl := "D:P(A;;0x000F01FF;;;SY)(A;;0x000F01FF;;;BA)"
	sd, err := windows.SecurityDescriptorFromString(unlockSddl)
	if err != nil {
		closeHnd.Call(hDac)
		return fmt.Errorf("build unlock SDDL: %w", err)
	}
	ret, _, _ := setSec2.Call(hDac, 4, uintptr(unsafe.Pointer(sd))) // DACL_SECURITY_INFORMATION = 4
	closeHnd.Call(hDac)
	if ret == 0 {
		fmt.Printf("Warning: could not unlock DACL (err=%v) — trying anyway\n", windows.GetLastError())
	} else {
		fmt.Println("  DACL unlocked. Service can now be stopped and removed.")
	}

	// Step 3: Open with STOP + ALL_ACCESS to stop and delete
	hFull, _, _ := openSvc.Call(scmHandle, uintptr(unsafe.Pointer(svcName)), SERVICE_ALL_ACCESS)
	if hFull == 0 {
		return fmt.Errorf("OpenService (full access) failed after DACL unlock: %w", windows.GetLastError())
	}

	// Stop the service if running
	var svcStatus windows.SERVICE_STATUS
	controlSvc := advapi32u.NewProc("ControlService")
	querySvc := advapi32u.NewProc("QueryServiceStatus")
	querySvc.Call(hFull, uintptr(unsafe.Pointer(&svcStatus)))
	if svcStatus.CurrentState != windows.SERVICE_STOPPED {
		controlSvc.Call(hFull, windows.SERVICE_CONTROL_STOP, uintptr(unsafe.Pointer(&svcStatus)))
		fmt.Println("  Stop signal sent. Waiting...")
		time.Sleep(3 * time.Second)
	}

	// Delete the service
	deleteSvc := advapi32u.NewProc("DeleteService")
	ret2, _, errDel := deleteSvc.Call(hFull)
	closeHnd.Call(hFull)
	if ret2 == 0 {
		return fmt.Errorf("DeleteService failed: %w", errDel)
	}

	fmt.Println("  Service uninstalled successfully.")
	fmt.Println("  The agent will stop sending events.")
	return nil
}

// ---------------------------------------------------------------------------
// Windows service preflight
// ---------------------------------------------------------------------------

// ensureWindowsServices checks that services required for event collection
// are running. If a service is disabled it re-enables it first, then starts it.
func ensureWindowsServices(logger *slog.Logger) {
	// EventLog is required for EvtSubscribe to work.
	// WinRM is needed for RPC-based event log access.
	required := []string{"EventLog", "WinRM"}

	m, err := mgr.Connect()
	if err != nil {
		logger.Warn("preflight: cannot connect to service manager", "err", err)
		return
	}
	defer m.Disconnect()

	for _, name := range required {
		s, err := m.OpenService(name)
		if err != nil {
			logger.Warn("preflight: cannot open service", "service", name, "err", err)
			continue
		}

		status, err := s.Query()
		if err != nil {
			logger.Warn("preflight: cannot query service", "service", name, "err", err)
			s.Close()
			continue
		}

		if status.State == svc.Running {
			logger.Info("preflight: service already running", "service", name)
			s.Close()
			continue
		}

		// Check if the service is disabled — if so, re-enable it first.
		cfgSvc, err := s.Config()
		if err == nil && cfgSvc.StartType == mgr.StartDisabled {
			logger.Info("preflight: service is disabled, re-enabling", "service", name)
			cfgSvc.StartType = mgr.StartAutomatic
			if err := s.UpdateConfig(cfgSvc); err != nil {
				logger.Warn("preflight: failed to re-enable service", "service", name, "err", err)
				s.Close()
				continue
			}
			logger.Info("preflight: service re-enabled", "service", name)
		}

		// Now start the service.
		logger.Info("preflight: starting service", "service", name)
		if err := s.Start(); err != nil {
			logger.Warn("preflight: failed to start service", "service", name, "err", err)
			s.Close()
			continue
		}

		// Wait up to 15 seconds for the service to reach Running state.
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			time.Sleep(500 * time.Millisecond)
			status, err = s.Query()
			if err != nil {
				break
			}
			if status.State == svc.Running {
				logger.Info("preflight: service started successfully", "service", name)
				break
			}
		}
		if status.State != svc.Running {
			logger.Warn("preflight: service did not reach running state", "service", name)
		}
		s.Close()
	}

	// Sysmon — auto-install if not present.
	// If not already admin, attempt to self-elevate via ShellExecute runas.
	switch sysmonpkg.Check() {
	case sysmonpkg.StatusRunning:
		logger.Info("preflight: Sysmon is running ✓")
	case sysmonpkg.StatusInstalled:
		if sysmonpkg.IsAdmin() {
			sysmonpkg.EnsureInstalled(logger)
		} else {
			logger.Warn("preflight: Sysmon installed but not running — attempting to start via elevation")
			if err := elevatedSysmonSetup(logger); err != nil {
				logger.Warn("preflight: elevation failed — start agent as Administrator", "err", err)
			}
		}
	case sysmonpkg.StatusNotInstalled:
		if sysmonpkg.IsAdmin() {
			logger.Info("preflight: Sysmon not installed — auto-installing now")
			sysmonpkg.EnsureInstalled(logger)
		} else {
			logger.Warn("preflight: Sysmon not installed — requesting elevation to install")
			if err := elevatedSysmonSetup(logger); err != nil {
				logger.Warn("preflight: could not auto-install Sysmon (run agent as Administrator for auto-install)", "err", err)
			}
		}
	}

	// W-01: record the *final* outcome (after any install/elevation
	// attempt above) so it reaches the management backend via the health
	// reporter — previously this whole preflight only logged locally, so
	// an admin had no way to know a host's process detections were
	// running blind (ETW alone gives PID/TID/opcode only, no image path,
	// command line, parent, or user) without reading that host's local
	// agent log.
	switch sysmonpkg.Check() {
	case sysmonpkg.StatusRunning:
		collector.SetSysmonStatus("running")
	case sysmonpkg.StatusInstalled:
		collector.SetSysmonStatus("installed_not_running")
	default:
		collector.SetSysmonStatus("not_installed")
	}
}

// elevatedSysmonSetup re-launches this same agent.exe with runas (UAC prompt)
// just to perform the Sysmon install/start, then returns.
// The current (non-elevated) agent continues running normally after this.
func elevatedSysmonSetup(logger *slog.Logger) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable: %w", err)
	}

	// ShellExecute with "runas" verb triggers UAC prompt
	modShell32 := windows.NewLazySystemDLL("shell32.dll")
	shellExecuteW := modShell32.NewProc("ShellExecuteW")

	operation, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exePath)
	params, _ := windows.UTF16PtrFromString("--sysmon-setup-only")
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(exePath))

	const SW_HIDE = 0
	ret, _, err := shellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(operation)),
		uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)),
		uintptr(unsafe.Pointer(dir)),
		SW_HIDE,
	)
	// ShellExecute returns >32 on success
	if ret <= 32 {
		return fmt.Errorf("ShellExecuteW runas: %d %w", ret, err)
	}

	logger.Info("preflight: UAC elevation launched for Sysmon setup — accept the prompt to install Sysmon")
	// Give the elevated process time to complete install before we continue
	time.Sleep(15 * time.Second)

	// Check if it worked
	if sysmonpkg.Check() == sysmonpkg.StatusRunning {
		logger.Info("preflight: Sysmon auto-install succeeded via elevation ✓")
		return nil
	}
	return fmt.Errorf("Sysmon still not running after elevated setup attempt")
}

// ---------------------------------------------------------------------------
// Audit policy enablement
// ---------------------------------------------------------------------------

// enableAuditPolicies ensures Windows is configured to emit the event IDs
// that ObsidianWatch relies on — specifically:
//   - Event 4688 with command line (process creation with full cmdline)
//   - PowerShell Script Block Logging (4104)
//   - PowerShell Module Logging (4103)
//
// These settings are written to the registry and take effect immediately.
// Requires administrator privileges — silently skips on failure.
func enableAuditPolicies(logger *slog.Logger) {
	modAdvapi32Reg := windows.NewLazySystemDLL("advapi32.dll")
	regSetValueEx := modAdvapi32Reg.NewProc("RegSetValueExW")
	regCreateKeyEx := modAdvapi32Reg.NewProc("RegCreateKeyExW")
	regCloseKey := modAdvapi32Reg.NewProc("RegCloseKey")

	setDWORD := func(hive windows.Handle, path, name string, val uint32) error {
		keyPtr, _ := windows.UTF16PtrFromString(path)
		namePtr, _ := windows.UTF16PtrFromString(name)
		const KEY_SET_VALUE = 0x0002
		const KEY_WOW64_64KEY = 0x0100
		const REG_OPTION_NON_VOLATILE = 0x00000000
		var hkey windows.Handle
		var disposition uint32
		// RegCreateKeyEx creates the key AND all intermediate keys if they don't exist
		ret, _, _ := regCreateKeyEx.Call(
			uintptr(hive), uintptr(unsafe.Pointer(keyPtr)),
			0, 0, REG_OPTION_NON_VOLATILE,
			KEY_SET_VALUE|KEY_WOW64_64KEY,
			0,
			uintptr(unsafe.Pointer(&hkey)),
			uintptr(unsafe.Pointer(&disposition)),
		)
		if ret != 0 {
			return fmt.Errorf("RegCreateKeyEx: %d", ret)
		}
		defer regCloseKey.Call(uintptr(hkey))
		ret, _, _ = regSetValueEx.Call(
			uintptr(hkey), uintptr(unsafe.Pointer(namePtr)),
			0, 4, // REG_DWORD
			uintptr(unsafe.Pointer(&val)),
			4,
		)
		if ret != 0 {
			return fmt.Errorf("RegSetValueEx: %d", ret)
		}
		return nil
	}

	// 1. Enable Process Creation auditing with command line inclusion (Event 4688 + cmdline)
	//    HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit
	//    ProcessCreationIncludeCmdLine_Enabled = 1
	if err := setDWORD(windows.HKEY_LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`,
		"ProcessCreationIncludeCmdLine_Enabled", 1); err != nil {
		logger.Warn("preflight: could not enable 4688 command line logging (need admin)", "err", err)
	} else {
		logger.Info("preflight: enabled Event 4688 command line inclusion")
	}

	// 2. Enable PowerShell Script Block Logging (Event 4104 — captures ACTUAL script text)
	//    HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
	//    EnableScriptBlockLogging = 1
	if err := setDWORD(windows.HKEY_LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`,
		"EnableScriptBlockLogging", 1); err != nil {
		logger.Warn("preflight: could not enable PowerShell Script Block Logging", "err", err)
	} else {
		logger.Info("preflight: enabled PowerShell Script Block Logging (Event 4104)")
	}

	// 3. Enable PowerShell Module Logging (Event 4103 — pipeline execution details)
	//    HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging
	//    EnableModuleLogging = 1
	if err := setDWORD(windows.HKEY_LOCAL_MACHINE,
		`SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging`,
		"EnableModuleLogging", 1); err != nil {
		logger.Warn("preflight: could not enable PowerShell Module Logging", "err", err)
	} else {
		logger.Info("preflight: enabled PowerShell Module Logging (Event 4103)")
	}
}

// ---------------------------------------------------------------------------
// File copy helper

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// ---------------------------------------------------------------------------
// Logger factory
// ---------------------------------------------------------------------------

func buildLogger(level, format string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}

	// Always write to log file in ProgramData (writable by services).
	logPath := `C:\ProgramData\ObsidianWatch\agent.log`
	os.MkdirAll(`C:\ProgramData\ObsidianWatch`, 0755)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)

	var handler slog.Handler
	if err == nil {
		// Write to both stdout and log file
		mw := io.MultiWriter(os.Stdout, logFile)
		if format == "text" {
			handler = slog.NewTextHandler(mw, opts)
		} else {
			handler = slog.NewJSONHandler(mw, opts)
		}
	} else {
		if format == "text" {
			handler = slog.NewTextHandler(os.Stdout, opts)
		} else {
			handler = slog.NewJSONHandler(os.Stdout, opts)
		}
	}
	return slog.New(handler)
}

var dataDirHardened sync.Once

// hardenDataDir restricts C:\ProgramData\ObsidianWatch (agent.log, queue,
// state) to SYSTEM and Administrators (W-06). Go's os file modes are ignored
// on Windows, so the default ProgramData ACL lets every local user read the
// log and queued events (which contain command lines). Best-effort: a
// failure is non-fatal, and it runs once per process.
func hardenDataDir() {
	dataDirHardened.Do(func() {
		_ = exec.Command("icacls", `C:\ProgramData\ObsidianWatch`,
			"/inheritance:r",
			"/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F",
		).Run()
	})
}
