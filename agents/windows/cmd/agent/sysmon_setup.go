//go:build windows

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"obsidianwatch/agent/internal/collector"
	sysmonpkg "obsidianwatch/agent/internal/sysmon"
)

const sysmonSetupLog = `C:\ProgramData\ObsidianWatch\sysmon-setup.log`

// runSysmonSetupOnly is the entry point for the elevated relaunch
// (agent.exe --sysmon-setup-only). It runs hidden, so everything is written
// to sysmon-setup.log. Returns the process exit code.
func runSysmonSetupOnly() int {
	_ = os.MkdirAll(`C:\ProgramData\ObsidianWatch`, 0700)
	f, err := os.OpenFile(sysmonSetupLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return 2
	}
	defer f.Close()
	logger := slog.New(slog.NewTextHandler(f, nil))
	if !sysmonpkg.IsAdmin() {
		logger.Error("sysmon setup: not elevated; the UAC prompt was declined or not shown")
		return 3
	}
	if sysmonpkg.EnsureInstalled(logger) {
		return 0
	}
	return 1
}

// retrySysmonInstall retries the install while Sysmon is not running. The
// startup preflight runs once; if the network was down or a download failed,
// the host would otherwise stay blind until the next agent restart. Only runs
// when the agent itself is elevated (a service running as SYSTEM).
func retrySysmonInstall(ctx context.Context, logger *slog.Logger) {
	const every = 30 * time.Minute
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if sysmonpkg.Check() == sysmonpkg.StatusRunning {
			collector.SetSysmonStatus("running")
			continue
		}
		if !sysmonpkg.IsAdmin() {
			continue
		}
		logger.Info("sysmon: not running, retrying install")
		if sysmonpkg.EnsureInstalled(logger) {
			collector.SetSysmonStatus("running")
		} else {
			logger.Warn(fmt.Sprintf("sysmon: install retry failed; next attempt in %s", every))
		}
	}
}
