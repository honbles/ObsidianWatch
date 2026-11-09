package main

import (
	"log/slog"
	"os"
	"time"
)

// watchRestartSignal replaces the M-08 docker.sock-based restart mechanism.
// The management API can no longer reach the Docker socket, so instead it
// touches a file on a shared volume; we poll that file's mtime and exit so
// the container's `restart: unless-stopped` policy brings it back up with
// the freshly-written config.
const restartSignalPath = "/var/run/obsidianwatch/restart-signal"

func watchRestartSignal(logger *slog.Logger) {
	var lastMTime time.Time
	if fi, err := os.Stat(restartSignalPath); err == nil {
		lastMTime = fi.ModTime()
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		fi, err := os.Stat(restartSignalPath)
		if err != nil {
			continue
		}
		if fi.ModTime().After(lastMTime) {
			logger.Info("restart signal detected, exiting for restart policy to reload config")
			os.Exit(0)
		}
	}
}
