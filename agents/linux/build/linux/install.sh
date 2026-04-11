#!/bin/bash
# ObsidianWatch Linux Agent — Build & Install Script
# Usage:
#   ./install.sh build              — compile binary only
#   ./install.sh install            — build + install as systemd service
#   sudo ./install.sh uninstall     — remove service and files

set -e

BINARY="obsidianwatch-agent"
CONFIG="configs/agent.yaml"
SERVICE_NAME="obsidianwatch-agent"

case "${1:-build}" in

  build)
    echo "[*] Building ObsidianWatch Linux agent..."
    GONOSUMDB=* GOFLAGS=-mod=mod go mod tidy 2>/dev/null || true
    GOOS=linux GOARCH=amd64 go build \
      -ldflags="-s -w" \
      -o "$BINARY" \
      ./cmd/agent/
    echo "[+] Built: $BINARY ($(du -sh $BINARY | cut -f1))"
    ;;

  install)
    echo "[*] Building..."
    GONOSUMDB=* GOFLAGS=-mod=mod go mod tidy 2>/dev/null || true
    GOOS=linux GOARCH=amd64 go build \
      -ldflags="-s -w" \
      -o "$BINARY" \
      ./cmd/agent/

    echo "[*] Installing ObsidianWatch agent as systemd service..."
    if [ "$EUID" -ne 0 ]; then
      echo "[!] Install requires root. Re-running with sudo..."
      exec sudo "$0" install
    fi

    ./"$BINARY" -config "$CONFIG" install
    ;;

  uninstall)
    echo "[*] Uninstalling ObsidianWatch agent..."
    if [ "$EUID" -ne 0 ]; then
      echo "[!] Uninstall requires root. Re-running with sudo..."
      exec sudo "$0" uninstall
    fi

    # Find the installed binary
    if [ -f "/usr/local/bin/$BINARY" ]; then
      /usr/local/bin/$BINARY -config /etc/obsidianwatch/agent.yaml uninstall
    else
      echo "[!] Agent binary not found at /usr/local/bin/$BINARY"
      echo "[!] Manual cleanup:"
      echo "    chattr -i /etc/obsidianwatch/agent.yaml /usr/local/bin/obsidianwatch-agent /etc/systemd/system/obsidianwatch-agent.service"
      echo "    systemctl stop obsidianwatch-agent && systemctl disable obsidianwatch-agent"
      echo "    rm -f /usr/local/bin/obsidianwatch-agent /etc/systemd/system/obsidianwatch-agent.service"
      echo "    rm -rf /etc/obsidianwatch /var/lib/obsidianwatch"
      exit 1
    fi
    ;;

  run)
    echo "[*] Running ObsidianWatch agent interactively (no install)..."
    echo "[*] Queue will use /tmp/obsidianwatch — edit config to change."
    mkdir -p /tmp/obsidianwatch/queue

    GOOS=linux GOARCH=amd64 go build \
      -ldflags="-s -w" \
      -o "$BINARY" \
      ./cmd/agent/

    # Run with a temp queue path for testing
    ./"$BINARY" -config "$CONFIG"
    ;;

  *)
    echo "Usage: $0 {build|run|install|uninstall}"
    exit 1
    ;;
esac
