#!/bin/bash
# build.sh — Build ObsidianWatch macOS agent
# Run this on a macOS machine or cross-compile from Linux/macOS.
#
# Requirements: Go 1.22+
# Output: build/obsidianwatch-macos-agent

set -e

cd "$(dirname "$0")"

VERSION="0.3.1"
OUTPUT="build/obsidianwatch-macos-agent"

echo "Building ObsidianWatch macOS agent v${VERSION}..."

# Download dependencies and generate go.sum if missing
GONOSUMDB=* GOFLAGS=-mod=mod go mod tidy 2>/dev/null || true
go mod download

# Build for macOS (arm64 = Apple Silicon, amd64 = Intel)
ARCH="${1:-arm64}"   # Default: Apple Silicon. Pass 'amd64' for Intel.

GOOS=darwin GOARCH="${ARCH}" go build \
    -ldflags="-s -w -X main.agentVersion=${VERSION}" \
    -o "${OUTPUT}-${ARCH}" \
    ./cmd/agent/

echo "Built: ${OUTPUT}-${ARCH}"
echo ""
echo "Installation:"
echo "  sudo ./${OUTPUT}-${ARCH} --config configs/agent.yaml install"
echo ""
echo "Uninstall:"
echo "  sudo ./${OUTPUT}-${ARCH} --config configs/agent.yaml uninstall"
echo ""
echo "Manual run (for testing):"
echo "  sudo ./${OUTPUT}-${ARCH} --config configs/agent.yaml"
