#!/usr/bin/env bash
# fetch-otel-sdk.sh - vendors the official OpenTelemetry Go SDK into the
# management backend and packs what changed into one zip to hand over.
#
# Run from anywhere inside the repository, on a machine with Go 1.25 and
# internet access:
#     bash tools/fetch-otel-sdk.sh
# Pin versions when the latest ones need a newer Go than the repository:
#     OTEL_VERSION=v1.38.0 OTEL_CONTRIB_VERSION=v0.63.0 bash tools/fetch-otel-sdk.sh
#
# Output: otel-sdk-vendor.zip at the repository root, holding
# management/backend/go.mod, go.sum, vendor/ and internal/otelsdk/deps.go.
# Your working tree keeps the changes; undo them with
#     git checkout -- management/backend && git clean -fd management/backend/vendor management/backend/internal/otelsdk
set -euo pipefail

OTEL_VERSION="${OTEL_VERSION:-latest}"
OTEL_CONTRIB_VERSION="${OTEL_CONTRIB_VERSION:-latest}"

command -v go >/dev/null || { echo "Go is not installed (https://go.dev/dl/)"; exit 1; }
root="$(git rev-parse --show-toplevel 2>/dev/null || (cd "$(dirname "$0")/.." && pwd))"
be="$root/management/backend"
[ -f "$be/go.mod" ] || { echo "cannot find $be/go.mod"; exit 1; }
cd "$be"

want_go="$(awk '/^go /{print $2; exit}' go.mod)"
echo "Repository Go version: $want_go; installed: $(go env GOVERSION)"

# go mod tidy drops modules nothing imports, so a build-tagged file keeps the
# SDK packages in go.mod and vendor/ until real code uses them.
mkdir -p internal/otelsdk
cat > internal/otelsdk/deps.go <<'EOF'
//go:build tools

// Package otelsdk pins the OpenTelemetry Go SDK in go.mod and vendor/ before
// any code imports it. Built only with -tags tools.
package otelsdk

import (
	_ "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	_ "go.opentelemetry.io/otel"
	_ "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	_ "go.opentelemetry.io/otel/sdk/resource"
	_ "go.opentelemetry.io/otel/sdk/trace"
	_ "go.opentelemetry.io/otel/semconv/v1.26.0"
)
EOF

# Keep the repository's Go version: never switch toolchains or raise "go".
export GOTOOLCHAIN=local
export GOFLAGS=-mod=mod

echo "Fetching OpenTelemetry Go $OTEL_VERSION and contrib $OTEL_CONTRIB_VERSION..."
if ! go get \
	"go.opentelemetry.io/otel@$OTEL_VERSION" \
	"go.opentelemetry.io/otel/sdk@$OTEL_VERSION" \
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp@$OTEL_VERSION" \
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp@$OTEL_CONTRIB_VERSION"; then
	rm -rf internal/otelsdk
	echo
	echo "go get failed (see the error above). Common causes:"
	echo "  - no access to proxy.golang.org (check the network or set GOPROXY)"
	echo "  - a module needs a newer Go than $want_go: pin older versions, for example"
	echo "    OTEL_VERSION=v1.38.0 OTEL_CONTRIB_VERSION=v0.63.0 bash tools/fetch-otel-sdk.sh"
	exit 1
fi

# semconv lives in the otel module; drop the import if this version lacks v1.26.0
if ! go list go.opentelemetry.io/otel/semconv/v1.26.0 >/dev/null 2>&1; then
	sed -i.bak '/semconv\/v1.26.0/d' internal/otelsdk/deps.go && rm -f internal/otelsdk/deps.go.bak
fi

go mod tidy
go mod vendor

if [ "$(awk '/^go /{print $2; exit}' go.mod)" != "$want_go" ]; then
	echo "warning: go.mod now says go $(awk '/^go /{print $2; exit}' go.mod) (was $want_go); the Docker image builds with $want_go."
	echo "Pin older versions (see the top of this script) if you want to keep $want_go."
fi

# The server only runs on Linux (it uses syscall.Flock): compile for Linux on any host.
echo "Checking that the SDK packages build from vendor/..."
GOOS=linux CGO_ENABLED=0 GOFLAGS=-mod=vendor go build -tags tools ./internal/otelsdk/
echo "Checking that the server still builds (Linux target)..."
if ! GOOS=linux CGO_ENABLED=0 GOFLAGS=-mod=vendor go build ./...; then
	echo "warning: the server does not build with your local source. The SDK zip is still fine;"
	echo "the errors above come from your checkout (for example an older file), not from the SDK."
fi

out="$root/otel-sdk-vendor.zip"
rm -f "$out"
if command -v zip >/dev/null; then
	(cd "$root" && zip -qr "$out" management/backend/go.mod management/backend/go.sum \
		management/backend/vendor management/backend/internal/otelsdk)
else
	out="$root/otel-sdk-vendor.tar.gz"
	(cd "$root" && tar -czf "$out" management/backend/go.mod management/backend/go.sum \
		management/backend/vendor management/backend/internal/otelsdk)
fi
echo
echo "Done: $out ($(du -h "$out" | cut -f1))"
grep -E 'go.opentelemetry.io/(otel|otel/sdk|contrib/instrumentation/net/http/otelhttp) ' go.mod | sed 's/^/  /'
