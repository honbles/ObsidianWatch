# fetch-otel-sdk.ps1 - Windows version of fetch-otel-sdk.sh: vendors the
# official OpenTelemetry Go SDK into the management backend and packs what
# changed into otel-sdk-vendor.zip at the repository root.
#
#   powershell -ExecutionPolicy Bypass -File tools\fetch-otel-sdk.ps1
#   # pin versions when the latest need a newer Go than the repository:
#   powershell -ExecutionPolicy Bypass -File tools\fetch-otel-sdk.ps1 -OtelVersion v1.38.0 -ContribVersion v0.63.0
#
# Undo the working-tree changes afterwards with:
#   git checkout -- management/backend; git clean -fd management/backend/vendor management/backend/internal/otelsdk
param(
    [string]$OtelVersion = "latest",
    [string]$ContribVersion = "latest"
)
# "Continue": Windows PowerShell turns a native command's stderr into errors when
# it is redirected, and go writes progress to stderr. Failures are caught by
# $LASTEXITCODE checks and explicit throws instead.
$ErrorActionPreference = "Continue"

if (-not (Get-Command go -ErrorAction SilentlyContinue)) { throw "Go is not installed (https://go.dev/dl/)" }
$root = (git rev-parse --show-toplevel 2>$null)
if (-not $root) { $root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path }
$be = Join-Path $root "management/backend"
if (-not (Test-Path (Join-Path $be "go.mod"))) { throw "cannot find $be/go.mod" }
Set-Location $be

function GoLine { (Select-String -Path go.mod -Pattern '^go (.+)$' | Select-Object -First 1).Matches[0].Groups[1].Value }
$wantGo = GoLine
Write-Host "Repository Go version: $wantGo; installed: $(go env GOVERSION)"

New-Item -ItemType Directory -Force -Path internal/otelsdk -ErrorAction Stop | Out-Null
@'
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
'@ | Set-Content -Encoding ascii internal/otelsdk/deps.go

$env:GOTOOLCHAIN = "local"   # never switch toolchains or raise the go line
$env:GOFLAGS = "-mod=mod"

Write-Host "Fetching OpenTelemetry Go $OtelVersion and contrib $ContribVersion..."
go get "go.opentelemetry.io/otel@$OtelVersion" `
       "go.opentelemetry.io/otel/sdk@$OtelVersion" `
       "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp@$OtelVersion" `
       "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp@$ContribVersion"
if ($LASTEXITCODE -ne 0) {
    Remove-Item -Recurse -Force internal/otelsdk
    throw "go get failed (see the error above). No access to proxy.golang.org (check the network or GOPROXY), or a module needs a newer Go than ${wantGo}: pin older versions with -OtelVersion v1.38.0 -ContribVersion v0.63.0"
}

go list go.opentelemetry.io/otel/semconv/v1.26.0 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    (Get-Content internal/otelsdk/deps.go) | Where-Object { $_ -notmatch 'semconv/v1.26.0' } | Set-Content -Encoding ascii internal/otelsdk/deps.go
}

go mod tidy;   if ($LASTEXITCODE -ne 0) { throw "go mod tidy failed" }
go mod vendor; if ($LASTEXITCODE -ne 0) { throw "go mod vendor failed" }

if ((GoLine) -ne $wantGo) {
    Write-Warning "go.mod now says go $(GoLine) (was $wantGo); the Docker image builds with $wantGo. Pin older versions to keep it."
}

# The server only runs on Linux (it uses syscall.Flock), so compile for Linux
# even when this script runs on Windows or macOS.
$env:GOFLAGS = "-mod=vendor"
$env:GOOS = "linux"
$env:CGO_ENABLED = "0"
Write-Host "Checking that the SDK packages build from vendor/..."
go build -tags tools ./internal/otelsdk/;    if ($LASTEXITCODE -ne 0) { throw "SDK packages do not build" }
Write-Host "Checking that the server still builds (Linux target)..."
go build ./...
if ($LASTEXITCODE -ne 0) {
    Write-Warning "The server does not build with your local source. The SDK zip is still fine; the errors above come from your checkout (for example an older file), not from the SDK."
}
Remove-Item Env:GOOS, Env:CGO_ENABLED

$out = Join-Path $root "otel-sdk-vendor.zip"
if (Test-Path $out) { Remove-Item $out }
Set-Location $root
# tar ships with Windows 10+ and keeps the folder structure in the zip
tar -a -c -f $out management/backend/go.mod management/backend/go.sum management/backend/vendor management/backend/internal/otelsdk
if ($LASTEXITCODE -ne 0) { throw "zip failed" }
Write-Host ""
Write-Host ("Done: {0} ({1:N1} MB)" -f $out, ((Get-Item $out).Length / 1MB))
Select-String -Path management/backend/go.mod -Pattern 'go.opentelemetry.io/(otel|otel/sdk|contrib/instrumentation/net/http/otelhttp) ' | ForEach-Object { "  " + $_.Line.Trim() }
