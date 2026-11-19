#!/usr/bin/env bash
# Proves the agent's OTLP receiver against a REAL OpenTelemetry SDK application.
#   ./verify.sh <port> <command that starts a sample app on that port ...>
# Example: OW_ALLOW_VULN_DEMO=1 ./verify.sh 5001 python3 python/app.py
# It starts the real receiver (agents/linux, loopback :4318, real process resolver), starts the sample
# app, runs attack_sim.py against it, then prints what the receiver decoded (verify_report.py).
# Needs: Go (see the repo README), and whatever runtime the sample needs. Linux only (the receiver's
# process identification is what is being tested).
set -euo pipefail
PORT="$1"; shift
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
TMP="$(mktemp -d)"; OUT="$TMP/out.json"; READY="$TMP/ready"
SECS="${OW_VERIFY_SECS:-45}"
cleanup() { [ -n "${APP_PID:-}" ] && kill "$APP_PID" 2>/dev/null || true; [ -n "${GO_PID:-}" ] && kill "$GO_PID" 2>/dev/null || true; }
trap cleanup EXIT
( cd "$ROOT/agents/linux" && OW_REAL_SDK_OUT="$OUT" OW_REAL_SDK_SECS="$SECS" OW_REAL_SDK_READY="$READY" \
    go test ./internal/otel -run TestRealSDK -count=1 >"$TMP/receiver.log" 2>&1 ) &
GO_PID=$!
for _ in $(seq 1 120); do [ -f "$READY" ] && break; sleep 1; done
[ -f "$READY" ] || { echo "receiver did not start:"; cat "$TMP/receiver.log"; exit 1; }
"$@" >"$TMP/app.log" 2>&1 &
APP_PID=$!
for _ in $(seq 1 60); do curl -fs "http://127.0.0.1:$PORT/health" >/dev/null && break; sleep 1; done
curl -fs "http://127.0.0.1:$PORT/health" >/dev/null || { echo "app did not start:"; cat "$TMP/app.log"; exit 1; }
python3 "$HERE/attack_sim.py" --base "http://127.0.0.1:$PORT"
echo "waiting for the receiver window to close ($SECS s total) ..."
wait "$GO_PID" || { cat "$TMP/receiver.log"; exit 1; }
python3 "$HERE/verify_report.py" "$OUT"
