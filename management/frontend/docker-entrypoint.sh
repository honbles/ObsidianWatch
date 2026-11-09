#!/bin/sh
set -e

CERT="/etc/nginx/certs/server.crt"
KEY="/etc/nginx/certs/server.key"

echo "mgmt-ui: waiting for TLS certificates..."
ATTEMPTS=0
while [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; do
  ATTEMPTS=$((ATTEMPTS + 1))
  # H-3: fail closed. Never serve the dashboard or API over plaintext HTTP;
  # exit so the orchestrator surfaces the failure instead.
  if [ $ATTEMPTS -gt 60 ]; then
    echo "mgmt-ui: ERROR - TLS certificates not found after 60s; refusing to start without TLS" >&2
    exit 1
  fi
  sleep 1
done

echo "mgmt-ui: TLS certificates found, starting nginx with HTTPS"
exec nginx -g "daemon off;"
