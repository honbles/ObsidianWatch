#!/bin/sh
set -e

CERT="/etc/nginx/certs/server.crt"
KEY="/etc/nginx/certs/server.key"

echo "mgmt-ui: waiting for TLS certificates..."
ATTEMPTS=0
while [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; do
  ATTEMPTS=$((ATTEMPTS + 1))
  if [ $ATTEMPTS -gt 30 ]; then
    echo "mgmt-ui: WARNING - certs not found after 30s, starting without TLS"
    # Fall back to HTTP-only config
    cp /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default.conf.bak
    cat > /etc/nginx/conf.d/default.conf << 'NGINX'
server {
    listen 80;
    root /usr/share/nginx/html;
    index index.html;
    location / { try_files $uri $uri/ /index.html; }
    location /api/ {
        proxy_pass https://mgmt-api:8443;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_read_timeout 180s;
    }
    location /ws/ {
        proxy_pass https://mgmt-api:8443;
        proxy_ssl_verify off;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
    }
    location /health { proxy_pass https://mgmt-api:8443; proxy_ssl_verify off; }
}
NGINX
    break
  fi
  sleep 1
done

if [ -f "$CERT" ] && [ -f "$KEY" ]; then
  echo "mgmt-ui: TLS certificates found, starting nginx with HTTPS"
else
  echo "mgmt-ui: Starting nginx with HTTP fallback"
fi

exec nginx -g "daemon off;"
