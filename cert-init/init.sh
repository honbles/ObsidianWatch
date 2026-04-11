#!/bin/sh
set -e

CERT_DIR="/certs"
CA_KEY="$CERT_DIR/ca.key"
CA_CRT="$CERT_DIR/ca.crt"
SRV_KEY="$CERT_DIR/server.key"
SRV_CRT="$CERT_DIR/server.crt"
META="$CERT_DIR/cert-meta.json"
MODE_FILE="$CERT_DIR/cert-mode"

echo "cert-init: ObsidianWatch TLS setup"
echo "cert-init: BACKEND_DOMAIN=${BACKEND_DOMAIN:-<not set>}"

# ── Let's Encrypt mode (domain provided) ──────────────────────────────────────
if [ -n "$BACKEND_DOMAIN" ]; then
  echo "cert-init: Domain provided — using Let's Encrypt for $BACKEND_DOMAIN"

  # Check if valid LE cert already exists
  if [ -f "$SRV_CRT" ] && [ -f "$SRV_KEY" ]; then
    # Check expiry — renew if less than 30 days remaining
    EXPIRY=$(openssl x509 -enddate -noout -in "$SRV_CRT" 2>/dev/null | cut -d= -f2)
    EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$EXPIRY" +%s 2>/dev/null || echo 0)
    NOW_EPOCH=$(date +%s)
    DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
    MODE=$(cat "$MODE_FILE" 2>/dev/null || echo "")
    if [ "$MODE" = "letsencrypt" ] && [ "$DAYS_LEFT" -gt 30 ]; then
      echo "cert-init: Let's Encrypt cert valid for $DAYS_LEFT more days — skipping"
      exit 0
    fi
  fi

  # Install acme.sh if not present
  if ! command -v acme.sh > /dev/null 2>&1; then
    apk add --no-cache curl socat > /dev/null 2>&1 || true
    curl -s https://get.acme.sh | sh -s email=admin@$BACKEND_DOMAIN 2>/dev/null || \
      wget -qO- https://get.acme.sh | sh -s -- email=admin@$BACKEND_DOMAIN 2>/dev/null
    . ~/.acme.sh/acme.sh.env 2>/dev/null || export PATH="$HOME/.acme.sh:$PATH"
  fi

  echo "cert-init: Requesting Let's Encrypt cert for $BACKEND_DOMAIN"
  echo "cert-init: NOTE: $BACKEND_DOMAIN must point to this server's public IP"

  # Issue cert using standalone HTTP challenge (port 80 must be free)
  ~/.acme.sh/acme.sh --issue \
    --standalone \
    --domain "$BACKEND_DOMAIN" \
    --server letsencrypt \
    --httpport 80 \
    --force 2>&1 | tail -5

  # Install cert to our cert dir
  ~/.acme.sh/acme.sh --install-cert \
    --domain "$BACKEND_DOMAIN" \
    --key-file "$SRV_KEY" \
    --cert-file "$SRV_CRT" \
    --ca-file "$CA_CRT" 2>&1 | tail -3

  echo "letsencrypt" > "$MODE_FILE"
  printf '{"private_ip":"%s","public_ip":"%s","backend_domain":"%s","cert_mode":"letsencrypt"}' \
    "${HOST_IP:-}" \
    "$(wget -qO- --timeout=8 https://api.ipify.org 2>/dev/null | tr -d '[:space:]' || echo '')" \
    "$BACKEND_DOMAIN" > "$META"

  echo "cert-init: Let's Encrypt certificate issued successfully"
  exit 0
fi

# ── Self-signed mode (no domain) ──────────────────────────────────────────────

# Skip if self-signed certs already exist and are still valid
if [ -f "$CA_CRT" ] && [ -f "$SRV_CRT" ] && [ -f "$SRV_KEY" ]; then
  MODE=$(cat "$MODE_FILE" 2>/dev/null || echo "selfsigned")
  if [ "$MODE" = "selfsigned" ] || [ "$MODE" = "" ]; then
    echo "cert-init: self-signed certificates already exist, skipping"
    exit 0
  fi
fi

echo "cert-init: Generating self-signed certificates..."

# Detect private IP
if [ -n "$HOST_IP" ]; then
  PRIVATE_IP="$HOST_IP"
else
  GATEWAY=$(ip route show default 2>/dev/null | awk '/default/{print $3}' | head -1)
  PRIVATE_IP="${GATEWAY:-127.0.0.1}"
fi
echo "cert-init: private IP = $PRIVATE_IP"

# Detect public IP
PUBLIC_IP=$(wget -qO- --timeout=8 https://api.ipify.org 2>/dev/null | tr -d '[:space:]')
if [ -z "$PUBLIC_IP" ]; then
  PUBLIC_IP=$(wget -qO- --timeout=8 https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]')
fi
case "$PUBLIC_IP" in
  *' '* | *'<'* | '' ) PUBLIC_IP="" ;;
esac
[ -n "$PUBLIC_IP" ] && echo "cert-init: public IP = $PUBLIC_IP" || echo "cert-init: no public IP detected"

# Build SAN entries
SAN="IP.1 = $PRIVATE_IP
IP.2 = 127.0.0.1"
IP_IDX=3
if [ -n "$PUBLIC_IP" ] && [ "$PUBLIC_IP" != "$PRIVATE_IP" ]; then
  SAN="$SAN
IP.$IP_IDX = $PUBLIC_IP"
  IP_IDX=$((IP_IDX + 1))
fi

echo "cert-init: SANs: $PRIVATE_IP, 127.0.0.1${PUBLIC_IP:+, $PUBLIC_IP}"

# Write OpenSSL SAN config
SAN_CNF="$CERT_DIR/san.cnf"
cat > "$SAN_CNF" << SANEOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = obsidianwatch

[v3_req]
subjectAltName = @alt_names
keyUsage = keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage = serverAuth

[alt_names]
$SAN
SANEOF

# Generate CA
echo "cert-init: Generating CA..."
openssl genrsa -out "$CA_KEY" 4096 2>/dev/null
openssl req -new -x509 -days 3650 -key "$CA_KEY" -out "$CA_CRT" \
  -subj "/CN=ObsidianWatch CA/O=ObsidianWatch" 2>/dev/null

# Generate server cert
echo "cert-init: Generating server certificate..."
openssl genrsa -out "$SRV_KEY" 2048 2>/dev/null
SRV_CSR="$CERT_DIR/server.csr"
openssl req -new -key "$SRV_KEY" -out "$SRV_CSR" \
  -subj "/CN=obsidianwatch/O=ObsidianWatch" -config "$SAN_CNF" 2>/dev/null
openssl x509 -req -days 3650 \
  -in "$SRV_CSR" -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
  -extensions v3_req -extfile "$SAN_CNF" \
  -out "$SRV_CRT" 2>/dev/null

openssl verify -CAfile "$CA_CRT" "$SRV_CRT" 2>/dev/null
echo "cert-init: SANs in cert:"
openssl x509 -in "$SRV_CRT" -noout -text 2>/dev/null | grep -A4 "Subject Alternative" || true

echo "selfsigned" > "$MODE_FILE"
printf '{"private_ip":"%s","public_ip":"%s","backend_domain":"","cert_mode":"selfsigned"}' \
  "$PRIVATE_IP" "${PUBLIC_IP:-}" > "$META"

echo "cert-init: Done. Certificates valid for 10 years."
