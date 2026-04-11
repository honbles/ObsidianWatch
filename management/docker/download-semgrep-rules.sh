#!/bin/sh
set -e
RULES=/semgrep-rules

mkdir -p $RULES

echo "Downloading semgrep rule packs..."

# Use semgrep to save rules locally
# semgrep --config=p/python --dry-run --dump-command to get rule list
# Better: download the semgrep-rules repo subset directly

REPO="https://raw.githubusercontent.com/semgrep/semgrep-rules/develop"

# Python security rules
for rule in \
  "python/lang/security/audit/exec-detected" \
  "python/lang/security/audit/formatted-sql-query" \
  "python/lang/security/audit/subprocess-shell-true" \
  "python/lang/security/audit/pickle" \
  "python/lang/security/audit/yaml-load" \
  "python/lang/security/audit/jinja2/missing-autoescape-disabled" \
  "python/lang/security/audit/dangerous-system-call" \
  "python/django/security/audit/csrf-exempt" \
  "python/django/security/audit/secure-set-cookie" \
  "python/flask/security/audit/debug-enabled" \
  "python/requests/security/disabled-cert-validation"; do
  curl -sf "$REPO/${rule}.yaml" -o "$RULES/$(echo $rule | tr '/' '-').yaml" 2>/dev/null && echo "✓ $rule" || echo "✗ $rule (skip)"
done

# JavaScript security
for rule in \
  "javascript/browser-and-node/security/audit/innerHTML" \
  "javascript/browser-and-node/security/audit/dangerous-spawn-usage" \
  "javascript/browser-and-node/security/audit/eval-detected" \
  "javascript/express/security/audit/dangerous-template-injection" \
  "javascript/express/security/audit/xss/no-res-render-injection" \
  "javascript/lang/security/audit/prototype-pollution" \
  "javascript/jose/security/jwt-none-alg"; do
  curl -sf "$REPO/${rule}.yaml" -o "$RULES/$(echo $rule | tr '/' '-').yaml" 2>/dev/null && echo "✓ $rule" || echo "✗ $rule (skip)"
done

# Go security
for rule in \
  "go/lang/security/audit/database/sql-string-format" \
  "go/lang/security/audit/dangerous-command-injection" \
  "go/lang/security/audit/crypto/bad-tls-settings" \
  "go/lang/security/audit/net/cookie-attribute-missing"; do
  curl -sf "$REPO/${rule}.yaml" -o "$RULES/$(echo $rule | tr '/' '-').yaml" 2>/dev/null && echo "✓ $rule" || echo "✗ $rule (skip)"
done

echo "Semgrep rules download complete. $(ls $RULES/*.yaml 2>/dev/null | wc -l) rules installed."
