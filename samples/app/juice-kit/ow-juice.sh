#!/usr/bin/env bash
# ObsidianWatch application-monitoring test: OWASP Juice Shop (Node/Express) with OpenTelemetry auto-instrumentation.
#
#   ./ow-juice.sh check     is the agent receiver listening, are Node/npm new enough
#   ./ow-juice.sh setup     clone, install, build, fetch the OTel Node package (idempotent; safe to re-run)
#   ./ow-juice.sh start     start Juice Shop on :3000 with telemetry going to the local agent
#   ./ow-juice.sh attack    send test traffic (normal, brute force, parameters, injection signatures, JSON bodies, burst)
#   ./ow-juice.sh status | logs | stop | clean
#
# Run this on the machine that hosts Juice Shop (the one with the ObsidianWatch agent). The management server can
# be a different machine: the agent forwards everything. Keep ow-payload.js and ow-juice-preload.js next to this
# script; setup copies them into the OTel work dir. They add request-body field capture (POST/PUT/PATCH JSON and
# form bodies) on top of plain auto-instrumentation, without editing Juice Shop.
#
# Env:  OW_WORK=~/ow-testapps   work dir (default)      JUICE_PORT=3000
#       OTEL_NODE_ENABLED_INSTRUMENTATIONS   default "http,express" (keeps traces focused; set to "" for everything)
#       OW_OTLP_ENDPOINT   local agent receiver (default http://127.0.0.1:4318)
#       OW_BODY_CAPTURE=0  start without request-body capture
#       OW_SECURITY_EVENTS=0  start without security events (Security tab) (plain auto-instrumentation)
# Needs: git, curl, Node 22.22+ or 24.15+, npm. The Juice Shop run is on the HOST (not Docker) so the agent can verify the process.
# SAFETY: Juice Shop is deliberately vulnerable and listens on ALL interfaces. Use a VM, or block port 3000 from the network
#         (e.g. ufw deny 3000 from anywhere except localhost). Do not run on a shared or internet-facing machine.
set -euo pipefail

WORK="${OW_WORK:-$HOME/ow-testapps}"
PORT="${JUICE_PORT:-3000}"
ENDPOINT="${OW_OTLP_ENDPOINT:-http://127.0.0.1:4318}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPERS="ow-payload.js ow-security.js ow-juice-preload.js"
JUICE_DIR="$WORK/juice-shop"
OTEL_DIR="$WORK/otel-node"
LOG="$WORK/logs/juice-shop.log"
PIDF="$WORK/pids/juice-shop.pid"
BASE="http://127.0.0.1:$PORT"
mkdir -p "$WORK/logs" "$WORK/pids"

die()  { echo "ERROR: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing: $1"; }
# any HTTP answer (even 404) means the server is listening
is_up() { local c; c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$1" || true); [ -n "$c" ] && [ "$c" != "000" ]; }
req()   { curl -s -o /dev/null -w '%{http_code}\n' --max-time 15 "$@" || true; }
tally() { sort | uniq -c | sort -rn | awk '{printf "HTTP %s x%s  ", $2, $1} END{print ""}'; }

node_ok() {
  node -e 'const [a,b]=process.versions.node.split(".").map(Number);process.exit((a>=24&&(a>24||b>=15))||(a===22&&b>=22)||a>=26?0:1)'
}

check_agent() {
  local code; code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 -X POST -H 'Content-Type: application/json' -d '{}' "$ENDPOINT/v1/traces" || true)
  if [ -z "$code" ] || [ "$code" = "000" ]; then
    echo "!! nothing listening on $ENDPOINT. Install an agent built with 'Enable the app-server profile' on THIS machine." >&2
    return 1
  fi
  echo "ok  agent receiver reachable ($ENDPOINT -> HTTP $code)"
}

cmd_check() {
  need git; need curl; need node; need npm
  if node_ok; then echo "ok  node $(node -v), npm $(npm -v)"; else echo "!! node $(node -v) is too old for Juice Shop (need 22.22+ or 24.15+)"; fi
  check_agent || true
  [ -d "$JUICE_DIR/node_modules" ] && echo "ok  Juice Shop installed" || echo "..  Juice Shop not installed yet (run setup)"
  [ -f "$JUICE_DIR/build/app.js" ] && echo "ok  server build present" || echo "..  server build missing (setup creates it)"
  [ -d "$OTEL_DIR/node_modules/@opentelemetry/auto-instrumentations-node" ] && echo "ok  OTel Node package installed" || echo "..  OTel Node package missing (setup installs it)"
  local h
  for h in $HELPERS; do
    [ -f "$SCRIPT_DIR/$h" ] && echo "ok  $h next to this script" || echo "!!  $h missing next to this script (needed by setup)"
    [ -f "$OTEL_DIR/$h" ] && echo "ok  $h installed in the OTel dir" || echo "..  $h not installed yet (setup copies it)"
  done
}

# ow-payload.js + ow-juice-preload.js: request-body field capture. Copied beside the OTel packages so they resolve them.
install_helpers() {
  mkdir -p "$OTEL_DIR"
  local h
  for h in $HELPERS; do
    [ -f "$SCRIPT_DIR/$h" ] || die "$h not found next to $0 (keep the files from the kit together)"
    cp "$SCRIPT_DIR/$h" "$OTEL_DIR/$h"
  done
  (cd "$OTEL_DIR" && node -e "require.resolve('@opentelemetry/sdk-node'); require.resolve('@opentelemetry/api')") \
    || die "@opentelemetry/sdk-node not resolvable in $OTEL_DIR; re-run setup"
  # security events (Security tab) need the OTel logs packages; add them when missing
  (cd "$OTEL_DIR" && node -e "['@opentelemetry/api-logs','@opentelemetry/sdk-logs','@opentelemetry/exporter-logs-otlp-http','@opentelemetry/resources'].forEach(m=>require.resolve(m))" 2>/dev/null) \
    || (cd "$OTEL_DIR" && npm install --no-audit --no-fund @opentelemetry/api-logs @opentelemetry/sdk-logs @opentelemetry/exporter-logs-otlp-http @opentelemetry/resources >/dev/null 2>&1) \
    || echo "   (could not install the OTel logs packages: security events will be skipped)"
  echo "   request-body helper installed in $OTEL_DIR"
}

cmd_setup() {
  need git; need curl; need node; need npm
  node_ok || die "Juice Shop needs Node 22.22+ or 24.15+ (found $(node -v)). Install Node 24, e.g. NodeSource setup_24.x."
  export CYPRESS_INSTALL_BINARY=0   # the Cypress test binary is large and not needed

  [ -d "$JUICE_DIR" ] || git clone --depth 1 https://github.com/juice-shop/juice-shop.git "$JUICE_DIR"

  if [ ! -d "$JUICE_DIR/node_modules" ]; then
    # --ignore-scripts: Juice Shop's postinstall runs a nested npm install + Angular build that fails on some npm
    # versions; the steps are done separately below so one failure does not block the API.
    echo "== installing Juice Shop dependencies"
    (cd "$JUICE_DIR" && npm install --omit=dev --ignore-scripts --no-audit --no-fund)
  fi

  # Native modules (Juice Shop needs sqlite3 and libxmljs2). Newer npm blocks their install scripts until approved.
  echo "== native modules"
  (cd "$JUICE_DIR" && { npm install-scripts approve sqlite3 libxmljs2 2>/dev/null || true; npm rebuild sqlite3 libxmljs2 2>&1 | tail -2 || true; })
  (cd "$JUICE_DIR" && node -e "require('sqlite3')") \
    || die "sqlite3 does not load. Try: cd $JUICE_DIR && npm install-scripts approve sqlite3 && npm rebuild sqlite3"
  # libxmljs2 is optional (one XXE challenge only). Try to add it; carry on without it.
  (cd "$JUICE_DIR" && node -e "require('libxmljs2')" 2>/dev/null) || {
    (cd "$JUICE_DIR" && npm install --no-save --no-audit --no-fund libxmljs2 >/dev/null 2>&1; npm install-scripts approve libxmljs2 2>/dev/null || true; npm rebuild libxmljs2 >/dev/null 2>&1 || true)
    (cd "$JUICE_DIR" && node -e "require('libxmljs2')" 2>/dev/null) && echo "   libxmljs2 ok" || echo "   libxmljs2 unavailable (optional; only one XXE challenge needs it)"
  }

  # --omit=dev leaves no TypeScript compiler, so the postinstall server build can fail silently: build it explicitly.
  if [ ! -f "$JUICE_DIR/build/app.js" ]; then
    echo "== building the server (TypeScript)"
    (cd "$JUICE_DIR" && npm install --no-save --no-audit --no-fund typescript && npm run build:server)
  fi
  [ -f "$JUICE_DIR/build/app.js" ] || die "server build missing (build/app.js); see the npm output above"

  if [ ! -d "$JUICE_DIR/frontend/dist/frontend" ]; then
    echo "== web UI (optional, several minutes; the API works without it)"
    (cd "$JUICE_DIR/frontend" && npm install --no-audit --no-fund && npm run build) >"$WORK/logs/frontend-build.log" 2>&1 \
      && echo "   frontend built" \
      || echo "   frontend build failed (see $WORK/logs/frontend-build.log). The API is fine; only the browser UI is missing."
  fi

  echo "== OpenTelemetry Node auto-instrumentation"
  mkdir -p "$OTEL_DIR"
  (cd "$OTEL_DIR" && { [ -f package.json ] || npm init -y >/dev/null; } && npm install --no-audit --no-fund @opentelemetry/auto-instrumentations-node)
  (cd "$OTEL_DIR" && node -p "require.resolve('@opentelemetry/auto-instrumentations-node/register')" >/dev/null) \
    || die "OTel register file not found in $OTEL_DIR"
  install_helpers
  echo "setup complete. Next: $0 start"
}

cmd_start() {
  [ -f "$JUICE_DIR/build/app.js" ] || die "not set up: run $0 setup"
  if is_up "$BASE/"; then echo "juice-shop already up on :$PORT"; return; fi
  check_agent || echo "(continuing: telemetry will be dropped until an agent is listening)"
  local reg
  if [ "${OW_BODY_CAPTURE:-1}" = "0" ]; then
    reg=$(cd "$OTEL_DIR" && node -p "require.resolve('@opentelemetry/auto-instrumentations-node/register')") \
      || die "OTel package missing: run $0 setup"
    echo "using plain OTel preload (body capture off): $reg"
  else
    install_helpers >/dev/null   # always run the copy next to this script, so edits take effect on restart
    reg="$OTEL_DIR/ow-juice-preload.js"
    [ -f "$reg" ] || die "preload missing: run $0 setup"
    echo "using OTel preload with request-body capture: $reg"
  fi

  export OTEL_SERVICE_NAME="juice-shop"
  export OTEL_RESOURCE_ATTRIBUTES="deployment.environment.name=test,service.version=$(cd "$JUICE_DIR" && node -p "require('./package.json').version" 2>/dev/null || echo 1.0.0)"
  export OTEL_EXPORTER_OTLP_ENDPOINT="$ENDPOINT"
  export OTEL_EXPORTER_OTLP_PROTOCOL="http/protobuf"   # the agent does not accept gRPC
  export OTEL_TRACES_EXPORTER="otlp"
  export OTEL_LOGS_EXPORTER="none"
  export OTEL_METRICS_EXPORTER="none"
  export OTEL_BSP_SCHEDULE_DELAY="1000"
  export OTEL_NODE_ENABLED_INSTRUMENTATIONS="${OTEL_NODE_ENABLED_INSTRUMENTATIONS-http,express}"
  [ -n "$OTEL_NODE_ENABLED_INSTRUMENTATIONS" ] || unset OTEL_NODE_ENABLED_INSTRUMENTATIONS
  export OW_JUICE_DIR="$JUICE_DIR"
  unset OW_JUICE_PRELOADED

  : > "$LOG"
  # 'npm start' is just 'node build/app'. Run node directly so the preload is not also loaded into npm itself
  # and the pid file holds the Juice Shop process.
  (cd "$JUICE_DIR" && PORT="$PORT" NODE_OPTIONS="--require $reg" nohup node build/app >>"$LOG" 2>&1 & echo $! >"$PIDF")
  echo "starting juice-shop (pid $(cat "$PIDF")) ..."
  for _ in $(seq 1 120); do
    if is_up "$BASE/"; then
      echo "juice-shop up: $BASE   (service name: juice-shop, environment: test)"
      if [ "${OW_BODY_CAPTURE:-1}" != "0" ]; then
        grep -q "request-body capture hooked" "$LOG" && echo "ok  request-body capture hooked into Juice Shop's body parser" \
          || echo "!!  body capture hook not seen in the log: POST routes will show no fields. See: $0 logs"
        grep -q "security events enabled" "$LOG" && echo "ok  security events enabled (Security tab: auth.login, authz.deny, input.rejected)" \
          || echo "..  security events not enabled (see: $0 logs); the Security tab stays empty"

      fi
      return
    fi
    sleep 1
  done
  echo "juice-shop did not come up; log tail:"; tail -25 "$LOG"; exit 1
}

must_be_up() { is_up "$BASE/" || die "juice-shop is not running on :$PORT. Run: $0 start (log: $LOG)"; }

cmd_attack() {
  must_be_up
  echo "== 1/6 normal traffic (builds the baseline)"
  for i in $(seq 1 30); do req "$BASE/rest/products/search?q=apple"; req "$BASE/api/Products/$((i%10+1))"; req "$BASE/rest/admin/application-version"; done | tally

  echo "== 2/6 login brute force: 25 failures from one client      -> APP-A01 (needs >= 20 in 5 min)"
  for i in $(seq 1 25); do req -X POST -H 'Content-Type: application/json' -d "{\"email\":\"admin@juice-sh.op\",\"password\":\"wrong$i\"}" "$BASE/rest/user/login"; done | tally

  echo "== 3/6 parameter names on a route (names only; route shows 'needs review')"
  for i in $(seq 1 15); do req -G "$BASE/rest/products/search" --data-urlencode "q=widget$i" --data-urlencode "page=$i" --data-urlencode "sort=asc" --data-urlencode "token=SECRET$i"; done | tally

  echo "== 4/6 injection signatures in query parameters (each class is counted per client and route) -> APP-A09 (needs >= 3 in 5 min)"
  {
    req -G "$BASE/rest/products/search" --data-urlencode "q=' OR 1=1--"                                   # sql-injection
    req -G "$BASE/rest/products/search" --data-urlencode "q=1 UNION SELECT id,email,password FROM Users"   # sql-injection
    req -G "$BASE/rest/products/search" --data-urlencode "q=%2527%2520OR%25201%253D1--"                    # sql-injection, double-encoded
    req -G "$BASE/rest/products/search" --data-urlencode "q=<script>alert(1)</script>"                     # script-injection
    req -G "$BASE/rest/products/search" --data-urlencode "q=../../../../etc/passwd"                        # path-traversal
    req -G "$BASE/rest/products/search" --data-urlencode "q=x; cat /etc/shadow"                            # command-injection
    req -G "$BASE/rest/products/search" --data-urlencode 'q=${jndi:ldap://x.example/a}'                    # jndi-injection
  } | tally

  echo "== 5/6 JSON bodies on POST/PUT/PATCH routes (field names show on the route; review the route, then re-run to see values)"
  {
    for i in $(seq 1 10); do
      req -X POST -H 'Content-Type: application/json' -d "{\"email\":\"ow-body$i@example.test\",\"password\":\"Passw0rd!$i\",\"passwordRepeat\":\"Passw0rd!$i\",\"securityQuestion\":{\"id\":1,\"answer\":\"x\"},\"securityAnswer\":\"x\"}" "$BASE/api/Users"
      req -X POST -H 'Content-Type: application/json' -d "{\"email\":\"ow-body$i@example.test\",\"password\":\"wrong$i\"}" "$BASE/rest/user/login"
      req -X POST -H 'Content-Type: application/json' -d "{\"comment\":\"ow feedback $i\",\"rating\":4,\"captchaId\":$i,\"captcha\":\"0\"}" "$BASE/api/Feedbacks"
      req -X PUT  -H 'Content-Type: application/json' -d "{\"message\":\"review $i\",\"author\":\"ow-body$i@example.test\"}" "$BASE/rest/products/1/reviews"
      req -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d "name=widget$i&qty=$i&card=4111111111111111" "$BASE/api/Quantitys"
    done
  } | tally

  echo "== 6/6 burst: 200 quick requests (Juice Shop does not rate-limit this route, so APP-A13 will not fire)"
  for i in $(seq 1 200); do req "$BASE/rest/admin/application-version"; done | tally

  cat <<EOF

Wait 1-2 minutes, then in the console: Applications > Services > juice-shop (environment test).
  Instances   identity should say 'verified' with the node process
  Routes      /rest/products/search with parameters q, page, sort, token (status: needs review);
              POST /rest/user/login with 25+ in the 401/403 column and body fields email, password
              (also POST /api/Users, POST /api/Feedbacks, PUT /rest/products/:id/reviews)
              Open Review on a route, mask what you want, save; wait up to 5 minutes for the agent to pull the
              policy, run attack again, then open Review again to see the samples (password/token/card never)
  Security / Alerts   [APP-A01] and [APP-A09] (Info while rules are in observe mode)
  Events      the service timeline (connections, lifecycle, alerts)
  Dependencies  outgoing calls (Juice Shop contacts a few external hosts; local ports link to discovered services)
Then: Settings > set exposure to 'internet' and promote a rule out of observe mode to see the real severity.
EOF
}

cmd_status() {
  check_agent || true
  if is_up "$BASE/"; then echo "juice-shop: UP on :$PORT"; else echo "juice-shop: down"; fi
  if [ -f "$LOG" ]; then
    grep -q "request-body capture hooked" "$LOG" && echo "body capture: hooked" || echo "body capture: NOT hooked (POST routes will show no fields)"
    grep -q "security events enabled" "$LOG" && echo "security events: enabled" || echo "security events: off (Security tab stays empty)"
  fi
  [ -f "$PIDF" ] && echo "pid file: $(cat "$PIDF")"
}

cmd_logs()  { [ -f "$LOG" ] && tail -n "${1:-40}" "$LOG" || echo "no log yet: $LOG"; }

cmd_stop() {
  if [ -f "$PIDF" ]; then
    local pid; pid=$(cat "$PIDF")
    pkill -P "$pid" 2>/dev/null || true
    kill "$pid" 2>/dev/null || true
    rm -f "$PIDF"; echo "stopped juice-shop"
  else
    echo "no pid file; nothing to stop"
  fi
  # npm start spawns node as a grandchild; make sure nothing is left listening on the port
  local left; left=$( (command -v lsof >/dev/null && lsof -ti tcp:"$PORT" -sTCP:LISTEN) 2>/dev/null || true)
  [ -n "$left" ] && { echo "killing leftover listener(s): $left"; kill $left 2>/dev/null || true; }
  return 0
}

cmd_clean() { cmd_stop; rm -rf "$WORK"; echo "removed $WORK"; }

case "${1:-}" in
  check)  cmd_check ;;
  setup)  cmd_setup ;;
  start)  cmd_start ;;
  attack) cmd_attack ;;
  status) cmd_status ;;
  logs)   cmd_logs "${2:-40}" ;;
  stop)   cmd_stop ;;
  clean)  cmd_clean ;;
  *)      sed -n 2,16p "$0" ;;
esac
