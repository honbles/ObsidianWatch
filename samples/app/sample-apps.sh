#!/usr/bin/env bash
# sample-apps.sh - fetch, instrument and run the ObsidianWatch sample applications, then attack them.
#
# Five real applications, one per language, instrumented to Tier 2 the way docs/application/ describes. Each is
# cloned from its upstream repository at a fixed commit and the ObsidianWatch instrumentation patch stored at the
# end of this file is applied (go-orders is ObsidianWatch's own small Go service, stored whole). Each app then
# installs its dependencies, builds and starts on its own free random port on 0.0.0.0.
#
#   ./sample-apps.sh               install missing tools, fetch + instrument, start every app, print the URLs
#   ./sample-apps.sh traffic       ordinary traffic for every running app (logins, denials, bad input, errors, queries)
#   ./sample-apps.sh attack        app-layer attacks on every running app: brute force, SQL/NoSQL injection,
#                                  auth bypass, IDOR, data export, a crash (fires the APP detection rules)
#   ./sample-apps.sh attack -n 3 juice-shop    three passes, one app
#   ./sample-apps.sh status        what is running and where
#   ./sample-apps.sh logs <app>    follow one app's log
#   ./sample-apps.sh stop          stop the apps and the databases they started
#   ./sample-apps.sh fetch         only fetch and instrument (FRESH=1 to fetch again)
#   ./sample-apps.sh clean         stop and delete everything under DEST
#
# Apps: juice-shop (Node 22, SQLite; admin@juice-sh.op / admin123), fastapi (Python 3.14, PostgreSQL;
# admin@example.com / changethis), petclinic (Java 17+, H2), eshop (.NET 8; demouser@microsoft.com / Pass@word1),
# go-orders (Go 1.25, PostgreSQL; alice@example.com / orders-demo-1, API only).
#
# Options (environment variables):
#   APPS="juice-shop go-orders"   only these apps (default: all five)
#   DEST=/srv/ow-apps             where the apps go (default: /opt/ow-sample-apps as root, else ~/ow-sample-apps)
#   OTEL_EXPORTER_OTLP_ENDPOINT   the ObsidianWatch agent on this host (default http://127.0.0.1:4318, app-server profile)
#   SKIP_INSTALL=1                do not install tools;  FRESH=1  fetch again over an existing copy
#
# Needs internet access on first run: GitHub, and the apps' package registries (npm, PyPI, Maven Central, NuGet,
# proxy.golang.org). On Debian/Ubuntu missing tools are installed (curl, git, python3, build-essential, Node.js 22,
# uv, OpenJDK 21, .NET 8 SDK, Go, and the PostgreSQL server when Docker is not running). An app whose tool or
# source cannot be fetched is skipped with the reason; the others still start. Each app's OBSIDIANWATCH.md lists
# its changes. These are test applications and Juice Shop is deliberately vulnerable: never expose them to the
# internet. Attacks only target the apps on this host.
set -euo pipefail
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
if [ "$(id -u)" = 0 ]; then DEST="${DEST:-/opt/ow-sample-apps}"; else DEST="${DEST:-$HOME/ow-sample-apps}"; fi
TOOLS=/opt/ow-tools
LOGS="$DEST/logs"
export OTEL_EXPORTER_OTLP_ENDPOINT="${OTEL_EXPORTER_OTLP_ENDPOINT:-http://127.0.0.1:4318}"
# Local traffic never goes through a proxy: the apps' telemetry to the agent (127.0.0.1:4318), the status checks
# and the sample traffic. Python (requests) and .NET honour HTTP(S)_PROXY for 127.0.0.1 unless NO_PROXY lists it,
# so with a proxy configured their telemetry went to the proxy and was lost, and the proxy's answer made a stopped
# app look "up". The tools' downloads still use the proxy.
export NO_PROXY="127.0.0.1,localhost,::1${NO_PROXY:+,$NO_PROXY}" no_proxy="127.0.0.1,localhost,::1${no_proxy:+,$no_proxy}"
ALL="juice-shop fastapi petclinic eshop go-orders"
APPS="${APPS:-$ALL}"

dir_of() { case $1 in juice-shop) echo juice-shop ;; fastapi) echo full-stack-fastapi-template ;; petclinic) echo spring-petclinic ;;
  eshop) echo eShopOnWeb ;; go-orders) echo go-orders ;; esac; }
say() { printf '\033[1m== %s\033[0m\n' "$*"; }
warn() { printf '\033[33m!! %s\033[0m\n' "$*" >&2; }

SUDO=""; [ "$(id -u)" = 0 ] || SUDO="sudo"
for d in "$TOOLS/node/bin" "$TOOLS/go/bin" "$TOOLS/dotnet" "$HOME/.local/bin" "$HOME/go/bin"; do
  [ -d "$d" ] && case ":$PATH:" in *":$d:"*) ;; *) PATH="$d:$PATH" ;; esac
done
export PATH
[ -d "$TOOLS/dotnet" ] && export DOTNET_ROOT="$TOOLS/dotnet"

# ---------- tools ----------
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }   # ver_ge have want
arch() { case "$(uname -m)" in x86_64|amd64) echo x64 ;; aarch64|arm64) echo arm64 ;; *) uname -m ;; esac; }
goarch() { case "$(uname -m)" in x86_64|amd64) echo amd64 ;; aarch64|arm64) echo arm64 ;; *) uname -m ;; esac; }
APT_UPDATED=""
apt_install() {
  command -v apt-get >/dev/null || { warn "no apt-get: install $* yourself"; return 1; }
  [ -n "$APT_UPDATED" ] || { $SUDO apt-get update -qq || warn "apt-get update reported problems (see above); using the package lists it has"; APT_UPDATED=1; }
  DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq "$@" >/dev/null
}
apt_has() { command -v apt-cache >/dev/null && apt-cache show "$1" >/dev/null 2>&1; }
need() { local a; for a in "$@"; do case " $APPS " in *" $a "*) return 0 ;; esac; done; return 1; }

# Downloads give up after 20 s without a connection instead of hanging for minutes on a blocked host.
CURL="curl -fsSL --connect-timeout 20 --retry 2"
SKIPPED=""
# skip_app removes an app whose tool could not be installed; the other apps still run.
skip_app() {
  warn "skipping $1: $2"
  SKIPPED="$SKIPPED $1"
  APPS=$(echo " $APPS " | sed "s/ $1 / /g" | xargs)
}

install_base() {
  local base=()
  for c in curl git python3 gzip; do command -v $c >/dev/null || base+=("$c"); done
  command -v cc >/dev/null || base+=(build-essential)
  command -v pip3 >/dev/null || base+=(python3-pip)
  command -v xz >/dev/null || base+=(xz-utils)
  [ -e /etc/ssl/certs/ca-certificates.crt ] || base+=(ca-certificates)
  [ ${#base[@]} -eq 0 ] && return 0
  say "installing ${base[*]}"
  apt_install "${base[@]}" || warn "apt could not install ${base[*]} (see the messages above)"
}

install_node() {   # Node.js 22.15+ (OpenTelemetry JS needs it)
  local nv; nv=$(node -v 2>/dev/null | tr -d v || true)
  [ -n "$nv" ] && ver_ge "$nv" 22.15.0 && return 0
  say "installing Node.js 22 into $TOOLS/node"
  local f; f=$($CURL https://nodejs.org/dist/latest-v22.x/SHASUMS256.txt | grep -o "node-v22[0-9.]*-linux-$(arch).tar.xz" | head -1) || true
  [ -n "$f" ] || return 1
  $SUDO mkdir -p "$TOOLS/node"
  $CURL "https://nodejs.org/dist/latest-v22.x/$f" | $SUDO tar -xJ -C "$TOOLS/node" --strip-components=1 || return 1
  PATH="$TOOLS/node/bin:$PATH"
}

install_uv() {     # uv fetches Python 3.14 itself
  command -v uv >/dev/null && return 0
  say "installing uv"
  if ! $CURL https://astral.sh/uv/install.sh | env UV_NO_MODIFY_PATH=1 sh >/dev/null; then
    python3 -m pip install --user --quiet uv 2>/dev/null || python3 -m pip install --user --quiet --break-system-packages uv || return 1
  fi
  PATH="$HOME/.local/bin:$PATH"
  command -v uv >/dev/null
}

install_java() {   # Java 17+
  local jv; jv=$(java -version 2>&1 | sed -n 's/.*version "\([0-9]*\).*/\1/p' | head -1 || true)
  [ -n "$jv" ] && [ "$jv" -ge 17 ] && return 0
  say "installing OpenJDK"
  local p
  for p in openjdk-21-jdk-headless openjdk-25-jdk-headless openjdk-17-jdk-headless; do
    apt_has "$p" && apt_install "$p" && return 0
  done
  return 1
}

install_dotnet() { # .NET SDK 8+
  dotnet --list-sdks 2>/dev/null | grep -q . && return 0
  say "installing the .NET SDK"
  local p
  for p in dotnet-sdk-8.0 dotnet-sdk-9.0 dotnet-sdk-10.0; do
    apt_has "$p" && apt_install "$p" && return 0
  done
  $CURL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh || return 1
  $SUDO bash /tmp/dotnet-install.sh --channel 8.0 --install-dir "$TOOLS/dotnet" >/dev/null || return 1
  export DOTNET_ROOT="$TOOLS/dotnet"; PATH="$TOOLS/dotnet:$PATH"
}

GO_FALLBACK=1.25.7
install_go() {     # Go 1.25+
  local gv; gv=$(go env GOVERSION 2>/dev/null | sed 's/^go//' || true)
  [ -n "$gv" ] && ver_ge "$gv" 1.25.0 && return 0
  # 1. The distribution's package, when it is new enough.
  if apt_has golang-go; then
    say "installing Go from apt"
    apt_install golang-go || true
    gv=$(go env GOVERSION 2>/dev/null | sed 's/^go//' || true)
    [ -n "$gv" ] && ver_ge "$gv" 1.25.0 && return 0
  fi
  # 2. The official archive: go.dev, or Google's download host when go.dev is blocked.
  local v; v=$($CURL 'https://go.dev/dl/?mode=json' 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin)[0]['version'])" 2>/dev/null || true)
  [ -n "$v" ] || v="go$GO_FALLBACK"
  local url
  for url in "https://go.dev/dl/$v.linux-$(goarch).tar.gz" "https://dl.google.com/go/$v.linux-$(goarch).tar.gz" "https://golang.google.cn/dl/$v.linux-$(goarch).tar.gz"; do
    say "installing $v from $(echo "$url" | cut -d/ -f3)"
    $SUDO rm -rf "$TOOLS/go.new"; $SUDO mkdir -p "$TOOLS/go.new"
    if $CURL "$url" | $SUDO tar -xz -C "$TOOLS/go.new" --strip-components=1 2>/dev/null; then
      $SUDO rm -rf "$TOOLS/go"; $SUDO mv "$TOOLS/go.new" "$TOOLS/go"
      PATH="$TOOLS/go/bin:$PATH"
      return 0
    fi
  done
  $SUDO rm -rf "$TOOLS/go.new"
  return 1
}

install_postgres() { # Docker if it runs, else a local server package
  { command -v docker >/dev/null && docker info >/dev/null 2>&1; } && return 0
  ls /usr/lib/postgresql/*/bin/initdb >/dev/null 2>&1 && return 0
  command -v initdb >/dev/null && return 0
  say "installing the PostgreSQL server (its default cluster is stopped and disabled; the apps start their own on random ports)"
  apt_install postgresql || return 1
  $SUDO systemctl disable --now postgresql >/dev/null 2>&1 || $SUDO service postgresql stop >/dev/null 2>&1 || true
}

install_tools() {
  say "checking tools"
  install_base
  need juice-shop && { install_node || skip_app juice-shop "Node.js 22 could not be installed (nodejs.org unreachable?)"; }
  need fastapi && { install_uv || skip_app fastapi "uv could not be installed (astral.sh and PyPI unreachable?)"; }
  need petclinic && { install_java || skip_app petclinic "no OpenJDK 17+ package available"; }
  need eshop && { install_dotnet || skip_app eshop ".NET SDK could not be installed"; }
  need go-orders && { install_go || skip_app go-orders "Go 1.25+ could not be installed (go.dev and dl.google.com unreachable?)"; }
  if need fastapi go-orders; then
    install_postgres || { need fastapi && skip_app fastapi "no PostgreSQL (start Docker or install postgresql)"; need go-orders && skip_app go-orders "no PostgreSQL (start Docker or install postgresql)"; }
  fi
  export PATH
  [ -n "$APPS" ] || { warn "no app can run: every tool install failed"; exit 1; }
}

# ---------- ports ----------
USED_PORTS=" "
free_port() {
  local p
  while :; do
    p=$(python3 -c "import socket;s=socket.socket();s.bind(('0.0.0.0',0));print(s.getsockname()[1]);s.close()")
    case "$USED_PORTS" in *" $p "*) continue ;; esac
    USED_PORTS="$USED_PORTS$p "; echo "$p"; return
  done
}

# ---------- commands ----------
# upstream repository and commit each app's instrumentation patch applies to (go-orders has no upstream)
upstream_of() { case $1 in
  juice-shop) echo "https://github.com/juice-shop/juice-shop c9f99228d9d56afb5f5ca7925376292f7fa44b13" ;;
  fastapi)    echo "https://github.com/fastapi/full-stack-fastapi-template f8c6c147b12bb1c4d3253cc1b06f8b5ef81b10dd" ;;
  petclinic)  echo "https://github.com/spring-projects/spring-petclinic 3aae6ccdd35535054dc972439a461243d41655e2" ;;
  eshop)      echo "https://github.com/dotnet-architecture/eShopOnWeb 4da8212117e87d808d4bbc7da6286fd2147ce606" ;;
  go-orders)  echo "" ;;
esac; }
# patch_of prints an app's instrumentation patch (stored gzip+base64 at the end of this file)
patch_of() { awk -v n="$1" '$0=="#@@PATCH "n{f=1;next} $0=="#@@END "n{f=0} f' "$SELF" | base64 -d | gunzip; }

fetch_apps() {
  mkdir -p "$DEST" "$LOGS"
  for a in $APPS; do
    local d; d="$DEST/$(dir_of "$a")"
    if [ -d "$d" ] && [ -z "${FRESH:-}" ]; then continue; fi
    rm -rf "${d:?}"; mkdir -p "$d"
    say "fetching $a"
    set -- $(upstream_of "$a")
    if ! (cd "$d" && git init -q && { [ -z "${1:-}" ] || { git fetch -q --depth 1 "$1" "$2" && git checkout -q FETCH_HEAD; }; } \
          && patch_of "$a" | git apply --whitespace=nowarn); then
      rm -rf "${d:?}"; skip_app "$a" "could not fetch ${1:-the source} or apply the instrumentation patch"; continue
    fi
    chmod +x "$d/run.sh" "$d/mvnw" 2>/dev/null || true
  done
}

pid_alive() { [ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null; }

start() {
  for a in $APPS; do
    local d="$DEST/$(dir_of "$a")" pidf="$LOGS/$a.pid"
    [ -d "$d" ] || continue
    if pid_alive "$pidf"; then say "$a already running"; continue; fi
    local port; port=$(free_port)
    say "starting $a (port $port)"
    # setsid makes the app its own process group, so stop can end it with every child it started
    (cd "$d" || exit 1; PORT=$port HOST=0.0.0.0 exec setsid bash -c 'echo $$ > "$1"; exec ./run.sh' _ "$pidf") > "$LOGS/$a.log" 2>&1 < /dev/null &
    for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$pidf" ] && break; sleep 0.2; done
    echo "$port" > "$LOGS/$a.port"
  done
  say "installing and building; first start takes several minutes per app (logs in $LOGS)"
  local deadline=$(( $(date +%s) + ${WAIT_SECONDS:-1500} ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    local pending=0
    for a in $APPS; do
      [ -f "$LOGS/$a.pid" ] || continue
      if pid_alive "$LOGS/$a.pid" && ! up "$a"; then pending=1; fi
    done
    [ $pending = 0 ] && break
    sleep 5
  done
  status
  [ -n "$SKIPPED" ] && warn "not started (tool missing):$SKIPPED"
  return 0
}

# up: the app's own port answers HTTP (any status). --noproxy: a proxy must not answer for 127.0.0.1.
up() {
  local code; code=$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$(cat "$LOGS/$1.port" 2>/dev/null)/" 2>/dev/null)
  [ -n "$code" ] && [ "$code" != "000" ]
}

status() {
  local ip; ip=$(hostname -I 2>/dev/null | awk '{print $1}'); ip=${ip:-127.0.0.1}
  printf '\n%-11s %-9s %-28s %s\n' APP STATE URL "SIGN-IN / NOTES"
  for a in $APPS; do
    local port state note; port=$(cat "$LOGS/$a.port" 2>/dev/null || echo -)
    if ! pid_alive "$LOGS/$a.pid"; then state=stopped; elif up "$a"; then state=up; else state=starting; fi
    case $a in
      juice-shop) note="register in the UI; admin@juice-sh.op / admin123" ;;
      fastapi)    note="admin@example.com / changethis (UI /, API /docs)" ;;
      petclinic)  note="no sign-in" ;;
      eshop)      note="demouser@microsoft.com / Pass@word1" ;;
      go-orders)  note="API only: alice@example.com / orders-demo-1" ;;
    esac
    printf '%-11s %-9s %-28s %s\n' "$a" "$state" "http://$ip:$port" "$note"
    if [ "$state" = stopped ] && [ -f "$LOGS/$a.log" ]; then
      warn "$a stopped; last lines of $LOGS/$a.log:"; tail -5 "$LOGS/$a.log" | sed 's/^/     /' >&2
    fi
  done
  echo; echo "Telemetry goes to $OTEL_EXPORTER_OTLP_ENDPOINT. Send traffic: $0 traffic   Attack: $0 attack"
}

traffic() {
  for a in $APPS; do
    local d="$DEST/$(dir_of "$a")"
    pid_alive "$LOGS/$a.pid" && up "$a" || { warn "$a is not up"; continue; }
    say "traffic: $a"; (cd "$d" && ./run.sh traffic) || warn "$a traffic failed"
  done
}

stop() {
  for a in $APPS; do
    local pidf="$LOGS/$a.pid"
    if pid_alive "$pidf"; then
      say "stopping $a"; local p; p=$(cat "$pidf")
      kill -TERM -- "-$p" 2>/dev/null || kill -TERM "$p" 2>/dev/null || true
      for _ in $(seq 1 20); do kill -0 "$p" 2>/dev/null || break; sleep 0.5; done
      kill -KILL -- "-$p" 2>/dev/null || true
    fi
    rm -f "$pidf"
    case $a in fastapi|go-orders|eshop) (cd "$DEST/$(dir_of "$a")" 2>/dev/null && ./run.sh stop-db >/dev/null 2>&1) || true ;; esac
  done
}

# ---------- attack ----------
# Wrapper functions (not string variables) so the --noproxy '*' is never glob-expanded by the shell.
C()  { curl --noproxy '*' -s -o /dev/null --max-time 10 "$@"; }   # discard the body
CB() { curl --noproxy '*' -s --max-time 10 "$@"; }                # keep the body (tokens)
port() { cat "$LOGS/$1.port" 2>/dev/null; }
running() { local p; p=$(port "$1"); [ -n "$p" ] && curl --noproxy '*' -s -o /dev/null --max-time 3 "http://127.0.0.1:$p/" 2>/dev/null; }
note() { printf '   %s\n' "$*"; }

# ── Per-app attack sets ─────────────────────────────────────────────────────────

atk_juice_shop() {   # Node, SQLite. Failed logins return 401 (feeds the login-failure burst rule).
  local b="http://127.0.0.1:$(port juice-shop)"
  note "credential brute force (25 bad logins)"
  for i in $(seq 1 25); do C -X POST -H 'Content-Type: application/json' -d "{\"email\":\"victim$i@juice-sh.op\",\"password\":\"Guess$i!\"}" "$b/rest/user/login"; done
  note "SQL injection on the login email"
  for p in "' OR 1=1 --" "') OR ('1'='1" "admin'--" "' UNION SELECT * FROM Users --"; do
    C -X POST -H 'Content-Type: application/json' -d "{\"email\":\"$p\",\"password\":\"x\"}" "$b/rest/user/login"; done
  note "SQL/NoSQL injection in product search and REST query strings"
  for q in "apple" "')) --" "' OR 1=1--" "qwert%27%20UNION%20SELECT" ; do C "$b/rest/products/search?q=$q"; done
  C "$b/rest/track-order/%27%20OR%201%3D1--"
  note "broken access control (unauthenticated and forged-token access)"
  for u in /rest/admin/application-configuration /api/Users /rest/user/whoami /api/Feedbacks /api/Challenges; do
    C -H "Authorization: Bearer forged.jwt.token" "$b$u"; C "$b$u"; done
  note "a valid login, then a data export (data.export event)"
  local tok; tok=$(CB -X POST -H 'Content-Type: application/json' -d '{"email":"jim@juice-sh.op","password":"ncc-1701"}' "$b/rest/user/login" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
  if [ -n "$tok" ]; then
    C -H "Authorization: Bearer $tok" "$b/rest/user/whoami"
    C -X POST -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' -d '{"format":"1"}' "$b/rest/user/data-export"
  fi
}

atk_fastapi() {   # Python. Failed login is 400, so the burst rule does not fire, but the events still show.
  local b="http://127.0.0.1:$(port fastapi)/api/v1"
  note "credential brute force (25 bad logins)"
  for i in $(seq 1 25); do C -X POST --data-urlencode "username=victim$i@example.com" --data-urlencode "password=Guess$i!" "$b/login/access-token"; done
  note "SQL injection in the login form"
  for p in "' OR '1'='1" "admin@example.com' --"; do C -X POST --data-urlencode "username=$p" --data-urlencode "password=x" "$b/login/access-token"; done
  note "broken access control (no token / forged token on protected routes)"
  for u in /users/ /users/me /items/; do C "$b$u"; C -H "Authorization: Bearer forged" "$b$u"; done
  note "invalid input (schema validation failures -> input.rejected)"
  C -H 'Content-Type: application/json' -d '{"email":"not-an-email","password":"x"}' "$b/users/signup"
  C -H 'Content-Type: application/json' -d '{"bad":"body"}' "$b/users/signup"
  note "a valid admin login, then listing users (data.export) and an admin create (admin.action)"
  local tok; tok=$(CB -X POST --data-urlencode "username=admin@example.com" --data-urlencode "password=changethis" "$b/login/access-token" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
  if [ -n "$tok" ]; then
    C -H "Authorization: Bearer $tok" "$b/users/"
    C -X POST -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' -d "{\"email\":\"intruder$RANDOM@example.com\",\"password\":\"evaluation-pass-1\"}" "$b/users/"
  fi
}

atk_petclinic() {   # Java, no auth. Exercises routes, form validation and a deliberate crash.
  local b="http://127.0.0.1:$(port petclinic)"
  note "enumerating owners and SQL-ish query strings"
  for q in "Davis" "%27%20OR%201%3D1--" "%3Cscript%3Ealert(1)%3C/script%3E"; do C "$b/owners?lastName=$q"; done
  for id in 1 2 7 9999; do C "$b/owners/$id"; done
  note "invalid form submissions (input.rejected)"
  for i in 1 2 3; do C -X POST -d "firstName=&lastName=&address=&city=&telephone=notaphone" "$b/owners/new"; done
  note "path-ish and unknown routes"
  for u in "/..%2f..%2fetc%2fpasswd" "/admin" "/actuator/env"; do C "$b$u"; done
  note "a deliberate server crash (error group)"
  for i in 1 2 3; do C "$b/oups"; done
}

atk_eshop() {   # .NET. Cookie auth: brute force needs the antiforgery token from the login page.
  local b="http://127.0.0.1:$(port eshop)" jar; jar=$(mktemp)
  note "credential brute force (15 bad logins, with CSRF token)"
  for i in $(seq 1 15); do
    local tok; tok=$(CB -c "$jar" -b "$jar" "$b/Identity/Account/Login" | sed -n 's/.*__RequestVerificationToken"[^>]*value="\([^"]*\)".*/\1/p' | head -1)
    C -c "$jar" -b "$jar" --data-urlencode "Input.Email=victim$i@example.com" --data-urlencode "Input.Password=Guess$i!" --data-urlencode "__RequestVerificationToken=$tok" "$b/Identity/Account/Login"
  done
  note "broken access control (protected pages while anonymous -> authz.deny)"
  for u in /order/my-orders /Basket/Checkout /order/detail/1 /admin; do C "$b$u"; done
  note "odd query strings on the catalog"
  C "$b/?q=%27%20OR%201%3D1--"
  rm -f "$jar"
}

atk_go_orders() {   # Go + Postgres. Failed login is 401 (feeds the burst rule); a report route errors on purpose.
  local b="http://127.0.0.1:$(port go-orders)/api"
  note "credential brute force on one account (25 attempts -> burst + rate limit)"
  for i in $(seq 1 25); do C -H 'Content-Type: application/json' -d "{\"email\":\"victim@example.com\",\"password\":\"Guess$i!\"}" "$b/login"; done
  note "SQL/XSS-ish product search"
  for q in "key" "%27%20OR%201%3D1--" "%3Cscript%3E"; do C "$b/products?q=$q"; done
  note "broken access control (no token, then another user's order)"
  C "$b/orders"; C -H "Authorization: Bearer forged" "$b/orders/1"
  local ta tb
  ta=$(CB -H 'Content-Type: application/json' -d '{"email":"alice@example.com","password":"orders-demo-1"}' "$b/login" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
  tb=$(CB -H 'Content-Type: application/json' -d '{"email":"bob@example.com","password":"orders-demo-1"}' "$b/login" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
  if [ -n "$ta" ]; then
    C -X POST -H "Authorization: Bearer $ta" -H 'Content-Type: application/json' -d '{"product_id":1,"qty":1}' "$b/orders"
    local id; id=$(CB -H "Authorization: Bearer $ta" "$b/orders" | sed -n 's/.*"id":\([0-9]*\).*/\1/p' | head -1)
    [ -n "$id" ] && [ -n "$tb" ] && { note "IDOR: bob reads alice's order (authz.deny)"; C -H "Authorization: Bearer $tb" "$b/orders/$id"; }
    note "data export, then a report route that errors on purpose (error group)"
    C -H "Authorization: Bearer $ta" "$b/orders?format=csv"
    for i in 1 2 3; do C -H "Authorization: Bearer $ta" "$b/reports/unshipped"; done
  fi
}

attack() {
  set +e
  local PASSES=1 ONLY=""
  while [ $# -gt 0 ]; do
    case "$1" in
      -n) PASSES="${2:-1}"; shift 2 ;;
      juice-shop|fastapi|petclinic|eshop|go-orders) ONLY="$ONLY $1"; shift ;;
      *) echo "unknown argument $1"; exit 1 ;;
    esac
  done
  local APPS="${ONLY:-$ALL}"
  ran=""
  for pass in $(seq 1 "$PASSES"); do
    [ "$PASSES" -gt 1 ] && say "pass $pass of $PASSES"
    for a in $APPS; do
      if ! running "$a"; then
        [ "$pass" = 1 ] && note "skipping $a (not running)"
        continue
      fi
      say "attacking $a on port $(port "$a")"
      case "$a" in
        juice-shop) atk_juice_shop ;;
        fastapi)    atk_fastapi ;;
        petclinic)  atk_petclinic ;;
        eshop)      atk_eshop ;;
        go-orders)  atk_go_orders ;;
      esac
      ran="$ran $a"
    done
  done

  echo
  if [ -n "$ran" ]; then
    say "done — attacked:$(echo $ran | tr ' ' '\n' | sort -u | tr '\n' ' ')"
    note "In ObsidianWatch: Application → Services (each attacked app should reach Tier 2), its Security, Endpoints,"
    note "Queries and Errors tabs, and Detect → Alerts for the login-failure burst and injection rules (a minute or two)."
  else
    echo "No running apps found. Start them first: $0 start"
  fi

}

case "${1:-start}" in
  start)   [ -n "${SKIP_INSTALL:-}" ] || install_tools; fetch_apps; start ;;
  fetch)   fetch_apps ;;
  attack)  shift; attack "$@" ;;
  clean)   stop; rm -rf "${DEST:?}"; say "removed $DEST" ;;
  traffic) traffic ;;
  status)  status ;;
  stop)    stop ;;
  logs)    tail -f "$LOGS/${2:?app name}.log" ;;
  *)       sed -n '2,30p' "$0"; exit 1 ;;
esac
exit 0

# ---------- instrumentation patches (gzip + base64; extracted by patch_of) ----------
#@@PATCH juice-shop
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
t2TCqCdzAAA=
#@@END juice-shop
#@@PATCH fastapi
H4sIAAAAAAAC/+S9+3ob2XX2+b+uogJrItIigDofqNAT2S3HPXF365PUdpJ2P+g6SnDzZAKUWumv
n2cuYq5wrmR+764qoAoEyCJBJ9/MdByRBOq49t7r8K53rV3Mq8oaj9/Pl1Y6nZTnH63M/HgyPy/K
n6zSCaPYdyeTwEn82LMtx7ZD338yHo+b4588f/68Peef/9kax0eR9Vz/8Mfvv3zz9t3s7bevX735
9u2rNydpcTY//+fyp/Ts8rSc5BdnTzYPmb1++fbtn79588VJ/iE9f18uP8wXT6wn1q+sV2fp/HTx
ZPz2q3evZ3/45u27k9OLPD39cLFYPnn+K2vLx5bFad9ki3kxT8//nC7zD9ay5OPsen5aHFvnF5Yu
aS3Kq4/l1ZG1uLBKcw8rvSqti6p6Yr366uWXf3w7+/2bb76amd9P5ufVRf8FzI3f/fHtye/T00XZ
/P36mzfvThzbDZ4UXfl+89u3X37x5cuv//zy3e/+MDkrkNvmR0/Oy09WNT8trbOLomzFXQ+GXf83
mSRO6DhxakZhWpQfp+fXp6fNQNy4oAbFPrKt586R5zMqktbvOd56u0zzH63fp4vly9dfWu9K3ild
lkfW/HyxvLo+K8+XZWFVF1cbMjx4/Xn54eL8yHo3L68s9/DJ8yfPv73klDI9O7Y+LJeXi+PplBf+
cJ1JRNOKO6SX82nFTccL3XTcfDReNje10qW1/FBaHH6GpObn1g8Zx5XnxTS9vJxefJp++/rtuzev
Xn41+903X3315bsfJrrtr35lvbk+f/KckbYm06vr88nig9X/71fmddJThvXTB+4yX1hn88Vifv6e
EV+mV8uF9Zq58v6qXBzxzfsrnobfzKRYWN9+aT23JJ2Lcyu1rtLz4uLMury4WuoDe2L+b+P2y6u0
qub56vaLMr84L5h5V8z99PTYqphjCPb04j1PdmQV5fmcP3M94pGVpQUPfHm95BHm78+vLxkOhMQ3
Zu1Y1zyYlebL+cX5YuPGi+XF5bjI1jfmbyPU9v3MH4v8an65rF+9LOpLmNkaM7P6QvwV8/AnHk3v
+8KyzOJy3Mi8tdN54QsrY37yQheXGjREc/pZo/OWF9BQcoDujCzThXVDBVhTa73UJ9bXZVksjq1L
M8c8C4lb+fXV6Qvr+qPGrhlMnmpetQOpg548r0omJy9Zz07Lmzj+ZPXqx9YPX7x89/K3L9++mn37
5o8/6OzPF9cMDjMCWZcsXQb4h8v2eCf6wfrighl4xZw8X6bzc37rTIInz1evK/GsrmCUj5WfXi8Y
cOsTi4BHni8ZloPmWd7+jz82Kse65PT0fflCcrm6uNCjWAh1ob8lsdXj/PDkuQb+cGK94+NPZSZh
Io3Lq1LK7OaCqa54aP74wTpoDzHPkl2fm+HpSO+QlfSuPC3PyuXV52OL5zlfajn+8M27V3+cvfo3
TQ708jfv/vh69urrL15/8+XX77hsUVbpNZfVeme5r+bFse858WG9gOY577C51H84evIcWzHnCaVi
rB+kk7mguR0W4E9f/u7V7OuXX706sr75M3f805dvvvn6q1dfv+Ptf+ATDnv11at3b/79xP6hlta8
frmL62VHdaVaIq2S+LNW/iekWs+0wjo4S69+5Oeop9pG6LLxDc2zbIUzufz8g/V//5//l5Z4ruG7
uvg4L7QemaSM0sX1FS98cJ6eoUQ7r3hkMdiLuVTmVcmQzpcXV5+PGl13eKQ12Crh5xbT4+UpE/ns
M39IuD9tvtSRJiEvy42L8pIHLc/zz8wXXvEKXXNV1JMnP52bkSwKHm3RPOPfrkuZS8vKLorPLO/y
tLD0vNIvHFD+lJeXuoeFnIpTnvrY8m1n6tueNf6NlV4vP/znhPvx9B/T03lhnscqr64urhY6wGiu
yVX51zJHuUy2SfPi0wyNeH01Xxp5Hlk/8Mll+vn0Ii3WAub5P5SnlzyAxVQ+sxZGXSzMRS4b83N9
3ozmzftgxs9XF/thPYAs9+vLg0Puqjt0pMdb6BMNQS3ao+5p6wE44OoaW1R3efhDfWOZNnPSYmp0
+urGEtfEfGQtrvOcUZhK919flZPeWVrai/VZUpCTWsUb66uvNWQ5BnZZTq8vC/0oeDrsZvaZ2bC4
RlI6DGuSLtNJ+ZMxUTpZb2Vsxul8sewL6vIzE1gjNVlenJ3WN/8GiayUwVpA8xLN/INcvPow+Tjy
kJjsPSfq0Cy4ry+W5bG589q8ny8+aTDTnvWrdZJv20c4Y0vNNOOFvXz9evzSdqyDTx/m+Bv5xfU5
Vrqdh0ilPrmWHku2uEDt6wLVHMfNzJc5BksP0BmCRvRW+bHU5RbLOS5QpX904NtmTlrLNOtpDYwX
mv5HacSDl5eXp/PcTHoz3d/WOs78vqnmeK7aP3phvTovLi/muunBD1ON+0enHvPpz/oxmxe//GBN
JpPDF9b/uC6vELZ1UKGZy6vLq7lxwrqmAyVQaiqyZN+iCn/3bvrl16jNd1O8sNcYuVfTL/j43SuL
OaG3OcW+rE+yFh8uPtUyMvKRtn+2kORwjFkeS+6LXcFTOzKjg+ACLMW5RM2I66Qnz1vdzmIo0yvZ
kBcrAb6wvpSJPpdYDpgSc5RMsdKA+EzOxK6X33XjM7aKEEHVQ3PA4rg8vmE3mFw9Z7q74LesQVzh
O45ovOog9n2n9CaTOAvKIvL7Ic5d16id7ruOkg/uKDByTGD0pB4BLeTl/Ky05mdmwep31vUybb5f
fr6Ue9N8+/KcOc4ZSPPl+WeCorE5qJHT6qjXX75pNNgXZvkyT/7w7t3rV61qx1N6yGlH1pvGeljd
81H2i0uWA6PdXOkP777645vmw41jW8XfHvrNS5an+zpdLD5htprr//7iiqjKSCw5Cq3nSR1Kmgsh
3vbc/Oq6eLL6dKLLo65WT/G766srJtO3Rim+RfXyCrzYkYWfOcvrL2dSsh/L2Up9dq6HHV0NS/vY
G1/zz3k1f78+ql48jXx1FCutHdmVTt0MSTsXVcB3unqDr3holucRHvGnVkTEXBfMsyNL7/X6OkMb
1b9/a4xC51rXy/n6UgdPjD/PWi8V3mBu68vNGDzEsTTXNBJ3XYnc9WqZN17GyXp2HCzT94uT70Zm
Yo++P1Ro/s/1YRM5qwejes5PU2PvxubSuFWYkqpW27P6m/qmB3X80fglx+0UO6qfd1EP23Fv/DBq
ZzNZueP1gvhu50RazeaDw++fWIdS1EaCx/UdRqOReW3POUqs55535Lh6710Puwoqmyc7aX4e1cDB
yerZJppNtR/YyrrzZftRfb3D+gcOuUyYTjyupaL/1j6IeZ6DRlJH1qgxZ6Mjc8rWW6NcFzzkaH5u
nLUZDgTGfDkHpxgdrl/mKp0TuvQW+4EMxvViljMjT4x9Lsql3nD05TlTHzdzWb+ydXG1esP2muVp
510m80WzzB7/rerr7vEq9QXMreT63/5ojQu3+9Ga5+hOmRme2FyR98latx801vSkVRiTl7/73au3
b2fvvvnXV18r4PryzavZV19+/e27V2+ba17ht16d11O3Mw27tzpZedW1n7gxdYdYztYP3W3P2iMa
y+lEflwF8WTipp7j2dUgy7m6xq2Wc3XUDcvZ6LTr63mxw0z+t9vGxd9OjS5f2aqLU007OewoMOIW
hcenLCKpz62Gzehi3+hiv2//NqxEMxvWNuBo84Ov9NHhw61Sz5KsTAgopWaYXPOZ0QR6pfOi/l2v
tcV2gFYAKJ2M6sFlITXGpP4TY2JUsd73uRegkLdboDuvYt6/G7qcfNcagduM/+H3R+1iq52XmZH0
iSS5aGytBDmWdWCJFTNzx4OtVmrx4/zymHB4yaOjck7nOLjt3ywSY4iYqOjEjavtMIjbbWH7KsZo
9F2eOx7gyfP1I6wsofnlDfNhXjZacTHp20k/PnI863ngHDlhaygfTRTmTuZCfNNcilC2zA9W4cvh
BOzvwHgdq4Nnl2ZsOOe7tVdUr5JZA1KUB2aAV9G01QCpi+83lX4dOXe0fjvJTlGi3dsdNmagOwQT
M/kPtyymjg7vTKcDmY+T7lWP6mD3xPxrXnPDvWqGYzo6etgM3za564dZTe3GfOiEg1/vmHh12MqH
Ov935oSNKd29Si3kXx89wrTecuPdU7n+3lJCxQxPfy6HodRr5Nbq9VHefGWYezOUmSmdPule/oYD
aa5bH3HS3OOGR2KQoY252Vx1tHM6Sj9eaVbMi5PaISt2zVDctpVPUmfCZuW5AITCgIPNY9VfdV7W
/G1cId50t4Ho+C3rs5YXJ73L1q8hb2rz85Uf3X6+8qKNhxCHxkdIvNpu9BTTLPvM2x9ohpsvagSt
mZtWPTfvHYjUJ+yequvx597Hxl2ZfPvtl1/0vmjm0cpyr6eScQDsWAHJc9eJpHab17r59DdmXZHN
uhOve8aNidcce9L8XM3w+83C+hbDZ+Fs9yxs9GTzPH0dWPtQBJkr4OyBirCZCfX1GlmOd8acdyqk
7gA/lgXfcuV6fjTAwKa2+6IGhNNG19XRfHLkK5xPjoJ2+vReuTu7N01t/8tG8kZ6/W9q9O5g2Dyp
L/OY86SRxsFZ/fNkJOk1b1m0uLsyz58J8XZGQU3CYCMeaT5top3K9QI3i8AJfTvInGh3tNOedzPC
ab+poxotbv7114jgZbr8cDrPWnf7NX9q/q8gpnMkO1sUP26Pb5os0vYoZhW6tEdt4HissG4U1fjb
bUTDsCDRZTk5mxckhj6lBv+6WuNt37x5+9Xqq25cY6A5vXd7KH/P6vV8b0DNHFWsxFPnYe4d2kA6
IaX4jmTm7Isv36AlJeaD2Uysi9nsEMuiWUleetSmUUcNIOnEJiSzj+KVz0Ci9+JstjJ71+dzJrzM
jXnF45UgzdIF8GbZdu3sWxKbb/599sXbr42NXX3++5dv33Gq8p/WP5xYI0ge5enFpVbm6LhdgO1s
mCjFfFAsUOtLqfgb1z5UzkqWfKbUJV+evLu6FmDx5PmN5NgNgR1bzUnmCQ2HoMVx6xwdrIWyEl5q
MgpEsuVPJJsYtyfmr5N2xjX6ZjlfnpZr9OP1m2/+D7IYdcq3PuKCmapZQt7/pBr9vAZKEMifnBlE
kF+mzTGTvwIGjWrw0nNRc889+XX8aaZeUczWE7a5PyEEKccPeAc43gSOvx59bwI7QAOdMz8ne1+U
zRQ9WM/WI6sJPbc8D9rvwefusmDrkcnTS3RdidnaMjj9PO9RJ7O76I7ujhzmlgs2o3XUSUUf1Zno
F50MsJkM/XyvGe5Ju2YO6ihlLrCQfPdJd83doolvUn02VOjNAwZRpmzHdnLb30qZuuPyawKVYU9V
cR7mjh9ljptlTu4Xnht4ee5kdlgphVTFTubYRXHrO85mWrOz2U2j0/9y0LuVYVKUbnLrDXtZ9pu3
7H09TKC5lwZZNUSg/Yt3+Gh+aCSKD9OnmDVew7gmKNRaxkTvDbnn4MLgbulpnXD+cmn4CjXv4fXL
N29ffdFeol4ODQOpJuc0DBfSmeeosssUUs8SzCNjndb8mvqAoswhdzSssdMyhQ7GehIx4UJ+XYc7
gUb5lH5eGE7EtdKkItjoaWss09IdDHnrg3g+5cd5+UlJvPNSHKB6pbYEBLOylKp/8vzgcpX0qRM0
UMSuCpMnhiV1odTse3GAFuZtzj9/+lAqu20wyXVut74wh+mpjbB+f5oufjyWll2PSqXPZg23Svrh
cB1VHKSVIDhz2pcrJXJxdXDY0SkzzjHnoQi/4eYijnRvoDSTRoKXulqUxayY58v2HgeivjWegPXF
X6F0wClYKW2xXVp2zJqwcWTkYGbOk+eNyZcl0AuaK8k8rH2A1ikQb0eHfPXy32a//XfwdYyT51q/
Zoq7/pPnL9+9kzswuvg0aabPRA890ik1rLF6D/1z2KQ0eIg3hnjDo9bvV8+6g/otm6FtnN2W+6WJ
J7abfjdpi8XEvIyxkFefO9mSJpsyX8ybxLq5uVSrufqV+VYfdc5ZO8jrzwSrSUaT4vrsctFepKZx
yXE47N1SgNfi0PqnE2slrI3rm6VzUgt10g239MXBYf9g+Tx6Y9JBNUmJ2XtwuHHF9qpmuqwW5YGG
hfipuWIzw1fge+caWjEyaBeZhJxm81M5KWe4aM1iy8AEfhR9qiVCteN6cwE0l619ZH3bTqLOuTrg
n2Xzav9n1uFXWcY7nK2XQO9l+wNsgATBoW20JEd4KUmS2Sg1wqPRIfkoGDRbxDo6Y/zmzLvlSLgm
F9IJFxjk5bgmWDSfbxH25hTRf2bqnrSvaQZWs+ZggT0Amqwdx82H2D1Bt9x14w7KpEFBMjrhAFE3
99Blu4fUDMuvL+Tw9yZMb0muv7tlnrRz5S6D2SGqbTVqne8HmczKSZIqjAaazO7VOzYzSbbbzA2n
/BZz+Yp4fdF35BtSlOHArUlO0Csh3RkgDTOwolIdbfh9ALuEPgbYn3yATYsv3CEKdvlsPX5arcNl
iPusM+7REhnXhs4YN2WYFuYS3KK1eDDgeJ3ytKopZy0FEiPSWH24g63pF4kVz7emY7UsW6PAYB11
beaT5xuEVqjEUi5zk0DHZhP5HtR42UUmKfDN4vBFx+5i6z/UlOuzTnj0ufYkrNaPYDxqE2BUV8dn
mYuSyaLm2WV9W8/iymriluPOrYqri8vmTpJK+nnSN4wIlFF7v/pbqejthnIy49hVTP9WT8bs+Pr6
LBMFccvxCj575/yRe5FSaJixt5/T8hSbU3+racz5tS3lEkJuLrZfoz4T1OhieXo5gce4vJgoRDEX
nrXfrnhGDDsXftV8rHf/w6s/UnEy+9OrN2+//OZrGf3Lz2MXmekC7w12Wqua1kKYELsl+R6tJtHJ
aCsBWhQ/veKo4yP8Tm7OxXluih0M/358fVlTIFfT9E3LIr5eNLUXTey9dg7en15kTOXmOevPVkzk
k40BWD3xSfvLYf8MEyJLZvW6mV22Yj/YMRwHG8I8WEmi/UXkb6LGAt0xA4dLPxOCn+LTUg9Duq+5
/1rMqyeRpak/PRhdNKrtkx5ixRsjnuyP22ELthoo8HI169pBK4VMGt02q8kjv/613IpFZ1SkDE0k
0KhNc/TEWp9U+w9ZaQ5aLzrRKy5FViwucsNLbpXmlGi9cT1U4eNPvMP14GHT2jfHJ9cM65ilrjVe
eT/y2n4e1U+lxxkdW90XGtWPPWv4lXzbl9Avm5droPqDn4kBhBZ9rNOiPxK9yE0w4pmYkpMDY4I/
1rYdI6KnPZIr8ksj9h8/8WzGakujMKPPLk/020T/zM65wFHjiuHx7z5k0aiZ2bnRMyd9tTP588s3
Xx9tOhGrc5blT6xBHTOqoY+TrnTWr32y/vVwm5PdjMpkY8ac9CfPj58MYNLTRWP0meVMfPu5daCz
QbB/ZNR+LD9/MiHB1XsTIW24r+/w7F6JN995hoH6tYk19BynWvNvv/hXzAHB4dXnen7WrCZj1rid
JiaI2+fb7rMRIK2knN/i35uP9OvMeKs/LQ/6AcQil7NvMvAbrtePn9pJaK4trJ+D29+PTAjQfNj8
elQ/xQzvEK7H6mDz5+GOQVxJ6sCM22GtFUC71mt9td5NHH9zcU+sl+2saSP9BuVkKSw6x/9YQj3V
xYdogxey0rVXY1xaFIEs+CUKvwkVjWdg1e5Fk2apa5x+1XgbiMQ8yuWivC4uzj9TyqOg83Pnka7P
T1X2UXt5NV3bgAWG0Z7jhVxpzFqWR6MvZ/lBDSe2CrLRrD+P6o8nDco4amHHX9a6tubLgXiQECqb
BE+tMupDmz8MJtL8ztz7cFG0X9S8vuabKjW/tc9hRnS0dkFZ7M2dTvp3rIVW38T8u7pL/WN1n/pH
fSf+X6t7/faH69fiu8d5qS2vwrUf70V2PL9xxWd1keHKGzCB5ZHVOuWd1+q+Se8VLy+Y0p93vEnt
64+OrN4NTrbe7qR31y2v2dyp/rHzvUwIMmtDkIMfCbX6T79ynm++Tf8F+sEML6FrnXQv2D7Y6oqr
33Y+3mJxVc2yU1UQFgdNTlPL+hYJ75wrutakudZolSHV1U62XLl52GGzA4ATO4qO/k+jrdZPzIA1
Vm/H8/YfceM63adtr3Ry45rNk+54NJNOM0Elz2N+3v5AnWncf7ZecDpqGGj1I928bPNMnbm5a10p
rJ3Vc/lgy0JqRsasg94n81Y3tOu+wyweJOtuQD26bVV1H6Hze/dJVr/dVEMdmz1kuBSVN4HXQWOk
6pt1ZCIYJ13rzE+L5tfsszy0WxXQxnRbowijNgKv3/PmrWtZNLeufzQ31z/tzc2/R8PftGZX9990
ZZt7L92Mz0goyug+75e2s2Ln+61ueLJ56/qlN6bGkJdr3I1Zen5xlp5+bvRq53VaAtEWoz3o1Vra
SHODvrrtPPsNotKGQrvlZW5D9brFvDdRt+63gxA9PyriMnCHIHq9a3fwPMfztgN6G2W/q3LOW3o3
3OjNYDy7NrFf0yuuTSeA2zP6mwl9PMeaZ1i8sHYkkkHkljyTMK8tCWRzo63VzKtHaMGvD1Rb4nmv
8cD3F21OrQb0VHq/zuMd3FKmvkpv7KhSn1j9enJLzq6pJzdQTVVtAGkXLRdlG03n+XbaTVsZ0Pty
siq0nrWF1u3xetLZja9X3NnZuu765lG7brLYeJg/ra5hQtDmtDXH5+aJvXIHAadv24M36ieaa03a
E9cJkCOrg2kbGPrrl7/9I5naE+Q6acrlFVQejLqjgoIYOaNDQ4Kxhc/94dWbV7s4O2s9NmtpaSva
Tc3X3HK3f/nyXZPpHxl4Y4XUCPjIzfw8qO8KI2iDG0Bepia79NI7usttpxhmah0yT3i2+eVBH8jK
ewlHrd3j3kM1ktsBHQ0K7++DqdbB9jZQ9S3h+RpVvQXDaCOBzkysP7j1rBrCaM54Z5ourJHlu87b
hi7reTvAcmOX2nzAlom4W7dormzVKhrfelAhwKzGtYF1T1Yv3hC3D35eD+KoCdRbnG/r03Q7ZIxM
xVy/THp02PHc8MsvTy8+S9lOOg0pdt6g129DV1dvjv4V22dcA46bV6F8v0UfdQlT8d2/xsd8MVl3
wphA85qIocm1Rg9rHzS6efVqokzJRHSL5jlXKqE5+JfDG+B5f44NA88NRLUBm/fm2cHmSrkJmdPq
Y6SUQZ2KGh0erjBKTWRTo2uebNbe+aD9pTmwmy7ckalo71GnJdoX4YuDavRdD2//vsOexOT+3F7h
Fyn+n9srT9aI6nfPujP32fdiZVe0wPnQZotbbVa7aLOL6mCTH93qaet/dlHxRh+u0uI1CGV6e3Wy
ww0DrpMf1v+li8/nec3RrOlz2+/ZuZt4HJt9VY5v6aMy3myi0uJ3XYpHF/q/W3f3QenhQO1QKsZc
dMwbo9AHbinXukn02KBkbOKBpIQvD+8+67xcAor/OLks68Wz7VzDhGiHtsl21oqlYUWMFfzUpvom
KaIzLWqczKQuRq/pXaVTXn9b/1BvtNEmN0Fkii50a6ilO7kTDYsh/ZTOV6QQw0bd5GhY1nYqlLmA
5L2d2LOazhuXM+XVvef8afzp06exQtsxqpRZS7xS7H7wbc9isjgH/XfRBQ8OD9tk0OHfk39j4rjb
9EKrEDpzY5GzNOqZYU4f9Z0ovtDMO8B3HslfZ9yNNJVEby8hy3PZOO8trLg1utnP/5pstqXaztvv
susGX6oJqtZu+r/9zizNB12MwuW0CdhaDsAqhOtfsL7klgffQgo80pwxvGjpBFGuSTaXKt1XWb3o
9d83Q7f9bj2m4UE9IiersFPn7Xjv/omHPcrWjeDpYHtI09xhbU3E6ZLQD26W+HDN4x2R0WGf0MeR
k05jAqOkTPsjOhwdGhujeba5Kgg2IMCIMbCjz8bGau96Bb08AOpjPjra0JStMu1hK927r1Cdmwbk
cHMpNHpxezS7rgriq7uGZXvMunVYmkYXu0Zmx5W6BhfdQDczDYdGqG5sdnD43bH3/YZogSBUcawM
+k91Bv0nc9bVVa2R+B4BozU12j+tcugjwydl2vMkV+YXo5oOv989cBuJjtEaABjdMlLrXMVoMpr8
FfftgEcyys8AdDfNwo7/7j3kQ4CKmxNAuc136jb16Updpa7qzGVDoBZB+AUyHIvnBOvrvOOgzhcN
ULPOQa4uvi1vtyXLwgjd1OjdIdiW2qxRyp3SuWVomjTeaNU3ZQPb3EwyrN/njjSDKbEbDUg0DH7x
3UmOwRkGrZDVX2Y1rP5auzhDpuONNOmDtNSKGbRR6N/D1evEwI100p3iuj0H0ktEjOq6pW4iYq/3
afIR299nW2Lifi+1Ld2hkV1d+XBXPvf+r9JL/K1eyHTYGfrMvUvcSO8NfqStiYR+28QOzt//oskU
RHHiFgGZgizO3ZCmhluLRjdO7ecPNr5c1yE68apf1bp+TFbpSQvVnDf8pO8ah/P735y4kwis6uif
PEFWo6bgDvLjXz8t9aUTbPnyUwHY/R3L9uLcPcryq8+XS65kT+ix2yIvm422D5oExHFLr62rGzfo
xjfKcppA/AbB6jcnYli1N9v4vkUmxwIuxwa4HMvxuPWkDde3hZT0WiGlXAPPWjvM9zzRuO2dc6zv
VZf63Rp4GL9nrl7SoaQ3CZuWy1nzy80cVRQEN3JUHqhkuD1H1Vymm45y7bpH+D/QYOdqSmfnqWkK
D51ZNpp223cmoe7ZPxzb/StdensL76YmY0fz7pu9u9svug27q6uyvNm1+1c7Ol+nw9peb/a7/tWO
JuAKcJr+tauPm4nPwecmC0eK7eDOfuB1DVnT+/tw44ad5t/b+n6L+rXR+NvIfN0fu9seu6lQfmFd
qJTr09x0tr7RDfug0yz7sCfvXmvszlV0x1taZE8v38/y5amlCmbr9b/89suvjbsg1rzIbvKhuQvY
zR8Omz7hagp+sK0lOHrdNI/VHbc2Bt9ILzYDsmp+fQvwf1fr64lJuFrj8vrCupxflmpp9+R5Tq/p
p8AsprcJv4KIgwu++eabdydPX//5C/qnvqN168lTfTKljn3MuL6wzn7kDGt8yQnme05pshq3PODJ
6OnPt3x9PN763L9sXLubZ1hdsfvh8Q0UvnuJXibBnN/75HiszIJOePkFre5ubgzxwjJfzF7/WSfv
2iTieLxuHa+LaaHPjPt1aP286iE/zq1R21NAk3j5Ag6p+WVS/zg4fLGYqIf9wcGzRj08O4Kq/qLG
xw38qCM1dkSDzvc6Pj+9WPDX6IVlSJDnzMfZ9Ufd2DRrJtcgkzf+qDn6m5Xetf7xHztg0XfW+CfG
9g/ffPVqOjHrwijc648j63sd+XPjp5pJf3LjwOOn+pwnqK9ongSALv9wYY1OTlrVKQ3DFV+s5XGm
ibnSrOOxaRYzHv/tes7E5XHdzvP+z/858Lzx2KB748Vn1vXZuOltryVqHmrAezx5biRpNNSsyFpR
sqqR0zly+rmrpI7HvyAlU3JzvhJANW/EWrVLZlpkk8tPkmf3TTozoiQRt1y0Q13/Nam7N34ofzpw
3MPDkfWbjcvpLrUeu/yEYD+dPKWKdblx0GHz9J25UNRKtD8fmg+1tUj3G/c3/+jUr7fyev+hPZY4
eDyuQwnr2c8/T75W+uGXX56RPkEjX1rjv/2EQ3xjhWIhule02stRXYfEtp+w+UiSI+Z9lX1YTTcz
bppsK7uDuaqtxmjzfngRYwQyNtpwx33HWDBs77+8efV2vSvM6KkGs/vVF789kf1ESa4V2nHgU9bb
sU/dl/jLOmbgVerHV/+c1r5dn9boW+1HdC7yQukZY6+bse+05daiEMGrgVrnqyF75AGrb1xktWWt
fzL52rvUlIut4pRIpsv8kjsqq0IQwW+ijT9bTCe/xh48WyE68tnmGr2nLIi/WY7l2bDWi4v2ZdQp
aNdtsOHzhQgOn63xtyvpabQ1SptzidlvtAYtyk/h0FuObrOu8Gw+XE21Wol0tQAwSnOLv53yDqvR
Ypr883o+PK0FJSoWetAMebsSu2tWJLSVNu2OZP1vLXv0lUyS8U+kg15I3fwnl+GLRm13Fnyz+Ud/
wesSXWfg4MYJh7XyuHHl+sxTI0/jnxOYTdcSmP5a6rSvv7F5yGz8J35T31sz7vUKbm9x3rtFY5Nk
h+pnaXTnz81S+fqi4zXK0+kOR+t914vpSHBjay46i+WgfckXahWz1Kgby/Ur62WzEUq9gUXtIbY7
oqxGetQ4d+w88NmsVEUaV7WXW9U1MQfTej8VbZEy/6gmfcemSMOqNxeafkyN6CYdPf7+w0k9E17U
FodhAaIaX6P9aVy5sjQ6rj0dWt/48v306QHRUdmMpRy40WHPdeOU0YveHDKNH/U5Lq9pnCfvov1A
v9fSaCaPZsZqIcFswOzKYZUSbTaOOW5/OTKf1qWgNYS6lppVW+bVfhIpXSffG0fptvddXHcW8cIy
/gnxhizo019rAIXhdT+o5s1obr2qZtg/UCy7vuhWi9fMtTdtgNRMi3Pj9KfWs/bsZ92XWjEk10LW
wFD+fHVjonbnXj0y5nH/QQtr9FSnrpyLJu3ZmjnD29liBRarCcsEazz4Zngbq9CZEvUNRk811vLM
5HxU1rP/bfGX82dWbeN+U8+c6eWnyfLssrnEdoHyaJ/O1xKtZ9zmXfqXq08DNbAigt/m0Danwryw
Rs86KuCZNf7CemYOetZX6+PLT8IfTp51Ls4hLxVupmfjxYd07AZhZ5ClX89q/2zj7Xb4buJ41xpo
5d1vuGM6orO2Nm3jpmOmwxvVt02Yy4trVEvzdO+F/Y92ybj9frWaWqnVgWxPanW2b7TNm7rr1PGp
9axzOz64sJ4xjRqrZo1/tMwQaw2qdwyea8OtgNi+MoKc9qnWzt2H0KO//peVe8XMa3T/JeYER+vD
2qtqZm5Wj0hvFixf5oIb1dIab6GmyL6frRZgXajPn6bo4hlW+NloffbKA+LUxjdDKFsfqiEhZ0Mf
jDt1go9H8RtG9SzT41jNArvpQ6wimYvLTiCTSxajGxPSnNG12YfibjRNRIwdPRzkp794UZ9jHvDX
h1Z2onuxKda4eGYx+pV7467SgsXmYd6Ow57+XByPm29qvfbLDf7MQ8wI835j1j8zGFZrXEar70f6
npEeme+luJuXLhdp3si8gdhamTc+G5LfUqnfH4paMTQb9IzUdKkXTQvHk9rvYHhPdd1ad216zISN
xmPW3nV6YZbseuHLxvT63D6dd7GPf1z1uv0EqfL907l0t261Lee/dpjvvtUz65s3lnPCghmv7/HT
bVfXdflNWrS9eveCTw1Is77W0xa0ue2a1vY4nAZayok1gbhpVGT65vAFVAlEbyqOD5519zV4dvTs
2WHjK5vm3sa5q/dWsqaGuDRt/z4rbxmQP1gjbSFycdUUsB1bv6VC1thyk8du3+fp9Z0C/4P17HcN
UU1F3sfWJqXsmWT4jJp+NTwdHY/wYMfp+bj+82idFj4esVcTU/KXZ60w6xep94Uc7XyC5uD67f93
kwU7SbN8dMtbPkWaHRNanp3QcSA9ffrm5ddffPNVd26OrGuOtbT5wp4SGP38l1oEfxkd/2X0tDz7
y+joL6u3Nx/qGa7rfIk+HzvmEPGATc2eOeYVx5gmyn8Z/TLaKajr2yZx2VlxN2753zSTjTJxLNfy
HjJrn+p9R/cZCdOU0whU88Z6OjeipqzTZA043HxnLHudceiKu55qA1bG7Y/bv9re16knwWgHneBX
olodm/Cxs4HeQ246/J7ctFO5aOYlDInOtLzjJg9aWQZaH5/Bo92ynO9ec+7NdbXvvJ8X3dneABDX
UrJ1NLNV/v9mGdLuY8kI/bvSI2jaNyZ8L27o2vqxGq/0lmdrtty71ywx175Li5vdV6YAdqfLDyQ7
yvzHemXUbonWGwx1fdzr27WxN+HTG8kb0+ql2dev9VYb9/RnxyDrtQfaODuH7S9N0Gw3fleTdTy0
Gk+393XtlDV5kSfPDa5E2cj5R+P8tRRYM+Trj+t51Z1Wg5i0Pf+5Hq8OZNXPhTR5wC5pYmS2FzZc
QiLadZ5QCPUFu2J8NJBGixBU1ratdqcm7Q4fF1JIBzlYPYHZddw4kKstfLltB/nT3rz9xMv5JTtZ
WuP3+sps2np9voLTkNoBScX27vr7T1++ezVTX2HFN+ZggUHmvtr/Z75OrZjRWIfZddbjYTkS5u4i
rcoDbyNP0lxzlRF8++p3b169m/3rq3/fCMmbAw9vbBZfO5O7N4hfOZtWp1n2SadRNvduhV+TA1rp
t4EpTycZNqNpJuJkup6LKZMuw9O/vuTkoqxh8z6Su1E/2ju9mUeaI0JR6I7QbP/2eRMEYHQMEUGw
Mj+Jsg5WWMfhL6vI86m+7Mq4QT5Wb9kyMVbbrmoj3zroefqzeAzH4ya9+cuxuRjNV9lIenpkNr5V
6xoUEP+SPe9VAD29rQ6uvb/g+mbDb+C6ZvCm1mqUXjRUiDZ+qhu+nhtyQGd39E0KxcjkzjtDZJIP
PUG3qsQAop1m/uOxqRQabb77SItcc7KRaJ9ic/1RickfIcc0v7XbhJapV8bFBEKc6/r5xmZn7bE1
rab9q27zH4hXE5gm/+02qGx99GTc1qbxV/Dkeecv74lh0WrnuFYbUf36mxOppCPrn3y4WU9MTeHp
tTHUZjPrqy71qz5rZkxce8/fnFjPuELwrGmXHpn9xfjXcXaTyH6uWyOdrAoNR+LsMjY6ZKSylYKu
xKPvrV+ONk8wFKfRli/+Oj//a+qab573vxnG67r7zB3krvufuH6He522poXdfS7stm1Culx8pr7l
fU/cTPYU1vg2Ydccvd7RNV9PHPOasrf9vM9FSkfL3DyCma5UIYhbaIfNvFjNxAJoccDEWGzMDPXz
opW2embWsxjkxXcmztE/OYZluHPmbDnRDW49r5lYN05k1k/8I62b5ryHTbsb1zX0wgdPxi3vZ8iA
D5ykj3a5zuR98DU1qXeL6/apvujN9S2D6U3C7mDeuhIWO5bCljcTm/W2FXLjFNiy3iRYr5zQMysn
YhtZs90OsLd2auwsGTn6J+siZ2VOtMmldLVMFVvZX1y9n7bUmanvTrNkWsVFWKWem6SZGzhunEVl
EldF7KVennl+kRRZkNlBkiaxH5VFkbE/TWqnlR8UeKjmzWc5pnQmhpP2nhhrGU3scX7pJWOq9Lzx
J7H8r85Cf/LpAxiUaV6rByV9Q/bmOLOrIsurwPFiz4vtJI9jN3a9KomL3K0Sz8mrMEiKJHV8Nwmd
MGVrgKLMMj+pgiJLfIlu/p+Sphs5fgJV/FKB4djsfc1tXNsNxnY09ux3jn1sO8dBMuF9/6MeDjFj
n3/3XSOV7ymVaYcmXbxHM1W4CGu7OvI0KuoUsSq5/xkd9h7ldfW5K3xo1XMj7sVc0fBIHv6i0XH3
Hqkwmyb2tAqqvHT8MuEn4vKyIC7j0s39KC9iv/DtwrGDIvTtyEtLJ82jwAnDInMCu7SnzcuM6+ef
4KlP3v/nzbGwPT/P4zyrIrew7YCb+FnJF5HtpXngM0HszC8Dxt/hK/aFyJOkSOMkScuyzLPOWARu
4jvbxiLECIxd750dHzveMWzJyAn+w8inM6OfP2hGu+U0s6dl7jpO6VRREoYuwslCP0ycIC7iIMTT
S9LUZ16Vjhe6TlaEKfsulX4VB7YfeBtywj/yiNHOSyDUz9tnb5UESZi6vifhhHHoRx6M/CoJqyp0
7ajKstRPNB5RHBRVmoeOX1R+WmY2jxP5RXf2Bmwwd7fEUFGJX8/e599rG5zu7LXWs5cG7U3XNEKR
jm9Iz4RYU7je1MaWVvHYwwuH81HUSlpOvZTkDvMhKZyytGPfz8OI1uRZxvRMC2YwrcpjNjhx/cov
I5RP7AaVH1Whk7iZnU+lT8auVLC0iOPX/y7vUiR26gRulMa2V9mpVAZSr1xmQkEW2nW8nLAsSrwo
Kt2oZE54oU/ZROJ6RWqHYZWsh8KJfScJdmiSZGzH71zvmP/5zBHbv1OTQCNl34YlMwmGlsbjalOp
BBPvv1in5O409+gfWoaFl8E5LpjFrNiqyrVmUKRp7mcA+34cp2FiO8iRHW6CuGJ3mogtavxo2rzW
bP1aY/MmO7UL/9hxHEeBV6WpGyfsKpOwSl0WCdf0k9DOM8xNHFBn4DFcIQqvLEMGyfWzoqq6A5R4
QbJjsThmsbjHfngcOBOu9UjqJcmnTjJ1IqfK8jjygsK1K5fXcIqo8mMsUpRiKwsnLDEvkRsmrl34
Us9pmAaunabZTpF15zm6ho6t7Kju+vVsn32M0+0zPveS1K9KN065aVylYRjlQZA7gY/yYZC8vEhy
lFPi5HnKqgs9j62DIi+0CzaZi8KO8vHsyA/vEqh/jG+dxO5/dH20e0qxcqdhOS2KAIUbUj0SJU6M
PcfxY/J5bIOHza+SPPBQjpWb5xEOh+9j98ug9N3CydN7S/GnOJztUhoJWyvh7bhOyn0i3KAwc6W4
I4JwNnS3K+CnMMT25ZgOQnIGNnXsHAFzTOJnHRH6vhcOESG2JYn2EaHvTZNiarOEPFyeykdGQZRl
YciUc2O8Az9P3DLysjALbTfJKycKXc/3yyyJPTt043KYCOcXi5njzexmGs4veZ6ShjxbBRlUccjK
TgK3iorSQ3VEeRnzePhySV76pc1WVikzEV/FdStPkxXJJokd5V6cRB1Buoy4PUCQPtVHewkyCadx
Na0wUegerG+ZpkFksxaYEqxbrFTgOWUaFHZRRUFsp0nhe7Li7EzPcmGR7SFItPg1OBpNDbbLM3aK
sIyKKkEjFp7PnmCl66CoWQWpH9sZujSqSpY6j+i7LCdKAJnHQYiXwyddeaJk4wHyDCZRstfaLspp
5U/j1Gd5JxmGNrCDvPSqrCrcKKtQ6VXJoo7KKvFDPgwzP0fvVOjJNLLxa5Nh8jxL84vFTzPHnjmB
NkWULU1P3e2CZP7h6xHEeBljm+EVp2nhBXkSICtMXhQRUTg4Kznuou25YYUHbfMSuR/kkR2vBenF
cZAkAwQJBSQK9xFkmk7TeGojrSRnMWUxGgNXO7MTtn9DN5ZlVMW46l6cEjIFPGtQOTkuHBo/Rehx
PFSQ559JW1z/5LRKcvXJzJ258bZPg1v1aVnid9mxDZgZujjYWYkb4bLWvZA97bDnNp5eigcQ2vga
qHTPycIkzgu3cjPX6U5blmI0RJ/GhHP7CLtMp34x9XDu4sB1Q78omZ3MWExpUqa+j02PQ9vOIyxm
XiYlagDzwEsSaaj80SnuKWzXdjDt6VX+YUO0TrT1Y8ah/XirzEMHj4MgugpCjEHhBqz/KiUgydkx
sCrjOJSkbe7KToJpyipkETqVh8VNcQSSrg3DBjoDZJ5M/CTYS+jeNMqnHo5dkuHL+RXqIilwNglx
gcKDLMaRSgk2GQYPzRClzJgkJ75CxaXy2x8k9Kuzj9HpDZnf/NRz2k936JSwQK+gP9AVhHtEfzlB
Rxr5BOKYtoTwO/FjwkumO/+Pn8s6jrHPcUaep+o6XmEYu3dLnCrvqA01HhwdB8W0LBTs4mkzGcKk
RJ9lTPIydSM3inDLwyxKEuyJHdheVPDQaULUZPsxbtlDJH55yZhBB9gQ+baPmebtx1uFnnoOcXtR
OJJ8hG+IG0HgVjh6zsgHkSAQt4Oy9Ao79ApeD+gj8UvmeVJ4RdkNtUPHGaBaAkC4ZC9FHgRT259i
aIrYxswFxA4OFNPMxuNI+NPFhHt+WVX4lQ4ub15gDd0sdrHxJZhBlD1E6AsvsX/aFPnNDxF4/eFW
cRM2ZJWdoVI8/KCcgAxQkEdPCdHTyHH9UPovj11CR9xkFCRmP3NzhsgVMNcVt2fbA7RK4KFVkn3E
jQMBiOOWGU/o5iw122WbctfBHqG28UWKLAxwj9NK8STBpS9Q0bEBvAiJADX9e4q7VhVX80X+cUNp
e8nq4+2GMo1xKIEoUApE4YmfO44eOysjHxgJnKiqnDSI9aDSIUHlMdUTMCwfTC+Ou4bSD1x/gHj9
SRjFe/l3Php7WmUeoW/B/rQBLQGcPPQkPI/JgFTRIQrl8ZnxrPgYY0kIkoUx1gjlOFC814vTWo4O
krzV9rF6qiAB6Uz8JE7l/0R2kniZDdSTJZVdEsXlfhkqDGHKCgFkJvtoDsLkyHe7ts8lSh8gxoA9
2vdSCrYztctpUrlgVNroN4946Ch3CXWLsgRTwE9itIHI7NSLQM1yRh2hsvdvjN4qiupBYrzFnhXo
eTtOgjiijg/9yT6CkZP6KXvR8zx+kufop6hicuaZg0NaMa5ZEDkZDpALuNbzIEB0BkgRH3mvuZj5
AntZEbgJLrCHn/LMqHrbL1KHpe2w6gsv9SPMgJ95KKUSx9PJXXDXpMwj136IEG81UAAsKHmvdIQC
lV7uSQ1mIGq2JlwVe04QFF5ERIczmcR2iDBB2R0pK/x3r2eg/CEhW4Dva3v7iNGJFAUjDmDwPMyK
IiENVALLRTjmzMYECDsmE5MlrJbMztIqAb/GchEvYQMCP3yIGG/VjGGImSwJZPBRsDEV4BkAbmm7
aUCmKiOQiHhOkw4pWPQkIrwysX3wF83MMO1rRi8YIMZkQqS/l3MVTIsY/8p1sxSImbAX3U6CJnVw
Xr3SB/jAYfY8EOcKJEsBLwmb0It5S+aLW8YPEeMt1tsPlOcgT5SGwr1JrhUYuJggXOm+kogM2ZCS
CHgkYkrgQuFrFY6gH0dR1F3REZHEneYlILMGGL5XIBYRiNlTfGWwtZJwHVAgAShi/QgjYMplZVZ6
hAZxFsvfS3KlJcskLDFDTgYu8xAh3ooOlqRvQscrCAJBUcHIK9vHj6BxikIqRhrvOPGJqbBvsZ/J
6XAcOwJgIPdgd7M7QTwAhEGK7oTX3ctIR1MHr5EohOQoT09gS7rJtUseO8OwALYzCcucnG4G3Bqg
sRyUNiorqIIgwNkYJsXLzzCpDYEbop7eA3zrU7o483bgMCCS+AekkX1Q3jgNSlxim3EluxyXBaAl
KjnFbfd9hItjkdtZhAdEWFu5mPgu+u8HgRsOkKU3ieK9LHVVTGMXY00GC3kBCthlznwIgNsInHO5
wsDuPosH8Aicxs3KALWpFcfsJekUDJMlma1dYiticpMlIUyONwPk4HjA5sA+EQu6QN0JrcrB+zK8
WwYxBfJPkzIC+Y2w24XbTZogDXuA2OjSFe3lhqf21C+nAL4Y4TDDFAOw+fgtJPqIfMCII0CrgnBB
PnCIy5YlvJ5NnEDo4FSkVQaLbZaeFTuZBWGYYjcUm8dytXwnrlxyMWg+5nsYAIKQtQmLBCcVMBD3
0I5A2rykJL4nN9lZvcjODgaILtx39YZYkXwaM61crs5LZiSYYuwtAoSiQb4kNbFizhjnihSiPBYQ
zcrlB2mA5B6iu4WUQRoBa4CrpJRsnBQhOCnzmWQIIRS6V9Cem5FIB5lxUCSxE4DJkHwl30Qg2xGd
HYSxM0B00cTbc9YhOharUwYFWbGI+QXdDLYE9ivHjbYL1LSILcCqDvnMRCPPog69NIpYPH48THTL
+8HPYR6LMxFjc1F/rAEQOTx9m1AfEeNe40VnHklR182Vfgjg1kBgiAsoGHjd9lqSsnhOMkCS8STY
y7UOo6mfTMGDIjDb3CZbWOUZSyN2RAMpyNsAPAOZZzmJfQcXQ0EM9tELSDp5pZ2kgwX52PBzlJJ0
yFgzLA3yJKx55kHqEglmYG/CzIkQobQwcQtIAHIqoip3UgeLDgrW9R1DO0wGLHkHmoK9HxTqTD2P
LBSZZZIPwkCJVTwYTz64mw/VJiEniQueKH+LxSZYK5gvkEgScnpEst59xf3YADSoZhqXoQcQDRbK
8yr21wgkicLBvFQuyJaCQMQFgEsSBbBv4hzzmQANdcNHRZ4DpA7H09/LYwfIsIEjSKslIYB5EhOV
lTEuUCq3KEk9OyHLAtHMgwrBRlzI2s2hqglVhxlFIuZhUn8kBFpzlwo/A7JAcWGbMFuG3yV5wcTG
H8mZKBXBBoQLfJMUfyBGM+Of2LEHWaGLQAfeELfAcSeB7ewJhgIi+1CtEpwmOy9ReSUBexIVBSg4
Io0x2VFIetPFJ1A6tlDUJ1jCL2ze40Eif0QIGvgFfITSAdEhAfw9zKOHnFHmaET0N+B0GecpuURh
o1i+HAYjjBqlvqMw7mGiXjBkouPDOnt5FGT7EzhZdqLwL45J++BYO3mgmAZTBM4Y4TAKoi7Jb1Wg
/g5kAWLVuCIu9IizHyT1R8Ggc9LtIBEwBDIg6JyUUKZuo2DoEbYShhJvk4Y2tJYQ+oYXQfKCFgFG
DQKDwHsYNAt9iDr3J0ni7KnOE080oazC5QX/IerSwnOdpCpAzXCPoAqVZYzKBNtNCBSA12IixwS0
jSkT3VfeDwehQZ3JQhSwMpwwEGvISyKSDwgdsAywEeDAtvGZQPsQfVAoRIOVix53oswt3R7UAlV3
gHzDCaDRnrnxMJ2WJL0dxYYFDgrhGbAAwAXqGpaJzCImBpuDhydlB18LfxYlD1SATz1UvsNRaBvL
AAgRek6Rc9O0xFlKgwTkggw+nET0AZBkRqoEyIocK1wO4VhYFZPpCboGEJhggJPnwOHcLzVVBFMv
n6ILSEviMPtMzSojIQFqSQQG3RqV5bksMpwRwGmmbeCB+YEp2E4GDFdUD5PjLUZNwQNAKBAKPqZc
NvjnIAKQMAplopBu6fqsKzAEG++I6BvHLiafg9kg7WT3wPzEG7Lck4nr7OW9+dk0IHDAcQt9BWhl
ppwNQsP1YdEnSuZk6NQkAltDNwFhBRH8J7hPpMxc8I4HifF2IBoUCuwETrioVQyki9MbhJAZUJtA
BGC95KNBXpAaWRtCIhhNwBusFPIAYQ+IhtI1APxzqXCI9vLHYKMW4dS1ERecsYQ6gxhHHSc+Q61H
AZTArAhCJyaRC74SKz0N6k/eicUGoWQo1LK8DxINEkAEGRM1CISJPCYjfG8f9hAxWkZWPw9SDBMs
Yxx38nYFtUe2I4cLfM1zuml+4vPAHSBHZxK4yZ78SuAXuJWwJTJPPHc7wfpQVsFQUxSQBYEAmcwj
h+gyK+ArRMIQ8kAIMbbPe5AcbzHi8FNdwfQxNOOA6QeTriJFg7NXwai0idbQmbl4qZl4LDireLE4
2K4Yg3HYo8h7vjvAVXXpQ+/tpRzdYuozoeCZgKRBnSmpE0iYhjgWQhIqkCqS83BGC+W/WGGxICNI
WXlM8o5yg4cpx9tCW+Y/qBUJBs/HkyOVGeEFAVUZ9moYqbaAnCaTFcoVBG70UQhO5KB/UlMr0g1t
PQgQA8ToTWJnP0IgSTZ7SvpAMHOAD1FA43EjyL9QBBArCRHIKKAcEcG3KgNwR/kYeiP0QTy6gUDg
8jYANY2rBB5xAikNd8GHDw6tD/0SC4+O5fZ4TECPEiSosjymo1RhATBTwJsFQO9CWTbJ5QFyw4fc
S2wh/qOPFxkiHkd0So9HwT2kVMqnbsQlLUdeO4ipz8IiOqBZSs0GoAQ5FHsWUDFcbLcBqE7qIRzu
E6Eo5CiWsYPHWCnM90mfKwWMYi7tMs0EnygehQVF+p3SLAa6B6DioQ8QXQjjZi/3MIimUTyFz4Ez
SywA9172DWciFrtTRNkozEDMc4hXEAMiKAEgmvDQAv4k/+D695HdbgSVexKcxznAsmeD1pJfAWYs
QfXIEpMbKlVggUqGNIEZVqjFULtU4LF2E3gM3WmHCzkg3UHnsWg/2UWFpl6SVCUZFlwHcLOU8i8Y
nKmeF4Jm4KJueBNobmS0QfIhaRL45lBTUkoQ7rDBQfPvvQDUimUKHIMnQjYIlJ4t0UH2bEwJgwV+
hGMPyoEqBMgL8hBpU4yFsoRWw1LJ/R5/F77mAEEmEzvcKwYsPBzrKVqHN8BLyBW9ZiCmQKnwGnnk
IpGPA+UHllqotJHwSOgopDZzOeTOUEE+On8XkAAKAGRcmK2y0hH1oRmsaJckFAEsK57CCHKd0G4i
FAO1GmghEmE2mYiNjCcOU3S3tD17X5JdCScpn1KEw1ImwZMRY1F7QEGMTcRCaANggCNni0aTV2Da
OG7YaxBtojC0PHT/e0r7sfFTfCfyADkYqTDRVB4RiUaXfBk8Fg+sNKoq+P0EQiTvwfQKh2wLOWdQ
pVxkp27c4/CkA4TuTAgC9oSVwPNIMkMXcmPIir7qQ1VqV0ByxMVT6XAkxkuG2a1g92LSFaeTqySZ
yTp+kNAfCT6lA0GWFGgKvOIKIA/otxTNG03rET1RGoiOVn0NWE2Kk+CoJC4PqFwgV0OOtxewO0Oc
Ak/wabynZQtSsoNoNnx22FpkYnJiH4otVBCNpUEtCoeAw2vSrVRdEvdBI/MNFSCpHiLxR0RPQ2Fh
PAklsHBR4HHAxlKZZqZCEWiNwDYhWga4NxE1UzRfkump1nOiGrs+gTcYwKbwQE/3m+Y2VfJ4Y+Rb
bJaWqnwDOOqeS4F6JssHSw/8miVaKfHEcfhjENIyD76FQyohsh8i9EcBTx1HdS6pjfGh7DbOiB/w
Q8i3gJhR4QC/L6SsDhwFxn3qKM4BHYOkTlYc7yjy+mD1EAqQh+O7X9wFATcLobDgAYFEyiLqSdAd
lP7BiHMoXovI18Obw8kF8YGNBs0eyCCGhYx/V9xXqzwcO4VCrkQQxdyUh0EztylRFD+aUDpV3Q76
g6DDw4knoiBuAAZK+R0CBzaf7EE3HoMyNMRSgp3uV1YExpJCasF/x3gQClWqIyqoz6IOC0NOioiq
7EQoMM4T7ONA5Q2Oah0pNAVQHTqZhyOnuMnQH7kjdxGo7LChHRWsttYVgKTqjUHI0Q0e4Cl5KvAo
0DMeM4rF7O76Gz5IxxApRpN4P4RfxZe0VMDn9PDa0FjUtkv7RmpKYZNNhFhHFSY5ccANxp3w28d1
hoPl6Wie/EFivMWcUdODCQOrxyXXCgEYg7QmZpznZSl3JLiAb0B5Mtx3lSzzP0o0YcXDE6t6bL+A
5M8Qc0YF0H5MFzsU87TIQUJFgaTWAK1D4WgSQ9nFzMJdQvkTrYlvBVGHxlilEvmeECyfKo/sIVK8
o8KkUrExBrVQRA0fOisxnQrHNAEBgUgAk13AsnpibKeigKGViI8po3LznoEKhiBVPj1v7H3JGmFA
SXBUUTFq48yA+hqwJTKwFQ4kycqMhLsXwu/EjaECEhefpaYSV0DiB4nxVs1YOJTCAz1SQo0LUord
YnNHNKOgPsBHSCRwsnzYGQqBhJAjyYLQDVYx8HSfhBEOCH0pS98T8ItcTUhoVgD4JDkw8G5IPT9K
JVWWAWJnDtRM0FZ6FBsE0uTUANMTIQPyyFyW/UPEeIv1xvWUkELiEwqBXHgglHviQDHtBJTaISgV
EKmdYv6AyEl2QllQQQm5JypF7F7qMxxivSlMp1R4LwyfTUedKQIR4SBBSCwOvFHmH9BpQaUTqgX+
XRlnnj6DnWxjFzE/NJoRHhI9SDHeFs5CYKJqE6CW5DZeGYklsFGfWknYsKge9AllIAUekKsWGGlY
4FDTuYWWIFh0QNauYhTYMUCKVKXvZ17CfOqn5OxTZIVjCZ4mUJfY1seFI21DZgtyR67ydMpcEoA1
D/8BhqN0J0S9Kh8mxdtIpwT1THfS6Rjgil5A9BmALA5RkmJdxs+BOVeyUgp1SAAVJYqyQQvIeeDP
kwbpkU7Jdg4QG8XnjrNnIs5hEZJJAAWIMBMoZKjG6BPVmHPDIvND0+kHSlUm8Bc/gmDPdigJJwOS
xoPFdhtmSusPIDzxQkAXUF6oNEI1p2BFED1CiYWGahKWgH0h7FRyWj5KUaW6uItB1cNM6VIzQHQR
63avHGbkia/r4MYiNIDSqFDlred56p8jpUPtghJH0LVTW3UMEKNgEdFUAjolDR387B6i2w2ZqvlG
QhAVmRqZIJHzD/ZBaoqxA/5gCFVpiEpRGwSGDpewAgwkm441yboZDjRQMETlxRN/v3Qb6ds4nAKN
+UFNnQF1LlR3itpDSEUoViSVKuQ+RKnFNSTlCuLH85LkwJUdBpnek3SKdaCQm6vDDkN72CT28Z8h
SIQ8WJiWPmxCeqnBJc+gnmC88Gxo8gMxq4CAmFdd0inMkCHrN2H97pUAhnLq0RgGhiaLVMUfoad2
QFDIqTzC2sGdiMWYICsIQywJ1UVAuAEFX/IHCaIGS/KxQdMCDlKoOmPALrQ0lpheSYSrsUoS1Y1F
GhxNAM8NfYR9pg2SC1UkVjwOgNZzeNCmd4ubcvBkv4ol3Gf1kaHvDpQwnEf0EFJkvcH8qiD6ygOH
WSVPl5ZNNPKiuI68HJQbgl7+9sr7ivvR2x74LtoHVUqtGCUhoEukeDK1eIOOmojHD/6vYvyyJHWA
J0LpuCoOCC9Uix/2WKehM8DNVD24vx8FMlWpmHiwsILwIAHBgAVAChxh1JQUqRGGT6hNpZ0jz53+
GCSbQ0EcROAc8DCpPxJsCr+RElAyFWEl/hWZSahjmQRMciuucKygr5WVw4IUyTcS7J5SbwvuXoE0
dfmPIGnJgACJmnB88b2AakdpaBHYUNKGBIlWFMUAzAGqL2yrSD2XHTJc1AIkyiG5YskSK9ObKk/t
/EEif0TcNKqYuYDMMK9w/6nhgu4IfwMSLUWaQqblrtEIAZ0oYhaWCPZRJTCMcvyk19+DtmThgAwY
peL7aZc0kWUUvw2iN+A/MIQImFRgUBGrUr2oIHkIBAW9l8RiofRATsyKV2urvD20HyT0R8FNsTJB
ivtmAlISiiSJeWhP5YfqhVFSmR2qi0AYqiYVbICQm/4SkcqPwXZ6fSaYYwNYP5SUh/u1BEPYEHdo
vkXBC50OHDHuCb9TVdFC9kBLQveVHsQxItksSiSZJbQibV4VMgThfeW9R+cD5nEFfCuWPaqYAjdV
ykKoyijmpkkUaAETWe2gSBfRuwruEJxqaAa4J3jRXcgPrHoI5BeEEFn2cvOiahr6ZGBYgbT+oaSI
7CKZWjpNMIkJL8TyzNByhJk8dFig3Mn6wyVJwX/JpN9VVLmW73DoFGAxUsMetc4TOkEzGhcEH+YU
sC3zDqAFPlAkK+5QuJiIxavuQAw7iUU77+Ww3GSIWoB0Gu4lR2pVoFZRLUt7VnA1bB80NNjxpLRi
FRzFymcJk4YA5iu9KeIk9hx+PTx7qKDJw+R4i02jiR+hfQk8r2agkSAr1k6hIm36+ogfq+IbHDp1
4KKKGxWAwrL1aaF66i5EgAs4ZDpCOk32dd7ISokDa6uVKVA4mVYYfWD3yg7a6kMJmJHk5GY1uIVJ
/AAjQdr21ESxepAYb7VSuFRyaqDpuoKmYrXtpJkQARH4nmom6C2tdkKlxjsG/wF+Jpqk9w0BHAB1
D7CK7yYLEeXYYNB7Bb50kaL7FxkbW21skBslg57ERuoj810+ZzWTvCESJXwyrCHQAyIk/DFcNJIj
D5LjrepRvQVzHHItbnrmKgbH+HiJ3ELpa9BGYXyqYGMcoWoDmieqLSTVTlmh31OPthsPkCOkU3/f
Ror0lgIKhWBqq/QiE+xLiVpMMyMiOoy7rS5BuAHkR3hQh0JIevIV8oRZag+cj7cYcfw3etDQHJMb
0I2ZOk+Sin4CAo4nSLJQ8TCRA84S7ULIpJOFpv2g7QjMxfz0fSYC5wFShHS6nxSRgh2rpUkYayVh
HvEugFhcem3Qd4B+erhL1CVTOVSaEnSqHYkgBBRSoRsAxDxIirfip+BiYGVq50gRReLIMbYNpQBs
hlJgaj4oG4nVY4cwJjItoiB4Ah0iVa/X1RO9YLsDxOhPaBi6V2cYWsuJKkExA21biVzV/kJtNigw
w4kL1FkJ7l8oX1rFwCBvNLmCZIb+ghkE2WOgGG8BUJn2JrjwQR4p+5Bf6JBDwPqiVUgUM5gUh4D6
wTklRlVzGJpwE/SpZAC6TwdAxU7ebZtDVe1D5N7LqISmVxnhhENbEEoEyGthOuAgkRHx1YSK9Ds8
NtrWUDdLP0/oMOqtlJCvJaoAHBgut9sQVPKUBQ2xyAv46hzm0HLBpnAbYJJ0JaYN50UtxVPTWRaV
Qks7MRMBCZNUy76LoEYDWpcILqNRxH6s00r/y1W1EEB8rdQPgpWpZmmOyhepX6H7LqApi4BcJw2N
pb4L1TAxT6jG8+8ju1tYp5BvQchMXREkG7qa04UavooN9xHWldA03EYcARGh6VcBz8ZRpyy3Es5W
dQN0KjEGrddokuzXVcw41hCeQ+07AKuTPsXsMOCqbzZ0caqI1YmKFQyiCf2NxhFQZWmbR0tFKhSB
CuPbKxaieheKNX6a3N0yFr56qH6f4HXgomBdAPEq0IO5Sc6tpAwFPYISYRUTEMKQxjoToFOiGAP2
dmagiPaDZmDC3knBnjNQXCVbROtUJeKAehiRUNtrYGWpDyAToaZEeBPqFaqKJSW3QctoNgYVMh8m
xcfGTnGyxE5Sno7GYbGaddFCOlb6vYT7nonvRiUDjaYoj+e1ZOsq5fSo7gNq7/UwV2nd3bKmYh8d
spe7k6kZfKoOLCq2YDm5agpNBGE62bNycA4L8eQT3BzKmcHwHJlzqujIBlR3aMpNWT82cEqhBcOd
qtaOphglZSJUuMNlA/ZCf9hqpeZCZyJTRd8PKX64AhS70DrK1i5lXbYI0UU0YHpTrp/sZ9S9agpj
FBVKJooabIo5IZ1CGvHVAgxCAaNAAZFD9wQ6f9BZGP1A9p6FSkMujH5yR1+U7SJ/JNRUDZBJuWhj
Foqt1faPyUxalciHkJwukBFgHZZBhEj2vYExRH0H2pleDzCY3aQ3xYmXB8ibHvPRfinBYEohsrpk
R4UrqC7w1fzAE3yaqHUhlCP6c3mVtnIQZZDaIz4H7MUfDbUA7i/vR4RMfXLiZDBoDBeboiLSho46
wpDOgAfra4cB0gGFsq+YY9ZvLNYpel4kFTvvFuQqzWAPEDndNb19G/TSBwTeATUiMUAC85iAM4wp
tSCoyslUp6oug59QYQFRgTT5V2s3Wy0dqO9z3fuL/HGIppFpVoozbePS0EfJMQw4VbykonCmoZio
RPraTUjbOTB3Am0JAxecHF6vYZ+6QA0QNj049+t7iLBoFmQYmtDiVAngq+cg8lZtE+2daZ8HL5w0
RynaGf0QgNUIIVgJTCRc4vBewn44Wkp5M/OAMkNIcXD6KikQTV/0RYGmprmNijSQqyMmMvVMmE2a
4ZUGlE7KHoMF0mQ4QLi05nT9PdF/9qyiGBKWAxXwmbzSSC0OaByKXsYPzaF8wqfGRSaIJXjw1EzI
7EMTC4mLBgl3OFTKTgnA+bRww40A26cLJ1vQwK9SL3GSmfBmjAGBMMdENU08ID2ojo4yd/iJXUhf
vaeHCDGekOLay+JFU2rRYBiioCAU0OOXim2cHwhLhDuqCCHCoMSsUCFlYix5Kkay6E6h9m+rHiDE
W6wYTTi06Rca1FZyHj45nHAgeWpy+YyvXG3hU6nzPA0HYcmJCY03SrNEEdC8XseZeEhIS3G+78d7
9uLII3WcIZCFrhKqlSMtzZwC+hR94UCe1COMwVbXWHKbgYBIsRPx3tgCBGTt/jK81S7B/4EDh5uq
/Ru4hWwmbZPUvjjSDmGp4ApSBtTLCpfCRQdKxV+koT/xeBb28JR4CCxFZX68N7GKnDUlfqC3hA3a
NoA5FqgrnA1RknI27aHF/hqonQKkj4wDRRCklaAREKXFd8BSW4V4q0rEwYb/yKMkegrYSqQNyWhB
GAGpIJuLovZV+oL3Ah8DB6siJxZjipQUI/bpqkRthzNAiOxG5u+lEiuKSErkSPtVmkepu5ekxRii
FmXEHTWHoEt8Rl6dmN3wXZh+KC3cL5jxA0OGofAowUiuEj5aQgLl4UvTDR1yF4AOiESBMqQSms1a
1Pqd9kVBpt0XydejJgFgwEv7xQvJAJyAYnJvv52j2FauKmn/QjdgCihokAhfBUafShNi2GjYRnEn
KK8loGGCwBmiUkfbH6lYvlCl1/1FeFvkqg2bSWBCRoNrQp0N+AoT3nTS4S/1NyNjBYEXn8YRqgdO
hc+cUVnBE5VO0dsEwg2HTEN8zD3bS6ZTUmjMLwilGlJISOpTC9BckIPVPomBdvaEjYhrTG6TTmIB
3QIC3E+yYqDB8RAZ3gKM4igGpZoxAVOg1Oj1QkoAfksKSp8JqiddoE2hSpHuqd3CHtPsNzT4S8hq
6ACjKEx7iNDCCeT8PctmUhSgmisQJBCx0bsJ8NultySfSFdrLy5KOzxKesU3xQp6aloMhkXowZIf
KLTbUFF4EmqKTNZEaAg6l66LWsKimzloO1Ym8DWH4AOC1tvafws0klovFfq4vY6c8P2GWA7xSp09
WwwhO5wFG+oSfj9hAv3q8LPEtAbDdbTxoqekqit6nAhmwCekKD0VSdPYJRgsuN2QqKH85nRSENPO
hWNFiy3dlwQ+eWXY1Hh4bPzmKmLR5mlk68Vxhu+Mz0omqyO4ZKC1UP34XnIzvQlpisFUA7qIbG1s
CSbpqQgfcM8XQULbW2aq5iDVnynXAVZAGl8boBS39H+4e0tTNcnCvdNmjCg19tvlFsJclDwjpGMO
oj7Ejwq1CwCUHspkNHZyYSCVdOAhGJDRAHlBZoRQc+eWpvnpPP+xv5Up9N2JW29lSrW5tjIFejhy
4kfZyVQhTMF+IomaPlcq81WuVSgwE0gpV6Ir+g8J5qPYxRZ1T82tSdJW6iKCjzs1u3Ffjalwd+65
mSm6lvCI9BrDHqAXM7QiwCdbTpJYohGSuh9Q7mMLpsP9Ahijio4+ltSfwth3Ogx8Vpa9q6LL9seO
986JAOiO2beZurA7NzN9f3Hx/rRki/HFOL84O2NLb7OJ+aK/pSn1OOFD90kuSnb7LsrzfF72tutc
7Zmt+2XX1Wq+PHxjZVfVpigBWOdk4WhdS7dByvpIpaLsyRSX2pWl0haV7M1DWUtEHEa5knby8dTZ
L52uxTGrxTGrxTGuJbBzL1SybJkultKlK1eqxiXtkUoppgK60ef4DDEID7dzaDCpvpi+AFnwY/gU
3bbeMOwCe/fGwe47s1OtqkeJGR5pL1Q7mIYFjVZobKfukWJ6gmpm2jIIV8ZWpxUCaWpXfLV6hzMB
V0olsWS8YE2Ayzl3SW6AomJ7NpVkq7KdDf6otlYRCvtv0E4DOIQVAjwM5Epimi41oO4oc2L62HQe
xb3t+BIQ96KdqYOODEkd+P7dmur9VVmen5bLvrKS/m2UFRsJmt3c2a7kCLrBo6gr/LpIPUe0dQeh
K5UF7AIK4EaRlbr0AMzSBAmABVvsaRccgnhgOowzaXsS0UUVT88+X36esbN9ea5n1kg4gwbC0UKh
PSe5JvG4aFJOLRfRMxPB1XYxqdJphYnWMBiUVwLFRswReuQRDdkdtBUEwdux77KvYXC0jZHCMeKS
O1XVBXpkWZ6WZyVaZ8xM29RRvhmQv4eOWnLO+fvxWpb7KyvtPUwkrZ1TYR+JIQWthcgQUifVD0wl
an9jsyBhNMMBM7V1Ci2pTdZGIIk77QlkhkDGtQx2aim68FLhFWvjUbCIEK53Kc4J/XVYXPAN8UkZ
UXJxVA7B8gm0ozNWC8cdPzjs7gcP5yu6ZYElMkJuYoqz4/iRlBQwJGRDzB8YANs6wgUghR4LKqDk
AU4sLcDoM8lqIK6gMaIj34kmTGTPKVIFaYc5vktiAxYF+WIyUpFSqxFxIe0B2TMLEQLwJ6CPtnZz
kP/A6iOPrYfL1bxW9cWq5ezITg1ug7tlB4shCbrKaciqKH+6vLha4h1KqOPlVXq+0Af9lSL/LPs7
rZSbi3TvlZJSkBVqC3paSLuqt4vRgKwVdgCj7bQ6bOHL0YpJ0JW6kDPo2uwuxKvFwEKbtTfGvRXS
TE8wWwlpXMtl5+oBdSDopyo7BTJBIzPhgB5Tmg9htLT3tZo+wfkxuECg3ZZS7BasF3ZRIPztRB4U
Ye0ETLurR4Cp/1irx5lmICawzlKjXGDA0rOU52UrSBIkvpqnMXdD9AsdfUAIQOQc9f1RxxFyJk58
LykOWFHkHyvtwwOxGp4WGsYxW4fYcorUPZwdLTPWLwsbzjOlsCoYhH1BD0e4VyAKHXkC/Pt3yxNz
765gv3pFNeKZXFwuWRzp6bg7vznkqvzbdblYbp3q7XcPXKEXy9PLxuf+71qei+LH/ZcnNVA0Hva0
uTt4Ik0eShFVaf2DD0wpNoh3hsGHACKStTbHCGn5wF4jNFsF/kCZF7smliTUOJN3rU1bFUzqAgkE
S7KC/ltqdsa+hjgqtPNQ21tP24RgQMHq6AOZKGEFSOGKI+zG3d2I6JJ891xSi4K6ff5jrM146kcQ
HdFXcLvIcyv9y45z0Doc4eIsPtFf5QLDZ6SKjNZV9CIhZkG5QVIjsTRYhAMWJuTKGBgUqdFGuFL7
OKA9ylvVeEg1J7n6R5IApomB2WUbnryr/+CRAn2mQXdh0m9ywML0eLToP/ZZSCbY2Lqc/p5+Yf+J
zDM8QhjLrqfx1NV+aHRWgPZP1Qk4jWmkAn+DLmf02RJwQ2VKKk4Ms4UGRNraLMcekei6dTaYp2zn
xB0OI5EW1iustMVXDjTP7uQwmF0V6lKjpr6HdAhgWlKB6QlvThUe0m8KTobNxC26jQOoExiwrNRu
IXykZSWvARIsHQFJFziQc2CMp1T72IHZOyZQowoaN9rqbUqXPsgipXiclDbSG5NOHWi2ewpyyOKC
AklylUiKDZjwIFztFINrrw0aobRn2h6G1CEqk7IL8u3ITVupVervzU7Zdhcp8HZmarqLC0bnqpR7
n8Ulsf/XLa2dwFQHh73D6bztoF2O8pFFkHeV6onWBv774ZfrWvV7ntVTYXee21E2g0z8bb7L3z3Y
pSuRjYEj/IT+TaQJPkanB5wEQfJUYFba/xH/AHUDCyJTi0BSRHj0wOO4q5BJB6xEM5J3KDSq6egK
DHNJO/CGop4DL5GoBzcha0BqjJwMvNUUGqX2TqFcka4KZMro2pySwe1y99R9doBCowNy8Ej6jD2O
6A1VKfalrzEqQvAwMDJ8LfKPUL/FaIJ0TS6Jhk1gabA8gYbYhoE2OJmymfeT4gBtZoiQWCPIC2Re
CIuhZjByFEuqWy7ZL4qyC5VTsiUf1D08mlI7ZFNcDpoEB67LxCGuu1ue8B+cwL+nNpufo5Guz/go
lZv/3x4N37pgS+hky3mOIjj/yBfrBbgBm5uXZqFu+/LTVXq53H/ZRqDp7PBEahlSi+igDJ2qNkq4
dfD48bYjnA61S1S3N21JFZs9c9VxnZJaOpRsTLiNgbjTq6flHv1FoUtBn1WTAjJ26tDHwi20yx4g
KHGqjDZKAgp/rgog6CTQlNjN1e1wlIjO7bscUS8WsTl0HguvUksOtganPSqaTtsu4sJDFDH7o5qG
J4WYIQEZUnLjEG7V/7DU/kgQhkvt25MOkt6QSBuOXq7dihztmY3bDoihPUxKMt10fScfGSqn7BGS
seGNqp0rFTnj0NNIC/ZIB1lXVfJdcowMdpXsuUrH6eL9/L9uqepuV2X1SO7FpsZ5tGXfP+t6OT+t
/bL9w3hfZZ+4xr52pCCkpAVOXftb1z5pa3g6QDNVXXGd1M9J29orPKBzgso7bp+tMwn4rgVPPxcg
U+2FoG2jsRwxqdiUKJgKIjJ5uSYtaWl6ONABLIMlBLsKPrd63VB+WvWoYPACByx4smjJY4XxWTwN
yynui7YOocMByD2JLLK+ENWIO4CK4SyQwEGPkrXCWqtEAF+Efg2gbLBq8+EiHJL4V/8ZyGYwNxMg
aYIblUiSPkLjCElAK6imkdgNVj35PDJNjCJ8T7bSjdPU60YaKIy7Vz1hvLdiSjx01Zsc++X8f2kb
fe/VvVW1/b9AJ8TTyGH34ly1jmpXmKmJDlQv/GJ6K0JfMCltVf1Dxab9Eb6otvGjFkP7fNHf7Y4J
3Qz2XWoBh4KSGxh5opJRP8siojsLlTYhNGoqqwEooK+Q1QpVcoPfGQsw9tk1U60Vq175R+gNUAtu
TMHNYyXXy2oK8dgRcmI214CDwKIM6HQGkK3GchRp0aQerlSh2nZ2PiONBYrCZoJQmGw8qXtJcYBm
8EWSTtSnBcw2RBMRJKRqYSj6IBkLUgBgs4C57CIG6kdk5qqOGFaPrW1P/C5a6jrR3ZqBTSH8MNhT
M0jeP/1/Sy88ygr/u7j+eK70k4P2qHpIOgYkIoOX8NMA+WiDFwgWptwGSq5SXvjh5OMKcsL0dVT6
Ggf3jklrRvPOhc9Wbdh208iVDceinOJ7ddsrQfrRN9q8nE5INBGCOklPAGJMusc5RAqUH1M6G/UX
fnz3wmcjDf+x4McArqQ9VeMpEg10eqWdE8xFSn3o5oTtV0IT1hDxCwo10L5CeOCQFAmZY9McO4nv
IcIh/oCoNFAIKOei6prekbSTYQDhAqvm2RWJQ/XkqqwhQ1NqbweVqxHME7VkPVg/ilxvwKpnuwZv
31W/+Ntpepp/KM8+//9z6f9XxPmw5qhmIESkboVpqIo41jSJHiwEltxV5gcGIxl39hOgSTFtbtnN
r1QnQ7h1BAJ32fn1IN614n2yg3S9s0XYzUJa4ED+pwUJjbgAu+ghJRZ2qC2mqThzlcwOUxILFKVR
AEqb2S48DgwwwNSTcYDB9lgRQIG3RPc20AdtE0GTM9rkUENDf3bt0KGCcjZmgFQL/gUVh5VOlEUx
P80RILfRdj66ryAHrHvS58BzRCXs90uPdiqSADmBM3kMmn/QRgUMAA6qSixc6s1gV7CRMQQHdgDK
1Zyoa+39Ieuevpp+dN91X+PZ/2XphcdjnZJ8JXCDrkg8TAfoRH3kaPLE/lQ+A69G84FcK3W7Awel
AlF9taDT4dxBUae9wCYtqc4D3AFks7sRlUSobqpn2B3AVqkFZaOUKTimRwGF/qW2hmDLGFoiM7vo
WE1/C1f9K4TLdgnF/s4y0g7wSudOuy5WeYR1EpVixItZUqlRKj2UMduYce1YXWgPtUJ9JQNVgGEk
aYiJeMH1KD0ka89+nK57i8wGLAmaobPk8HQpgNcuaDQLIr1O8AK6ldF8hv242FIF4rwvDIwKA8Jo
ihyobJAS7PakUTepAdQT+RX2fZNwyt38N6WyHxWq/jsklKDGOtQ+qVxabQASbTESZ6bFIG2qIDaJ
68H+QtTOYsvY+0EbmtHMXs156SVBcLUxgZD1XUuO3AXF23CUaXbmsFtiyuVZ5dgqiPswps1uY7To
IT3jqXoN65mqyxJNLIDT4qKX64jsAbwI+rbiGj7SmmO/MMqeoCJm6oxAFtpVZ1l2L+I9WGWw6aBW
ITwh6xVkAyo+Me3q9komhw0Ug3CnyIZA0BSc0TYQxj0FPDSkcsySVyd47UZO8K4GPbSA0s1pCy41
RfE4ZAcMPwY07Boh2JUDFJa8z1Wr4cFLbtuU/l/L7/w7rCZq0ykvD3BN0IGuytMhUdEcBL2oHZrh
BycqFaJUnNpIuqvhueTaQpn93woxhPJNhKIV46wjxrs8P9APbQkaYDfJ7GizBXaQMK14Keii8Yuv
jo4EedQ0Al2kQBLqLkwTRwwvDmF3hoh6NsSk0ae3rmF9hOXFxj14fzAW1cHM0x5H7E+pih9aueK5
igmqLVF43FwkbCIuOzcGBq6cq6yVPVyGQyAeuN2haN4oJUwbiWBxiChoCg2Nh/UP7q0N4tmUhBZX
ZODpEqQN0NntTH35+5svDMnMegFlcvddb2so49EW2cNJCqEal8HNpnyfHRTUmbtQdlvFWnRYo/Ma
IotFe8N7Y23QOqTUVma5XD2aydJGqj+Cerk6n37X1M9UwUhm3NZNqHanBQOdlNGTNi3UMDQyaEkm
OiOEMIB7SBQUwmhzOkpfupsDOWpPd3fQQwdlaGSPNPNhBsfFVNUK1GISXpBB8CrSqMx0deUAQZTR
pfyYMlq6geBXYRrpWszmIIEcvqi6Q24Dpjugc6YNNLXnpI3qyuiHRb09iSt2G6GiVvAKnI9AGzwR
lrHnJ3VLBDvU0UTafGktQZWe3y1A2uT5vcm+vXJoHbz3SoeoYW4qh8inm8ohOgkcuc6jFA5px2sK
RknesccmAR7d+tnym01x6HqsGnC0KIXu5O88zepI1c2Cc1LsMD3BYGZU08ur8kdk36svvaPAkXgH
kgfJLXrtlq5ujfIDgCc5SG+mSvuS4G/H6hhDjzGzrbOtDsZ0Q6L4pBu3A4VRir0Dq7MTVTjascHq
oNa4d5cNrSK9noaJJl44+S/XMMmUKlI2iVC/zVRtG1WwBbJJG2A+oBkRSAGzMtXyARBgh3t1FvMw
IUiFLnr2tH2bcf0Cu3EUHDkCehp6edrhjC2eUtofE2vFtJFkERDvGECCZjNZqM0DfW2RJs+K/fBI
73bGg50QvWj3cETvXJv1oDbYIDKPR3Vi9zCqwnBAcQUiwmf1hzTbf7DLDb0tSE1oJ8tY/YgCOQEx
RgwEM1DL7DwLNiVlCnXt+zePVHMj9jDA+XdhW8VCu+hWSZdZ8jeZarbpMQRtm9WkA0tVUdPJB9NQ
liYq6ATaAaopGSBI9W/eq7UGeB59sOm+z85ZONfaK5bItdDuVPhuKbsCUePlqRcd23vgoNA1l82R
icbh8uIDwtK6XXrbGhluL9Z3IAPDDaKPES2MXG24B2Sf4vpr+59CTQ5SdV6guzi1zmTwoZCxHbar
LfIEVXWIJ0BPzhDhUUvo7NXaxYnYXYT+m1SnwDjQpqDkEwHuaQJCy0fK9Ng+XT3E5RLQ3TKlAx1J
CREiFOCwhrPhwrulpQstjEuJj85glDZ5MMHZZ4H0AYsBq6k942jAQL8jttmADshY2jk9xMHyEjUZ
6O75RIcrdxds1xOdRxnmXj2uoHnSGIf24GGgZimmwQINfLBEqRrSwoSilwHdhthzme1hQ5E7qOUz
2x8CQ6pz23DR3dbKRZX1HuWwCImon4lHqQcN1LRTLg00IJuqqRVkKDZypasMPT+oD2TbT0JdyKcg
Zd1p5w2TnbZK3qu5Btv8ORn7p9Jtimw2nSu0sSdEG+1PjSHQruyExzTNJUjCllMBSYjOJNAOVWxO
QTHKbbK7pYULaBrbFTE6aC9HrfNps66Wp7DqAOAKbSdCO2uqGjMRV9gHlTxWUWm75hBRdktnWKLs
7jFAWLT7c/fqqBGn2q0eWg09LfyS9ulQAyPtU8/mGeww62lDbDWdoUCFDcoJFakPpfVFIG4iPAEY
AncI69bWLWzMSacvKMqOdv+l9yGNlCgxQP0nyuczq5hMoLKmeI6miSTz1fSRNtFsGBh4PYuws6F1
T2DRxIn365zmqxk4HfJ4SLxAW45h4LBXGHlR7ASgK60wYBwmyrmgWAjE4S9FIj+ja5gD8Q2B3e2U
wxfBraQBEeCXdt81OwOLiEThOIgTCosqP7WkhWwmjAxeF645vdybNhzdhGNCpmSAoGjTt+qOdotb
vvicX1y+36znpwqp9srZCjwybjlZ0cdyyytn6rhTuFbwz6kvwVPG6IFUoqDyijpsNA1WRFt7FBSE
a0dBbTVHmSvb5REzRR5T9vPn9Ox0rD4U3r26j9BHjaYNjtBSeob72s+VVuUs8ET1cfDdM2i9bDIF
6yNWyyZtc8RNSTEQ7JZ2t3LVBxFydpT0J2M3eOc67HVrtuhx7+4+sipD6Pnm7sTz/14wd15eLefV
VmCt6bEzXvfY2XbUvDhPt33OdDidZ94jlDvTudubggnhuGHHClP0TAaHTS2AjTKVGLPhAT659vmj
JFp2n4aRPh4CDHza/FTTVqzjWpK7y7tMARIMD5VBoDK1kz23Cek2RQpJ3dC0SQS1h9pinopNeqao
yZyvrCahRNHjAcW7QFk7GDv+OwfufqAmVA0l4DHKJu2pNmLS7lKZwROw9niVqDS2USEBkNMzQZt3
onlLLBhddsG+6boID4MXcUSw3pDUkD4A9FajdMFR8AYaGQpYo5tnoK3iCXTZsI2FDfkNNjroqbZF
xrmh3RBZVcoeSrvbQ8GOggEiC6kC9+7UaVfz/P/p7e5XLbmqIIC/kM7tPv39Hv4vp79QRAIqCHn6
/KodpM/I7bMzfREhmESTmXV3771WVa2qv7xeaFx1q5j2HDdaXE5zo+lS/tBNX2OodHh4P9zrchFy
dT+Any40Qe/Ri83frURdeADiZ3aDrd61MeLxk1k1tdvHv7f5n78sf9v8AOoyk5haM2mEoPhfk7hp
6X6IkyXv3AQeeN6iX3V9sbXU9tEsUd97gASiitZD4JzfFLuLn3UrNbTnT5X6N4kyZoXx9ir7jxTj
h3us+79DDKjo2WdBzh99f+3ccx1zd7jHswIAEtvT3T03WJz/QsdBxaG/JOuCDPjoHx/H7+SPxy/+
8z2qA0kzw7l1Drt8du12Q6tjJ2OJ9WTVx4EtpAGDR2ks2Dk9EiWR9MP5HIgyJhT+CnHzM6j6mCHQ
SX3VzbHotD/8TvgOYKC7KEp12cKCmBAwOukSGk/Gyh1zzO8v2VEsuVDDCd8jgpzOVTq/xa/BvpdJ
CZHV2Ec9goq8wcF/2YU2TwksphcAr6BN2Q5jGv/4yz8zoogcTljC4xywxf2CcuNdCbtsgvoX3xpS
+EXqu2MYA9tAJJKvzFlINmr5gWt+o8wHWD0jJDf6ZenM20JJQrQH6evf1q3+c3XVyvDRwleaeKGW
xmLrRlOc9MBnWYcVZu1UPrqcS35rGYs9cC4iyWSUi96Hl6px9iyo2vitv1c1TqVtb28v/kk8m9bY
g4qrh8Jw7BSMSAckJGCPqekSM8BlW/w5E8isKvqQqAg/r9pXB3gwmxyCwXAHZhEtjsXlnhjKw12W
l+0SF0xnlVIxm0zoXA5QWQME4HAHf3F/l9Jbvy+wlb6quZduUMnKJGHjCNkkjsPIb5Oa4QOFCdtb
D3T+PCth5NVILuJwsB4XM2wFJwo99/sCf3Vqh8vYGJRpx8slZveJPzoUY5gJ+KYPPPHtkdEzGbZW
N2bzRbMB6wnf+WIEnwNUUGe4YnULo6g9LsTsyR4EEPim96M1tTDG0nCERHFNTWaENA8bgvj8OppC
HSkhvumcL/f7Ov+8tX6bVLNMj/Tr8frWgMUExPElLKInAiFzBIQ6VkcE1eRS0MhxrxcQAUo7u8I3
ebcKKgpsnO5dDaNyxtNqQ5DtQX6wf/WEQ1nzHKxmQC2MOwwVmDQdXThukquR21V6CLT284qW++k/
Y6buvtyiTzR1JAaJThnqicSjbzmiwZjuEwIrHms+V7xGju8+/lx++Dl61BpDyTfP52G8dRZpTutK
D6rN3+M6E4+txK9RcAm5w2RQjvuV2ozGeEc5HtdVVmAK2+UhbUord3nm+Pa7Y9wwOyRnjWV5Nje6
pCNXFrAjVIhpvj6iTyxBNlSp7WBHfSQAVXXWBFmeKXjE4+tZ3QK45zpghD3tI06N/yvPpaSmUH5g
tREEvTwPUF5mGF9v7CqMn1UcUpekHW2llbt8ZjI3YWq4SIq1duWxNOTQQaVIsEB/KtWxTcQ3q1qn
M8a9uArGqPH1DSF//lht0Q4FhRtcf7doFRZalC4phORG97LPg2c9zs53aL6xjRi/oa2JOxWTvjWy
5BDipug5+fBL+2nhLvBZGGZiSpSCGRgGwpoDo0etPVdfzZf8xhlCay0apmYJYg4JwP+Mh4/z5Ho7
dzy2pEs+zvHkPPdzHHQjhfXDk+neRf4gAjjnzYLP98B/MAZGt7qDKfb9yLWskaGnDgOybEfYVLyq
1BU4u+M0maqjo7M3gpQTpcKM3FqY36Y1dZBanzaGdyANB7WLs86TgKERZUJ//iD1h21dcK7sNv13
PvzJ9qWJA1TeyEYrYnTF2zuqE6Y8G/aWsbMnAt5Ix53hmkfzLuyP4h2Vx4iwvq7W5910DcdQgCXw
CBcJr84a21XRVuQc26LvezAUishfrDczfr+AMflz/l9G6uGlm2YHXtBNE8IO96BsLr/JtewSVtmn
hdrnrLZbW0Clx5QP5LBbsI3sA3dir06D4guyYdtlZZGFxifV+lf58Eaqw2qMQJFRKkttBdHdgGnY
/jbRyDlNjs/hycEpQXnnTONaILaq+Pizd10iVwo+SnLG+h7D5N5HDLMsRNugkXByz3THBl1zWeZz
f8fmpshzcNUc0/naUEoNjekJy8k+5G3h3kxvq0hhWFmdPPMYeW4mMArZ8bBo94hHKBKA09VaRYEa
Z3zw4xRmH0Z+ZgTYdzePgrK132yl3koHXD44arVVYh8MQzgTTUc636ym59EHpT9jqEAmGyAVlkIj
HFe2PS435AtXZfvq8c1WnLlCulSS12OY6dtgLGFNBjXFdAJFlngLozNB7moRPIyMx6nxykJnzq1c
GJmxoMKAu+ZWeBdNzHOPdDJJf141JLaInCkMpMfBJYywo5wME79l4TRhWVR3zkgip5gELQUV/ur5
rcoGkiZZUoQNXVZoS+4ekLy+uA3RnLhO25F94tSoBNaE0tfiiUWTocPO+UkYyr6g82Om29X3QkUZ
otUk4C6p54YrgPWPzH65f+bJdLvDb9Jd4JzHXJou0DVIlAeoSgKP9aT3hf75Ac47HENX0GKb/S8t
FCk/IH+VEWtD6ZFFpSGprWuistuoNC2ix8ifVsSG6Gs69VByO4h2qMabOa1wcP8Q++mxjSI+odMw
FEh1k4SS7lVHhmKl3vSjl+6QqZmyFFIaMo7n/OclLZ/g5giy2UWOQFg0KyNpkfJC2/cghcT0/HLx
fb4U23QmdNKLNZhjnifRI/05AzTDZgGa0FrpvpfDAmqGw26ReHH7IFIT0MunRwPnQnrkGgXr8VaO
Rzb+XpKNoxqRmvNJswY7Ky3dNWywJhtJpIjuGRw+4KyjQGxxChIQiQtov5pscADvlgjej5bevuGW
9KwXzxGc/7UP7ffS1TK8bn3Iehgxy+4RN2YeUOPndqxHmaAQYeK74oiNFxtnl5DPJzpPv51IPs3z
21pcuksEO1kGnFnAFk0SOQH8eVEol7cAccOWkJaMQHwh09lqxbUSZBaG5jiknCo35NQVVK4BG9w6
dMygQVgs0egdocWWrVnOwXexE1IheJC19klngmtWM6ZQ5uhkzBlYiPq4rvpyP6/cVU6SuZBYvIKV
D8uRcj5ofchRkO6DTxevqw8MqWsdj4gQ4sIqxl8K6iLo8NwvIhj7glJh/9pb2BQfUlq4SfI41w3a
tyAUuhwsEblNYrB0s3XYtxhqDqbdmbZKG+kyRitvSSC4KtXVFJeWveoPkVYTfFGgLqshb1aXLZHN
CcpRGqrD/86sCw3LVpH/NucYdi99otuvoFxY1u7eXMLEt/O+9sRA4PvmyIxyExNOudRIqSBsCfuU
rpM47zHamGgLnTSeCTi45k25Pm+reQHS0mSeFSLKds3j6F/gYrNe1aavd3DpZyw1Ehf7Dsl/4aTJ
ysUqoSReht5mLLnCRilct6YR+zJZlYb9EJxGcmCytH1eHafnMHgy90bVsDT5i30oJT92mVJQ5jQn
/0sldd//WE7BOb+wYDfSEl3gGNJFd7TExN88LOuNyQ3RZQACZqyhteJkqHrxcx+aHyi4kmPG0v1e
s1z30RH5RVdWsoIZ4rVXHGZPaRDPTJkHdG70956YDHgGY3qR5rjs7EDgad7W7c0Q519NbsgUk/ok
qn+pETZUEsU5pg1q42QbIJSPV3D42PMt8fEIyqPQ2ysFNxV0vhKlpn64eZfJvbQAr2w+gUj4HsdH
SUwjTsMKpx8sMe3O/N51B0zmJ6ibHwIhRUY6XVTtq2c4/35RPDjBOKFxCzqs+XytU8w2BdJlH2k2
KCk7pW1OHtg2y11gZ9rNFxe0QDgFBY785V4gZrZxhQjFFxJFoUtHDQehERrkKAzCoY8GlBEh0MRI
b8eADKeP0Ri+Hbn1vsBfPcIhr+gKtekEeK5Z845JyEoGESnG3+OGkAOtkkwal8VDwl81B6FnjwDa
5YXqfFQFWCGZcHUvvVXK9ZwA14SQuPNJBtdHyME1K2OyPh8BDiE88HIC1fwYpI7iZLouEh1x0/X7
Ov/8BEdJCDmkWcRuIv2wr2Z3x3c+7CbgZMIBJAS1yQvSA1LGRhjqu9MrwtHOY0iT+MCCinbfhnsU
HHstaawaY5BdgEJcmI/ezZmIF5C0IAp2BCYl9BgQNPphHXZeAh7nXAaXiwv1d0RaJzFxSRaQ3Yyn
FGj8ujxwcoBHiGqgwRppaHIxmBu1EQBqLIYsVCXleHuh4BzlgsrR8d5rEPee1clH1khVT9cKOEzY
9xCJVjiQPcBNoBCPgoyuFWYbbbSteYuwlNN7aeUuz1wE63JDFtNjDKiCEAwhz1WJtJZwPRCxa5Qg
bAlo4NA9MdV2quwdAIXPZw4tUUD7UhkP98LAjSC6Y+76bCZ8MN5qxCWMjooGLONbdamT6/oV2sv1
5TD6ADlapHNFAbzc8oWVu4QKGU8hnCMzys/LCQuotoQ59+R49Kxu6vYtCtL7Z5XZ/8rca/Flc8M8
9hcK7vPs1pOGqxLA0vf3ESyCMmMT+wWzBiE7RBCplM+E6i/gtmHTZeNOZ1xcZxVkjuftEku9+dPC
XUxvRq7liDIhc/MjE2LrWWOFOEZtpL+pskbqmEl2xNy47qToNMfsjSv0uf5AwU0FlUKTDLc6nmFJ
/gHFXwzWrSh0cTj3lrnHCO7GhMu3kQ97kNH6Mi/nlDALAUaYJJBMV5W6Gt44CxIKw78cFu6G/IQc
aGdXD+A6zcCLkCPEPXxlp2w48i93faC0tJaP5ysF92gKqsWbZuhvRtt2lYHErARGITRER2Z7hAcV
qpV7qvc0fa8pPehknJMt9At2MpQmG61rrqv1eTdt3R70oLuwLWvtwFJJtMTJ8kAvYE1t5sFTAE8+
O0axbaL3QHgoc++llYpXCq57FFSr/dZ0d9dvNnYH2VhIs8QcBxSUh90bsIsed5fUuUtdv1nokDbl
75hws4FglH+8ikzP1fodFJyfTJU4RHQlt2C+xYjdPcoOQpA1UtcpFC9nUv+hpYzaMsogvQh+bn6x
t60yRRUUTq/R38II5i0NHHLDTbLHbwvYEy/Vac/NarWU/oEhMDNeZqGHBxdtxhY3VfvtfeyS3hfu
HQUH3QzxjZMXuZ6c0i1ETzxWZAruOfljznVFkGRCcuj1Z3Y2NxceuWr7SsG1Q0HZNBrVLdCON/Vz
QPx6nLLy6JdaEYnINGY+yTljzQIkraKFNC420xH+F1koHxD9SHjE9apsXz2+uVShw8OYXGUw2DOm
aSOogX2DJccYPtol9QEnqIHigHCynpH9S9JMEaAvWLxeueRgjrdfi2fCkYMVoQ3oYnmVzJEFxOxP
02kqSm5xqmrhUGNM/gI46RKJge2kT94LKvzV81uctomlp2TrIuIOjgieS/LOVgLU4DrvY8Zt5nBX
YG/hlmYlceGui8cL1zllGfp9oRMYe5NNfsSgwTwxBUDJEqVWH3wT+Jw3y1K10U/usY6iHFsTYq4J
y9OJBHd26pKj/PMDnBVjW42auyEvtq1F9ziGBq7UJ2MW3AuLzRKJ2W0w6LV5hGLO3tlbbevz2T20
GQUlrWE7txCxaY2Gsg0wDo1uMrVPCSSzQO0xJ5zs83bXDaw/o2c2DgMv8j6gsV9JxauLkpZPcFQM
bib106QnWS56XvapTxkzuDehDvHGlYMHs6YJ8S3wBMzPmtnOaM1qeQmmb+uCtoffOm3wrfdoSZ9I
WOYzEiqWRM2OfFrPuD8iluFfaaXDMwVIRsxSP+gZ5+wzET5kTWEvLd3lqbOHEd2EJhAOhy61DP6w
IXwEi9lRlEVNjr63x4rPduiM7Uj6zEG1x17y+dQ93vi3fC9dK5j21o3ZrfYgPvT7fexItc8wTyCx
34ifPlE/cwisIliWt39qllRNS3w4Hj4VhtW5Ky3d1VvDpdsPCEsEnvbJcp1bs84iBcjg475mJO4X
t9rzQaCqK5ldFG9iW4zt1Lznt6Z6E8DzvXL9t+aewcJUxylLW6sBsu/OfWrlQmWiNOk6d9HvU9DK
PyQyltLYZLvd3WOLCS2gX7l6a6723A2Ecux43zk4FqCTOmXUAfHzz2wdcOMbXbs1FX+0dhN3kTbT
kDRfaEz3SsF1Bc9ynWXHW4pTJpk8Y9jq2KzqYmgE1qAiIDG2BMeflf6bdwL1f0hCbvx0B0+Xcxcz
/sMjv70s1dUUp5dOtIZmYI6Xgp8Owo/qKWk11KiiIKO2fqaFYWGadtsklIxCTlgUuT9ItUpm3nqS
xdHcFGPwPSF+sGLmVwzvBPbg3bgewahYart6Ew7AbVf3knSTKTNMF7TPrjODojfl+rytZo3gDLFP
OvY94cO0HT5Mm0crPk5DBZiYErWhN4ywOQOfV9OUFwDhxd+wiifW+3JZm7npojCg4PhoUrG5OvAc
gVUAKTRLPgFaiHgBIyFAoPoVLwQfTY1BNr14toTFfy1XQVpYHQDQPwmwGjMGkilGwd6cbP6LUV4D
RbnIuD6u4TOquF444AEMjCsnce6YjfOCpcHxW9e/XZ399a+//v2Xf/ywPMvMKMuzvwH1kno384QB
AA==
#@@END fastapi
#@@PATCH petclinic
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
#@@END petclinic
#@@PATCH eshop
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
#@@END eshop
#@@PATCH go-orders
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
#@@END go-orders
