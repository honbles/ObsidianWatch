#!/usr/bin/env bash
# Unzip and start the ObsidianWatch sample applications, each on its own free random port on 0.0.0.0.
#
#   ./run-all.sh               install missing tools, unzip, start every app, print the URLs
#   ./run-all.sh traffic       send sample traffic to every running app
#   ./run-all.sh status        show what is running and where
#   ./run-all.sh stop          stop every app and the databases the apps started
#   ./run-all.sh logs <app>    follow one app's log (juice-shop, fastapi, petclinic, eshop, go-orders)
#
# Options (environment variables):
#   APPS="juice-shop go-orders"   only these apps (default: all five)
#   DEST=/srv/ow-apps             where the apps are unpacked (default: /opt/ow-sample-apps as root, else ~/ow-sample-apps)
#   OTEL_EXPORTER_OTLP_ENDPOINT   the ObsidianWatch agent on this host (default http://127.0.0.1:4318)
#   SKIP_INSTALL=1                do not install tools
#   FRESH=1                       unpack again over an existing copy (keeps nothing from a previous run)
#
# Ports: each app gets a port the kernel reports free at start (never 80, 443 or another port in use); the
# databases the apps start bind random loopback ports too. Open the printed ports in your firewall to reach the
# apps from outside. The apps are test applications (Juice Shop is deliberately vulnerable): do not expose them
# to the internet.
#
# Tools installed when missing (Debian/Ubuntu with apt; run as root or with sudo):
#   curl unzip git python3 build-essential, Node.js 22, uv (Python 3.14), OpenJDK 21, .NET SDK 8, Go 1.25+,
#   PostgreSQL server (only when Docker is not running; its default cluster is stopped and disabled so it
#   takes no port). Node, Go and .NET (when apt has no package) go to /opt/ow-tools.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ "$(id -u)" = 0 ]; then DEST="${DEST:-/opt/ow-sample-apps}"; else DEST="${DEST:-$HOME/ow-sample-apps}"; fi
TOOLS=/opt/ow-tools
LOGS="$DEST/logs"
export OTEL_EXPORTER_OTLP_ENDPOINT="${OTEL_EXPORTER_OTLP_ENDPOINT:-http://127.0.0.1:4318}"
ALL="juice-shop fastapi petclinic eshop go-orders"
APPS="${APPS:-$ALL}"

zip_of() { case $1 in juice-shop) echo juice-shop-obsidianwatch.zip ;; fastapi) echo fastapi-template-obsidianwatch.zip ;;
  petclinic) echo spring-petclinic-obsidianwatch.zip ;; eshop) echo eshoponweb-obsidianwatch.zip ;; go-orders) echo ow-orders-go-obsidianwatch.zip ;; esac; }
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
  [ -n "$APT_UPDATED" ] || { $SUDO apt-get update -qq; APT_UPDATED=1; }
  DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq "$@" >/dev/null
}
apt_has() { command -v apt-cache >/dev/null && apt-cache show "$1" >/dev/null 2>&1; }
need() { local a; for a in "$@"; do case " $APPS " in *" $a "*) return 0 ;; esac; done; return 1; }

install_tools() {
  say "checking tools"
  local base=()
  for c in curl unzip git python3; do command -v $c >/dev/null || base+=("$c"); done
  command -v cc >/dev/null || base+=(build-essential)
  command -v pip3 >/dev/null || base+=(python3-pip)
  [ -e /etc/ssl/certs/ca-certificates.crt ] || base+=(ca-certificates)
  [ ${#base[@]} -eq 0 ] || { say "installing ${base[*]}"; apt_install "${base[@]}"; }

  if need juice-shop; then   # Node.js 22.15+ (OpenTelemetry JS needs it)
    local nv; nv=$(node -v 2>/dev/null | tr -d v || true)
    if [ -z "$nv" ] || ! ver_ge "$nv" 22.15.0; then
      command -v xz >/dev/null || apt_install xz-utils
      say "installing Node.js 22 into $TOOLS/node"
      local f; f=$(curl -fsSL https://nodejs.org/dist/latest-v22.x/SHASUMS256.txt | grep -o "node-v22[0-9.]*-linux-$(arch).tar.xz" | head -1)
      $SUDO mkdir -p "$TOOLS/node"
      curl -fsSL "https://nodejs.org/dist/latest-v22.x/$f" | $SUDO tar -xJ -C "$TOOLS/node" --strip-components=1
      PATH="$TOOLS/node/bin:$PATH"
    fi
  fi

  if need fastapi; then      # uv (fetches Python 3.14 itself)
    if ! command -v uv >/dev/null; then
      say "installing uv"
      curl -LsSf https://astral.sh/uv/install.sh | env UV_NO_MODIFY_PATH=1 sh >/dev/null
      PATH="$HOME/.local/bin:$PATH"
    fi
  fi

  if need petclinic; then    # Java 17+
    local jv; jv=$(java -version 2>&1 | sed -n 's/.*version "\([0-9]*\).*/\1/p' | head -1 || true)
    if [ -z "$jv" ] || [ "$jv" -lt 17 ]; then
      say "installing OpenJDK"
      if apt_has openjdk-21-jdk-headless; then apt_install openjdk-21-jdk-headless; else apt_install openjdk-17-jdk-headless; fi
    fi
  fi

  if need eshop; then        # .NET SDK 8+
    if ! dotnet --list-sdks 2>/dev/null | grep -q .; then
      say "installing the .NET 8 SDK"
      if apt_has dotnet-sdk-8.0; then apt_install dotnet-sdk-8.0
      else
        curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh
        $SUDO bash /tmp/dotnet-install.sh --channel 8.0 --install-dir "$TOOLS/dotnet" >/dev/null
        export DOTNET_ROOT="$TOOLS/dotnet"; PATH="$TOOLS/dotnet:$PATH"
      fi
    fi
  fi

  if need go-orders; then    # Go 1.25+
    local gv; gv=$(go env GOVERSION 2>/dev/null | tr -d go || true)
    if [ -z "$gv" ] || ! ver_ge "$gv" 1.25.0; then
      local g; g=$(curl -fsSL 'https://go.dev/dl/?mode=json' | python3 -c "import sys,json;print(json.load(sys.stdin)[0]['version'])")
      say "installing $g into $TOOLS/go"
      $SUDO rm -rf "$TOOLS/go"; $SUDO mkdir -p "$TOOLS"
      curl -fsSL "https://go.dev/dl/$g.linux-$(goarch).tar.gz" | $SUDO tar -xz -C "$TOOLS"
      PATH="$TOOLS/go/bin:$PATH"
    fi
  fi

  if need fastapi go-orders; then   # PostgreSQL: Docker if it runs, else a local server package
    if ! { command -v docker >/dev/null && docker info >/dev/null 2>&1; } && ! ls /usr/lib/postgresql/*/bin/initdb >/dev/null 2>&1 && ! command -v initdb >/dev/null; then
      say "installing the PostgreSQL server (its default cluster is stopped and disabled; the apps start their own on random ports)"
      apt_install postgresql
      $SUDO systemctl disable --now postgresql >/dev/null 2>&1 || $SUDO service postgresql stop >/dev/null 2>&1 || true
    fi
  fi
  export PATH
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
unpack() {
  mkdir -p "$DEST" "$LOGS"
  for a in $APPS; do
    local z d; z="$HERE/$(zip_of "$a")"; d="$(dir_of "$a")"
    [ -f "$z" ] || { warn "missing $z"; continue; }
    if [ -d "$DEST/$d" ] && [ -z "${FRESH:-}" ]; then continue; fi
    rm -rf "${DEST:?}/$d"; say "unpacking $a"; unzip -q -o "$z" -d "$DEST"
    chmod +x "$DEST/$d/run.sh" "$DEST/$d/mvnw" 2>/dev/null || true
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
}

up() { curl -s -o /dev/null --max-time 3 "http://127.0.0.1:$(cat "$LOGS/$1.port" 2>/dev/null)/"; }

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
  echo; echo "Telemetry goes to $OTEL_EXPORTER_OTLP_ENDPOINT. Send traffic: $0 traffic"
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

case "${1:-start}" in
  start)   [ -n "${SKIP_INSTALL:-}" ] || install_tools; unpack; start ;;
  traffic) traffic ;;
  status)  status ;;
  stop)    stop ;;
  logs)    tail -f "$LOGS/${2:?app name}.log" ;;
  *)       sed -n '2,12p' "$0"; exit 1 ;;
esac
