# ── Stage 1: Build management server ──────────────────────────────────────────
FROM golang:1.25.7-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build/management/backend
COPY management/backend/go.mod management/backend/go.sum* ./
RUN go mod download 2>/dev/null || true
COPY management/backend/ .
RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /management-server ./cmd/server

# ── Stage 2: Runtime with Go toolchain for on-demand agent compilation ─────────
# The Go toolchain stays in the final image so the API can cross-compile
# agents at runtime when an admin clicks "Download" in the Agent Builder.
FROM golang:1.25.7-alpine

RUN echo "https://mirror.csclub.uwaterloo.ca/alpine/v3.19/main" > /etc/apk/repositories \
    && echo "https://mirror.csclub.uwaterloo.ca/alpine/v3.19/community" >> /etc/apk/repositories \
    && apk add --no-cache ca-certificates tzdata wget git gcc musl-dev python3 py3-pip py3-wheel openjdk17-jre-headless nodejs gcompat \
    || (echo "https://dl-cdn.alpinelinux.org/alpine/v3.19/main" > /etc/apk/repositories \
    && echo "https://dl-cdn.alpinelinux.org/alpine/v3.19/community" >> /etc/apk/repositories \
    && apk add --no-cache ca-certificates tzdata wget git gcc musl-dev python3 py3-pip py3-wheel openjdk17-jre-headless nodejs gcompat)
# ── Code scanners (Code step 2) ───────────────────────────────────────────────
# Every scanner is pinned. Each download is checked against the release's own
# checksum file, and against the *_SHA256 build argument when one is given
# (set them: the Trivy release channel was compromised in March 2026, v0.69.4).
# A scanner that fails to install is skipped; the server reports it as
# "missing" and runs the others.
ARG TARGETARCH
ARG OPENGREP_VERSION=v1.31.0
ARG OPENGREP_SHA256=
ARG OPENGREP_RULES_REF=main
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256=
ARG TRIVY_VERSION=0.71.2
ARG TRIVY_SHA256=
COPY management/docker/install-scanners.sh /tmp/install-scanners.sh
RUN sh /tmp/install-scanners.sh && rm -f /tmp/install-scanners.sh

# Semgrep CE engine (LGPL-2.1) as a fallback when the opengrep binary is not
# available. Only the bundled rules above are ever used: the Semgrep registry
# rules (p/default) are under the Semgrep Rules License, which does not allow
# use in a product like this.
RUN [ -x /usr/local/bin/opengrep ] || pip3 install --break-system-packages "semgrep==1.100.0" 2>/dev/null || echo "semgrep install failed"

# Trivy databases baked into the image so dependency scanning works offline.
# With network access the server refreshes them when stale
# (OW_SCANNER_DB_UPDATE=false keeps them frozen).
ENV OW_TRIVY_CACHE_DIR=/var/cache/trivy
RUN [ ! -x /usr/local/bin/trivy ] || { trivy image --download-db-only --cache-dir /var/cache/trivy --no-progress \
      && trivy image --download-java-db-only --cache-dir /var/cache/trivy --no-progress; } \
    || echo "trivy DB download failed - dependency scanning needs network at scan time"

# Set JAVA_HOME so CodeQL uses system Java instead of its bundled glibc Java
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk
ENV PATH="${JAVA_HOME}/bin:${PATH}"

# H-4: pinned release (bump deliberately); set CODEQL_SHA256 to also verify the download.
# 2.23.3+ is needed for C/C++ build-mode none and Rust.
ARG CODEQL_VERSION=v2.23.3
ARG CODEQL_SHA256=
# Install CodeQL CLI - best-effort, falls back to the other engines if unavailable
RUN ARCH=$(uname -m) &&     if [ "$ARCH" = "x86_64" ]; then CODEQL_ARCH="linux64"; else CODEQL_ARCH="linux-arm64"; fi &&     wget -q --timeout=300       "https://github.com/github/codeql-action/releases/download/codeql-bundle-${CODEQL_VERSION}/codeql-bundle-${CODEQL_ARCH}.tar.gz"       -O /tmp/codeql.tar.gz 2>/dev/null &&     { [ -z "$CODEQL_SHA256" ] || echo "$CODEQL_SHA256  /tmp/codeql.tar.gz" | sha256sum -c -; } &&     tar -xzf /tmp/codeql.tar.gz -C /usr/local/ 2>/dev/null &&     ln -sf /usr/local/codeql/codeql /usr/local/bin/codeql &&     rm -f /tmp/codeql.tar.gz &&     codeql version && echo "CodeQL installed successfully"     || echo "CodeQL install failed - SAST will run without CodeQL"

WORKDIR /app

# Management server binary
COPY --from=builder /management-server ./management-server
COPY management/docker/server.yaml ./server.yaml

RUN mkdir -p certs

# ── Agent source trees for on-demand compilation ──────────────────────────────
# Paths inside container:
#   /agent-src/linux/    - obsidianwatch/linux-agent
#   /agent-src/windows/  - obsidianwatch/agent  (windows)
#   /agent-src/macos/    - obsidianwatch/macos-agent
#   /agent-src/network/  - obsidianwatch/network-probe
COPY agents/linux/   /agent-src/linux/
COPY agents/windows/ /agent-src/windows/
COPY agents/macos/   /agent-src/macos/
COPY agents/network/ /agent-src/network/

# Set GOPATH/GOMODCACHE so modules land in /root/go/pkg/mod - the same path
# the runtime compiler uses (GOPATH=/root/go in agent_builder.go)
ENV GOPATH=/root/go
ENV GOMODCACHE=/root/go/pkg/mod

# Pre-fetch all agent dependencies so runtime compile needs no network.
# go mod tidy regenerates go.sum; go mod download populates the module cache.
# Both run at IMAGE BUILD TIME when internet is available.
RUN cd /agent-src/linux   && go mod tidy && go mod download
RUN cd /agent-src/windows && go mod tidy && go mod download
RUN cd /agent-src/macos   && go mod tidy && go mod download
# Network agent deps skipped - large sqlite package, built on-demand
# RUN cd /agent-src/network && go mod tidy && go mod download

# Binary cache dir (mounted as a volume so compiled binaries survive restarts)
RUN mkdir -p /var/lib/obsidianwatch/agent-cache/linux \
             /var/lib/obsidianwatch/agent-cache/windows \
             /var/lib/obsidianwatch/agent-cache/macos \
             /var/lib/obsidianwatch/agent-cache/network

EXPOSE 8443
HEALTHCHECK --interval=15s --timeout=10s --retries=5 --start-period=20s \
  CMD cat /proc/net/tcp6 2>/dev/null | grep -q 20FB || cat /proc/net/tcp 2>/dev/null | grep -q 20FB || exit 1

ENTRYPOINT ["./management-server", "-config", "server.yaml"]
