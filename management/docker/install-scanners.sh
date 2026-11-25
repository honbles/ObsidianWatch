#!/bin/sh
# Installs the pinned code scanners into /usr/local/bin and the opengrep rules
# into /opt/obsidianwatch/rules/opengrep. Best effort per tool.
set -u
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  GL_ARCH=x64;   TV_ARCH=64bit; OG_ASSET=opengrep_musllinux_x86 ;;
  aarch64) GL_ARCH=arm64; TV_ARCH=ARM64; OG_ASSET=opengrep_musllinux_aarch64 ;;
  *) echo "unsupported arch $ARCH"; exit 0 ;;
esac
cd /tmp

# check FILE SUMS_FILE EXPECTED_SHA: verify against the release checksum list
# and, if given, the pinned hash.
check() {
  f="$1"; sums="$2"; want="$3"
  if [ -n "$sums" ] && [ -f "$sums" ]; then
    grep " $(basename "$f")\$" "$sums" | sed "s#  .*#  $f#" | sha256sum -c - >/dev/null || { echo "checksum list mismatch for $f"; return 1; }
  fi
  if [ -n "$want" ]; then
    echo "$want  $f" | sha256sum -c - >/dev/null || { echo "pinned hash mismatch for $f"; return 1; }
  fi
  return 0
}

# gitleaks (MIT)
GL=gitleaks_${GITLEAKS_VERSION}_linux_${GL_ARCH}.tar.gz
if wget -q --timeout=120 "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${GL}" -O "$GL" \
   && wget -q "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_checksums.txt" -O gl.sums \
   && check "$GL" gl.sums "${GITLEAKS_SHA256:-}" && tar -xzf "$GL" gitleaks && install -m 0755 gitleaks /usr/local/bin/gitleaks; then
  gitleaks version || true
else
  echo "gitleaks install failed - history secrets use the built-in patterns"
fi
rm -f "$GL" gl.sums gitleaks

# Trivy (Apache-2.0)
TV=trivy_${TRIVY_VERSION}_Linux-${TV_ARCH}.tar.gz
if wget -q --timeout=180 "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${TV}" -O "$TV" \
   && wget -q "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt" -O tv.sums \
   && check "$TV" tv.sums "${TRIVY_SHA256:-}" && tar -xzf "$TV" trivy && install -m 0755 trivy /usr/local/bin/trivy; then
  trivy --version || true
else
  echo "trivy install failed - dependency scanning falls back to OSV lookups"
fi
rm -f "$TV" tv.sums trivy

# opengrep engine (LGPL-2.1)
if wget -q --timeout=180 "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/${OG_ASSET}" -O opengrep \
   && check opengrep "" "${OPENGREP_SHA256:-}" && install -m 0755 opengrep /usr/local/bin/opengrep && opengrep --version; then
  :
else
  rm -f /usr/local/bin/opengrep
  echo "opengrep install failed - the semgrep engine will be used if installed"
fi
rm -f opengrep

# opengrep-rules (LGPL-2.1 community rules, forked before the Semgrep Rules
# License change). Only rule directories are kept; test fixtures are dropped.
DEST=/opt/obsidianwatch/rules/opengrep
if git clone --quiet --depth 1 --branch "${OPENGREP_RULES_REF}" https://github.com/opengrep/opengrep-rules.git rules-src; then
  mkdir -p "$DEST"
  for d in bash c csharp dockerfile elixir generic go html java javascript json kotlin ocaml php python ruby rust scala solidity swift terraform typescript yaml; do
    [ -d "rules-src/$d" ] && cp -r "rules-src/$d" "$DEST/"
  done
  find "$DEST" -type f ! -name '*.yaml' ! -name '*.yml' -delete
  find "$DEST" -type f \( -name '*.test.yaml' -o -name '*.test.yml' -o -name '*.fixed.*' \) -delete
  cp rules-src/LICENSE "$DEST/LICENSE" 2>/dev/null || true
  echo "opengrep rules: $(find "$DEST" -name '*.yaml' | wc -l) files"
else
  echo "opengrep-rules download failed - pattern rules limited to the built-in set"
fi
rm -rf rules-src
exit 0
