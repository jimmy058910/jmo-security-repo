#!/usr/bin/env bash
# update_tools.sh — Update curated tools user-locally (no sudo), idempotent.
# Targets: gitleaks, trivy (binary). Nosey Parker is containerized by default.

set -u
IFS=$'\n\t'

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
log() { echo -e "${BLUE}[update]${NC} $*"; }
ok() { echo -e "${GREEN}[ok]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }

mkdir -p "$HOME/.local/bin" 2>/dev/null || true
case ":$PATH:" in *":$HOME/.local/bin:"*) : ;; *) export PATH="$HOME/.local/bin:$PATH" ;; esac

update_gitleaks() {
  log "Updating gitleaks"
  local TAG FILE URL ARCH
  ARCH=$(uname -m)
  TAG=$(curl -sSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r '.tag_name') || return 0
  FILE="gitleaks_${TAG#v}_linux_x64.tar.gz"
  [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ] && FILE="gitleaks_${TAG#v}_linux_arm64.tar.gz"
  URL="https://github.com/gitleaks/gitleaks/releases/download/${TAG}/$FILE"
  curl -fsSL "$URL" -o /tmp/gitleaks.tgz || {
    warn "download failed"
    return 0
  }
  tar -xzf /tmp/gitleaks.tgz -C /tmp gitleaks 2>/dev/null || true
  install -m 0755 /tmp/gitleaks "$HOME/.local/bin/gitleaks" 2>/dev/null || true
  ok "$(gitleaks version 2>/dev/null || echo gitleaks updated)"
}

update_trivy() {
  log "Updating trivy"
  local TAG FILE URL ARCH
  ARCH=$(uname -m)
  TAG=$(curl -sSL https://api.github.com/repos/aquasecurity/trivy/releases/latest | jq -r '.tag_name') || return 0
  FILE="trivy_${TAG#v}_Linux-64bit.tar.gz"
  [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ] && FILE="trivy_${TAG#v}_Linux-ARM64.tar.gz"
  URL="https://github.com/aquasecurity/trivy/releases/download/${TAG}/$FILE"
  curl -fsSL "$URL" -o /tmp/trivy.tgz || {
    warn "download failed"
    return 0
  }
  tar -xzf /tmp/trivy.tgz -C /tmp trivy 2>/dev/null || true
  install -m 0755 /tmp/trivy "$HOME/.local/bin/trivy" 2>/dev/null || true
  ok "$(trivy --version 2>/dev/null | head -n1 || echo trivy updated)"
}

case "${1:-all}" in
gitleaks) update_gitleaks ;;
trivy) update_trivy ;;
all)
  update_gitleaks
  update_trivy
  ;;
*) log "Unknown target: $1" ;;
esac
