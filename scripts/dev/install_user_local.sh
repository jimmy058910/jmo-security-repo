#!/usr/bin/env bash
# install_user_local.sh — Install security CLI tools into ~/.local/bin without sudo.
# Goals:
# - Avoid terminal closures by never exiting non-zero (best-effort installs)
# - Install per-user into $HOME/.local/bin
# - Keep steps small, idempotent, and chatty
#
# Usage examples:
#   bash scripts/dev/install_user_local.sh trivy
#   bash scripts/dev/install_user_local.sh all

set -u # (no -e; we don't want to abort on first error)
IFS=$'\n\t'

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${BLUE}[install]${NC} $*"; }
ok() { echo -e "${GREEN}[ok]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
err() { echo -e "${RED}[err]${NC} $*"; }

mkdir -p "$HOME/.local/bin" 2>/dev/null || true
case ":$PATH:" in
*":$HOME/.local/bin:"*) : ;;
*)
  export PATH="$HOME/.local/bin:$PATH"
  warn "Added ~/.local/bin to PATH for this session"
  ;;
esac

download() {
  # download <url> <dest>
  local url="$1" dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$dest" && return 0
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$dest" "$url" && return 0
  fi
  return 1
}

install_trivy() {
  log "Installing trivy (user-local)"
  # Official installer supports -b for target dir
  local script="/tmp/install-trivy.sh"
  if download "https://raw.githubusercontent.com/aquasecurity/trivy/main/install.sh" "$script"; then
    # Run installer in a subshell to isolate environment; ignore failure
    (sh "$script" -b "$HOME/.local/bin" >/tmp/trivy-install.log 2>&1) || warn "trivy installer returned non-zero (see /tmp/trivy-install.log)"
  else
    warn "Failed to download trivy installer"
  fi
  if command -v trivy >/dev/null 2>&1; then
    ok "trivy installed: $(trivy --version 2>/dev/null | head -n1)"
  else
    warn "trivy not found after attempt"
  fi
}

verify() {
  echo ""
  log "Verification"
  if command -v trivy >/dev/null 2>&1; then
    echo "  - trivy: OK ($(trivy --version 2>/dev/null | head -n1 || echo present))"
  else
    echo "  - trivy: missing"
  fi
}

main() {
  if [ $# -eq 0 ] || [ "$1" = "all" ]; then
    set +e
    install_trivy
    verify
    exit 0
  fi
  for tool in "$@"; do
    case "$tool" in
    trivy) install_trivy ;;
    *) warn "Unknown tool: $tool" ;;
    esac
  done
  verify
}

main "$@"
