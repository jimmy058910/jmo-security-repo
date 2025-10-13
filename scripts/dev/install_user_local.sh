#!/usr/bin/env bash
# install_user_local.sh — Install security CLI tools into ~/.local/bin without sudo.
# Goals:
# - Avoid terminal closures by never exiting non-zero (best-effort installs)
# - Install per-user into $HOME/.local/bin
# - Keep steps small, idempotent, and chatty
#
# Usage examples:
#   bash scripts/dev/install_user_local.sh gitleaks
#   bash scripts/dev/install_user_local.sh trivy noseyparker
#   bash scripts/dev/install_user_local.sh all

set -u  # (no -e; we don't want to abort on first error)
IFS=$'\n\t'

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${BLUE}[install]${NC} $*"; }
ok()   { echo -e "${GREEN}[ok]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
err()  { echo -e "${RED}[err]${NC} $*"; }

mkdir -p "$HOME/.local/bin" 2>/dev/null || true
case ":$PATH:" in
  *":$HOME/.local/bin:"*) : ;;
  *) export PATH="$HOME/.local/bin:$PATH"; warn "Added ~/.local/bin to PATH for this session" ;;
esac

ARCH_RAW=$(uname -m || echo x86_64)
case "$ARCH_RAW" in
  x86_64|amd64)  ARCH_GH=x86_64; ARCH_GL=x86_64 ;;
  aarch64|arm64) ARCH_GH=arm64;   ARCH_GL=arm64 ;;
  *)             ARCH_GH=x86_64; ARCH_GL=x86_64 ;;
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

install_gitleaks() {
  log "Installing gitleaks (user-local)"
  # Use direct latest download URL (avoid GitHub API rate limits)
  # Expected asset names: gitleaks_Linux_x86_64.tar.gz | gitleaks_Linux_arm64.tar.gz
  local url="https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_Linux_${ARCH_GL}.tar.gz"
  local tgz="/tmp/gitleaks.tgz"
  if download "$url" "$tgz"; then
    # Extract only the gitleaks binary regardless of path inside the tar
    local binpath
    binpath=$(tar -tzf "$tgz" 2>/dev/null | grep -E '(^|/)gitleaks$' | head -1)
    if [ -n "$binpath" ]; then
      tar -xzf "$tgz" -C /tmp "$binpath" 2>/dev/null || true
      install -m 0755 "/tmp/$binpath" "$HOME/.local/bin/gitleaks" 2>/dev/null || true
    else
      # Fallback: extract all and try common location
      tar -xzf "$tgz" -C /tmp 2>/dev/null || true
      if [ -f /tmp/gitleaks ]; then
        install -m 0755 /tmp/gitleaks "$HOME/.local/bin/gitleaks" 2>/dev/null || true
      fi
    fi
  else
    warn "Could not download gitleaks tarball. Check network/GitHub access."
  fi
  if command -v gitleaks >/dev/null 2>&1; then
    ok "gitleaks installed: $(gitleaks version 2>/dev/null || echo installed)"
  else
    warn "gitleaks not found after attempt"
  fi
}

install_trivy() {
  log "Installing trivy (user-local)"
  # Official installer supports -b for target dir
  local script="/tmp/install-trivy.sh"
  if download "https://raw.githubusercontent.com/aquasecurity/trivy/main/install.sh" "$script"; then
    # Run installer in a subshell to isolate environment; ignore failure
    ( sh "$script" -b "$HOME/.local/bin" >/tmp/trivy-install.log 2>&1 ) || warn "trivy installer returned non-zero (see /tmp/trivy-install.log)"
  else
    warn "Failed to download trivy installer"
  fi
  if command -v trivy >/dev/null 2>&1; then
    ok "trivy installed: $(trivy --version 2>/dev/null | head -n1)"
  else
    warn "trivy not found after attempt"
  fi
}

install_noseyparker() {
  log "Installing noseyparker (user-local)"
  # Try common prebuilt asset names first, then cargo as fallback
  # Typical asset example: noseyparker-v0.20.0-x86_64-unknown-linux-gnu.tar.gz
  local base="https://github.com/praetorian-inc/noseyparker/releases/latest/download"
  local cand1="noseyparker-x86_64-unknown-linux-gnu.tar.gz"
  local cand2="noseyparker-aarch64-unknown-linux-gnu.tar.gz"
  local pick="$cand1"
  [ "$ARCH_GH" = "arm64" ] && pick="$cand2"
  local tgz="/tmp/noseyparker.tgz"
  if download "$base/$pick" "$tgz"; then
    local inner
    inner=$(tar -tzf "$tgz" 2>/dev/null | grep -E '(^|/)(noseyparker|np)$' | head -1)
    if [ -n "$inner" ]; then
      tar -xzf "$tgz" -C /tmp "$inner" 2>/dev/null || true
      # Binary might be named noseyparker or np; normalize to noseyparker
      if [ -f "/tmp/$inner" ]; then
        install -m 0755 "/tmp/$inner" "$HOME/.local/bin/noseyparker" 2>/dev/null || true
      fi
    else
      tar -xzf "$tgz" -C /tmp 2>/dev/null || true
      if [ -f /tmp/noseyparker ]; then
        install -m 0755 /tmp/noseyparker "$HOME/.local/bin/noseyparker" || true
      elif [ -f /tmp/np ]; then
        install -m 0755 /tmp/np "$HOME/.local/bin/noseyparker" || true
      fi
    fi
  else
    warn "Prebuilt noseyparker download failed; trying cargo fallback if available"
    if command -v cargo >/dev/null 2>&1; then
      ( cargo install noseyparker >/tmp/noseyparker-cargo.log 2>&1 && cp "$HOME/.cargo/bin/noseyparker" "$HOME/.local/bin/noseyparker" ) || warn "cargo build/install failed (see /tmp/noseyparker-cargo.log)"
    else
      warn "Rust toolchain (cargo) not found; install rustup/cargo to build noseyparker from source"
    fi
  fi
  if command -v noseyparker >/dev/null 2>&1; then
    ok "noseyparker installed: $(noseyparker --version 2>/dev/null || echo installed)"
  else
    warn "noseyparker not found after attempt"
  fi
}

verify() {
  echo ""
  log "Verification"
  for t in gitleaks trivy noseyparker; do
    if command -v "$t" >/dev/null 2>&1; then
      echo "  - $t: OK ($($t --version 2>/dev/null | head -n1 || echo present))"
    else
      echo "  - $t: missing"
    fi
  done
}

main() {
  if [ $# -eq 0 ] || [ "$1" = "all" ]; then
    set +e
    install_gitleaks
    install_trivy
    install_noseyparker
    verify
    exit 0
  fi
  for tool in "$@"; do
    case "$tool" in
      gitleaks)      install_gitleaks ;;
      trivy)         install_trivy ;;
      noseyparker)   install_noseyparker ;;
      *) warn "Unknown tool: $tool" ;;
    esac
  done
  verify
}

main "$@"
