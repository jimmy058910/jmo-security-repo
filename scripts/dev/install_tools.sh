#!/usr/bin/env bash
# install_tools.sh - `make tools`: the developer prerequisites, then every scanner
# through `jmo tools install` (#1562).
# - Prerequisites: python3, pip, jq, curl, git, and shfmt (for `make fmt`)
# - Scanners: `jmo tools install`, the one install path jmo reads. It installs
#   each at its versions.yaml pin into ~/.jmo and checks its sha256 (#1374).
#   This script used to install them itself, from `latest`, and ZAP as a snap
#   jmo never finds.
# The jmo it runs: $JMO, else this checkout's .venv (`make dev-setup`), else PATH.
# Usage:
#   bash scripts/dev/install_tools.sh           # install what is missing
#   bash scripts/dev/install_tools.sh --upgrade # refresh, and `jmo tools update`

set -Eeuo pipefail
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

OS="$(uname -s)"
log "Detected OS: $OS"

UPGRADE=0
if [ "${1-}" = "--upgrade" ] || [ "${1-}" = "-u" ]; then
  UPGRADE=1
  log "Upgrade mode enabled"
fi

# Helper to install Homebrew packages
brew_install() {
  local pkg="$1"
  if ! brew list "$pkg" >/dev/null 2>&1; then
    brew install "$pkg"
  else
    if [ "$UPGRADE" = "1" ]; then
      brew upgrade "$pkg" || true
      ok "brew package upgraded: $pkg"
    else
      ok "brew package already installed: $pkg"
    fi
  fi
}

# Helper to install apt packages
apt_install() {
  local pkg="$1"
  if ! dpkg -s "$pkg" >/dev/null 2>&1; then
    sudo apt-get update -y
    sudo apt-get install -y "$pkg"
  elif [ "$UPGRADE" = "1" ]; then
    sudo apt-get update -y || warn "apt update failed; $pkg may be stale"
    if sudo apt-get install -y "$pkg"; then
      ok "apt package refreshed: $pkg"
    else
      warn "Failed to refresh $pkg via apt"
    fi
  else
    ok "apt package already installed: $pkg"
  fi
}

case "$OS" in
Darwin)
  if ! command -v brew >/dev/null 2>&1; then
    warn "Homebrew not found. Installing..."
    # Download Homebrew installer with SHA256 verification
    BREW_INSTALLER="/tmp/brew-install-$$.sh"
    BREW_URL="https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh"

    # Download installer
    if ! curl -fsSL "$BREW_URL" -o "$BREW_INSTALLER"; then
      err "Failed to download Homebrew installer"
      exit 1
    fi

    # Verify SHA256 checksum
    # Note: Homebrew installer changes occasionally; check https://brew.sh for current hash
    # For now, we verify the download succeeded and the file is not empty
    if [ ! -s "$BREW_INSTALLER" ]; then
      err "Downloaded Homebrew installer is empty"
      rm -f "$BREW_INSTALLER"
      exit 1
    fi

    # Display hash for manual verification (defensive measure)
    ACTUAL_HASH=$(shasum -a 256 "$BREW_INSTALLER" | awk '{print $1}')
    log "Homebrew installer SHA256: $ACTUAL_HASH"
    log "Verify at: https://github.com/Homebrew/install/blob/HEAD/install.sh"

    # Execute installer
    /bin/bash "$BREW_INSTALLER"
    rm -f "$BREW_INSTALLER"
    eval "$($(command -v brew) shellenv)"
  fi
  brew_install python@3 || true
  brew_install jq || true
  brew_install git || true
  brew_install shfmt || true
  ;;
Linux)
  # Linux/WSL
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y
    if ! sudo apt-get install -y python3 python3-pip jq curl git; then
      warn "Failed to install core apt packages (python3, jq, curl, git)"
    fi
    # shfmt, for `make fmt`: apt has none
    if ! command -v shfmt >/dev/null 2>&1; then
      warn "shfmt not in apt; attempting install via Go or binary"
      if command -v go >/dev/null 2>&1; then
        go install mvdan.cc/sh/v3/cmd/shfmt@latest
      else
        case "$(uname -m)" in
        x86_64 | amd64) SHFMT_ARCH=amd64 ;;
        aarch64 | arm64) SHFMT_ARCH=arm64 ;;
        *) SHFMT_ARCH=amd64 ;;
        esac
        sudo curl -sSL "https://github.com/mvdan/sh/releases/latest/download/shfmt_Linux_${SHFMT_ARCH}" -o /usr/local/bin/shfmt || true
        sudo chmod +x /usr/local/bin/shfmt || true
      fi
    fi
  else
    warn "Unsupported Linux distribution: install python3, pip, jq, curl, git and shfmt yourself"
  fi
  ;;
*)
  warn "Unsupported OS: $OS. Please install dependencies manually."
  ;;
esac

# The scanners, through jmo: the install path `jmo tools check` and a scan read.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [ -z "${JMO:-}" ]; then
  for candidate in "$REPO_ROOT/.venv/bin/jmo" "$REPO_ROOT/.venv/Scripts/jmo.exe"; do
    if [ -x "$candidate" ]; then
      JMO="$candidate"
      break
    fi
  done
fi
if [ -z "${JMO:-}" ]; then
  JMO="$(command -v jmo || true)"
fi
if [ -z "$JMO" ]; then
  err "jmo not found: run 'make dev-setup' first, then 'make tools'"
  exit 1
fi

if [ "$UPGRADE" = "1" ]; then
  log "Updating the scanners: $JMO tools update"
  "$JMO" tools update --yes
else
  log "Installing the scanners: $JMO tools install"
  "$JMO" tools install --yes
fi

ok "Environment bootstrap complete. jmo installed the scanners under ~/.jmo; check them with: jmo tools check"
