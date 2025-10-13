#!/usr/bin/env bash
# install_tools.sh - Bootstrap curated CLIs for Linux/WSL and macOS
# Installs core + curated tools:
# - Core: python3, pip, jq, curl, git
# - Linters: shellcheck, shfmt, ruff, bandit
# - Secrets: gitleaks, trufflehog, noseyparker (optional)
# - SAST: semgrep
# - SBOM/Vuln/Misconfig: syft, trivy
# - IaC: checkov, tfsec
# - Dockerfile: hadolint
# - Deps: osv-scanner
# Usage:
#   bash scripts/dev/install_tools.sh          # install if missing
#   bash scripts/dev/install_tools.sh --upgrade # upgrade/refresh when possible

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

is_wsl() { grep -qiE "(microsoft|wsl)" /proc/version 2>/dev/null || true; }
bg_jobs=()
bg() {
  "$@" &
  bg_jobs+=("$!")
}
bg_wait() {
  if [ ${#bg_jobs[@]} -gt 0 ]; then wait "${bg_jobs[@]}" || true; fi
  bg_jobs=()
}

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

pipx_or_pip_install() {
  local pkg="$1"
  if command -v pipx >/dev/null 2>&1; then
    if pipx list 2>/dev/null | grep -q "^package $pkg "; then
      if [ "$UPGRADE" = "1" ]; then pipx upgrade "$pkg" || true; fi
      ok "pipx package present: $pkg"
    else
      pipx install "$pkg" || true
    fi
  else
    if [ "$UPGRADE" = "1" ]; then pip3 install --user -U "$pkg" || true; else pip3 install --user "$pkg" || true; fi
  fi
}

install_linux_binary() {
  # $1: url, $2: dest path
  local url="$1"
  shift
  local dest="$1"
  curl -sSL "$url" -o "/tmp/.dl-$(basename "$dest")" && sudo install -m 0755 "/tmp/.dl-$(basename "$dest")" "$dest"
}

case "$OS" in
Darwin)
  if ! command -v brew >/dev/null 2>&1; then
    warn "Homebrew not found. Installing..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    eval "$($(command -v brew) shellenv)"
  fi
  brew_install python@3 || true
  brew_install jq || true
  brew_install git || true
  # Single bulk brew install is usually faster
  brew tap trufflesecurity/tap >/dev/null 2>&1 || true
  brew install shellcheck shfmt ruff bandit semgrep gitleaks syft trivy hadolint tfsec checkov trufflesecurity/tap/trufflehog osv-scanner || true
  # Nosey Parker (optional; requires Rust env)
  if ! command -v noseyparker >/dev/null 2>&1; then
    warn "noseyparker not found; install via: brew install noseyparker (if available) or see upstream docs"
  fi
  ;;
Linux)
  # Linux/WSL
  if command -v apt-get >/dev/null 2>&1; then
    # Batch apt installs to reduce overhead
    sudo apt-get update -y
    if ! sudo apt-get install -y python3 python3-pip jq curl git shellcheck; then
      warn "Failed to install core apt packages (python3, jq, curl, git, shellcheck)"
    fi
    # shfmt via snap or direct download if needed
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
    # Linters (Python)
    # Run python tool installs in parallel
    bg pipx_or_pip_install ruff
    bg pipx_or_pip_install bandit
    # Semgrep
    if ! command -v semgrep >/dev/null 2>&1; then
      bg pipx_or_pip_install semgrep
    else ok "semgrep installed"; fi
    # Gitleaks
    if ! command -v gitleaks >/dev/null 2>&1; then
      bg bash -c 'curl -sSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | jq -r ".assets[] | select(.name | test(\"linux_amd64.tar.gz\")) | .browser_download_url" | head -1 | xargs -I{} bash -c "curl -L -o /tmp/gitleaks.tgz {} && sudo tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks"'
    else ok "gitleaks installed"; fi
    # TruffleHog
    if ! command -v trufflehog >/dev/null 2>&1; then
      bg bash -c 'curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin'
    else ok "trufflehog installed"; fi
    # Nosey Parker - optional
    if ! command -v noseyparker >/dev/null 2>&1; then
      warn "noseyparker not found; see https://github.com/praetorian-inc/noseyparker for install options"
    fi
    # SBOM & scanners
    if ! command -v syft >/dev/null 2>&1; then
      bg bash -c 'curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin'
    else ok "syft installed"; fi
    if ! command -v trivy >/dev/null 2>&1; then
      bg bash -c 'curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/install.sh | sudo sh -s -- -b /usr/local/bin'
    else ok "trivy installed"; fi
    # hadolint binary
    if ! command -v hadolint >/dev/null 2>&1; then
      case "$(uname -m)" in
      x86_64 | amd64) HAD_ARCH=x86_64 ;;
      aarch64 | arm64) HAD_ARCH=arm64 ;;
      *) HAD_ARCH=x86_64 ;;
      esac
      bg bash -c 'sudo curl -sSL "https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-'"${HAD_ARCH}"'" -o /usr/local/bin/hadolint && sudo chmod +x /usr/local/bin/hadolint'
    else ok "hadolint installed"; fi
    # tfsec binary
    if ! command -v tfsec >/dev/null 2>&1; then
      bg bash -c 'sudo curl -sSL https://github.com/aquasecurity/tfsec/releases/latest/download/tfsec-linux-amd64 -o /usr/local/bin/tfsec && sudo chmod +x /usr/local/bin/tfsec'
    else ok "tfsec installed"; fi
    # checkov (python)
    if ! command -v checkov >/dev/null 2>&1; then
      bg pipx_or_pip_install checkov
    else ok "checkov installed"; fi
    # osv-scanner binary
    if ! command -v osv-scanner >/dev/null 2>&1; then
      bg bash -c 'sudo curl -sSL https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 -o /usr/local/bin/osv-scanner && sudo chmod +x /usr/local/bin/osv-scanner'
    else ok "osv-scanner installed"; fi
    # Wait for background installers to finish
    bg_wait
  else
    warn "Unsupported Linux distribution: please install dependencies manually (python3, pip, jq, curl, semgrep, gitleaks, trufflehog, shellcheck, shfmt)"
  fi
  ;;
*)
  warn "Unsupported OS: $OS. Please install dependencies manually."
  ;;
esac

ok "Environment bootstrap complete. Ensure that ~/.local/bin is on PATH for pip user installs."
