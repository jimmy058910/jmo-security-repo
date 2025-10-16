#!/usr/bin/env bash
# install_tools.sh - Bootstrap curated CLIs for Linux/WSL and macOS (v0.5.0)
# Installs core + curated tools:
# - Core: python3, pip, jq, curl, git
# - Linters: shellcheck, shfmt, ruff, bandit
# - Secrets: trufflehog (verified), noseyparker (optional, deep profile)
# - SAST: semgrep, bandit (Python-specific)
# - SBOM/Vuln/Misconfig: syft, trivy
# - IaC: checkov
# - Dockerfile: hadolint
# - DAST: OWASP ZAP (web security)
# - Runtime: Falco (container/K8s monitoring, deep profile)
# - Fuzzing: AFL++ (coverage-guided fuzzing, deep profile)
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
  # Single bulk brew install is usually faster (v0.5.0 tool suite)
  brew tap trufflesecurity/tap >/dev/null 2>&1 || true
  brew install shellcheck shfmt ruff bandit semgrep syft trivy hadolint checkov trufflesecurity/tap/trufflehog || true
  # OWASP ZAP (DAST)
  if ! command -v zap.sh >/dev/null 2>&1 && ! command -v zap >/dev/null 2>&1; then
    brew install --cask owasp-zap || warn "ZAP installation failed; install manually from https://www.zaproxy.org/download/"
  fi
  # Nosey Parker (optional; deep profile only)
  if ! command -v noseyparker >/dev/null 2>&1; then
    warn "noseyparker not found (optional for deep profile); install via: brew install noseyparker or see upstream docs"
  fi
  # Falco (optional; deep profile, requires kernel modules)
  if ! command -v falco >/dev/null 2>&1; then
    warn "falco not found (optional for deep profile); install via: brew tap falcosecurity/tap && brew install falco"
  fi
  # AFL++ (optional; deep profile)
  if ! command -v afl-fuzz >/dev/null 2>&1; then
    warn "AFL++ not found (optional for deep profile); install via: brew install afl++"
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
    # TruffleHog (primary secrets scanner)
    if ! command -v trufflehog >/dev/null 2>&1; then
      bg bash -c 'curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin'
    else ok "trufflehog installed"; fi
    # Nosey Parker - optional (deep profile only)
    if ! command -v noseyparker >/dev/null 2>&1; then
      warn "noseyparker not found (optional for deep profile); see https://github.com/praetorian-inc/noseyparker for install options"
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
    # checkov (python)
    if ! command -v checkov >/dev/null 2>&1; then
      bg pipx_or_pip_install checkov
    else ok "checkov installed"; fi
    # OWASP ZAP (DAST - web security)
    if ! command -v zap.sh >/dev/null 2>&1 && ! command -v zap >/dev/null 2>&1; then
      warn "OWASP ZAP not found; installing via snap or manual download"
      if command -v snap >/dev/null 2>&1; then
        bg bash -c 'sudo snap install zaproxy --classic'
      else
        warn "ZAP installation requires manual setup; see https://www.zaproxy.org/download/"
      fi
    else ok "ZAP installed"; fi
    # Falco (runtime security - optional, deep profile)
    if ! command -v falco >/dev/null 2>&1; then
      warn "falco not found (optional for deep profile); requires kernel modules - see https://falco.org/docs/getting-started/installation/"
    fi
    # AFL++ (fuzzing - optional, deep profile)
    if ! command -v afl-fuzz >/dev/null 2>&1; then
      warn "AFL++ not found (optional for deep profile); install via: sudo apt-get install afl++ or build from source"
    fi
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
