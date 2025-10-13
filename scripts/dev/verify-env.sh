#!/usr/bin/env bash
# verify-env.sh - Detect OS/WSL/macOS and check required tools on PATH

set -Eeuo pipefail
IFS=$'\n\t'

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${BLUE}[env]${NC} $*"; }
ok() { echo -e "${GREEN}[ok]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
fail() { echo -e "${RED}[fail]${NC} $*"; exit 1; }

OS=$(uname -s)
WSL=false
if grep -qiE "(microsoft|wsl)" /proc/version 2>/dev/null; then WSL=true; fi

log "OS: $OS | WSL: $WSL"

REQ_TOOLS=(python3 pip3 jq curl git)
# Curated tools by category
OPT_TOOLS=(gitleaks noseyparker semgrep syft trivy checkov hadolint tfsec trufflehog osv-scanner shellcheck shfmt docker)

missing=()
for t in "${REQ_TOOLS[@]}"; do
  if ! command -v "$t" >/dev/null 2>&1; then missing+=("$t"); fi
done

if [ ${#missing[@]} -gt 0 ]; then
  warn "Missing required tools: ${missing[*]}"
  warn "Run: bash scripts/dev/install_tools.sh"
else
  ok "Core tools present: ${REQ_TOOLS[*]}"
fi

present=()
for t in "${OPT_TOOLS[@]}"; do
  if command -v "$t" >/dev/null 2>&1; then present+=("$t"); fi
done

log "Optional tools detected: ${present[*]:-none}"

# If docker is available, noseyparker can be run via container even if local binary is missing
if ! command -v noseyparker >/dev/null 2>&1 && command -v docker >/dev/null 2>&1; then
  ok "noseyparker: will use container image (docker present)"
fi

# Guidance per OS
hint_install() {
  local tool="$1"
  case "$OS" in
    Darwin)
      case "$tool" in
        gitleaks|semgrep|hadolint|checkov|trivy|syft|tfsec) echo "brew install $tool";;
        trufflehog) echo "brew install trufflesecurity/trufflehog/trufflehog";;
        noseyparker) echo "brew install noseyparker (or see upstream)";;
        osv-scanner) echo "brew install osv-scanner";;
        *) echo "brew install $tool";;
      esac
      ;;
    Linux)
      case "$tool" in
        semgrep) echo "pipx install semgrep || pip3 install --user semgrep";;
        gitleaks) echo "curl -sSL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks-linux-amd64 -o /usr/local/bin/gitleaks && chmod +x /usr/local/bin/gitleaks";;
        trufflehog) echo "pipx install trufflehog || pip3 install --user truffleHog";;
        noseyparker) echo "Prefer container: docker run ghcr.io/praetorian-inc/noseyparker:latest ... (local binary may require newer glibc)";;
        syft) echo "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin";;
        trivy) echo "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/install.sh | sh -s -- -b /usr/local/bin";;
        checkov) echo "pipx install checkov || pip3 install --user checkov";;
        hadolint) echo "curl -sSL https://github.com/hadolint/hadolint/releases/latest/download/hadolint-$(uname -s)-$(uname -m) -o /usr/local/bin/hadolint && chmod +x /usr/local/bin/hadolint";;
        tfsec) echo "curl -sSL https://github.com/aquasecurity/tfsec/releases/latest/download/tfsec-linux-amd64 -o /usr/local/bin/tfsec && chmod +x /usr/local/bin/tfsec";;
        osv-scanner) echo "curl -sSL https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64 -o /usr/local/bin/osv-scanner && chmod +x /usr/local/bin/osv-scanner";;
        *) echo "sudo apt-get install -y $tool";;
      esac
      ;;
    *) echo "Install $tool from your platform package manager";;
  esac
}

# Show hints for missing optional tools
missing_opt=()
for t in "${OPT_TOOLS[@]}"; do
  if ! command -v "$t" >/dev/null 2>&1; then
    missing_opt+=("$t")
  fi
done
if [ ${#missing_opt[@]} -gt 0 ]; then
  warn "Optional tools missing: ${missing_opt[*]}"
  for t in "${missing_opt[@]}"; do
    echo "  -> $(hint_install "$t")" || true
  done
fi

case "$OS" in
  Darwin)
    ok "macOS detected. Prefer Homebrew for installs (brew install <tool>)."
    ;;
  Linux)
    if [ "$WSL" = true ]; then
      ok "WSL detected. Use apt on the Linux side; ensure Windows antivirus exclusions for better performance."
    else
      ok "Linux detected. Use apt/yum/pacman as appropriate. install_tools.sh supports apt."
    fi
    ;;
  *)
    warn "Unsupported OS for auto-detection."
    ;;
 esac

ok "Environment looks good."
