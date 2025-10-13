#!/bin/bash
# check_and_install_tools.sh - Robust tool bootstrap for security scanning
# Detects WSL vs Linux, verifies tools, and optionally auto-installs

set -e
set -o pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default mode
MODE="check"
FORCE_REINSTALL=0

# Display usage
usage() {
  echo "Usage: $0 [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  --check               Check tool installation status (default)"
  echo "  --auto-install        Attempt to auto-install missing tools"
  echo "  --print-commands      Print installation commands without executing"
  echo "  --force-reinstall     Force reinstallation of all tools"
  echo "  -h, --help            Display this help message"
  echo ""
  echo "Examples:"
  echo "  $0                           # Check tool installation"
  echo "  $0 --auto-install            # Auto-install missing tools"
  echo "  $0 --print-commands          # Show installation commands"
  echo "  $0 --force-reinstall         # Force reinstall all tools"
  echo ""
  exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
  --check)
    MODE="check"
    shift
    ;;
  --auto-install)
    MODE="auto-install"
    shift
    ;;
  --print-commands)
    MODE="print-commands"
    shift
    ;;
  --force-reinstall)
    FORCE_REINSTALL=1
    MODE="auto-install"
    shift
    ;;
  -h | --help)
    usage
    ;;
  *)
    echo -e "${RED}Unknown option: $1${NC}"
    usage
    ;;
  esac
done

# Logging functions
log_info() {
  echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
  echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
  echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $1"
}

# Detect environment (WSL vs Linux)
detect_environment() {
  if grep -qiE "(microsoft|wsl)" /proc/version 2>/dev/null; then
    echo "WSL"
  elif [ -f /etc/os-release ]; then
    echo "Linux"
  else
    echo "Unknown"
  fi
}

# Check if running as root
is_root() {
  [ "$EUID" -eq 0 ]
}

# Check if a tool is installed
check_tool() {
  local tool_name=$1
  local check_command=$2

  if eval "$check_command" &>/dev/null; then
    return 0
  else
    return 1
  fi
}

# Get tool version
get_tool_version() {
  local check_command=$1
  eval "$check_command" 2>&1 | head -1 || echo "unknown"
}

# Print installation command
print_install_command() {
  local tool_name=$1
  local install_cmd=$2

  echo ""
  echo -e "${CYAN}${tool_name} Installation:${NC}"
  echo -e "  ${install_cmd}"
}

# Install tool
install_tool() {
  local tool_name=$1
  local install_cmd=$2

  log_info "Installing ${tool_name}..."
  if eval "$install_cmd" &>/dev/null; then
    log_success "${tool_name} installed successfully"
    return 0
  else
    log_error "Failed to install ${tool_name}"
    return 1
  fi
}

# Banner
echo -e "${CYAN}"
cat <<"EOF"
╔═══════════════════════════════════════════════════════════╗
║        Security Tool Bootstrap & Installation            ║
║     Detect, Verify, and Install Security Tools           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Detect environment
ENV=$(detect_environment)
log_info "Environment detected: ${ENV}"
echo ""

# Track installation status
ALL_INSTALLED=true
MISSING_TOOLS=()
INSTALL_COMMANDS=()

# Define tools and their check/install commands
declare -A TOOLS
declare -A CHECK_CMDS
declare -A INSTALL_CMDS_APT
declare -A INSTALL_CMDS_PIPX
declare -A INSTALL_CMDS_MANUAL

# Core system tools
TOOLS["bash"]="Bash Shell"
CHECK_CMDS["bash"]="bash --version"
INSTALL_CMDS_APT["bash"]="sudo apt-get update && sudo apt-get install -y bash"

TOOLS["git"]="Git Version Control"
CHECK_CMDS["git"]="git --version"
INSTALL_CMDS_APT["git"]="sudo apt-get update && sudo apt-get install -y git"

TOOLS["jq"]="JSON Processor"
CHECK_CMDS["jq"]="jq --version"
INSTALL_CMDS_APT["jq"]="sudo apt-get update && sudo apt-get install -y jq"

TOOLS["cloc"]="Code Line Counter"
CHECK_CMDS["cloc"]="cloc --version"
INSTALL_CMDS_APT["cloc"]="sudo apt-get update && sudo apt-get install -y cloc"

TOOLS["python3"]="Python 3"
CHECK_CMDS["python3"]="python3 --version"
INSTALL_CMDS_APT["python3"]="sudo apt-get update && sudo apt-get install -y python3 python3-pip"

TOOLS["pipx"]="Python Package Manager (pipx)"
CHECK_CMDS["pipx"]="pipx --version"
INSTALL_CMDS_APT["pipx"]="sudo apt-get update && sudo apt-get install -y pipx && pipx ensurepath"

# Security scanning tools
TOOLS["semgrep"]="Semgrep (SAST Scanner)"
CHECK_CMDS["semgrep"]="semgrep --version"
INSTALL_CMDS_PIPX["semgrep"]="pipx install semgrep"

TOOLS["gitleaks"]="Gitleaks (Secret Scanner)"
CHECK_CMDS["gitleaks"]="gitleaks version"
INSTALL_CMDS_MANUAL["gitleaks"]="wget https://github.com/zricethezav/gitleaks/releases/latest/download/gitleaks-linux-amd64 -O /tmp/gitleaks && chmod +x /tmp/gitleaks && sudo mv /tmp/gitleaks /usr/local/bin/"

TOOLS["trufflehog"]="TruffleHog (Secret Scanner)"
CHECK_CMDS["trufflehog"]="trufflehog --version"
INSTALL_CMDS_MANUAL["trufflehog"]="curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b ~/.local/bin"

TOOLS["noseyparker"]="Nosey Parker (Secret Scanner)"
CHECK_CMDS["noseyparker"]="noseyparker --version"
INSTALL_CMDS_MANUAL["noseyparker"]="echo 'Download from: https://github.com/praetorian-inc/noseyparker/releases'"

# Check each tool
echo -e "${BLUE}Checking tool installation status...${NC}"
echo "=================================================="

for tool in bash git jq cloc python3 pipx semgrep gitleaks trufflehog noseyparker; do
  tool_name="${TOOLS[$tool]}"
  check_cmd="${CHECK_CMDS[$tool]}"

  echo -n "Checking ${tool_name}... "

  if [ "$FORCE_REINSTALL" -eq 0 ] && check_tool "$tool" "$check_cmd"; then
    version=$(get_tool_version "$check_cmd")
    echo -e "${GREEN}✓ Installed${NC} ($version)"
  else
    echo -e "${RED}✗ Not found${NC}"
    ALL_INSTALLED=false
    MISSING_TOOLS+=("$tool")

    # Determine install command
    if [ -n "${INSTALL_CMDS_APT[$tool]}" ]; then
      INSTALL_COMMANDS+=("${INSTALL_CMDS_APT[$tool]}")
    elif [ -n "${INSTALL_CMDS_PIPX[$tool]}" ]; then
      INSTALL_COMMANDS+=("${INSTALL_CMDS_PIPX[$tool]}")
    elif [ -n "${INSTALL_CMDS_MANUAL[$tool]}" ]; then
      INSTALL_COMMANDS+=("${INSTALL_CMDS_MANUAL[$tool]}")
    fi
  fi
done

echo "=================================================="
echo ""

# Handle different modes
if [ "$ALL_INSTALLED" = true ] && [ "$FORCE_REINSTALL" -eq 0 ]; then
  log_success "All tools are installed and ready!"
  exit 0
fi

if [ "$MODE" = "check" ]; then
  log_warning "Some tools are missing: ${MISSING_TOOLS[*]}"
  echo ""
  echo -e "${CYAN}To install missing tools:${NC}"
  echo "  1. Run with --auto-install: $0 --auto-install"
  echo "  2. Run with --print-commands to see installation commands: $0 --print-commands"
  echo ""
  exit 1
fi

if [ "$MODE" = "print-commands" ]; then
  echo -e "${CYAN}Installation Commands:${NC}"
  echo "=================================================="
  echo ""

  for tool in "${MISSING_TOOLS[@]}"; do
    tool_name="${TOOLS[$tool]}"

    if [ -n "${INSTALL_CMDS_APT[$tool]}" ]; then
      print_install_command "$tool_name (apt)" "${INSTALL_CMDS_APT[$tool]}"
    elif [ -n "${INSTALL_CMDS_PIPX[$tool]}" ]; then
      print_install_command "$tool_name (pipx)" "${INSTALL_CMDS_PIPX[$tool]}"
    elif [ -n "${INSTALL_CMDS_MANUAL[$tool]}" ]; then
      print_install_command "$tool_name (manual)" "${INSTALL_CMDS_MANUAL[$tool]}"
    fi
  done

  echo ""
  echo "=================================================="
  exit 0
fi

if [ "$MODE" = "auto-install" ]; then
  log_info "Starting auto-installation of missing tools..."
  echo ""

  # Check if we have sudo access
  if ! is_root && ! sudo -n true 2>/dev/null; then
    log_warning "Some installations may require sudo access"
    echo ""
  fi

  # Install apt packages first
  apt_tools=()
  for tool in "${MISSING_TOOLS[@]}"; do
    if [ -n "${INSTALL_CMDS_APT[$tool]}" ]; then
      apt_tools+=("$tool")
    fi
  done

  if [ ${#apt_tools[@]} -gt 0 ]; then
    log_info "Installing system packages via apt..."
    for tool in "${apt_tools[@]}"; do
      if eval "${INSTALL_CMDS_APT[$tool]}" 2>/dev/null; then
        log_success "${TOOLS[$tool]} installed"
      else
        log_error "Failed to install ${TOOLS[$tool]}"
        log_info "You may need to run manually: ${INSTALL_CMDS_APT[$tool]}"
      fi
    done
    echo ""
  fi

  # Install pipx packages
  pipx_tools=()
  for tool in "${MISSING_TOOLS[@]}"; do
    if [ -n "${INSTALL_CMDS_PIPX[$tool]}" ]; then
      pipx_tools+=("$tool")
    fi
  done

  if [ ${#pipx_tools[@]} -gt 0 ]; then
    # Ensure pipx is available
    if ! check_tool "pipx" "pipx --version"; then
      log_warning "pipx not installed, installing it first..."
      if eval "${INSTALL_CMDS_APT[pipx]}" 2>/dev/null; then
        log_success "pipx installed"
      else
        log_error "Failed to install pipx"
      fi
    fi

    log_info "Installing Python tools via pipx..."
    for tool in "${pipx_tools[@]}"; do
      if eval "${INSTALL_CMDS_PIPX[$tool]}" 2>/dev/null; then
        log_success "${TOOLS[$tool]} installed"
      else
        log_error "Failed to install ${TOOLS[$tool]}"
        log_info "You may need to run manually: ${INSTALL_CMDS_PIPX[$tool]}"
      fi
    done
    echo ""
  fi

  # Manual installation tools
  manual_tools=()
  for tool in "${MISSING_TOOLS[@]}"; do
    if [ -n "${INSTALL_CMDS_MANUAL[$tool]}" ]; then
      manual_tools+=("$tool")
    fi
  done

  if [ ${#manual_tools[@]} -gt 0 ]; then
    log_info "Manual installation required for some tools:"
    echo ""
    for tool in "${manual_tools[@]}"; do
      tool_name="${TOOLS[$tool]}"
      install_cmd="${INSTALL_CMDS_MANUAL[$tool]}"

      echo -e "${CYAN}${tool_name}:${NC}"
      echo "  ${install_cmd}"
      echo ""

      # Try to auto-install if it's a downloadable binary
      if [[ $install_cmd == *"wget"* ]] || [[ $install_cmd == *"curl"* ]]; then
        log_info "Attempting auto-install for ${tool_name}..."
        if eval "$install_cmd" 2>/dev/null; then
          log_success "${tool_name} installed"
        else
          log_warning "Auto-install failed. Please run the command manually."
        fi
      fi
    done
  fi

  echo ""
  log_info "Re-checking tool installation..."
  echo ""

  # Re-check all tools
  final_check=true
  for tool in bash git jq cloc python3 pipx semgrep gitleaks trufflehog noseyparker; do
    tool_name="${TOOLS[$tool]}"
    check_cmd="${CHECK_CMDS[$tool]}"

    echo -n "Checking ${tool_name}... "
    if check_tool "$tool" "$check_cmd"; then
      version=$(get_tool_version "$check_cmd")
      echo -e "${GREEN}✓ Installed${NC} ($version)"
    else
      echo -e "${RED}✗ Not found${NC}"
      final_check=false
    fi
  done

  echo ""
  if [ "$final_check" = true ]; then
    log_success "All tools are now installed and ready!"
    exit 0
  else
    log_warning "Some tools are still missing. Please install them manually."
    echo ""
    echo -e "${CYAN}Run with --print-commands to see installation commands:${NC}"
    echo "  $0 --print-commands"
    exit 1
  fi
fi
