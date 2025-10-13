#!/bin/bash
# check_tools.sh - Verify all security tools are installed and working

echo "Security Tool Installation Check"
echo "================================="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

check_tool() {
  local tool_name=$1
  local check_command=$2
  local install_hint=$3

  echo -n "Checking $tool_name... "
  if eval "$check_command" &>/dev/null; then
    echo -e "${GREEN}✓ Installed${NC}"
    eval "$check_command" 2>&1 | head -1
  else
    echo -e "${RED}✗ Not found${NC}"
    echo "  Install hint: $install_hint"
    return 1
  fi
  echo ""
}

# Track if all tools are installed
ALL_INSTALLED=true

# Check each tool
check_tool "cloc" \
  "cloc --version" \
  "apt install cloc OR brew install cloc" || ALL_INSTALLED=false

check_tool "Gitleaks" \
  "gitleaks version" \
  "Download from https://github.com/zricethezav/gitleaks/releases" || ALL_INSTALLED=false

check_tool "TruffleHog" \
  "trufflehog --version" \
  "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b ~/.local/bin" || ALL_INSTALLED=false

check_tool "Semgrep" \
  "semgrep --version" \
  "pip install semgrep OR brew install semgrep" || ALL_INSTALLED=false

check_tool "Nosey Parker" \
  "noseyparker --version" \
  "Download from https://github.com/praetorian-inc/noseyparker/releases" || ALL_INSTALLED=false

# Optional but useful
check_tool "jq (JSON processor)" \
  "jq --version" \
  "apt install jq OR brew install jq" || ALL_INSTALLED=false

echo "================================="
if [ "$ALL_INSTALLED" = true ]; then
  echo -e "${GREEN}All tools are installed and ready!${NC}"
  exit 0
else
  echo -e "${RED}Some tools are missing. Please install them before running the audit.${NC}"
  exit 1
fi
