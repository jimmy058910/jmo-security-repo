#!/bin/bash
# security_audit.sh - Simplified wrapper for comprehensive security auditing

set -e

# Color codes for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Paths to helper scripts
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "$SCRIPT_DIR/../core" && pwd)"
TOOL_BOOTSTRAP="$CORE_DIR/check_and_install_tools.sh"
TOOL_CHECK_FALLBACK="$CORE_DIR/check_tools.sh"

run_tool_check() {
  if [ -f "$TOOL_BOOTSTRAP" ]; then
    bash "$TOOL_BOOTSTRAP" --check "$@"
  elif [ -f "$TOOL_CHECK_FALLBACK" ]; then
    bash "$TOOL_CHECK_FALLBACK" "$@"
  else
    echo -e "${RED}Unable to locate tool check scripts in $CORE_DIR${NC}" >&2
    return 1
  fi
}

# Banner
echo -e "${CYAN}"
cat <<"EOF"
╔═══════════════════════════════════════════════════════════╗
║     Security Audit Tool - Comprehensive Analysis          ║
║     Powered by: Gitleaks, TruffleHog, Semgrep & More     ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Display usage
usage() {
  echo "Usage: $0 [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  -d, --dir <path>       Directory containing repositories to scan"
  echo "  -o, --output <path>    Output directory for results (default: auto-generated)"
  echo "  -c, --check            Check if required tools are installed"
  echo "  -h, --help             Display this help message"
  echo ""
  echo "Examples:"
  echo "  $0 --check                           # Check tool installation"
  echo "  $0 -d ~/my-repos                     # Scan repositories in ~/my-repos"
  echo "  $0 -d ~/repos -o ~/scan-results      # Scan with custom output directory"
  echo ""
  exit 1
}

# Parse command line arguments
TESTING_DIR=""
OUTPUT_DIR=""
CHECK_ONLY=0

while [[ $# -gt 0 ]]; do
  case $1 in
  -d | --dir)
    TESTING_DIR="$2"
    shift 2
    ;;
  -o | --output)
    OUTPUT_DIR="$2"
    shift 2
    ;;
  -c | --check)
    CHECK_ONLY=1
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

# Check tools
if [ $CHECK_ONLY -eq 1 ]; then
  run_tool_check "$@"
  exit $?
fi

# Validate testing directory
if [ -z "$TESTING_DIR" ]; then
  echo -e "${YELLOW}No testing directory specified. Using default: $HOME/security-testing${NC}"
  TESTING_DIR="$HOME/security-testing"
fi

if [ ! -d "$TESTING_DIR" ]; then
  echo -e "${RED}Error: Testing directory does not exist: $TESTING_DIR${NC}"
  echo -e "${YELLOW}Please create the directory or specify a valid path with -d option${NC}"
  exit 1
fi

# Run tool check first
echo -e "${BLUE}Checking required tools...${NC}"
if ! run_tool_check "$@" >/dev/null 2>&1; then
  echo -e "${YELLOW}Some tools are missing. Running full check:${NC}"
  echo ""
  run_tool_check "$@"
  echo ""
  echo -e "${YELLOW}Install missing tools before continuing.${NC}"
  exit 1
fi
echo -e "${GREEN}✓ All required tools are installed${NC}"
echo ""

# Run the main audit
echo -e "${BLUE}Starting security audit...${NC}"
echo ""

if [ -n "$OUTPUT_DIR" ]; then
  bash "$CORE_DIR/run_security_audit.sh" "$TESTING_DIR" "$OUTPUT_DIR"
else
  bash "$CORE_DIR/run_security_audit.sh" "$TESTING_DIR"
fi

# Get the results directory (from the audit script output or use last created)
RESULTS_DIR=$(
  python3 - <<'PY'
import os
from pathlib import Path

home = Path(os.path.expanduser("~"))
dirs = sorted(
    (p for p in home.glob("security-results-*") if p.is_dir()),
    key=lambda p: p.stat().st_mtime,
    reverse=True,
)
print(dirs[0]) if dirs else print("")
PY
)

if [ -n "$RESULTS_DIR" ] && [ -d "$RESULTS_DIR" ]; then
  echo ""
  echo -e "${BLUE}Generating HTML dashboard...${NC}"
  python3 "$CORE_DIR/generate_dashboard.py" "$RESULTS_DIR"

  echo ""
  echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}║              Security Audit Complete!                     ║${NC}"
  echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "${CYAN}📁 Results Directory:${NC} $RESULTS_DIR"
  echo ""
  echo -e "${CYAN}📊 Generated Reports:${NC}"
  echo -e "  • Summary Report:    ${BLUE}$RESULTS_DIR/SUMMARY_REPORT.md${NC}"
  echo -e "  • HTML Dashboard:    ${BLUE}$RESULTS_DIR/dashboard.html${NC}"
  echo -e "  • Tool Comparison:   ${BLUE}$RESULTS_DIR/tool-comparisons/comparison.md${NC}"
  echo ""
  echo -e "${CYAN}📂 Individual Reports:${NC}"
  echo -e "  • Repository Reports: ${BLUE}$RESULTS_DIR/individual-repos/*/README.md${NC}"
  echo ""
  echo -e "${CYAN}Quick Commands:${NC}"
  echo -e "  View summary:        ${YELLOW}cat $RESULTS_DIR/SUMMARY_REPORT.md${NC}"
  echo -e "  Open dashboard (mac):${YELLOW} open $RESULTS_DIR/dashboard.html${NC}"
  echo -e "  Open dashboard (linux):${YELLOW} xdg-open $RESULTS_DIR/dashboard.html${NC}"
  echo -e "  List all reports:    ${YELLOW}ls -la $RESULTS_DIR/individual-repos/*/README.md${NC}"
  echo ""
fi
