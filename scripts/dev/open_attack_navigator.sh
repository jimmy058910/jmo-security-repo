#!/usr/bin/env bash
# Open ATT&CK Navigator with JMo Security findings
#
# Usage:
#   ./scripts/dev/open_attack_navigator.sh [attack-navigator.json]
#
# Default: Opens results/summaries/attack-navigator.json in browser

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default paths
DEFAULT_JSON="results/summaries/attack-navigator.json"
ATTACK_NAV_URL="https://mitre-attack.github.io/attack-navigator/"

# Parse arguments
JSON_FILE="${1:-$DEFAULT_JSON}"

# Validate file exists
if [ ! -f "$JSON_FILE" ]; then
    echo -e "${RED}Error: File not found: $JSON_FILE${NC}"
    echo ""
    echo "Usage: $0 [attack-navigator.json]"
    echo "Example: $0 results/summaries/attack-navigator.json"
    exit 1
fi

echo -e "${GREEN}Opening ATT&CK Navigator with findings...${NC}"
echo "File: $JSON_FILE"
echo ""

# Get absolute path
ABS_PATH=$(realpath "$JSON_FILE")

# Method 1: Try to open with local file protocol (may not work in all browsers)
echo -e "${YELLOW}Method 1: Attempting to open with local file upload...${NC}"
echo "1. Opening ATT&CK Navigator in browser"
echo "2. You'll need to manually upload: $ABS_PATH"
echo ""

# Detect OS and open browser
if command -v xdg-open &> /dev/null; then
    # Linux
    xdg-open "$ATTACK_NAV_URL" &
    echo -e "${GREEN}✓ Browser opened (Linux)${NC}"
elif command -v open &> /dev/null; then
    # macOS
    open "$ATTACK_NAV_URL"
    echo -e "${GREEN}✓ Browser opened (macOS)${NC}"
elif command -v cmd.exe &> /dev/null; then
    # WSL (Windows Subsystem for Linux)
    cmd.exe /c start "$ATTACK_NAV_URL"
    echo -e "${GREEN}✓ Browser opened (WSL)${NC}"
else
    echo -e "${RED}Could not detect browser launcher${NC}"
    echo "Please manually open: $ATTACK_NAV_URL"
fi

echo ""
echo -e "${YELLOW}Instructions:${NC}"
echo "1. Wait for ATT&CK Navigator to load in your browser"
echo "2. Click the '+' button (top-left) to create a new layer"
echo "3. Click 'Open Existing Layer'"
echo "4. Click 'Upload from local'"
echo "5. Select file: $ABS_PATH"
echo ""
echo -e "${GREEN}Alternative: Copy-paste method${NC}"
echo "If upload doesn't work:"
echo "  1. Copy the JSON content:"
echo "     cat $JSON_FILE | xclip -selection clipboard"
echo "  2. In Navigator: Click '+' → 'Open Existing Layer' → 'Enter Layer JSON'"
echo "  3. Paste the JSON content"
echo ""
echo -e "${YELLOW}Tip: Serve via local HTTP server${NC}"
echo "If you want direct URL loading:"
echo "  python3 -m http.server 8000 --directory $(dirname "$ABS_PATH")"
echo "  Then open: http://localhost:8000/$(basename "$ABS_PATH")"
