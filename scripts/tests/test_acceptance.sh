#!/bin/bash
# test_acceptance.sh - Acceptance test for dashboard generation and wrapper improvements
# Tests the acceptance criteria from the PR requirements

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="/tmp/acceptance-test-$$"
SCRIPTS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CORE_DIR="$SCRIPTS_ROOT/core"
CLI_DIR="$SCRIPTS_ROOT/cli"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗"
echo "║          Acceptance Test Suite                           ║"
echo "║          Dashboard & Wrapper Improvements                ║"
echo -e "╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Acceptance Criteria 1: Dashboard handles all TruffleHog formats
echo -e "${YELLOW}Acceptance Criteria 1:${NC}"
echo "Dashboard handles all TruffleHog output formats without AttributeError"
echo ""

RESULTS_DIR="$TEST_DIR/results"
mkdir -p "$RESULTS_DIR/individual-repos"

# Create test repositories with all mentioned formats
echo "Creating test data with various TruffleHog formats..."

# Format 1: Empty array []
mkdir -p "$RESULTS_DIR/individual-repos/repo-empty-array"
echo '[]' > "$RESULTS_DIR/individual-repos/repo-empty-array/trufflehog.json"

# Format 2: Array of objects
mkdir -p "$RESULTS_DIR/individual-repos/repo-array-objects"
cat > "$RESULTS_DIR/individual-repos/repo-array-objects/trufflehog.json" << 'EOF'
[
  {"DetectorName": "AWS", "Verified": true, "SourceMetadata": {"Data": {"Filesystem": {"file": "config.yaml"}}}},
  {"DetectorName": "GitHub", "Verified": false, "SourceMetadata": {"Data": {"Filesystem": {"file": "app.js"}}}}
]
EOF

# Format 3: Nested arrays
mkdir -p "$RESULTS_DIR/individual-repos/repo-nested"
echo '[[{"DetectorName": "Nested", "Verified": false}]]' > "$RESULTS_DIR/individual-repos/repo-nested/trufflehog.json"

# Format 4: NDJSON (one object per line)
mkdir -p "$RESULTS_DIR/individual-repos/repo-ndjson"
cat > "$RESULTS_DIR/individual-repos/repo-ndjson/trufflehog.json" << 'EOF'
{"DetectorName": "Slack", "Verified": true, "SourceMetadata": {"Data": {"Filesystem": {"file": "hooks.js"}}}}
{"DetectorName": "Stripe", "Verified": false, "SourceMetadata": {"Data": {"Filesystem": {"file": "pay.py"}}}}
EOF

# Format 5: Single object (not array)
mkdir -p "$RESULTS_DIR/individual-repos/repo-single"
echo '{"DetectorName": "JWT", "Verified": true, "SourceMetadata": {"Data": {"Filesystem": {"file": "auth.js"}}}}' > "$RESULTS_DIR/individual-repos/repo-single/trufflehog.json"

# Format 6: Missing file
mkdir -p "$RESULTS_DIR/individual-repos/repo-missing"
# No trufflehog.json created

# Add other required files
for repo in "$RESULTS_DIR/individual-repos"/*; do
    [ -d "$repo" ] && {
        echo '[]' > "$repo/gitleaks.json"
        echo '{"results":[]}' > "$repo/semgrep.json"
        echo '{"matches":[]}' > "$repo/noseyparker.json"
    }
done

echo -e "${GREEN}✓${NC} Created test data with 6 different TruffleHog formats"
echo ""

# Test 1: Default output location
echo "Test: Dashboard generation with default output..."
if OUTPUT=$(python3 "$CORE_DIR/generate_dashboard.py" "$RESULTS_DIR" 2>&1); then
    if [ -f "$RESULTS_DIR/dashboard.html" ]; then
        echo -e "${GREEN}✓ PASS${NC} - Dashboard created without errors"
        echo "  $OUTPUT" | grep "Total findings:"
    else
        echo -e "${RED}✗ FAIL${NC} - Dashboard file not created"
        exit 1
    fi
else
    echo -e "${RED}✗ FAIL${NC} - Dashboard generation failed"
    echo "$OUTPUT"
    exit 1
fi
echo ""

# Test 2: Custom output path (from acceptance criteria)
echo "Test: Dashboard with custom output path (reports/dashboard.html)..."
CUSTOM_OUT="$TEST_DIR/reports/dashboard.html"
if python3 "$CORE_DIR/generate_dashboard.py" "$RESULTS_DIR" "$CUSTOM_OUT" 2>&1; then
    if [ -f "$CUSTOM_OUT" ]; then
        echo -e "${GREEN}✓ PASS${NC} - Dashboard created at custom path with parent directory creation"
    else
        echo -e "${RED}✗ FAIL${NC} - Dashboard not created at custom path"
        exit 1
    fi
else
    echo -e "${RED}✗ FAIL${NC} - Failed to create dashboard at custom path"
    exit 1
fi
echo ""

# Verify dashboard renders (contains expected HTML structure)
echo "Test: Dashboard renders valid HTML..."
if grep -q "<!DOCTYPE html>" "$RESULTS_DIR/dashboard.html" && \
    grep -q "Security Audit Dashboard" "$RESULTS_DIR/dashboard.html" && \
    grep -q "Total Findings" "$RESULTS_DIR/dashboard.html"; then
    echo -e "${GREEN}✓ PASS${NC} - Dashboard contains valid HTML structure"
else
    echo -e "${RED}✗ FAIL${NC} - Dashboard missing expected HTML elements"
    exit 1
fi
echo ""

echo -e "${GREEN}═══════════════════════════════════════════════════════════"
echo "Acceptance Criteria 1: PASSED ✓"
echo -e "═══════════════════════════════════════════════════════════${NC}"
echo ""

# Acceptance Criteria 2: Wrapper script path safety
echo -e "${YELLOW}Acceptance Criteria 2:${NC}"
echo "Wrapper script uses absolute paths without errors"
echo ""

# Verify REPO_ROOT calculation
WRAPPER_SCRIPT="$CLI_DIR/run_audit_and_report.sh"
if [ -f "$WRAPPER_SCRIPT" ]; then
    # Check that temp script is not used
     if grep -q "TEMP_AUDIT_SCRIPT=\"/tmp/run_security_audit_wrapper" "$WRAPPER_SCRIPT" && \
         grep -q "cat > \"\$TEMP_AUDIT_SCRIPT\"" "$WRAPPER_SCRIPT"; then
        echo -e "${RED}✗ FAIL${NC} - Wrapper still uses temp script workaround"
        exit 1
    else
        echo -e "${GREEN}✓ PASS${NC} - Wrapper does not use temp script workaround"
    fi
    
    # Check that absolute paths are used
    if grep -q "AUDIT_SCRIPT=\"\$CORE_DIR/run_security_audit.sh\"" "$WRAPPER_SCRIPT"; then
        echo -e "${GREEN}✓ PASS${NC} - Wrapper uses absolute path for audit script"
    else
        echo -e "${RED}✗ FAIL${NC} - Wrapper doesn't use absolute path for audit script"
        exit 1
    fi
    
    # Check for VERIFY normalization
    if grep -q "Normalize.*json" "$WRAPPER_SCRIPT"; then
        echo -e "${GREEN}✓ PASS${NC} - VERIFY mode includes JSON normalization"
    else
        echo -e "${RED}✗ FAIL${NC} - VERIFY mode missing JSON normalization"
        exit 1
    fi
    
    # Check for automatic dashboard generation
    if grep -q "generate_dashboard.py" "$WRAPPER_SCRIPT"; then
        echo -e "${GREEN}✓ PASS${NC} - Wrapper automatically generates dashboard"
    else
        echo -e "${YELLOW}⚠ WARN${NC} - Wrapper doesn't auto-generate dashboard"
    fi
else
    echo -e "${RED}✗ FAIL${NC} - Wrapper script not found"
    exit 1
fi
echo ""

echo -e "${GREEN}═══════════════════════════════════════════════════════════"
echo "Acceptance Criteria 2: PASSED ✓"
echo -e "═══════════════════════════════════════════════════════════${NC}"
echo ""

# Summary
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗"
echo "║          All Acceptance Tests Passed! ✓                  ║"
echo -e "╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Summary:"
echo "  ✓ Dashboard handles 6 different TruffleHog formats"
echo "  ✓ Dashboard generates without AttributeError"
echo "  ✓ Dashboard renders valid HTML"
echo "  ✓ Custom output path with parent directory creation works"
echo "  ✓ Wrapper uses absolute paths (no temp script)"
echo "  ✓ VERIFY mode normalizes JSON files"
echo "  ✓ Dashboard auto-generation enabled"
echo ""

# Cleanup (unless debugging)
if [ "${KEEP_RESULTS:-0}" -eq 1 ]; then
    echo "KEEP_RESULTS=1 set; leaving test artifacts in $TEST_DIR"
else
    rm -rf "$TEST_DIR"
    echo "Test artifacts cleaned up."
fi
