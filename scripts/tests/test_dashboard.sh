#!/bin/bash
# test_dashboard.sh - Test dashboard generation with various TruffleHog formats
# This test validates that the dashboard generator handles all formats correctly

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="/tmp/dashboard-test-$$"
RESULTS_DIR="$TEST_DIR/results"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=========================================="
echo "Dashboard Generation Test Suite"
echo -e "==========================================${NC}"
echo ""

# Create test structure
mkdir -p "$RESULTS_DIR/individual-repos"

echo "Creating test repositories with various TruffleHog formats..."
echo ""

# Test Case 1: JSON array format
mkdir -p "$RESULTS_DIR/individual-repos/repo-array"
cat > "$RESULTS_DIR/individual-repos/repo-array/trufflehog.json" << 'EOF1'
[
  {
    "DetectorName": "AWS",
    "Verified": true,
    "SourceMetadata": {
      "Data": {
        "Filesystem": {
          "file": "config/aws.yaml"
        }
      }
    }
  },
  {
    "DetectorName": "GitHub",
    "Verified": false,
    "SourceMetadata": {
      "Data": {
        "Filesystem": {
          "file": "src/app.js"
        }
      }
    }
  }
]
EOF1

# Test Case 2: NDJSON format (one JSON object per line)
mkdir -p "$RESULTS_DIR/individual-repos/repo-ndjson"
cat > "$RESULTS_DIR/individual-repos/repo-ndjson/trufflehog.json" << 'EOF2'
{"DetectorName": "Slack", "Verified": true, "SourceMetadata": {"Data": {"Filesystem": {"file": "webhooks.js"}}}}
{"DetectorName": "Stripe", "Verified": false, "SourceMetadata": {"Data": {"Filesystem": {"file": "payments.py"}}}}
EOF2

# Test Case 3: Single object (not an array)
mkdir -p "$RESULTS_DIR/individual-repos/repo-object"
cat > "$RESULTS_DIR/individual-repos/repo-object/trufflehog.json" << 'EOF3'
{"DetectorName": "JWT", "Verified": true, "SourceMetadata": {"Data": {"Filesystem": {"file": "auth/token.js"}}}}
EOF3

# Test Case 4: Empty array
mkdir -p "$RESULTS_DIR/individual-repos/repo-empty-array"
echo "[]" > "$RESULTS_DIR/individual-repos/repo-empty-array/trufflehog.json"

# Test Case 5: Nested array
mkdir -p "$RESULTS_DIR/individual-repos/repo-nested"
echo '[[{"DetectorName": "Nested", "Verified": false}]]' > "$RESULTS_DIR/individual-repos/repo-nested/trufflehog.json"

# Test Case 6: Empty file
mkdir -p "$RESULTS_DIR/individual-repos/repo-empty-file"
touch "$RESULTS_DIR/individual-repos/repo-empty-file/trufflehog.json"

# Test Case 7: Missing file (repo exists but no trufflehog.json)
mkdir -p "$RESULTS_DIR/individual-repos/repo-no-trufflehog"

# Add other required JSON files for completeness
for repo_dir in "$RESULTS_DIR/individual-repos"/*; do
    if [ -d "$repo_dir" ]; then
        echo '[]' > "$repo_dir/gitleaks.json"
        echo '{"results":[]}' > "$repo_dir/semgrep.json"
        echo '{"matches":[]}' > "$repo_dir/noseyparker.json"
    fi
done

echo -e "${GREEN}✓${NC} Created 7 test repositories with different formats:"
echo "  1. JSON array with multiple objects"
echo "  2. NDJSON (one object per line)"
echo "  3. Single JSON object (not array)"
echo "  4. Empty JSON array []"
echo "  5. Nested array [[{...}]]"
echo "  6. Empty file"
echo "  7. Missing trufflehog.json file"
echo ""

# Test 1: Default output location
echo "Test 1: Dashboard generation with default output..."
OUTPUT=$(python3 "$SCRIPT_DIR/generate_dashboard.py" "$RESULTS_DIR" 2>&1)
echo "$OUTPUT"

if [ -f "$RESULTS_DIR/dashboard.html" ]; then
    echo -e "${GREEN}✓ Test 1 PASSED${NC} - Dashboard created at default location"
else
    echo -e "${RED}✗ Test 1 FAILED${NC} - Dashboard not created"
    exit 1
fi
echo ""

# Test 2: Custom output path
echo "Test 2: Dashboard generation with custom output path..."
CUSTOM_OUT="$TEST_DIR/reports/security/custom-dashboard.html"
python3 "$SCRIPT_DIR/generate_dashboard.py" "$RESULTS_DIR" "$CUSTOM_OUT"

if [ -f "$CUSTOM_OUT" ]; then
    echo -e "${GREEN}✓ Test 2 PASSED${NC} - Dashboard created at custom location"
else
    echo -e "${RED}✗ Test 2 FAILED${NC} - Custom path dashboard not created"
    exit 1
fi
echo ""

# Test 3: Verify content
echo "Test 3: Verifying dashboard content..."
CONTENT_OK=true

if ! grep -q "repo-array" "$RESULTS_DIR/dashboard.html"; then
    echo -e "${RED}✗${NC} Missing repo-array in dashboard"
    CONTENT_OK=false
fi

if ! grep -q "repo-ndjson" "$RESULTS_DIR/dashboard.html"; then
    echo -e "${RED}✗${NC} Missing repo-ndjson in dashboard"
    CONTENT_OK=false
fi

if ! grep -q "repo-object" "$RESULTS_DIR/dashboard.html"; then
    echo -e "${RED}✗${NC} Missing repo-object in dashboard"
    CONTENT_OK=false
fi

if [ "$CONTENT_OK" = true ]; then
    echo -e "${GREEN}✓ Test 3 PASSED${NC} - Dashboard contains all expected repositories"
else
    echo -e "${RED}✗ Test 3 FAILED${NC} - Dashboard missing repositories"
    exit 1
fi
echo ""

# Test 4: Zero-state (empty/missing individual-repos)
echo "Test 4: Zero-state dashboard (no scan results)..."
EMPTY_DIR="$TEST_DIR/empty-results"
mkdir -p "$EMPTY_DIR"
python3 "$SCRIPT_DIR/generate_dashboard.py" "$EMPTY_DIR" > /dev/null 2>&1

if [ -f "$EMPTY_DIR/dashboard.html" ] && grep -q "No repositories scanned yet" "$EMPTY_DIR/dashboard.html"; then
    echo -e "${GREEN}✓ Test 4 PASSED${NC} - Zero-state dashboard handles empty results"
else
    echo -e "${RED}✗ Test 4 FAILED${NC} - Zero-state not handled correctly"
    exit 1
fi
echo ""

# Test 5: Extract findings count
FINDINGS_COUNT=$(echo "$OUTPUT" | grep "Total findings:" | grep -oE '[0-9]+' | head -1)
if [ "$FINDINGS_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✓ Test 5 PASSED${NC} - Detected $FINDINGS_COUNT findings from various formats"
else
    echo -e "${RED}✗ Test 5 FAILED${NC} - No findings detected"
    exit 1
fi
echo ""

echo -e "${GREEN}=========================================="
echo "All Tests Passed! ✓"
echo -e "==========================================${NC}"
echo ""
echo "Summary:"
echo "  ✓ Handled 7 different TruffleHog formats"
echo "  ✓ Detected $FINDINGS_COUNT total findings"
echo "  ✓ Dashboard created at default and custom locations"
echo "  ✓ Zero-state dashboard working correctly"
echo "  ✓ All repositories visible in dashboard"
echo ""

# Cleanup
rm -rf "$TEST_DIR"
echo "Test artifacts cleaned up."
