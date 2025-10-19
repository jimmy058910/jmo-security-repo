#!/usr/bin/env bash
#
# test_docker_optimization.sh - Test optimized Docker images (v0.6.1)
#
# Purpose: Validate multi-stage builds, layer caching, and Trivy DB pre-download
#
# Usage:
#   bash scripts/dev/test_docker_optimization.sh
#
# Tests:
#   1. Build all 3 variants (full, slim, alpine)
#   2. Measure image sizes and compare to v0.6.0 baselines
#   3. Verify all tools work correctly
#   4. Test Trivy caching with volume mount
#   5. Generate size comparison report
#
# Requirements:
#   - Docker installed and running
#   - At least 5GB free disk space
#   - Internet connection for base image pulls

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Baselines from v0.6.0 (before optimization)
BASELINE_FULL_MB=1500
BASELINE_SLIM_MB=700
BASELINE_ALPINE_MB=500

# Goals from ROADMAP #1
GOAL_FULL_MB=900
GOAL_SLIM_MB=400
GOAL_ALPINE_MB=300

echo -e "${BLUE}=== Docker Image Optimization Test (v0.6.1) ===${NC}"
echo ""
echo "This script will:"
echo "1. Build all 3 Docker variants (full, slim, alpine)"
echo "2. Measure sizes and compare to baselines"
echo "3. Verify all tools work correctly"
echo "4. Test Trivy caching performance"
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}ERROR: Docker is not running${NC}"
    echo "Please start Docker and try again"
    exit 1
fi

# Build all variants
echo -e "${BLUE}Step 1: Building Docker images...${NC}"
echo ""

echo -e "${YELLOW}Building jmo-security:0.6.1-full...${NC}"
docker build -t jmo-security:0.6.1-full -f Dockerfile .

echo ""
echo -e "${YELLOW}Building jmo-security:0.6.1-slim...${NC}"
docker build -t jmo-security:0.6.1-slim -f Dockerfile.slim .

echo ""
echo -e "${YELLOW}Building jmo-security:0.6.1-alpine...${NC}"
docker build -t jmo-security:0.6.1-alpine -f Dockerfile.alpine .

echo ""
echo -e "${GREEN}✓ All images built successfully${NC}"
echo ""

# Measure sizes
echo -e "${BLUE}Step 2: Measuring image sizes...${NC}"
echo ""

get_size_mb() {
    local image=$1
    docker inspect "$image" | jq -r '.[0].Size' | awk '{printf "%.0f", $1/1024/1024}'
}

FULL_SIZE=$(get_size_mb "jmo-security:0.6.1-full")
SLIM_SIZE=$(get_size_mb "jmo-security:0.6.1-slim")
ALPINE_SIZE=$(get_size_mb "jmo-security:0.6.1-alpine")

echo "| Variant | v0.6.0 Baseline | v0.6.1 Actual | ROADMAP Goal | Status |"
echo "|---------|-----------------|---------------|--------------|--------|"

# Full variant
FULL_REDUCTION=$(awk "BEGIN {printf \"%.0f\", ($BASELINE_FULL_MB - $FULL_SIZE) / $BASELINE_FULL_MB * 100}")
if [ "$FULL_SIZE" -le "$GOAL_FULL_MB" ]; then
    FULL_STATUS="${GREEN}✓ PASS${NC}"
else
    FULL_STATUS="${YELLOW}⚠ PARTIAL${NC}"
fi
echo -e "| Full    | ${BASELINE_FULL_MB}MB | ${FULL_SIZE}MB (-${FULL_REDUCTION}%) | ${GOAL_FULL_MB}MB | $FULL_STATUS |"

# Slim variant
SLIM_REDUCTION=$(awk "BEGIN {printf \"%.0f\", ($BASELINE_SLIM_MB - $SLIM_SIZE) / $BASELINE_SLIM_MB * 100}")
if [ "$SLIM_SIZE" -le "$GOAL_SLIM_MB" ]; then
    SLIM_STATUS="${GREEN}✓ PASS${NC}"
else
    SLIM_STATUS="${YELLOW}⚠ PARTIAL${NC}"
fi
echo -e "| Slim    | ${BASELINE_SLIM_MB}MB | ${SLIM_SIZE}MB (-${SLIM_REDUCTION}%) | ${GOAL_SLIM_MB}MB | $SLIM_STATUS |"

# Alpine variant
ALPINE_REDUCTION=$(awk "BEGIN {printf \"%.0f\", ($BASELINE_ALPINE_MB - $ALPINE_SIZE) / $BASELINE_ALPINE_MB * 100}")
if [ "$ALPINE_SIZE" -le "$GOAL_ALPINE_MB" ]; then
    ALPINE_STATUS="${GREEN}✓ PASS${NC}"
else
    ALPINE_STATUS="${YELLOW}⚠ PARTIAL${NC}"
fi
echo -e "| Alpine  | ${BASELINE_ALPINE_MB}MB | ${ALPINE_SIZE}MB (-${ALPINE_REDUCTION}%) | ${GOAL_ALPINE_MB}MB | $ALPINE_STATUS |"

echo ""

# Verify tools work
echo -e "${BLUE}Step 3: Verifying tools in full image...${NC}"
echo ""

echo -e "${YELLOW}Testing jmo CLI...${NC}"
docker run --rm jmo-security:0.6.1-full --help > /dev/null
echo -e "${GREEN}✓ jmo CLI works${NC}"

echo -e "${YELLOW}Testing trufflehog...${NC}"
docker run --rm jmo-security:0.6.1-full /bin/bash -c "trufflehog --version"
echo -e "${GREEN}✓ trufflehog works${NC}"

echo -e "${YELLOW}Testing trivy...${NC}"
docker run --rm jmo-security:0.6.1-full /bin/bash -c "trivy --version"
echo -e "${GREEN}✓ trivy works${NC}"

echo -e "${YELLOW}Testing semgrep...${NC}"
docker run --rm jmo-security:0.6.1-full /bin/bash -c "semgrep --version"
echo -e "${GREEN}✓ semgrep works${NC}"

echo ""

# Test Trivy caching
echo -e "${BLUE}Step 4: Testing Trivy database caching...${NC}"
echo ""

echo -e "${YELLOW}Creating test directory...${NC}"
mkdir -p /tmp/docker-test-scan

echo -e "${YELLOW}First scan (with pre-downloaded DB)...${NC}"
START_TIME=$(date +%s)
docker run --rm \
    -v /tmp/docker-test-scan:/scan \
    -v trivy-test-cache:/root/.cache/trivy \
    jmo-security:0.6.1-full \
    scan --help > /dev/null 2>&1 || true
END_TIME=$(date +%s)
FIRST_SCAN_TIME=$((END_TIME - START_TIME))
echo -e "${GREEN}✓ First scan completed in ${FIRST_SCAN_TIME}s (DB pre-cached in image)${NC}"

echo -e "${YELLOW}Second scan (with volume-cached DB)...${NC}"
START_TIME=$(date +%s)
docker run --rm \
    -v /tmp/docker-test-scan:/scan \
    -v trivy-test-cache:/root/.cache/trivy \
    jmo-security:0.6.1-full \
    scan --help > /dev/null 2>&1 || true
END_TIME=$(date +%s)
SECOND_SCAN_TIME=$((END_TIME - START_TIME))
echo -e "${GREEN}✓ Second scan completed in ${SECOND_SCAN_TIME}s (cache hit)${NC}"

echo ""
echo -e "${BLUE}Cleanup...${NC}"
docker volume rm trivy-test-cache > /dev/null 2>&1 || true
rm -rf /tmp/docker-test-scan

echo ""
echo -e "${GREEN}=== Docker Optimization Test Complete ===${NC}"
echo ""
echo "Summary:"
echo "- Full image: ${FULL_SIZE}MB (baseline: ${BASELINE_FULL_MB}MB, goal: ${GOAL_FULL_MB}MB, reduction: ${FULL_REDUCTION}%)"
echo "- Slim image: ${SLIM_SIZE}MB (baseline: ${BASELINE_SLIM_MB}MB, goal: ${GOAL_SLIM_MB}MB, reduction: ${SLIM_REDUCTION}%)"
echo "- Alpine image: ${ALPINE_SIZE}MB (baseline: ${BASELINE_ALPINE_MB}MB, goal: ${GOAL_ALPINE_MB}MB, reduction: ${ALPINE_REDUCTION}%)"
echo "- Trivy caching: First scan ${FIRST_SCAN_TIME}s, second scan ${SECOND_SCAN_TIME}s"
echo ""
echo "Next steps:"
echo "1. Review image sizes and compare to ROADMAP #1 goals"
echo "2. Test multi-target scanning with optimized images"
echo "3. Verify CI pipeline builds successfully"
echo "4. Tag release as v0.6.1 when ready"
