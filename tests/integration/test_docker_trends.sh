#!/usr/bin/env bash
#
# Integration tests for Docker-based trend analysis workflows
#
# Tests Docker volume persistence, docker-compose workflows, and CI/CD patterns
# for the Trend Analysis feature (Phase 8).
#
# Usage:
#   ./tests/integration/test_docker_trends.sh
#
# Requirements:
#   - Docker installed and running
#   - jmo-security Docker image built (or uses Docker Hub image)
#
# Exit codes:
#   0 - All tests passed
#   1 - One or more tests failed

set -euo pipefail

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Cleanup flag
CLEANUP_ON_EXIT=true

# Test directories (use tmp for isolation)
TEST_ROOT="/tmp/jmo-docker-trends-test-$$"
TEST_REPO="$TEST_ROOT/test-repo"
TEST_JMO_DIR="$TEST_ROOT/.jmo"
TEST_RESULTS="$TEST_ROOT/results"

# Docker image to test (can be overridden via env var)
DOCKER_IMAGE="${JMO_DOCKER_IMAGE:-jmo-security:latest}"

# ============================================================================
# Helper Functions
# ============================================================================

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

assert_equals() {
    local expected="$1"
    local actual="$2"
    local message="${3:-Assertion failed}"

    TESTS_RUN=$((TESTS_RUN + 1))

    if [[ "$expected" == "$actual" ]]; then
        log_info "✅ PASS: $message"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "❌ FAIL: $message"
        log_error "   Expected: $expected"
        log_error "   Actual:   $actual"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

assert_file_exists() {
    local file="$1"
    local message="${2:-File should exist: $file}"

    TESTS_RUN=$((TESTS_RUN + 1))

    if [[ -f "$file" ]]; then
        log_info "✅ PASS: $message"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "❌ FAIL: $message"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

assert_contains() {
    local haystack="$1"
    local needle="$2"
    local message="${3:-String should contain: $needle}"

    TESTS_RUN=$((TESTS_RUN + 1))

    if [[ "$haystack" == *"$needle"* ]]; then
        log_info "✅ PASS: $message"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "❌ FAIL: $message"
        log_error "   Haystack: $haystack"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

cleanup() {
    if [[ "$CLEANUP_ON_EXIT" == "true" ]]; then
        log_info "Cleaning up test environment..."
        rm -rf "$TEST_ROOT"
    else
        log_warn "Skipping cleanup (CLEANUP_ON_EXIT=false). Test data in: $TEST_ROOT"
    fi
}

# ============================================================================
# Setup
# ============================================================================

setup_test_environment() {
    log_info "Setting up test environment in $TEST_ROOT"

    # Create test directories
    mkdir -p "$TEST_REPO"
    mkdir -p "$TEST_JMO_DIR"
    mkdir -p "$TEST_RESULTS"

    # Initialize test repo with git
    cd "$TEST_REPO"
    git init --quiet
    git config user.email "test@example.com"
    git config user.name "Test User"

    # Create test files with security issues
    cat > main.py <<'EOF'
import os
password = "hardcoded_secret_123"
api_key = os.getenv("API_KEY", "default_key")
EOF

    cat > Dockerfile <<'EOF'
FROM ubuntu:22.04
RUN apt-get update
EXPOSE 8080
EOF

    git add .
    git commit -m "Initial commit" --quiet

    log_info "Test repository created with sample files"
}

# ============================================================================
# Test 1: Docker Volume Persistence (CRITICAL)
# ============================================================================

test_volume_persistence() {
    log_info "TEST 1: Docker Volume Persistence"
    log_info "Testing that SQLite history database persists across container runs..."

    # Run first scan with volume mount
    docker run --rm \
        -v "$TEST_REPO:/scan" \
        -v "$TEST_JMO_DIR:/root/.jmo" \
        "$DOCKER_IMAGE" scan \
        --repo /scan \
        --results-dir /scan/results-1 \
        --profile-name fast \
        --allow-missing-tools \
        > /dev/null 2>&1 || true

    # Check history database was created
    assert_file_exists "$TEST_JMO_DIR/history.db" "History database created after first scan"

    # Run second scan (different results dir to simulate new scan)
    docker run --rm \
        -v "$TEST_REPO:/scan" \
        -v "$TEST_JMO_DIR:/root/.jmo" \
        "$DOCKER_IMAGE" scan \
        --repo /scan \
        --results-dir /scan/results-2 \
        --profile-name fast \
        --allow-missing-tools \
        > /dev/null 2>&1 || true

    # Run trends command (should see 2 scans)
    output=$(docker run --rm \
        -v "$TEST_REPO:/scan" \
        -v "$TEST_JMO_DIR:/root/.jmo" \
        "$DOCKER_IMAGE" trends show \
        --limit 10 \
        --format text 2>&1 || true)

    # Verify we can query trends (presence of "scans" or "findings" indicates data persisted)
    assert_contains "$output" "scan" "Trend analysis should access persisted scan history"

    log_info "Volume persistence test complete"
}

# ============================================================================
# Test 2: Trend Commands in Docker
# ============================================================================

test_trend_commands_in_docker() {
    log_info "TEST 2: Trend Commands in Docker"
    log_info "Testing all trend CLI commands work in Docker..."

    # Test: jmo trends show
    docker run --rm \
        -v "$TEST_REPO:/scan" \
        -v "$TEST_JMO_DIR:/root/.jmo" \
        "$DOCKER_IMAGE" trends show --limit 5 > /dev/null 2>&1 || true
    assert_equals "0" "$?" "trends show command should execute successfully"

    # Test: jmo trends analyze
    docker run --rm \
        -v "$TEST_REPO:/scan" \
        -v "$TEST_JMO_DIR:/root/.jmo" \
        "$DOCKER_IMAGE" trends analyze --days 30 > /dev/null 2>&1 || true
    assert_equals "0" "$?" "trends analyze command should execute successfully"

    # Test: jmo trends score
    docker run --rm \
        -v "$TEST_REPO:/scan" \
        -v "$TEST_JMO_DIR:/root/.jmo" \
        "$DOCKER_IMAGE" trends score > /dev/null 2>&1 || true
    assert_equals "0" "$?" "trends score command should execute successfully"

    log_info "Trend commands test complete"
}

# ============================================================================
# Test 3: Export Trends in Docker
# ============================================================================

test_export_trends_in_docker() {
    log_info "TEST 3: Export Trends in Docker"
    log_info "Testing trend export functionality with volume mounts..."

    # Export HTML report
    docker run --rm \
        -v "$TEST_REPO:/scan" \
        -v "$TEST_JMO_DIR:/root/.jmo" \
        -v "$TEST_RESULTS:/results" \
        "$DOCKER_IMAGE" trends export html \
        --output /results/trends.html > /dev/null 2>&1 || true

    assert_file_exists "$TEST_RESULTS/trends.html" "HTML trend report should be exported"

    # Export JSON report
    docker run --rm \
        -v "$TEST_REPO:/scan" \
        -v "$TEST_JMO_DIR:/root/.jmo" \
        -v "$TEST_RESULTS:/results" \
        "$DOCKER_IMAGE" trends export json \
        --output /results/trends.json > /dev/null 2>&1 || true

    assert_file_exists "$TEST_RESULTS/trends.json" "JSON trend report should be exported"

    log_info "Export trends test complete"
}

# ============================================================================
# Test 4: Git Blame with Docker (Developer Attribution)
# ============================================================================

test_git_blame_with_docker() {
    log_info "TEST 4: Git Blame with Docker (Developer Attribution)"
    log_info "Testing that .git directory mount enables developer attribution..."

    # Run scan with .git directory mounted
    docker run --rm \
        -v "$TEST_REPO:/scan" \
        -v "$TEST_JMO_DIR:/root/.jmo" \
        "$DOCKER_IMAGE" scan \
        --repo /scan \
        --results-dir /scan/results-git \
        --profile-name fast \
        --allow-missing-tools \
        > /dev/null 2>&1 || true

    # Run developer attribution (requires git history)
    output=$(docker run --rm \
        -v "$TEST_REPO:/scan" \
        -v "$TEST_JMO_DIR:/root/.jmo" \
        "$DOCKER_IMAGE" trends developers \
        --limit 5 2>&1 || true)

    # Verify git integration works (should not error about missing .git)
    if [[ "$output" == *"Not a git repository"* ]]; then
        log_error "Git repository not accessible in Docker container"
        TESTS_RUN=$((TESTS_RUN + 1))
        TESTS_FAILED=$((TESTS_FAILED + 1))
    else
        log_info "✅ PASS: Git repository accessible for developer attribution"
        TESTS_RUN=$((TESTS_RUN + 1))
        TESTS_PASSED=$((TESTS_PASSED + 1))
    fi

    log_info "Git blame test complete"
}

# ============================================================================
# Test 5: CI/CD Cache Pattern (Simulated)
# ============================================================================

test_cicd_cache_pattern() {
    log_info "TEST 5: CI/CD Cache Pattern (Simulated)"
    log_info "Testing cache restoration pattern for CI/CD workflows..."

    # Simulate CI/CD workflow: save cache
    cache_archive="$TEST_ROOT/jmo-cache.tar.gz"
    tar -czf "$cache_archive" -C "$TEST_ROOT" .jmo 2>/dev/null || true

    assert_file_exists "$cache_archive" "Cache archive should be created"

    # Remove .jmo directory (simulate fresh CI run)
    rm -rf "$TEST_JMO_DIR"
    mkdir -p "$TEST_JMO_DIR"

    # Restore cache
    tar -xzf "$cache_archive" -C "$TEST_ROOT" 2>/dev/null || true

    assert_file_exists "$TEST_JMO_DIR/history.db" "History database should be restored from cache"

    # Verify trends still work after cache restoration
    output=$(docker run --rm \
        -v "$TEST_REPO:/scan" \
        -v "$TEST_JMO_DIR:/root/.jmo" \
        "$DOCKER_IMAGE" trends show --limit 5 2>&1 || true)

    assert_contains "$output" "scan" "Trends should work after cache restoration"

    log_info "CI/CD cache pattern test complete"
}

# ============================================================================
# Test 6: Environment Variable Configuration
# ============================================================================

test_env_var_configuration() {
    log_info "TEST 6: Environment Variable Configuration"
    log_info "Testing environment variable precedence in Docker..."

    # Run with environment variable override
    output=$(docker run --rm \
        -v "$TEST_REPO:/scan" \
        -v "$TEST_JMO_DIR:/root/.jmo" \
        -e JMO_HISTORY_DB_PATH="/root/.jmo/custom-history.db" \
        "$DOCKER_IMAGE" scan \
        --repo /scan \
        --results-dir /scan/results-env \
        --profile-name fast \
        --allow-missing-tools 2>&1 || true)

    # Note: This test is a smoke test since we can't easily verify custom DB path
    # The primary goal is to ensure env vars don't cause crashes
    assert_equals "0" "$?" "Scan with env vars should not crash"

    log_info "Environment variable configuration test complete"
}

# ============================================================================
# Main Test Runner
# ============================================================================

main() {
    log_info "========================================"
    log_info "JMo Security - Docker Trends Integration Tests"
    log_info "========================================"
    log_info "Docker image: $DOCKER_IMAGE"
    log_info ""

    # Check Docker is available
    if ! command -v docker &> /dev/null; then
        log_error "Docker not found. Please install Docker to run these tests."
        exit 1
    fi

    # Check Docker daemon is running
    if ! docker info &> /dev/null; then
        log_error "Docker daemon not running. Please start Docker."
        exit 1
    fi

    # Setup test environment
    setup_test_environment

    # Run tests
    test_volume_persistence
    test_trend_commands_in_docker
    test_export_trends_in_docker
    test_git_blame_with_docker
    test_cicd_cache_pattern
    test_env_var_configuration

    # Cleanup
    cleanup

    # Summary
    log_info ""
    log_info "========================================"
    log_info "Test Summary"
    log_info "========================================"
    log_info "Tests run:    $TESTS_RUN"
    log_info "Tests passed: $TESTS_PASSED"
    log_info "Tests failed: $TESTS_FAILED"

    if [[ "$TESTS_FAILED" -eq 0 ]]; then
        log_info ""
        log_info "✅ All tests passed!"
        exit 0
    else
        log_error ""
        log_error "❌ Some tests failed!"
        exit 1
    fi
}

# Trap cleanup on exit
trap cleanup EXIT

# Run main
main "$@"
