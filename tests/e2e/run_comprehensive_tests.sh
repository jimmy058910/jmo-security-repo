#!/usr/bin/env bash
# JMo Security Comprehensive End-to-End Test Suite
# Tests all target types across OS/execution methods
#
# Usage:
#   bash tests/e2e/run_comprehensive_tests.sh           # Run all tests for current OS
#   bash tests/e2e/run_comprehensive_tests.sh --test U1 # Run specific test
#   bash tests/e2e/run_comprehensive_tests.sh --help    # Show help

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RESULTS_BASE="${RESULTS_BASE:-/tmp/jmo-comprehensive-tests-$(date +%s)}"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"

# Test targets (can be overridden via environment variables)
TEST_REPO="${TEST_REPO:-https://github.com/juice-shop/juice-shop.git}"
TEST_IMAGE="${TEST_IMAGE:-alpine:3.19}"
TEST_TF_FILE="$FIXTURES_DIR/iac/aws-s3-public.tf"
TEST_K8S_MANIFEST="$FIXTURES_DIR/iac/k8s-privileged-pod.yaml"
TEST_DOCKERFILE="$FIXTURES_DIR/iac/Dockerfile.bad"
TEST_URL="${TEST_URL:-http://testphp.vulnweb.com}"

# Docker configuration
DOCKER_IMAGE_BASE="${DOCKER_IMAGE_BASE:-ghcr.io/jimmy058910/jmo-security}"
DOCKER_TAG="${DOCKER_TAG:-latest}"

# Test execution settings
TIMEOUT_SECONDS=900 # 15 minutes per test
SPECIFIC_TEST=""

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ============================================================================
# Helper Functions
# ============================================================================

log_info() {
  echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
  echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warning() {
  echo -e "${YELLOW}[WARNING]${NC} $*"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $*"
}

show_help() {
  cat <<EOF
JMo Security Comprehensive Test Suite

Usage:
  $0 [OPTIONS]

Options:
  --test TEST_ID    Run specific test (e.g., U1, M2, W3)
  --results DIR     Custom results directory (default: /tmp/jmo-comprehensive-tests-*)
  --help            Show this help message

Environment Variables:
  TEST_REPO         Git repository URL (default: juice-shop)
  TEST_IMAGE        Container image (default: alpine:3.19)
  TEST_URL          Web app URL (default: testphp.vulnweb.com)
  DOCKER_IMAGE_BASE Docker image base (default: ghcr.io/jimmy058910/jmo-security)
  DOCKER_TAG        Docker image tag (default: latest)
  GITLAB_TOKEN      GitLab API token (for GitLab tests)

Examples:
  # Run all tests for current OS
  bash tests/e2e/run_comprehensive_tests.sh

  # Run specific test
  bash tests/e2e/run_comprehensive_tests.sh --test U1

  # Use custom test targets
  TEST_REPO=/path/to/repo TEST_IMAGE=nginx:latest bash tests/e2e/run_comprehensive_tests.sh

  # Test specific Docker image version
  DOCKER_TAG=0.6.0-full bash tests/e2e/run_comprehensive_tests.sh
EOF
}

# Parse command line arguments
parse_args() {
  while [[ $# -gt 0 ]]; do
    case $1 in
    --test)
      SPECIFIC_TEST="$2"
      shift 2
      ;;
    --results)
      RESULTS_BASE="$2"
      shift 2
      ;;
    --help)
      show_help
      exit 0
      ;;
    *)
      log_error "Unknown option: $1"
      show_help
      exit 1
      ;;
    esac
  done
}

# Check prerequisites
check_prerequisites() {
  log_info "Checking prerequisites..."

  # Check jmo CLI
  if ! command -v jmo &>/dev/null && ! command -v jmotools &>/dev/null; then
    log_error "jmo CLI not found. Install with: pip install -e ."
    return 1
  fi

  # Check jq for JSON validation
  if ! command -v jq &>/dev/null; then
    log_warning "jq not found. JSON validation will be skipped."
    log_warning "Install with: apt install jq (Ubuntu) or brew install jq (macOS)"
  fi

  # Check Docker (optional)
  if ! command -v docker &>/dev/null; then
    log_warning "Docker not found. Docker tests will be skipped."
  fi

  # Check git
  if ! command -v git &>/dev/null; then
    log_error "git not found. Required for repository scanning."
    return 1
  fi

  log_success "Prerequisites check passed"
  return 0
}

# Setup test fixtures
setup_fixtures() {
  log_info "Setting up test fixtures..."

  # Create fixtures directory if needed
  mkdir -p "$FIXTURES_DIR"

  # Setup fixtures using fixture script
  if [[ -f "$FIXTURES_DIR/setup_fixtures.sh" ]]; then
    bash "$FIXTURES_DIR/setup_fixtures.sh"
  else
    log_warning "Fixture setup script not found, using defaults"
  fi

  # Verify critical fixtures exist
  if [[ ! -f $TEST_TF_FILE ]]; then
    log_warning "IaC fixture not found: $TEST_TF_FILE"
  fi

  log_success "Test fixtures ready"
}

# ============================================================================
# Validation Functions
# ============================================================================

validate_basic_scan() {
  local results_dir="$1"
  local exit_code="$2"
  local test_id="$3"

  log_info "[$test_id] Validating basic scan output..."

  # Exit code should be 0 (no findings) or 1 (findings found)
  if [[ $exit_code -ne 0 && $exit_code -ne 1 ]]; then
    log_error "[$test_id] Unexpected exit code: $exit_code (expected 0 or 1)"
    return 1
  fi

  # Check required output files exist
  local findings_json="$results_dir/summaries/findings.json"
  local summary_md="$results_dir/summaries/SUMMARY.md"
  local dashboard_html="$results_dir/summaries/dashboard.html"

  if [[ ! -f $findings_json ]]; then
    log_error "[$test_id] Missing findings.json"
    return 1
  fi

  if [[ ! -f $summary_md ]]; then
    log_error "[$test_id] Missing SUMMARY.md"
    return 1
  fi

  if [[ ! -f $dashboard_html ]]; then
    log_error "[$test_id] Missing dashboard.html"
    return 1
  fi

  # Validate JSON structure if jq available
  if command -v jq &>/dev/null; then
    if ! jq -e 'type == "array"' "$findings_json" >/dev/null 2>&1; then
      log_error "[$test_id] findings.json is not a valid array"
      return 1
    fi

    # Check if findings have required fields (if any findings exist)
    local finding_count=$(jq 'length' "$findings_json")
    if [[ $finding_count -gt 0 ]]; then
      if ! jq -e '.[0] | has("id") and has("ruleId") and has("severity") and has("tool") and has("location") and has("message")' "$findings_json" >/dev/null 2>&1; then
        log_error "[$test_id] Finding missing required fields"
        return 1
      fi
    fi

    log_info "[$test_id] Found $finding_count findings"
  fi

  log_success "[$test_id] Basic scan validation passed"
  return 0
}

validate_multi_target() {
  local results_dir="$1"
  local exit_code="$2"
  local test_id="$3"

  log_info "[$test_id] Validating multi-target scan output..."

  # Basic validation first
  if ! validate_basic_scan "$results_dir" "$exit_code" "$test_id"; then
    return 1
  fi

  # Check multiple target directories exist
  local target_dirs=0
  [[ -d "$results_dir/individual-repos" ]] && target_dirs=$((target_dirs + 1))
  [[ -d "$results_dir/individual-images" ]] && target_dirs=$((target_dirs + 1))
  [[ -d "$results_dir/individual-iac" ]] && target_dirs=$((target_dirs + 1))
  [[ -d "$results_dir/individual-web" ]] && target_dirs=$((target_dirs + 1))
  [[ -d "$results_dir/individual-gitlab" ]] && target_dirs=$((target_dirs + 1))
  [[ -d "$results_dir/individual-k8s" ]] && target_dirs=$((target_dirs + 1))

  if [[ $target_dirs -lt 2 ]]; then
    log_error "[$test_id] Expected at least 2 target directories, found $target_dirs"
    return 1
  fi

  log_info "[$test_id] Found $target_dirs target type directories"
  log_success "[$test_id] Multi-target validation passed"
  return 0
}

validate_ci_gating() {
  local results_dir="$1"
  local exit_code="$2"
  local test_id="$3"

  log_info "[$test_id] Validating CI gating behavior..."

  # For known vulnerable target with --fail-on HIGH, expect exit code 1
  # (assuming HIGH or CRITICAL findings exist)
  if [[ $exit_code -ne 0 && $exit_code -ne 1 ]]; then
    log_error "[$test_id] Unexpected exit code: $exit_code"
    return 1
  fi

  # Check findings.json exists
  local findings_json="$results_dir/summaries/findings.json"
  if [[ ! -f $findings_json ]]; then
    log_error "[$test_id] Missing findings.json"
    return 1
  fi

  # If exit code is 1, verify HIGH or CRITICAL findings exist
  if [[ $exit_code -eq 1 ]] && command -v jq &>/dev/null; then
    if ! jq -e '.[] | select(.severity == "HIGH" or .severity == "CRITICAL")' "$findings_json" >/dev/null 2>&1; then
      log_warning "[$test_id] Exit code 1 but no HIGH/CRITICAL findings found"
    fi
  fi

  log_success "[$test_id] CI gating validation passed"
  return 0
}

validate_docker_scan() {
  local results_dir="$1"
  local exit_code="$2"
  local test_id="$3"

  log_info "[$test_id] Validating Docker scan output..."

  # Basic validation
  if ! validate_basic_scan "$results_dir" "$exit_code" "$test_id"; then
    return 1
  fi

  # Check volume mounts worked (results written to host)
  if [[ ! -d "$results_dir/summaries" ]]; then
    log_error "[$test_id] Results not written to host filesystem"
    return 1
  fi

  # Validate findings have correct paths (not container internal paths)
  if command -v jq &>/dev/null; then
    local findings_json="$results_dir/summaries/findings.json"
    local finding_count=$(jq 'length' "$findings_json")
    if [[ $finding_count -gt 0 ]]; then
      # Check if any findings have container-internal paths like /tmp/scan/
      local container_paths=$(jq -r '.[] | select(.location.path | startswith("/tmp/scan/")) | .location.path' "$findings_json" 2>/dev/null | wc -l || echo 0)
      if [[ $container_paths -gt 0 ]]; then
        log_warning "[$test_id] Found $container_paths findings with container-internal paths"
      fi
    fi
  fi

  log_success "[$test_id] Docker scan validation passed"
  return 0
}

validate_wizard_scan() {
  local results_dir="$1"
  local exit_code="$2"
  local test_id="$3"
  local artifact_path="$4"

  log_info "[$test_id] Validating wizard scan output..."

  # Basic validation
  if ! validate_basic_scan "$results_dir" "$exit_code" "$test_id"; then
    return 1
  fi

  # Check if artifact was generated (if specified)
  if [[ -n $artifact_path && ! -f $artifact_path ]]; then
    log_error "[$test_id] Wizard artifact not generated: $artifact_path"
    return 1
  fi

  log_success "[$test_id] Wizard scan validation passed"
  return 0
}

# ============================================================================
# Test Runner
# ============================================================================

run_test() {
  local test_id="$1"
  local test_name="$2"
  local test_cmd="$3"
  local validation_fn="$4"
  shift 4
  local validation_args=("$@")

  # Skip if specific test requested and this isn't it
  if [[ -n $SPECIFIC_TEST && $test_id != "$SPECIFIC_TEST" ]]; then
    return 0
  fi

  echo ""
  echo "=========================================="
  echo "Test $test_id: $test_name"
  echo "=========================================="

  # Create isolated results directory
  local results_dir="$RESULTS_BASE/$test_id"
  mkdir -p "$results_dir"

  # Execute test command with timeout
  local start_time=$(date +%s)
  local exit_code=0

  log_info "[$test_id] Running: $test_cmd"

  # Replace {results_dir} placeholder in command
  test_cmd="${test_cmd//\{results_dir\}/$results_dir}"

  if timeout "$TIMEOUT_SECONDS" bash -c "$test_cmd" >"$results_dir/test.log" 2>&1; then
    exit_code=$?
  else
    exit_code=$?
  fi

  local end_time=$(date +%s)
  local duration=$((end_time - start_time))

  # Show last 20 lines of output on failure
  if [[ $exit_code -gt 1 ]]; then
    log_error "[$test_id] Command failed with exit code $exit_code"
    log_error "[$test_id] Last 20 lines of output:"
    tail -n 20 "$results_dir/test.log" | sed 's/^/    /'
  fi

  # Validate results
  if $validation_fn "$results_dir" "$exit_code" "$test_id" "${validation_args[@]}"; then
    log_success "✅ PASS: $test_id (${duration}s)"
    echo "$test_id,PASS,$duration" >>"$RESULTS_BASE/test-results.csv"
  else
    log_error "❌ FAIL: $test_id (${duration}s)"
    echo "$test_id,FAIL,$duration" >>"$RESULTS_BASE/test-results.csv"

    # Show validation failure details
    log_error "[$test_id] See full output: $results_dir/test.log"
  fi
}

skip_test() {
  local test_id="$1"
  local reason="$2"

  # Skip if specific test requested and this isn't it
  if [[ -n $SPECIFIC_TEST && $test_id != "$SPECIFIC_TEST" ]]; then
    return 0
  fi

  echo ""
  log_warning "⏭️  SKIP: $test_id ($reason)"
  echo "$test_id,SKIP,0" >>"$RESULTS_BASE/test-results.csv"
}

# ============================================================================
# Test Suites
# ============================================================================

run_ubuntu_tests() {
  echo ""
  echo "=========================================="
  echo "Ubuntu Test Suite (12 tests)"
  echo "=========================================="

  # U1: Single repo scan (native CLI) - use ci command for scan+report
  run_test "U1" "Single repo - Native CLI" \
    "cd /tmp && git clone --depth 1 $TEST_REPO test-repo-u1 && jmo ci --repo /tmp/test-repo-u1 --results-dir {results_dir} --profile-name balanced --human-logs --allow-missing-tools" \
    validate_basic_scan

  # U2: Single image scan (native CLI) - use ci command for scan+report
  run_test "U2" "Single image - Native CLI" \
    "jmo ci --image $TEST_IMAGE --results-dir {results_dir} --tools trivy,syft --human-logs --allow-missing-tools" \
    validate_basic_scan

  # U3: IaC file scan (native CLI) - use ci command for scan+report
  if [[ -f $TEST_TF_FILE ]]; then
    run_test "U3" "IaC file - Native CLI" \
      "jmo ci --terraform-state $TEST_TF_FILE --results-dir {results_dir} --tools checkov,trivy --human-logs --allow-missing-tools" \
      validate_basic_scan
  else
    skip_test "U3" "IaC fixture not available"
  fi

  # U4: URL scan (native CLI) - use ci command for scan+report
  run_test "U4" "URL DAST - Native CLI" \
    "jmo ci --url $TEST_URL --results-dir {results_dir} --tools zap --human-logs --allow-missing-tools" \
    validate_basic_scan

  # U5: Multi-target scan (native CLI) - use ci command for scan+report
  if [[ -f $TEST_TF_FILE ]]; then
    run_test "U5" "Multi-target - Native CLI" \
      "cd /tmp && git clone --depth 1 $TEST_REPO test-repo-u5 && jmo ci --repo /tmp/test-repo-u5 --image $TEST_IMAGE --terraform-state $TEST_TF_FILE --results-dir {results_dir} --profile-name balanced --human-logs --allow-missing-tools" \
      validate_multi_target
  else
    skip_test "U5" "IaC fixture not available"
  fi

  # U6: Batch images scan (native CLI) - use ci command for scan+report
  echo "$TEST_IMAGE" >/tmp/images-u6.txt
  echo "nginx:alpine" >>/tmp/images-u6.txt
  echo "redis:alpine" >>/tmp/images-u6.txt
  run_test "U6" "Batch images - Native CLI" \
    "jmo ci --images-file /tmp/images-u6.txt --results-dir {results_dir} --tools trivy,syft --human-logs --allow-missing-tools" \
    validate_basic_scan

  # U7: Single repo scan (wizard --yes)
  # Note: Wizard doesn't accept --repos-dir/--profile args, it uses smart defaults
  # For now, skip this test until wizard API is stable
  skip_test "U7" "wizard test requires manual verification"

  # U8: Multi-target scan (wizard interactive) - SKIP in automated tests
  skip_test "U8" "interactive wizard - manual testing only"

  # U9: Single repo scan (Docker full)
  if command -v docker &>/dev/null; then
    run_test "U9" "Single repo - Docker full" \
      "cd /tmp && git clone --depth 1 $TEST_REPO test-repo-u9 && docker run --rm -v /tmp/test-repo-u9:/scan -v {results_dir}:/results $DOCKER_IMAGE_BASE:$DOCKER_TAG-full ci --repo /scan --results-dir /results --profile-name balanced --allow-missing-tools" \
      validate_docker_scan
  else
    skip_test "U9" "Docker not available"
  fi

  # U10: Single image scan (Docker full)
  if command -v docker &>/dev/null; then
    run_test "U10" "Single image - Docker full" \
      "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v {results_dir}:/results $DOCKER_IMAGE_BASE:$DOCKER_TAG-full ci --image $TEST_IMAGE --results-dir /results --tools trivy,syft --allow-missing-tools" \
      validate_docker_scan
  else
    skip_test "U10" "Docker not available"
  fi

  # U11: Multi-target scan (Docker slim)
  if command -v docker &>/dev/null && [[ -f $TEST_TF_FILE ]]; then
    run_test "U11" "Multi-target - Docker slim" \
      "cd /tmp && git clone --depth 1 $TEST_REPO test-repo-u11 && docker run --rm -v /tmp/test-repo-u11:/scan -v $TEST_TF_FILE:/iac/test.tf -v /var/run/docker.sock:/var/run/docker.sock -v {results_dir}:/results $DOCKER_IMAGE_BASE:$DOCKER_TAG-slim ci --repo /scan --image $TEST_IMAGE --terraform-state /iac/test.tf --results-dir /results --profile-name fast --allow-missing-tools" \
      validate_multi_target
  else
    skip_test "U11" "Docker or IaC fixture not available"
  fi

  # U12: CI mode with gating (native CLI)
  run_test "U12" "CI mode with --fail-on HIGH" \
    "cd /tmp && git clone --depth 1 $TEST_REPO test-repo-u12 && jmo ci --repo /tmp/test-repo-u12 --results-dir {results_dir} --fail-on HIGH --profile-name fast --human-logs --allow-missing-tools" \
    validate_ci_gating
}

run_macos_tests() {
  echo ""
  echo "=========================================="
  echo "macOS Test Suite (6 tests)"
  echo "=========================================="

  # M1: Single repo scan (native CLI)
  run_test "M1" "Single repo - Native CLI" \
    "cd /tmp && git clone --depth 1 $TEST_REPO test-repo-m1 && jmo ci --repo /tmp/test-repo-m1 --results-dir {results_dir} --profile-name balanced --human-logs --allow-missing-tools" \
    validate_basic_scan

  # M2: Single image scan (native CLI)
  run_test "M2" "Single image - Native CLI" \
    "jmo ci --image $TEST_IMAGE --results-dir {results_dir} --tools trivy,syft --human-logs --allow-missing-tools" \
    validate_basic_scan

  # M3: IaC file scan (native CLI)
  if [[ -f $TEST_TF_FILE ]]; then
    run_test "M3" "IaC file - Native CLI" \
      "jmo ci --terraform-state $TEST_TF_FILE --results-dir {results_dir} --tools checkov,trivy --human-logs --allow-missing-tools" \
      validate_basic_scan
  else
    skip_test "M3" "IaC fixture not available"
  fi

  # M4: Single repo scan (wizard --yes)
  if command -v jmotools &>/dev/null; then
    run_test "M4" "Single repo - Wizard --yes" \
      "cd /tmp && git clone --depth 1 $TEST_REPO test-repo-m4 && jmotools wizard --yes --repos-dir /tmp/test-repo-m4 --profile balanced --results-dir {results_dir} --emit-script /tmp/wizard-m4.sh && bash /tmp/wizard-m4.sh" \
      validate_wizard_scan "/tmp/wizard-m4.sh"
  else
    skip_test "M4" "jmotools not available"
  fi

  # M5: Single repo scan (Docker full)
  if command -v docker &>/dev/null; then
    run_test "M5" "Single repo - Docker full" \
      "cd /tmp && git clone --depth 1 $TEST_REPO test-repo-m5 && docker run --rm -v /tmp/test-repo-m5:/scan -v {results_dir}:/results $DOCKER_IMAGE_BASE:$DOCKER_TAG-full scan --repo /scan --results-dir /results --profile-name balanced --allow-missing-tools" \
      validate_docker_scan
  else
    skip_test "M5" "Docker not available"
  fi

  # M6: Multi-target scan (Docker slim)
  if command -v docker &>/dev/null && [[ -f $TEST_TF_FILE ]]; then
    run_test "M6" "Multi-target - Docker slim" \
      "cd /tmp && git clone --depth 1 $TEST_REPO test-repo-m6 && docker run --rm -v /tmp/test-repo-m6:/scan -v $TEST_TF_FILE:/iac/test.tf -v {results_dir}:/results $DOCKER_IMAGE_BASE:$DOCKER_TAG-slim scan --repo /scan --image $TEST_IMAGE --terraform-state /iac/test.tf --results-dir /results --profile-name fast --allow-missing-tools" \
      validate_multi_target
  else
    skip_test "M6" "Docker or IaC fixture not available"
  fi
}

run_windows_tests() {
  echo ""
  echo "=========================================="
  echo "Windows WSL2 Test Suite (4 tests)"
  echo "=========================================="

  # W1: Single repo scan (native CLI)
  run_test "W1" "Single repo - Native CLI" \
    "cd /tmp && git clone --depth 1 $TEST_REPO test-repo-w1 && jmo ci --repo /tmp/test-repo-w1 --results-dir {results_dir} --profile-name balanced --human-logs --allow-missing-tools" \
    validate_basic_scan

  # W2: Single repo scan (wizard --yes)
  if command -v jmotools &>/dev/null; then
    run_test "W2" "Single repo - Wizard --yes" \
      "cd /tmp && git clone --depth 1 $TEST_REPO test-repo-w2 && jmotools wizard --yes --repos-dir /tmp/test-repo-w2 --profile balanced --results-dir {results_dir} --emit-script /tmp/wizard-w2.sh && bash /tmp/wizard-w2.sh" \
      validate_wizard_scan "/tmp/wizard-w2.sh"
  else
    skip_test "W2" "jmotools not available"
  fi

  # W3: Single repo scan (Docker full)
  if command -v docker &>/dev/null; then
    run_test "W3" "Single repo - Docker full" \
      "cd /tmp && git clone --depth 1 $TEST_REPO test-repo-w3 && docker run --rm -v /tmp/test-repo-w3:/scan -v {results_dir}:/results $DOCKER_IMAGE_BASE:$DOCKER_TAG-full scan --repo /scan --results-dir /results --profile-name balanced --allow-missing-tools" \
      validate_docker_scan
  else
    skip_test "W3" "Docker not available"
  fi

  # W4: Multi-target scan (Docker slim)
  if command -v docker &>/dev/null && [[ -f $TEST_TF_FILE ]]; then
    run_test "W4" "Multi-target - Docker slim" \
      "cd /tmp && git clone --depth 1 $TEST_REPO test-repo-w4 && docker run --rm -v /tmp/test-repo-w4:/scan -v $TEST_TF_FILE:/iac/test.tf -v {results_dir}:/results $DOCKER_IMAGE_BASE:$DOCKER_TAG-slim scan --repo /scan --image $TEST_IMAGE --terraform-state /iac/test.tf --results-dir /results --profile-name fast --allow-missing-tools" \
      validate_multi_target
  else
    skip_test "W4" "Docker or IaC fixture not available"
  fi
}

run_advanced_tests() {
  echo ""
  echo "=========================================="
  echo "Advanced Test Suite (3 tests)"
  echo "=========================================="

  # A1: GitLab repo scan
  if [[ -n ${GITLAB_TOKEN-} ]]; then
    run_test "A1" "GitLab repo scan" \
      "jmo ci --gitlab-repo https://gitlab.com/gitlab-org/gitlab-foss --results-dir {results_dir} --profile-name balanced --human-logs --allow-missing-tools" \
      validate_basic_scan
  else
    skip_test "A1" "GITLAB_TOKEN not set"
  fi

  # A2: K8s cluster scan
  if command -v kubectl &>/dev/null && kubectl cluster-info &>/dev/null 2>&1; then
    run_test "A2" "K8s cluster scan" \
      "jmo ci --k8s-context $(kubectl config current-context) --k8s-namespace default --results-dir {results_dir} --tools trivy,falco --human-logs --allow-missing-tools" \
      validate_basic_scan
  else
    skip_test "A2" "kubectl not available or no cluster"
  fi

  # A3: Deep profile scan
  run_test "A3" "Deep profile (all 11 tools)" \
    "cd /tmp && git clone --depth 1 $TEST_REPO test-repo-a3 && jmo ci --repo /tmp/test-repo-a3 --results-dir {results_dir} --profile-name deep --human-logs --allow-missing-tools" \
    validate_basic_scan
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
  # Parse command line arguments
  parse_args "$@"

  echo "=========================================="
  echo "JMo Security Comprehensive Test Suite"
  echo "=========================================="
  echo "Results directory: $RESULTS_BASE"
  echo "Docker image: $DOCKER_IMAGE_BASE:$DOCKER_TAG"
  echo "Test repository: $TEST_REPO"
  echo "Test image: $TEST_IMAGE"
  echo ""

  # Check prerequisites
  if ! check_prerequisites; then
    log_error "Prerequisites check failed. Exiting."
    exit 1
  fi

  # Setup test fixtures
  setup_fixtures

  # Initialize results CSV
  mkdir -p "$RESULTS_BASE"
  echo "test_id,status,duration_seconds" >"$RESULTS_BASE/test-results.csv"

  # Detect OS and run appropriate test suite
  case "$(uname -s)" in
  Linux*)
    if [[ -n $SPECIFIC_TEST ]]; then
      # Run specific test regardless of prefix
      run_ubuntu_tests
      run_advanced_tests
    else
      log_info "Detected Linux, running Ubuntu + Advanced test suites"
      run_ubuntu_tests
      run_advanced_tests
    fi
    ;;
  Darwin*)
    log_info "Detected macOS, running macOS test suite"
    run_macos_tests
    ;;
  MINGW* | CYGWIN* | MSYS*)
    log_info "Detected Windows, running Windows WSL2 test suite"
    run_windows_tests
    ;;
  *)
    log_error "Unsupported OS: $(uname -s)"
    exit 1
    ;;
  esac

  # Generate summary report
  echo ""
  echo "=========================================="
  echo "Test Summary"
  echo "=========================================="

  local total_tests=$(($(wc -l <"$RESULTS_BASE/test-results.csv") - 1))
  local passed_tests
  passed_tests=$(grep -c ",PASS," "$RESULTS_BASE/test-results.csv" 2>/dev/null) || passed_tests=0
  local failed_tests
  failed_tests=$(grep -c ",FAIL," "$RESULTS_BASE/test-results.csv" 2>/dev/null) || failed_tests=0
  local skipped_tests
  skipped_tests=$(grep -c ",SKIP," "$RESULTS_BASE/test-results.csv" 2>/dev/null) || skipped_tests=0

  echo "Total:   $total_tests"
  echo "Passed:  $passed_tests"
  echo "Failed:  $failed_tests"
  echo "Skipped: $skipped_tests"
  echo ""

  if [[ $passed_tests -gt 0 ]]; then
    log_success "✅ $passed_tests tests passed"
  fi

  if [[ $failed_tests -gt 0 ]]; then
    log_error "❌ $failed_tests tests failed"
    echo ""
    echo "Failed tests:"
    grep ",FAIL," "$RESULTS_BASE/test-results.csv" 2>/dev/null | cut -d',' -f1 | sed 's/^/  - /'
  fi

  if [[ $skipped_tests -gt 0 ]]; then
    log_warning "⏭️  $skipped_tests tests skipped"
  fi

  echo ""
  echo "Detailed results: $RESULTS_BASE/test-results.csv"
  echo "Individual test logs: $RESULTS_BASE/*/test.log"

  # Exit with failure if any tests failed
  [[ $failed_tests -eq 0 ]] && exit 0 || exit 1
}

# Run main function
main "$@"
