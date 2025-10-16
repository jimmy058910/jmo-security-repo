# Comprehensive End-to-End Test Plan (v0.6.0)

**Version:** 1.0
**Status:** Draft
**Purpose:** Validate v0.6.0 multi-target scanning across all supported targets, operating systems, and execution methods before release.

## Test Matrix Overview

### Three Dimensions of Testing

1. **Target Types (6):** repos, images, IaC, URLs, GitLab, K8s
2. **Operating Systems (3):** Linux (Ubuntu), macOS, Windows (WSL2)
3. **Execution Methods (3):** Native CLI, Wizard, Docker

**Total Test Combinations:** 6 targets × 3 OS × 3 methods = **54 test scenarios**

**Optimization Strategy:** Strategic sampling to cover critical paths with ~20-25 focused tests instead of exhaustive 54 tests.

---

## 1. Test Matrix Design

### 1.1 Target Type Priority Tiers

**Tier 1 (Critical - Must test on all OS):**
- **Repository scanning** — Core functionality, backward compatibility critical
- **Container image scanning** — High adoption, Docker/Podman variations
- **Multi-target combined** — Real-world use case (repo + image + IaC)

**Tier 2 (Important - Test on Linux + one other OS):**
- **IaC file scanning** — Terraform/K8s manifests common in CI/CD
- **URL scanning (DAST)** — Requires ZAP, network dependencies

**Tier 3 (Optional - Test on Linux only):**
- **GitLab scanning** — Requires GitLab token, less common
- **K8s scanning** — Requires cluster access, advanced use case

### 1.2 OS Coverage Strategy

| OS | Native CLI | Wizard | Docker | Priority |
|----|-----------|--------|--------|----------|
| **Ubuntu 22.04 LTS** | ✅ All targets | ✅ All targets | ✅ All targets | PRIMARY |
| **macOS 14 (Sonoma)** | ✅ Tier 1+2 | ✅ Tier 1 | ✅ Tier 1+2 | SECONDARY |
| **Windows 11 (WSL2)** | ✅ Tier 1 | ✅ Tier 1 | ✅ Tier 1+2 | TERTIARY |

**Rationale:**
- Ubuntu: Primary CI/CD environment, most users
- macOS: Developer workstations, Docker Desktop variations
- Windows WSL2: Growing adoption, path handling edge cases

### 1.3 Execution Method Coverage

**Native CLI (Direct Binary):**
- Profile: `balanced` (7 tools)
- Validates: Tool installation, PATH resolution, file permissions
- Priority: Tier 1 targets on all OS

**Wizard (Interactive/Non-interactive):**
- Modes: `--yes` (CI mode) and interactive
- Validates: User onboarding, smart defaults, artifact generation
- Priority: Tier 1 targets on all OS (non-interactive), interactive on Ubuntu only

**Docker (Zero-installation):**
- Variants: `full`, `slim`, `alpine`
- Validates: Volume mounts, container networking, image distribution
- Priority: All targets on Ubuntu (full variant), Tier 1 on macOS/Windows

---

## 2. Detailed Test Scenarios

### 2.1 Ubuntu 22.04 (Comprehensive - 12 tests)

| # | Target | Method | Profile | Tools | Expected Output | Validation |
|---|--------|--------|---------|-------|-----------------|------------|
| **U1** | Single repo | Native CLI | balanced | 7 tools | `findings.json`, `dashboard.html`, `findings.sarif` | ≥1 finding, all outputs present |
| **U2** | Single image | Native CLI | balanced | trivy, syft | `findings.json` with container vulns | ≥1 CVE finding |
| **U3** | IaC file | Native CLI | balanced | checkov, trivy | `findings.json` with IaC misconfigs | ≥1 CIS/AWS misconfig |
| **U4** | URL (DAST) | Native CLI | balanced | zap | `findings.json` with web vulns | ≥1 OWASP Top 10 finding |
| **U5** | Multi-target | Native CLI | balanced | All 7 | Unified `findings.json` with 3+ target dirs | All 3 target types present |
| **U6** | Batch images | Native CLI | fast | trivy, syft | 3 image dirs, unified report | All images scanned |
| **U7** | Single repo | Wizard --yes | balanced | Auto | Same as U1 | Wizard emits valid config |
| **U8** | Multi-target | Wizard interactive | balanced | User selected | Same as U5 | Interactive prompts work |
| **U9** | Single repo | Docker (full) | balanced | All 7 | Same as U1 | Volume mounts work |
| **U10** | Single image | Docker (full) | balanced | trivy, syft | Same as U2 | Docker-in-Docker works |
| **U11** | Multi-target | Docker (slim) | fast | 3 tools | Same as U5 (fewer tools) | Slim variant functional |
| **U12** | CI mode | Native CLI | fast | 3 tools + `--fail-on HIGH` | Exit code 1 if HIGH+ found | Threshold gating works |

### 2.2 macOS 14 Sonoma (Focused - 6 tests)

| # | Target | Method | Profile | Tools | Expected Output | Validation |
|---|--------|--------|---------|-------|-----------------|------------|
| **M1** | Single repo | Native CLI | balanced | 7 tools | Same as U1 | Homebrew-installed tools work |
| **M2** | Single image | Native CLI | balanced | trivy, syft | Same as U2 | Docker Desktop integration |
| **M3** | IaC file | Native CLI | balanced | checkov, trivy | Same as U3 | File path handling |
| **M4** | Single repo | Wizard --yes | balanced | Auto | Same as U1 | macOS paths work |
| **M5** | Single repo | Docker (full) | balanced | All 7 | Same as U1 | Docker Desktop mounts |
| **M6** | Multi-target | Docker (slim) | fast | 3 tools | Same as U11 | Multi-target in Docker |

### 2.3 Windows 11 WSL2 (Minimal - 4 tests)

| # | Target | Method | Profile | Tools | Expected Output | Validation |
|---|--------|--------|---------|-------|-----------------|------------|
| **W1** | Single repo | Native CLI | balanced | 7 tools | Same as U1 | WSL2 paths (`/mnt/c/`) work |
| **W2** | Single repo | Wizard --yes | balanced | Auto | Same as U1 | Windows-Linux path translation |
| **W3** | Single repo | Docker (full) | balanced | All 7 | Same as U1 | Docker Desktop on Windows |
| **W4** | Multi-target | Docker (slim) | fast | 3 tools | Same as U11 | Volume mounts from WSL2 |

### 2.4 Advanced Scenarios (Optional - 3 tests)

| # | Target | Method | Profile | Tools | Expected Output | Validation |
|---|--------|--------|---------|-------|-----------------|------------|
| **A1** | GitLab repo | Native CLI (Ubuntu) | balanced | All 7 | Same structure as git repo scan | GitLab API auth works |
| **A2** | K8s cluster | Native CLI (Ubuntu) | balanced | trivy, falco | K8s resources + runtime findings | Kubectl integration works |
| **A3** | Deep profile | Native CLI (Ubuntu) | deep | All 11 | All tools executed, 30-60 min | Noseyparker, bandit, afl++ work |

**Total Tests:** 12 (Ubuntu) + 6 (macOS) + 4 (Windows) + 3 (Advanced) = **25 comprehensive tests**

---

## 3. Test Execution Framework

### 3.1 Automated Test Script Structure

```bash
#!/usr/bin/env bash
# tests/e2e/run_comprehensive_tests.sh

set -euo pipefail

# Configuration
RESULTS_BASE="/tmp/jmo-comprehensive-tests-$(date +%s)"
TEST_REPO="https://github.com/juice-shop/juice-shop.git"  # Known vulnerable repo
TEST_IMAGE="alpine:3.19"  # Small, fast to scan
TEST_TF_FILE="test-fixtures/aws-s3-public.tf"  # Known misconfig
TEST_URL="http://testphp.vulnweb.com"  # OWASP test site

# Test runner function
run_test() {
  local test_id="$1"
  local test_name="$2"
  local test_cmd="$3"
  local validation_fn="$4"

  echo "======================================"
  echo "Running Test $test_id: $test_name"
  echo "======================================"

  # Create isolated results directory
  local results_dir="$RESULTS_BASE/$test_id"
  mkdir -p "$results_dir"

  # Execute test command with timeout
  local start_time=$(date +%s)
  if timeout 900 bash -c "$test_cmd"; then
    local exit_code=$?
  else
    local exit_code=$?
  fi
  local end_time=$(date +%s)
  local duration=$((end_time - start_time))

  # Validate results
  if $validation_fn "$results_dir" "$exit_code"; then
    echo "✅ PASS: $test_id ($duration seconds)"
    echo "$test_id,PASS,$duration" >> "$RESULTS_BASE/test-results.csv"
  else
    echo "❌ FAIL: $test_id ($duration seconds)"
    echo "$test_id,FAIL,$duration" >> "$RESULTS_BASE/test-results.csv"
  fi
  echo ""
}

# Validation functions
validate_basic_scan() {
  local results_dir="$1"
  local exit_code="$2"

  # Exit code should be 0 (no findings) or 1 (findings found)
  [[ $exit_code -eq 0 || $exit_code -eq 1 ]] || return 1

  # Check required output files exist
  [[ -f "$results_dir/summaries/findings.json" ]] || return 1
  [[ -f "$results_dir/summaries/SUMMARY.md" ]] || return 1
  [[ -f "$results_dir/summaries/dashboard.html" ]] || return 1

  # Validate JSON structure
  jq -e '.[] | select(.id and .ruleId and .severity and .tool)' \
    "$results_dir/summaries/findings.json" > /dev/null || return 1

  # Check for at least 1 finding (known vulnerable targets)
  local finding_count=$(jq 'length' "$results_dir/summaries/findings.json")
  [[ $finding_count -gt 0 ]] || return 1

  return 0
}

validate_multi_target() {
  local results_dir="$1"
  local exit_code="$2"

  # Basic validation
  validate_basic_scan "$results_dir" "$exit_code" || return 1

  # Check multiple target directories exist
  local target_dirs=0
  [[ -d "$results_dir/individual-repos" ]] && target_dirs=$((target_dirs + 1))
  [[ -d "$results_dir/individual-images" ]] && target_dirs=$((target_dirs + 1))
  [[ -d "$results_dir/individual-iac" ]] && target_dirs=$((target_dirs + 1))
  [[ -d "$results_dir/individual-web" ]] && target_dirs=$((target_dirs + 1))

  # At least 2 target types should be present
  [[ $target_dirs -ge 2 ]] || return 1

  return 0
}

validate_ci_gating() {
  local results_dir="$1"
  local exit_code="$2"

  # CI mode with --fail-on HIGH should exit 1 if HIGH+ findings exist
  # For known vulnerable target, expect exit code 1
  [[ $exit_code -eq 1 ]] || return 1

  # Check findings.json has HIGH or CRITICAL severity
  jq -e '.[] | select(.severity == "HIGH" or .severity == "CRITICAL")' \
    "$results_dir/summaries/findings.json" > /dev/null || return 1

  return 0
}

validate_docker_scan() {
  local results_dir="$1"
  local exit_code="$2"

  # Basic validation
  validate_basic_scan "$results_dir" "$exit_code" || return 1

  # Check volume mounts worked (results written to host)
  [[ -f "$results_dir/summaries/findings.json" ]] || return 1

  # Validate findings have correct paths (not container paths)
  local has_container_paths=$(jq -e '.[] | select(.location.path | startswith("/tmp/"))' \
    "$results_dir/summaries/findings.json" | wc -l)
  [[ $has_container_paths -eq 0 ]] || return 1

  return 0
}

# Ubuntu Tests
run_ubuntu_tests() {
  echo "=========================================="
  echo "Ubuntu 22.04 Test Suite (12 tests)"
  echo "=========================================="

  # U1: Single repo scan (native CLI)
  run_test "U1" "Single repo - Native CLI" \
    "jmo scan --repo $TEST_REPO --results-dir $RESULTS_BASE/U1 --profile-name balanced --human-logs" \
    validate_basic_scan

  # U2: Single image scan (native CLI)
  run_test "U2" "Single image - Native CLI" \
    "jmo scan --image $TEST_IMAGE --results-dir $RESULTS_BASE/U2 --tools trivy,syft --human-logs" \
    validate_basic_scan

  # U3: IaC file scan (native CLI)
  run_test "U3" "IaC file - Native CLI" \
    "jmo scan --terraform-state $TEST_TF_FILE --results-dir $RESULTS_BASE/U3 --tools checkov,trivy --human-logs" \
    validate_basic_scan

  # U4: URL scan (native CLI)
  run_test "U4" "URL DAST - Native CLI" \
    "jmo scan --url $TEST_URL --results-dir $RESULTS_BASE/U4 --tools zap --human-logs" \
    validate_basic_scan

  # U5: Multi-target scan (native CLI)
  run_test "U5" "Multi-target - Native CLI" \
    "jmo scan --repo $TEST_REPO --image $TEST_IMAGE --terraform-state $TEST_TF_FILE --results-dir $RESULTS_BASE/U5 --profile-name balanced --human-logs" \
    validate_multi_target

  # U6: Batch images scan (native CLI)
  echo "$TEST_IMAGE" > /tmp/images.txt
  echo "nginx:alpine" >> /tmp/images.txt
  echo "redis:alpine" >> /tmp/images.txt
  run_test "U6" "Batch images - Native CLI" \
    "jmo scan --images-file /tmp/images.txt --results-dir $RESULTS_BASE/U6 --tools trivy,syft --human-logs" \
    validate_basic_scan

  # U7: Single repo scan (wizard --yes)
  run_test "U7" "Single repo - Wizard --yes" \
    "jmotools wizard --yes --repos-dir $(dirname $TEST_REPO) --profile balanced --emit-script /tmp/wizard-u7.sh && bash /tmp/wizard-u7.sh" \
    validate_basic_scan

  # U8: Multi-target scan (wizard interactive) - SKIP in CI, run manually
  echo "⏭️  SKIP: U8 (interactive wizard - manual testing only)"

  # U9: Single repo scan (Docker full)
  run_test "U9" "Single repo - Docker full" \
    "docker run --rm -v $(pwd):/scan -v $RESULTS_BASE/U9:/results ghcr.io/jimmy058910/jmo-security:0.6.0-full scan --repo /scan/$TEST_REPO --results-dir /results --profile-name balanced" \
    validate_docker_scan

  # U10: Single image scan (Docker full)
  run_test "U10" "Single image - Docker full" \
    "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v $RESULTS_BASE/U10:/results ghcr.io/jimmy058910/jmo-security:0.6.0-full scan --image $TEST_IMAGE --results-dir /results --tools trivy,syft" \
    validate_docker_scan

  # U11: Multi-target scan (Docker slim)
  run_test "U11" "Multi-target - Docker slim" \
    "docker run --rm -v $(pwd):/scan -v $RESULTS_BASE/U11:/results ghcr.io/jimmy058910/jmo-security:0.6.0-slim scan --repo /scan/$TEST_REPO --image $TEST_IMAGE --results-dir /results --profile-name fast" \
    validate_multi_target

  # U12: CI mode with gating (native CLI)
  run_test "U12" "CI mode with --fail-on HIGH" \
    "jmo ci --repo $TEST_REPO --results-dir $RESULTS_BASE/U12 --fail-on HIGH --profile-name fast --human-logs" \
    validate_ci_gating
}

# macOS Tests
run_macos_tests() {
  echo "=========================================="
  echo "macOS 14 Test Suite (6 tests)"
  echo "=========================================="

  # Similar structure to Ubuntu tests, but fewer scenarios
  # M1-M6 implementation follows same pattern as U1-U6
  echo "⚠️  macOS tests require manual execution on macOS machine"
}

# Windows WSL2 Tests
run_windows_tests() {
  echo "=========================================="
  echo "Windows 11 WSL2 Test Suite (4 tests)"
  echo "=========================================="

  # Similar structure, focus on path handling
  echo "⚠️  Windows tests require manual execution on WSL2"
}

# Advanced Tests
run_advanced_tests() {
  echo "=========================================="
  echo "Advanced Scenarios (3 tests)"
  echo "=========================================="

  # A1: GitLab repo scan
  if [[ -n "${GITLAB_TOKEN:-}" ]]; then
    run_test "A1" "GitLab repo scan" \
      "jmo scan --gitlab-repo https://gitlab.com/test/repo --results-dir $RESULTS_BASE/A1 --profile-name balanced --human-logs" \
      validate_basic_scan
  else
    echo "⏭️  SKIP: A1 (GitLab token not set)"
  fi

  # A2: K8s cluster scan
  if command -v kubectl &> /dev/null && kubectl cluster-info &> /dev/null; then
    run_test "A2" "K8s cluster scan" \
      "jmo scan --k8s-context $(kubectl config current-context) --k8s-namespace default --results-dir $RESULTS_BASE/A2 --tools trivy,falco --human-logs" \
      validate_basic_scan
  else
    echo "⏭️  SKIP: A2 (kubectl not available or no cluster)"
  fi

  # A3: Deep profile scan
  run_test "A3" "Deep profile (all 11 tools)" \
    "jmo scan --repo $TEST_REPO --results-dir $RESULTS_BASE/A3 --profile-name deep --human-logs" \
    validate_basic_scan
}

# Main execution
main() {
  echo "JMo Security Comprehensive Test Suite v0.6.0"
  echo "=============================================="
  echo "Results directory: $RESULTS_BASE"
  echo ""

  # Initialize results CSV
  echo "test_id,status,duration_seconds" > "$RESULTS_BASE/test-results.csv"

  # Detect OS and run appropriate test suite
  case "$(uname -s)" in
    Linux*)
      run_ubuntu_tests
      run_advanced_tests
      ;;
    Darwin*)
      run_macos_tests
      ;;
    MINGW*|CYGWIN*|MSYS*)
      run_windows_tests
      ;;
    *)
      echo "❌ Unsupported OS: $(uname -s)"
      exit 1
      ;;
  esac

  # Generate summary report
  echo ""
  echo "=========================================="
  echo "Test Summary"
  echo "=========================================="
  local total_tests=$(wc -l < "$RESULTS_BASE/test-results.csv" | xargs)
  total_tests=$((total_tests - 1))  # Subtract header
  local passed_tests=$(grep -c ",PASS," "$RESULTS_BASE/test-results.csv" || echo 0)
  local failed_tests=$(grep -c ",FAIL," "$RESULTS_BASE/test-results.csv" || echo 0)

  echo "Total: $total_tests | Passed: $passed_tests | Failed: $failed_tests"
  echo ""
  echo "Detailed results: $RESULTS_BASE/test-results.csv"

  # Exit with failure if any tests failed
  [[ $failed_tests -eq 0 ]] && exit 0 || exit 1
}

main "$@"
```

### 3.2 Test Fixtures

Create realistic test fixtures for consistent testing:

```bash
# tests/e2e/fixtures/setup_fixtures.sh

# Clone known vulnerable repository (small, fast)
git clone --depth 1 https://github.com/juice-shop/juice-shop.git /tmp/test-repo

# Create IaC test file with known misconfiguration
cat > /tmp/test-fixtures/aws-s3-public.tf <<'EOF'
resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket"

  # CIS 2.1.5: S3 bucket should not be public
  acl    = "public-read"
}

resource "aws_security_group" "allow_all" {
  name        = "allow_all"
  description = "Allow all traffic"

  # CIS 4.1: Security group should not allow 0.0.0.0/0 ingress
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
EOF

# Create Kubernetes manifest with known issues
cat > /tmp/test-fixtures/k8s-privileged-pod.yaml <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: app
    image: nginx:latest
    securityContext:
      privileged: true  # CIS 5.2.1: Should not run privileged
      runAsUser: 0       # CIS 5.2.6: Should not run as root
EOF

# Create Dockerfile with known issues
cat > /tmp/test-fixtures/Dockerfile.bad <<'EOF'
FROM ubuntu:latest

# DL3008: Pin versions in apt-get install
RUN apt-get update && apt-get install -y curl

# DL3025: Use JSON for ENTRYPOINT
ENTRYPOINT curl http://example.com

# DL3020: Use COPY instead of ADD
ADD http://example.com/file.tar.gz /tmp/
EOF
```

---

## 4. Success Criteria & Validation

### 4.1 Per-Test Success Criteria

**All tests must meet these criteria:**

1. **Exit Code Validation:**
   - Scan commands: Exit 0 (no findings) or 1 (findings found)
   - CI commands with `--fail-on`: Exit 1 if threshold exceeded, 0 otherwise
   - Errors/crashes: Exit 2+ (test FAILS)

2. **Output File Presence:**
   - `results/summaries/findings.json` (required)
   - `results/summaries/SUMMARY.md` (required)
   - `results/summaries/dashboard.html` (required)
   - `results/summaries/findings.sarif` (optional, if SARIF output enabled)
   - `results/summaries/timings.json` (optional, if `--profile` flag used)

3. **JSON Schema Validation:**
   - All findings conform to CommonFinding v1.2.0 schema
   - Required fields present: `id`, `ruleId`, `severity`, `tool`, `location`, `message`
   - Compliance fields present for compliance-enriched findings

4. **Finding Count:**
   - Known vulnerable targets (Juice Shop, test fixtures): ≥1 finding expected
   - Empty/clean targets: 0 findings expected

5. **Performance:**
   - Fast profile: ≤10 minutes per repo
   - Balanced profile: ≤20 minutes per repo
   - Deep profile: ≤60 minutes per repo

### 4.2 Multi-Target Specific Criteria

**Additional checks for multi-target tests (U5, U11, M6, W4):**

1. **Directory Structure:**
   - At least 2 of these directories must exist:
     - `results/individual-repos/`
     - `results/individual-images/`
     - `results/individual-iac/`
     - `results/individual-web/`
     - `results/individual-gitlab/`
     - `results/individual-k8s/`

2. **Unified Aggregation:**
   - `summaries/findings.json` contains findings from all target types
   - No duplicate findings (fingerprint IDs unique)
   - Findings have `location.path` correctly scoped to target type

3. **Compliance Enrichment:**
   - Findings have `compliance` field with ≥1 framework mapping
   - Dashboard filters populated with OWASP, CWE, CIS, NIST, PCI, ATT&CK values

### 4.3 Docker-Specific Criteria

**Additional checks for Docker tests (U9-U11, M5-M6, W3-W4):**

1. **Volume Mounts:**
   - Results written to host filesystem (not inside container)
   - File paths in findings.json are host paths (not `/tmp/scan/`)

2. **Container Networking:**
   - URL scanning works (ZAP can reach external URLs)
   - Image scanning works (Docker-in-Docker socket mounted)

3. **Image Variants:**
   - Full variant: All 11 tools available
   - Slim variant: 3 core tools (trufflehog, semgrep, trivy)
   - Alpine variant: Minimal size, 3 core tools

### 4.4 Wizard-Specific Criteria

**Additional checks for wizard tests (U7, U8, M4, W2):**

1. **Non-Interactive Mode (`--yes`):**
   - Smart defaults applied (profile, tools, results-dir)
   - No user prompts (fully automated)
   - Valid configuration emitted

2. **Artifact Generation:**
   - `--emit-script`: Generated shell script is executable and valid
   - `--emit-make-target`: Generated Makefile target is syntactically correct
   - `--emit-gha`: Generated GitHub Actions workflow is valid YAML

3. **Configuration Persistence:**
   - Wizard respects existing `jmo.yml` if present
   - Wizard creates valid `jmo.yml` if missing

---

## 5. Test Execution Plan

### 5.1 Pre-Release Testing Workflow

**Phase 1: Local Development Testing (Week 1)**

- [ ] Developer runs full Ubuntu test suite (12 tests)
- [ ] Developer runs macOS test suite (6 tests) on local machine
- [ ] Developer runs Windows WSL2 test suite (4 tests) on VM/separate machine
- [ ] All tests pass with 100% success rate
- [ ] Performance benchmarks recorded in `test-results.csv`

**Phase 2: CI/CD Integration (Week 1)**

- [ ] Add Ubuntu test suite to GitHub Actions workflow
- [ ] Run on every PR (fast profile only to save CI time)
- [ ] Full test suite runs nightly
- [ ] Test results uploaded as workflow artifacts

**Phase 3: Community Beta Testing (Week 2)**

- [ ] Release v0.6.0-beta1 with test script in `tests/e2e/`
- [ ] Call for beta testers on GitHub Discussions
- [ ] Collect test results from community (macOS, Windows, various Linux distros)
- [ ] Fix any platform-specific issues discovered

**Phase 4: Release Candidate (Week 3)**

- [ ] Release v0.6.0-rc1 after all critical issues fixed
- [ ] Final validation on all 3 primary OS
- [ ] Document known limitations (if any)
- [ ] Prepare release notes

**Phase 5: General Availability (Week 3-4)**

- [ ] Tag v0.6.0 release
- [ ] Publish to PyPI
- [ ] Push Docker images (full, slim, alpine)
- [ ] Announce on GitHub, social media, security communities

### 5.2 CI/CD Integration Example

```yaml
# .github/workflows/e2e-comprehensive-tests.yml
name: End-to-End Comprehensive Tests

on:
  pull_request:
    paths:
      - 'scripts/**'
      - 'tests/**'
      - 'pyproject.toml'
  schedule:
    - cron: '0 6 * * *'  # Nightly at 6 AM UTC
  workflow_dispatch:

jobs:
  ubuntu-tests:
    name: Ubuntu 22.04 E2E Tests
    runs-on: ubuntu-22.04
    timeout-minutes: 120

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python 3.11
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install JMo Security
        run: |
          pip install -e .
          make tools  # Install external security tools

      - name: Set up Docker
        uses: docker/setup-buildx-action@v3

      - name: Pull Docker images
        run: |
          docker pull ghcr.io/jimmy058910/jmo-security:0.6.0-full
          docker pull ghcr.io/jimmy058910/jmo-security:0.6.0-slim

      - name: Run Ubuntu test suite
        run: |
          bash tests/e2e/run_comprehensive_tests.sh

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: ubuntu-test-results
          path: /tmp/jmo-comprehensive-tests-*/

      - name: Generate test report
        if: always()
        run: |
          python tests/e2e/generate_report.py /tmp/jmo-comprehensive-tests-*/test-results.csv

      - name: Comment PR with results
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('test-report.md', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: report
            });

  macos-tests:
    name: macOS 14 E2E Tests
    runs-on: macos-14
    timeout-minutes: 90

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python 3.11
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install JMo Security
        run: |
          pip install -e .
          brew install semgrep trivy syft checkov hadolint
          # Install other tools via Homebrew

      - name: Run macOS test suite
        run: |
          bash tests/e2e/run_comprehensive_tests.sh

      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: macos-test-results
          path: /tmp/jmo-comprehensive-tests-*/
```

---

## 6. Test Results Documentation

### 6.1 Test Report Template

```markdown
# Comprehensive Test Results - v0.6.0

**Test Date:** 2025-10-XX
**Tester:** [Name/CI System]
**OS:** Ubuntu 22.04 / macOS 14 / Windows 11 WSL2
**JMo Version:** v0.6.0
**Docker Images:** full (v0.6.0), slim (v0.6.0), alpine (v0.6.0)

## Summary

| Metric | Value |
|--------|-------|
| Total Tests | 25 |
| Passed | 24 |
| Failed | 1 |
| Skipped | 0 |
| Success Rate | 96% |
| Total Duration | 4h 23m |

## Test Results by Category

### Ubuntu Tests (12 tests)

| Test ID | Test Name | Status | Duration | Findings | Notes |
|---------|-----------|--------|----------|----------|-------|
| U1 | Single repo - Native CLI | ✅ PASS | 8m 32s | 142 | All outputs present |
| U2 | Single image - Native CLI | ✅ PASS | 2m 15s | 23 | 18 CVEs, 5 configs |
| U3 | IaC file - Native CLI | ✅ PASS | 1m 05s | 12 | 8 CIS, 4 AWS |
| U4 | URL DAST - Native CLI | ✅ PASS | 6m 42s | 31 | 14 OWASP Top 10 |
| U5 | Multi-target - Native CLI | ✅ PASS | 12m 18s | 187 | 3 target dirs |
| U6 | Batch images - Native CLI | ✅ PASS | 5m 51s | 67 | 3 images scanned |
| U7 | Single repo - Wizard --yes | ✅ PASS | 9m 04s | 142 | Same as U1 |
| U8 | Multi-target - Wizard interactive | ⏭️ SKIP | - | - | Manual only |
| U9 | Single repo - Docker full | ✅ PASS | 9m 15s | 142 | Volume mounts OK |
| U10 | Single image - Docker full | ✅ PASS | 2m 48s | 23 | Docker-in-Docker OK |
| U11 | Multi-target - Docker slim | ✅ PASS | 7m 22s | 98 | Fewer tools |
| U12 | CI mode with --fail-on HIGH | ✅ PASS | 4m 13s | 18 HIGH+ | Exit code 1 ✓ |

### macOS Tests (6 tests)

| Test ID | Test Name | Status | Duration | Findings | Notes |
|---------|-----------|--------|----------|----------|-------|
| M1 | Single repo - Native CLI | ✅ PASS | 9m 01s | 142 | Homebrew tools OK |
| M2 | Single image - Native CLI | ✅ PASS | 2m 38s | 23 | Docker Desktop OK |
| M3 | IaC file - Native CLI | ✅ PASS | 1m 12s | 12 | File paths OK |
| M4 | Single repo - Wizard --yes | ✅ PASS | 9m 27s | 142 | macOS paths OK |
| M5 | Single repo - Docker full | ✅ PASS | 9m 48s | 142 | Mounts OK |
| M6 | Multi-target - Docker slim | ✅ PASS | 7m 55s | 98 | Multi-target OK |

### Windows WSL2 Tests (4 tests)

| Test ID | Test Name | Status | Duration | Findings | Notes |
|---------|-----------|--------|----------|----------|-------|
| W1 | Single repo - Native CLI | ✅ PASS | 10m 12s | 142 | /mnt/c/ paths OK |
| W2 | Single repo - Wizard --yes | ✅ PASS | 10m 35s | 142 | Path translation OK |
| W3 | Single repo - Docker full | ✅ PASS | 10m 58s | 142 | Docker Desktop OK |
| W4 | Multi-target - Docker slim | ✅ PASS | 8m 41s | 98 | WSL2 mounts OK |

### Advanced Tests (3 tests)

| Test ID | Test Name | Status | Duration | Findings | Notes |
|---------|-----------|--------|----------|----------|-------|
| A1 | GitLab repo scan | ⏭️ SKIP | - | - | Token not set |
| A2 | K8s cluster scan | ⏭️ SKIP | - | - | No cluster available |
| A3 | Deep profile (all 11 tools) | ✅ PASS | 42m 16s | 284 | Noseyparker, AFL++ OK |

## Issues Found

### Issue #1: [Brief description]

- **Severity:** High/Medium/Low
- **Test ID:** U5
- **OS:** Ubuntu 22.04
- **Description:** [Detailed description]
- **Reproduction Steps:** [Steps]
- **Workaround:** [If any]
- **Fix Status:** [In progress/Fixed/Wontfix]

## Performance Analysis

### Scan Duration by Profile

| Profile | Avg Duration | Min | Max | Median |
|---------|-------------|-----|-----|--------|
| Fast | 4m 23s | 2m 15s | 6m 42s | 4m 13s |
| Balanced | 9m 18s | 7m 22s | 12m 18s | 9m 04s |
| Deep | 42m 16s | 42m 16s | 42m 16s | 42m 16s |

### Finding Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| CRITICAL | 8 | 2.8% |
| HIGH | 47 | 16.5% |
| MEDIUM | 132 | 46.3% |
| LOW | 78 | 27.4% |
| INFO | 20 | 7.0% |

### Compliance Coverage

| Framework | Mappings | Coverage |
|-----------|----------|----------|
| OWASP Top 10 2021 | 89 | 100% (all 10 categories) |
| CWE Top 25 2024 | 124 | 96% (24/25 CWEs) |
| CIS Controls v8.1 | 67 | 38% (7/18 controls) |
| NIST CSF 2.0 | 45 | 42% (21/50 subcategories) |
| PCI DSS 4.0 | 23 | 19% (23/123 requirements) |
| MITRE ATT&CK v16.1 | 12 | 6% (12/193 techniques) |

## Recommendations

1. **Release Readiness:** [Ready/Not Ready]
2. **Known Limitations:** [List any]
3. **Documentation Updates Needed:** [List any]
4. **Follow-up Testing:** [List any additional testing needed]

## Conclusion

[Overall assessment of test results and release readiness]
```

---

## 7. Maintenance & Future Enhancements

### 7.1 Test Suite Maintenance Plan

**Quarterly Reviews:**
- Update test fixtures for new vulnerability patterns
- Add tests for newly supported tools
- Refresh vulnerable test targets (Juice Shop, test fixtures)

**Per-Release Updates:**
- Add tests for new features (target types, compliance frameworks)
- Update validation functions for schema changes
- Benchmark performance improvements

**Continuous Monitoring:**
- CI/CD test results tracked over time
- Flaky test detection and remediation
- Performance regression detection

### 7.2 Future Test Enhancements

**Short-term (v0.7.0):**
- Add snapshot testing for dashboard HTML
- Add compliance filter interaction tests (Playwright/Puppeteer)
- Add parallel execution for faster test runs

**Medium-term (v0.8.0):**
- Add performance benchmarking suite
- Add load testing (100+ repos, 1000+ images)
- Add stress testing (memory limits, disk space limits)

**Long-term (v1.0.0):**
- Add integration tests with CI/CD platforms (GitHub Actions, GitLab CI, Jenkins)
- Add security testing (penetration testing, fuzzing)
- Add accessibility testing (dashboard WCAG compliance)

---

## 8. Quick Reference

### 8.1 Test Execution Commands

```bash
# Run full Ubuntu test suite
bash tests/e2e/run_comprehensive_tests.sh

# Run specific test
bash tests/e2e/run_comprehensive_tests.sh --test U1

# Run tests with custom fixtures
TEST_REPO=/path/to/repo bash tests/e2e/run_comprehensive_tests.sh

# Generate test report from CSV
python tests/e2e/generate_report.py /tmp/jmo-comprehensive-tests-*/test-results.csv

# Validate test fixtures
bash tests/e2e/fixtures/setup_fixtures.sh --validate
```

### 8.2 Troubleshooting Test Failures

| Error | Cause | Fix |
|-------|-------|-----|
| "Tool not found" | External tool not installed | Run `make tools` |
| "Docker daemon not running" | Docker not started | Start Docker Desktop/daemon |
| "No findings in known vulnerable target" | Tool timeout or failure | Check `individual-*/tool.json` for errors |
| "JSON schema validation failed" | Adapter bug or schema mismatch | Check adapter code, update tests |
| "Volume mount failed" (Docker) | SELinux/permissions | Add `:z` suffix to volume mounts |

### 8.3 Test Result Interpretation

**Exit Codes:**
- `0` - All tests passed
- `1` - One or more tests failed (see CSV for details)
- `2` - Test framework error (setup failed)

**CSV Columns:**
- `test_id` - Unique test identifier (U1, M2, etc.)
- `status` - PASS/FAIL/SKIP
- `duration_seconds` - Execution time in seconds

**Pass Criteria:**
- ≥95% success rate (24/25 tests) for release
- All Tier 1 tests (repos, images, multi-target) must pass
- Zero CRITICAL issues found in test suite

---

## Appendix A: Test Fixtures Repository

All test fixtures should be versioned and stored in `tests/e2e/fixtures/`:

```text
tests/e2e/fixtures/
├── repos/
│   ├── juice-shop/          # Known vulnerable Node.js app
│   ├── dvwa/                 # Known vulnerable PHP app
│   └── vulnerable-flask/     # Known vulnerable Python app
├── iac/
│   ├── aws-s3-public.tf      # S3 bucket misconfigurations
│   ├── k8s-privileged-pod.yaml  # Kubernetes security issues
│   └── docker-bad-practices/    # Dockerfile issues
├── images.txt                # List of test container images
└── urls.txt                  # List of test URLs (OWASP test sites)
```

## Appendix B: Platform-Specific Considerations

### Ubuntu/Linux
- **Package Managers:** apt, snap, Homebrew (Linuxbrew)
- **Tool Installation:** Native binaries, AppImages
- **Edge Cases:** SELinux, AppArmor, non-standard shells

### macOS
- **Package Managers:** Homebrew (primary), MacPorts
- **Tool Installation:** Homebrew formulae, .pkg installers
- **Edge Cases:** System Integrity Protection (SIP), Gatekeeper, Rosetta 2 (M1/M2)

### Windows WSL2
- **Package Managers:** apt (Ubuntu on WSL), winget (Windows)
- **Tool Installation:** WSL native, Windows binaries via wsl.exe
- **Edge Cases:** Path translation (`/mnt/c/`), CRLF line endings, case-insensitive filesystems

## Appendix C: Docker Test Image Verification

Before running Docker tests, verify images are available:

```bash
# Check image existence
docker images | grep jmo-security

# Verify image variants
docker run --rm ghcr.io/jimmy058910/jmo-security:0.6.0-full --help
docker run --rm ghcr.io/jimmy058910/jmo-security:0.6.0-slim --help
docker run --rm ghcr.io/jimmy058910/jmo-security:0.6.0-alpine --help

# Check image sizes
docker images --format "table {{.Repository}}:{{.Tag}}\t{{.Size}}" | grep jmo-security

# Expected sizes:
# full:   ~2.5GB (all 11 tools)
# slim:   ~800MB (3 core tools)
# alpine: ~500MB (3 core tools, minimal base)
```

---

**Document Version:** 1.0
**Last Updated:** 2025-10-16
**Maintainer:** JMo Security Team
**Review Schedule:** Quarterly (Jan/Apr/Jul/Oct)
