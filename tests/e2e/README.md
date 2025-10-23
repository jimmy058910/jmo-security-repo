# E2E Comprehensive Test Suite

End-to-end test suite for validating JMo Security v0.6.0 across all target types, operating systems, and execution methods.

## Quick Start

```bash
# Run full test suite for your OS
bash tests/e2e/run_comprehensive_tests.sh

# Run specific test
bash tests/e2e/run_comprehensive_tests.sh --test U1

# Generate report
python tests/e2e/generate_report.py /tmp/jmo-comprehensive-tests-*/test-results.csv
```

## Test Matrix

**25 comprehensive tests** covering:

- **6 target types:** repos, images, IaC, URLs, GitLab, K8s
- **3 operating systems:** Ubuntu, macOS, Windows WSL2
- **3 execution methods:** Native CLI, Wizard, Docker

## Directory Structure

```text
tests/e2e/
├── README.md                          # This file
├── run_comprehensive_tests.sh         # Main test script
├── generate_report.py                 # Report generator
└── fixtures/
    ├── setup_fixtures.sh              # Fixture creation script
    ├── iac/                           # IaC test files
    │   ├── aws-s3-public.tf           # Terraform with CIS violations
    │   ├── k8s-privileged-pod.yaml    # K8s security issues
    │   ├── Dockerfile.bad             # Hadolint violations
    │   └── docker-compose.insecure.yml
    ├── python/
    │   └── vulnerable_app.py          # Flask app with OWASP Top 10
    ├── javascript/
    │   ├── package.json               # Vulnerable dependencies
    │   └── vulnerable_app.js          # Node.js vulnerabilities
    └── configs/
        ├── .env.example               # Hardcoded secrets
        └── secrets.yaml               # API keys
```

## Test Suites

### Ubuntu Tests (U1-U12)

**Comprehensive testing on primary platform:**

- U1: Single repo - Native CLI
- U2: Single image - Native CLI
- U3: IaC file - Native CLI
- U4: URL DAST - Native CLI
- U5: Multi-target - Native CLI
- U6: Batch images - Native CLI
- U7: Single repo - Wizard --yes
- U8: Multi-target - Wizard interactive (manual only)
- U9: Single repo - Docker full
- U10: Single image - Docker full
- U11: Multi-target - Docker slim
- U12: CI mode with --fail-on HIGH

### macOS Tests (M1-M6)

**Focused testing on developer workstations:**

- M1: Single repo - Native CLI
- M2: Single image - Native CLI
- M3: IaC file - Native CLI
- M4: Single repo - Wizard --yes
- M5: Single repo - Docker full
- M6: Multi-target - Docker slim

### Windows WSL2 Tests (W1-W4)

**Minimal testing for Windows users:**

- W1: Single repo - Native CLI
- W2: Single repo - Wizard --yes
- W3: Single repo - Docker full
- W4: Multi-target - Docker slim

### Advanced Tests (A1-A3)

**Optional advanced scenarios:**

- A1: GitLab repo scan (requires GITLAB_TOKEN)
- A2: K8s cluster scan (requires kubectl + cluster)
- A3: Deep profile (all 11 tools, 30-60 min)

## Usage Examples

### Run Specific Test

```bash
# Ubuntu repo scan
bash tests/e2e/run_comprehensive_tests.sh --test U1

# macOS image scan
bash tests/e2e/run_comprehensive_tests.sh --test M2

# Advanced deep scan
bash tests/e2e/run_comprehensive_tests.sh --test A3
```

### Custom Test Targets

```bash
# Use custom repository
TEST_REPO=https://github.com/myorg/myrepo.git bash tests/e2e/run_comprehensive_tests.sh --test U1

# Use custom image
TEST_IMAGE=nginx:1.25 bash tests/e2e/run_comprehensive_tests.sh --test U2

# Use custom Docker image
DOCKER_TAG=0.6.0-full bash tests/e2e/run_comprehensive_tests.sh --test U9
```

### Generate Report

```bash
# Run tests
bash tests/e2e/run_comprehensive_tests.sh

# Generate markdown report
python tests/e2e/generate_report.py /tmp/jmo-comprehensive-tests-*/test-results.csv

# View report
cat test-report.md
```

## Test Fixtures

### Setup

```bash
# Create all fixtures
bash tests/e2e/fixtures/setup_fixtures.sh
```

### Fixture Categories

**IaC (Infrastructure as Code):**

- `aws-s3-public.tf` - S3 buckets with CIS violations
- `k8s-privileged-pod.yaml` - Privileged K8s pods
- `Dockerfile.bad` - Hadolint violations
- `docker-compose.insecure.yml` - Docker Compose issues

**Python:**

- `vulnerable_app.py` - Flask app with OWASP Top 10 vulnerabilities
  - SQL injection, command injection, XSS, SSRF, etc.
  - Hardcoded secrets, weak crypto, insecure configs

**JavaScript:**

- `package.json` - Outdated vulnerable dependencies
- `vulnerable_app.js` - Express app with security issues

**Configs:**

- `.env.example` - Hardcoded API keys, passwords
- `secrets.yaml` - AWS keys, database credentials

## Validation

Each test validates:

1. **Exit code:** 0 (no findings) or 1 (findings found), not 2+ (error)
2. **Output files:** findings.json, SUMMARY.md, dashboard.html present
3. **JSON schema:** CommonFinding v1.2.0 compliance
4. **Findings count:** ≥1 finding for vulnerable targets
5. **Performance:** Within profile time limits

### Multi-Target Specific

- ≥2 target directories present
- Unified findings.json with all target types
- No duplicate findings (fingerprint ID unique)
- Compliance enrichment (OWASP, CWE, CIS, etc.)

### Docker Specific

- Results written to host filesystem
- Volume mounts functional
- Container networking works (DAST, image scanning)

## CI/CD Integration

### GitHub Actions

See [.github/workflows/e2e-comprehensive-tests.yml](../../.github/workflows/e2e-comprehensive-tests.yml)

**Triggers:**

- Pull requests (fast profile only)
- Nightly schedule (full suite)
- Manual workflow dispatch

**Jobs:**

- `ubuntu-e2e` - Full Ubuntu + Advanced tests
- `macos-e2e` - macOS tests (nightly only)
- `summary` - Aggregate results

### Workflow Dispatch Inputs

```yaml
test_id: U1           # Run specific test
docker_tag: 0.6.0     # Test specific Docker image version
```

## Success Criteria

For release readiness:

- **≥95% success rate** (24/25 tests passing)
- **All Tier 1 tests pass** (U1, U2, U5, U9, U12)
- **Zero CRITICAL issues** in test suite
- **Performance within bounds:**
  - Fast: ≤10 minutes
  - Balanced: ≤20 minutes
  - Deep: ≤60 minutes

## Troubleshooting

### Test Failures

```bash
# View test log
cat /tmp/jmo-e2e-results-*/U1/test.log

# Check findings
jq . /tmp/jmo-e2e-results-*/U1/summaries/findings.json

# Re-run with verbose output
bash tests/e2e/run_comprehensive_tests.sh --test U1
```

### Tool Issues

```bash
# Verify tool installations
make verify-env
make tools

# Check specific tool
which trufflehog
trufflehog --version
```

### Docker Issues

```bash
# Verify Docker running
docker ps

# Pull required images
docker pull alpine:3.19
docker pull ghcr.io/jimmy058910/jmo-security:latest

# Test volume mounts
docker run --rm -v $(pwd):/test alpine:3.19 ls /test

# Check Docker-in-Docker
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock alpine:3.19 ls -la /var/run/docker.sock
```

### Fixture Issues

```bash
# Re-create fixtures
bash tests/e2e/fixtures/setup_fixtures.sh

# Verify fixtures
ls -la tests/e2e/fixtures/iac/
cat tests/e2e/fixtures/iac/aws-s3-public.tf
```

## Report Format

### CSV Output

```csv
test_id,status,duration_seconds
U1,PASS,523
U2,PASS,135
U3,FAIL,42
U4,SKIP,0
```

### Markdown Report

Generated by `generate_report.py`:

- Summary table (total, passed, failed, skipped)
- Results by test suite (Ubuntu, macOS, Windows, Advanced)
- Failed test details with troubleshooting hints
- Performance analysis (slowest tests, averages)
- Release readiness recommendation

### Console Output

Color-coded summary with:

- Overall statistics
- Results by suite
- Release readiness indicator (✅/⚠️/❌)

## Advanced Usage

### Custom Results Directory

```bash
RESULTS_BASE=/custom/path bash tests/e2e/run_comprehensive_tests.sh
```

### Skip Prerequisites Check

```bash
# For CI environments where tools are pre-validated
sed -i 's/check_prerequisites/true #/' tests/e2e/run_comprehensive_tests.sh
```

### Parallel Execution

```bash
# Run Ubuntu and Advanced tests in parallel (requires tmux/screen)
bash tests/e2e/run_comprehensive_tests.sh --test U1 &
bash tests/e2e/run_comprehensive_tests.sh --test U2 &
wait
```

## Contributing

When adding new tests:

1. Add test function to appropriate suite (Ubuntu/macOS/Windows/Advanced)
2. Use `run_test` helper with validation function
3. Add test ID to documentation (TEST.md, COMPREHENSIVE_TEST_PLAN.md)
4. Update CI workflow if needed
5. Test locally before committing

### Test Function Template

```bash
run_test "TEST_ID" "Test Description" \
  "command to execute with {results_dir} placeholder" \
  validation_function_name
```

## References

- [Comprehensive Test Plan](../../docs/COMPREHENSIVE_TEST_PLAN.md) - Full test design
- [Testing Guide](../../TEST.md) - General testing instructions
- [User Guide](../../docs/USER_GUIDE.md) - Multi-target scanning documentation
- [CI Workflow](../../.github/workflows/e2e-comprehensive-tests.yml) - GitHub Actions config

---

**Version:** 1.0 (v0.6.0)
**Maintainer:** JMo Security Team
**Last Updated:** 2025-10-16
