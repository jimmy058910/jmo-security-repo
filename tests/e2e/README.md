# E2E Test Suite

End-to-end tests for validating JMo Security across target types, operating systems, and execution methods. All tests are pytest-based.

## Quick Start

```bash
# Run full E2E suite
make test-e2e

# Run specific test file
pytest tests/e2e/test_scan_workflows.py -v

# Run specific test by ID (e.g., U1, U9, A1)
pytest tests/e2e/ -k "U1" -v

# Run Docker-based tests
pytest tests/e2e/ -m docker -v

# Skip Docker tests (default for local dev)
pytest tests/e2e/ -m "not docker" -v
```

## Test Matrix

**23 automatable tests** covering:

- **6 target types:** repos, images, IaC, URLs, GitLab, K8s
- **3 operating systems:** Ubuntu, macOS, Windows WSL2
- **3 execution methods:** Native CLI, Wizard, Docker

## Directory Structure

```text
tests/e2e/
├── README.md                          # This file
├── conftest.py                        # Shared fixtures and hooks
├── fixtures/
│   ├── conftest.py                    # Fixture data loaders
│   ├── iac/                           # IaC test files
│   │   ├── aws-s3-public.tf           # Terraform with CIS violations
│   │   ├── k8s-privileged-pod.yaml    # K8s security issues
│   │   ├── Dockerfile.bad             # Hadolint violations
│   │   └── docker-compose.insecure.yml
│   ├── python/
│   │   └── vulnerable_app.py          # Flask app with OWASP Top 10
│   ├── javascript/
│   │   ├── package.json               # Vulnerable dependencies
│   │   └── vulnerable_app.js          # Node.js vulnerabilities
│   └── configs/
│       ├── .env.example               # Hardcoded secrets
│       └── secrets.yaml               # API keys
├── test_scan_workflows.py             # U1-U6, M1-M3, W1
├── test_wizard_workflows.py           # M4, W2
├── test_ci_gating.py                  # U12
├── test_advanced_targets.py           # A1-A3
├── test_docker_workflows.py           # U9-U11, M5-M6, W3-W4
├── test_dashboard_visual.py           # Playwright visual tests for HTML dashboard
├── test_cross_platform.py             # Cross-platform compatibility
├── test_linux_specific.py             # Linux-only features
├── test_macos_specific.py             # macOS-only features
└── test_windows_specific.py           # Windows-only features
```

## Test Suites

### Scan Workflows (U1-U6, M1-M3, W1)

`test_scan_workflows.py` — Native CLI and Wizard scans:

- U1: Single repo - Native CLI
- U2: Single image - Native CLI
- U3: IaC file - Native CLI
- U4: URL DAST - Native CLI
- U5: Multi-target - Native CLI
- U6: Batch images - Native CLI
- M1: Single repo - Native CLI (macOS)
- M2: Single image - Native CLI (macOS)
- M3: IaC file - Native CLI (macOS)
- W1: Single repo - Native CLI (Windows)

### Wizard Workflows (M4, W2)

`test_wizard_workflows.py` — Wizard emit-script and non-interactive wizard:

- M4: Single repo - Wizard --yes (macOS)
- W2: Single repo - Wizard --yes (Windows)

### CI Gating (U12)

`test_ci_gating.py` — CI mode exit codes and severity thresholds:

- U12: CI mode with --fail-on HIGH

### Advanced Targets (A1-A3)

`test_advanced_targets.py` — Optional advanced scenarios:

- A1: GitLab repo scan (requires GITLAB_TOKEN)
- A2: K8s cluster scan (requires kubectl + cluster)
- A3: Deep profile (all 28 tools, 40-70 min)

### Dashboard Visual Tests

`test_dashboard_visual.py` — Playwright visual tests for the HTML dashboard:

Requires installation before use:

```bash
pip install pytest-playwright
playwright install chromium
```

Run via `make test-e2e-visual` or `pytest tests/e2e/test_dashboard_visual.py -v`. Tests are automatically skipped if Playwright is not installed.

### Docker Workflows (U9-U11, M5-M6, W3-W4)

`test_docker_workflows.py` — Docker-based scanning (requires Docker):

- U9: Single repo - Docker full
- U10: Single image - Docker full
- U11: Multi-target - Docker slim
- M5: Single repo - Docker full (macOS)
- M6: Multi-target - Docker slim (macOS)
- W3: Single repo - Docker full (Windows)
- W4: Multi-target - Docker slim (Windows)

## Usage Examples

### Run Specific Tests

```bash
# By test ID
pytest tests/e2e/ -k "U1 or U2 or U5" -v

# By file
pytest tests/e2e/test_docker_workflows.py -v

# Docker tests only
pytest tests/e2e/ -m docker -v

# With custom targets via environment variables
TEST_REPO=https://github.com/myorg/myrepo.git pytest tests/e2e/test_scan_workflows.py -k "U1" -v
TEST_IMAGE=nginx:1.25 pytest tests/e2e/test_scan_workflows.py -k "U2" -v
DOCKER_TAG=0.6.0-full pytest tests/e2e/test_docker_workflows.py -k "U9" -v
```

## Validation

Each test validates:

1. **Exit code:** 0 (no findings) or 1 (findings found), not 2+ (error)
2. **Output files:** findings.json, SUMMARY.md, dashboard.html present
3. **JSON schema:** CommonFinding v1.2.0 compliance
4. **Findings count:** >= 1 finding for vulnerable targets
5. **Performance:** Within profile time limits

## CI/CD Integration

See [.github/workflows/scheduled.yml](../../.github/workflows/scheduled.yml)

**Triggers:**

- Schedule: 4AM UTC weekdays (e2e-ubuntu, e2e-macos jobs)
- Manual workflow dispatch with `task: e2e` or `task: all`

## Success Criteria

For release readiness:

- **>= 95% success rate** (24/25 tests passing)
- **All Tier 1 tests pass** (U1, U2, U5, U9, U12)
- **Zero CRITICAL issues** in test suite
- **Performance within bounds:** fast <= 10min, balanced <= 20min, deep <= 60min

## Troubleshooting

### Test Failures

```bash
# Re-run with verbose output
pytest tests/e2e/ -k "U1" -v -s

# Verify tool installations
jmo tools check --profile balanced
jmo tools install --profile balanced
```

### Docker Issues

```bash
# Verify Docker running
docker ps

# Pull required images
docker pull alpine:3.19
docker pull ghcr.io/jimmy058910/jmo-security:latest-full

# Test volume mounts
docker run --rm -v $(pwd):/test alpine:3.19 ls /test
```

### Fixture Issues

```bash
# Verify fixtures exist
ls -la tests/e2e/fixtures/iac/
ls -la tests/e2e/fixtures/python/
```

## Contributing

When adding new tests:

1. Add parametrized test cases to the appropriate `test_*.py` file
2. Use fixtures from `conftest.py` for shared setup
3. Add test ID to documentation (TEST.md)
4. Update CI workflow if new markers or flags are needed
5. Test locally before committing

## References

- [Testing Guide](../../TEST.md) - General testing instructions
- [User Guide](../../docs/USER_GUIDE.md) - Multi-target scanning documentation
- [CI Workflow](../../.github/workflows/scheduled.yml) - GitHub Actions config (E2E jobs)

---

**Maintainer:** JMo Security Team
**Last Updated:** March 2026
