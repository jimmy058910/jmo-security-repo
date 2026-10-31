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

- A1: GitLab repo scan with `--gitlab-repo` (requires GITLAB_TOKEN); clones
  the default branch (no ref option, so it is not pinned) and scans the
  images the repository names
- A2: K8s cluster scan (requires kubectl + cluster)
- A3: Full scan with the default tool matrix (long-running)

### Dashboard Visual Tests

`test_dashboard_visual.py` — Playwright visual tests for the HTML dashboard:

Requires installation before use:

```bash
pip install pytest-playwright
playwright install chromium
```

Run via `make test-e2e-visual` or `pytest tests/e2e/test_dashboard_visual.py -v`. Tests are automatically skipped if Playwright is not installed.

### Docker Workflows (U9-U11, M5-M6, W3-W4)

`test_docker_workflows.py` — Docker-based scanning with the one JMo image (requires Docker):

- U9: Single repo - Docker
- U10: Single image - Docker
- U11: Multi-target - Docker
- M5: Single repo - Docker (macOS)
- M6: Multi-target - Docker (macOS)
- W3: Single repo - Docker (Windows)
- W4: Multi-target - Docker (Windows)

## Usage Examples

### Run Specific Tests

```bash
# By test ID
pytest tests/e2e/ -k "U1 or U2 or U5" -v

# By file
pytest tests/e2e/test_docker_workflows.py -v

# Docker tests only
pytest tests/e2e/ -m docker -v

# With custom targets via environment variables. The repository cases clone
# TEST_REPO at TEST_REPO_COMMIT (default: juice-shop at its pinned commit); set
# both, because a commit of one repository does not exist in another.
TEST_REPO=https://github.com/myorg/myrepo.git TEST_REPO_COMMIT=<40-char sha> pytest tests/e2e/test_scan_workflows.py -k "U1" -v
TEST_IMAGE=nginx:1.25 pytest tests/e2e/test_scan_workflows.py -k "U2" -v
# A1 scans TEST_GITLAB_REPO (group/repo, not a URL; default gitlab-org/gitlab-runner)
# on TEST_GITLAB_URL (https:// or http://, default https://gitlab.com; a value
# without a scheme fails the test, since jmo would clone from gitlab.com instead)
GITLAB_TOKEN=<token> TEST_GITLAB_REPO=mygroup/myrepo pytest tests/e2e/test_advanced_targets.py -k "gitlab" -v
# Test a local build instead of the released image
JMO_DOCKER_REGISTRY=jmo-security-dev pytest tests/e2e/test_docker_workflows.py -k "U9" -v
```

## Validation

Each test validates:

1. **Exit code:** 0 (no findings) or 1 (findings found), not 2+ (error)
2. **Output files:** findings.json, SUMMARY.md, dashboard.html present
3. **JSON schema:** CommonFinding v1.2.0 compliance
4. **Scanned something:** `meta.target_count` >= 1 for every scan, and >= 1
   finding for a repository target, whether `--repo` or `--gitlab-repo` (a scan
   that rejected every target exits 1 and writes empty outputs, so existing
   files prove nothing)
5. **Performance:** Within the test's time limit

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
- **Performance within bounds:** each test finishes inside its own timeout

## Troubleshooting

### Test Failures

```bash
# Re-run with verbose output
pytest tests/e2e/ -k "U1" -v -s

# Verify tool installations
jmo tools check
jmo tools install
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
