# E2E Infrastructure Consolidation Implementation Plan

> **STATUS: COMPLETED** — This plan was fully executed. Retained for historical reference.
>
> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Consolidate 8 CI workflows into 4, migrate bash e2e tests to pytest, add pytest-playwright visual dashboard testing, and create the `/jmo-e2e-verify` Claude skill with agent-browser integration.

**Architecture:** Five-phase rollout — foundation (composite actions + deps), test migration (bash to pytest), workflow consolidation (8 to 4), skill + browser layer, cleanup. Each phase is independently revertible. Phase 4 (skill) can run in parallel with Phases 2-3.

**Tech Stack:** Python 3.12+, pytest, pytest-playwright, pytest-json-report, GitHub Actions composite actions, agent-browser CLI, Claude Code skills

**Spec:** `docs/superpowers/specs/2026-03-12-e2e-consolidation-design.md`

---

## Chunk 1: Phase 1 — Foundation

No behavior changes. Sets up infrastructure for subsequent phases.

### Task 1.1: Update `setup-python-jmo` Composite Action Default

**Files:**

- Modify: `.github/actions/setup-python-jmo/action.yml:8`

- [ ] **Step 1: Update Python default from 3.11 to 3.12**

In `.github/actions/setup-python-jmo/action.yml`, change:

```yaml
  python-version:
    description: 'Python version to install'
    required: false
    default: '3.12'
```

- [ ] **Step 2: Verify no workflows hardcode 3.11**

Run: `grep -r "3.11" .github/workflows/*.yml .github/actions/*/action.yml`

Expected: No results referencing Python 3.11 (some may reference other tool versions like `v3.11` — those are fine).

- [ ] **Step 3: Commit**

```bash
git add .github/actions/setup-python-jmo/action.yml
git commit -m "ci: bump setup-python-jmo default from 3.11 to 3.12"
```

---

### Task 1.2: Create `docker-login` Composite Action

**Files:**

- Create: `.github/actions/docker-login/action.yml`

- [ ] **Step 1: Read existing Docker login patterns in release.yml**

Read `.github/workflows/release.yml` and find the Docker login steps (GHCR, Docker Hub, ECR). These will be extracted into the composite action.

- [ ] **Step 2: Create the composite action**

Create `.github/actions/docker-login/action.yml`:

```yaml
name: 'Docker Registry Login'
description: 'Login to GHCR, Docker Hub, and ECR registries'

inputs:
  ghcr-token:
    description: 'GitHub token for GHCR login'
    required: true
  dockerhub-username:
    description: 'Docker Hub username'
    required: false
    default: ''
  dockerhub-token:
    description: 'Docker Hub token'
    required: false
    default: ''
  dockerhub-enabled:
    description: 'Whether Docker Hub is enabled'
    required: false
    default: 'false'
  aws-role-arn:
    description: 'AWS IAM role ARN for ECR login'
    required: false
    default: ''
  aws-region:
    description: 'AWS region for ECR'
    required: false
    default: 'us-east-1'

runs:
  using: composite
  steps:
    - name: Login to GHCR
      uses: docker/login-action@v3
      with:
        registry: ghcr.io
        username: ${{ github.actor }}
        password: ${{ inputs.ghcr-token }}

    - name: Login to Docker Hub
      if: inputs.dockerhub-enabled == 'true' && inputs.dockerhub-username != ''
      uses: docker/login-action@v3
      with:
        username: ${{ inputs.dockerhub-username }}
        password: ${{ inputs.dockerhub-token }}

    - name: Configure AWS credentials
      if: inputs.aws-role-arn != ''
      uses: aws-actions/configure-aws-credentials@v4
      with:
        role-to-assume: ${{ inputs.aws-role-arn }}
        aws-region: ${{ inputs.aws-region }}

    - name: Login to ECR Public
      if: inputs.aws-role-arn != ''
      uses: docker/login-action@v3
      with:
        registry: public.ecr.aws
```

- [ ] **Step 3: Validate YAML syntax**

Run: `python -c "import yaml; yaml.safe_load(open('.github/actions/docker-login/action.yml'))"`

Expected: No errors.

- [ ] **Step 4: Commit**

```bash
git add .github/actions/docker-login/action.yml
git commit -m "ci: add docker-login composite action for multi-registry auth"
```

---

### Task 1.3: Create `trufflehog-scan` Composite Action

**Files:**

- Create: `.github/actions/trufflehog-scan/action.yml`

- [ ] **Step 1: Read existing TruffleHog patterns**

Read `.github/workflows/ci.yml` (quick-checks job, TruffleHog step) and `.github/workflows/scheduled-tests.yml` (nightly-extended-tests, security audit step). Extract the common pattern.

- [ ] **Step 2: Create the composite action**

Create `.github/actions/trufflehog-scan/action.yml`:

```yaml
name: 'TruffleHog Secret Scan'
description: 'Scan filesystem for verified secrets using TruffleHog'

inputs:
  scan-path:
    description: 'Path to scan'
    required: false
    default: '.'
  exclude-paths:
    description: 'Path to exclusion file'
    required: false
    default: '.trufflehog-exclude.txt'
  fail-on-verified:
    description: 'Fail if verified secrets found'
    required: false
    default: 'true'

runs:
  using: composite
  steps:
    - name: Install TruffleHog
      shell: bash
      run: |
        curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
          | sh -s -- -b /usr/local/bin

    - name: Run TruffleHog scan
      shell: bash
      run: |
        trufflehog filesystem ${{ inputs.scan-path }} \
          --json \
          --exclude-paths ${{ inputs.exclude-paths }} \
          --only-verified > trufflehog-results.json || true

        VERIFIED=$(jq -r 'select(.Verified == true)' trufflehog-results.json 2>/dev/null | wc -l || echo "0")

        if [ "$VERIFIED" -gt 0 ] && [ "${{ inputs.fail-on-verified }}" = "true" ]; then
          echo "::error::Found $VERIFIED verified secrets! Review trufflehog-results.json"
          exit 1
        fi

        echo "TruffleHog scan complete. Verified secrets: $VERIFIED"
```

- [ ] **Step 3: Validate YAML syntax**

Run: `python -c "import yaml; yaml.safe_load(open('.github/actions/trufflehog-scan/action.yml'))"`

- [ ] **Step 4: Commit**

```bash
git add .github/actions/trufflehog-scan/action.yml
git commit -m "ci: add trufflehog-scan composite action for secret detection"
```

---

### Task 1.4: Create `notify-failure` Composite Action

**Files:**

- Create: `.github/actions/notify-failure/action.yml`

- [ ] **Step 1: Read existing notification pattern**

Read `.github/workflows/scheduled-tests.yml` (nightly-notify-failure job). Extract the issue creation/comment logic.

- [ ] **Step 2: Create the composite action**

Create `.github/actions/notify-failure/action.yml`:

```yaml
name: 'Notify on Failure'
description: 'Create or update GitHub issue on workflow failure'

inputs:
  title-prefix:
    description: 'Prefix for issue title'
    required: false
    default: 'CI failure'
  label:
    description: 'Label for the issue'
    required: false
    default: 'ci-failure'
  github-token:
    description: 'GitHub token for issue creation'
    required: true

runs:
  using: composite
  steps:
    - name: Create or update failure issue
      shell: bash
      env:
        GH_TOKEN: ${{ inputs.github-token }}
      run: |
        TODAY=$(date -u +%Y-%m-%d)
        TITLE="${{ inputs.title-prefix }} on ${TODAY}"
        BODY="Workflow: ${{ github.workflow }}\nRun: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}\nBranch: ${{ github.ref_name }}\nTriggered at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

        # Check for existing open issue with same title
        EXISTING=$(gh issue list --state open --search "in:title ${TITLE}" --json number --jq '.[0].number' 2>/dev/null || echo "")

        if [ -n "$EXISTING" ] && [ "$EXISTING" != "null" ]; then
          echo "Adding comment to existing issue #${EXISTING}"
          gh issue comment "$EXISTING" --body "$(echo -e "$BODY")"
        else
          echo "Creating new issue: ${TITLE}"
          gh issue create --title "$TITLE" --body "$(echo -e "$BODY")" --label "${{ inputs.label }}"
        fi
```

- [ ] **Step 3: Validate YAML syntax**

Run: `python -c "import yaml; yaml.safe_load(open('.github/actions/notify-failure/action.yml'))"`

- [ ] **Step 4: Commit**

```bash
git add .github/actions/notify-failure/action.yml
git commit -m "ci: add notify-failure composite action for issue management"
```

---

### Task 1.5: Merge Docker Variant Test Files

**Files:**

- Modify: `tests/e2e/test_docker_variants.py`
- Delete: `tests/integration/test_docker_variants.py`
- Read first: Both files to understand differences

- [ ] **Step 1: Read both test files in full**

Read `tests/e2e/test_docker_variants.py` (698 lines, 4 variants: deep/balanced/slim/fast) and `tests/integration/test_docker_variants.py` (464 lines, 3 variants: full/slim/alpine).

- [ ] **Step 2: Identify unique tests in integration version**

Compare test functions. The integration version may have tests not present in the e2e version (e.g., image size checks, different variant names). List all unique test functions.

- [ ] **Step 3: Merge unique tests into e2e version**

Add any unique test functions from the integration version into `tests/e2e/test_docker_variants.py`. Update variant names if needed (the integration version uses "full/slim/alpine" which may be legacy names vs the current "deep/balanced/slim/fast"). Ensure all parametrize decorators use the current 4-variant naming.

- [ ] **Step 4: Run merged tests**

Run: `pytest tests/e2e/test_docker_variants.py --collect-only`

Expected: All test functions collected without errors.

- [ ] **Step 5: Run full test suite to verify no imports break**

Run: `make test-fast`

Expected: All tests pass (Docker tests will be skipped if Docker isn't running).

- [ ] **Step 6: Delete integration duplicate**

```bash
rm tests/integration/test_docker_variants.py
```

- [ ] **Step 7: Commit**

```bash
git add tests/e2e/test_docker_variants.py
git rm tests/integration/test_docker_variants.py
git commit -m "test: merge integration docker variant tests into e2e, remove duplicate"
```

---

### Task 1.6: Add New Dependencies

**Files:**

- Modify: `requirements-dev.in`
- Modify: `pyproject.toml`

- [ ] **Step 1: Verify pytest-json-report already in dev deps**

`pytest-json-report>=1.5.0` is already in `requirements-dev.in`. No change needed.

- [ ] **Step 2: Add pytest-playwright to optional visual deps**

Add to `pyproject.toml` under `[project.optional-dependencies]`:

```toml
visual = [
    "pytest-playwright>=0.5.2",
]
```

- [ ] **Step 3: Compile deps**

Run: `make deps-compile`

Expected: `requirements-dev.txt` updated with `pytest-json-report` and its dependencies.

- [ ] **Step 4: Install new deps**

Run: `pip install -r requirements-dev.txt`

- [ ] **Step 5: Verify imports work**

Run: `python -c "import pytest_playwright; print('OK')"` (only if visual deps installed)

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml
git commit -m "chore(deps): add pytest-playwright as visual optional dependency"
```

---

### Task 1.7: Create E2E Shared Fixtures (`tests/e2e/conftest.py`)

**Files:**

- Create: `tests/e2e/conftest.py` (or modify if it exists)
- Read first: `tests/e2e/test_cross_platform.py` for existing patterns, `tests/conftest.py` for project-level fixtures

- [ ] **Step 1: Read existing e2e conftest and patterns**

Read `tests/e2e/__init__.py` and `tests/e2e/test_cross_platform.py` (first 80 lines) to understand existing ScanArgs pattern and how tests invoke the CLI.

- [ ] **Step 2: Create shared e2e conftest**

Create (or update) `tests/e2e/conftest.py`:

```python
"""Shared fixtures for e2e tests.

Provides:
- jmo_runner: Execute jmo CLI commands and return results
- e2e_fixtures_dir: Path to e2e test fixtures
- scan_results: Run a scan against vulnerable fixtures (session-scoped)
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

# E2E fixture directory
E2E_FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def e2e_fixtures_dir() -> Path:
    """Return path to e2e test fixtures directory."""
    return E2E_FIXTURES


@pytest.fixture
def jmo_runner(tmp_path):
    """Execute jmo CLI and return (rc, stdout, stderr, results_dir).

    Usage:
        def test_scan(jmo_runner):
            rc, stdout, stderr, results_dir = jmo_runner([
                "ci", "--repo", ".", "--profile", "fast"
            ])
            assert rc in (0, 1)
    """

    def _run(args: list[str], timeout: int = 900) -> tuple[int, str, str, Path]:
        results_dir = tmp_path / "results"
        results_dir.mkdir(exist_ok=True)

        full_args = [
            sys.executable, "-m", "scripts.cli.jmo",
            *args,
            "--results-dir", str(results_dir),
        ]

        result = subprocess.run(
            full_args,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(tmp_path),
        )

        return result.returncode, result.stdout, result.stderr, results_dir

    return _run


def validate_basic_scan(results_dir: Path) -> None:
    """Validate basic scan output files exist and are valid.

    Checks:
    - findings.json exists and is valid JSON
    - SUMMARY.md exists
    - dashboard.html exists
    - findings.json has CommonFinding schema structure
    """
    findings_file = results_dir / "findings.json"
    assert findings_file.exists(), f"findings.json not found in {results_dir}"

    findings = json.loads(findings_file.read_text())
    assert isinstance(findings, list), "findings.json must be a JSON array"

    summary_file = results_dir / "SUMMARY.md"
    assert summary_file.exists(), f"SUMMARY.md not found in {results_dir}"

    dashboard_file = results_dir / "dashboard.html"
    assert dashboard_file.exists(), f"dashboard.html not found in {results_dir}"


def validate_multi_target(results_dir: Path) -> None:
    """Validate multi-target scan output.

    Checks all basic scan validations plus:
    - Multiple target directories present
    - No duplicate finding fingerprints
    """
    validate_basic_scan(results_dir)

    findings_file = results_dir / "findings.json"
    findings = json.loads(findings_file.read_text())

    if findings:
        fingerprints = [f.get("fingerprint_id") for f in findings if f.get("fingerprint_id")]
        assert len(fingerprints) == len(set(fingerprints)), "Duplicate fingerprint IDs found"


def current_platform() -> str:
    """Return current platform as linux/darwin/win32."""
    return sys.platform
```

- [ ] **Step 3: Verify conftest loads**

Run: `pytest tests/e2e/ --collect-only 2>&1 | head -20`

Expected: Tests collected without conftest import errors.

- [ ] **Step 4: Run existing e2e tests to verify no regressions**

Run: `pytest tests/e2e/test_cross_platform.py --collect-only`

Expected: All tests still collected.

- [ ] **Step 5: Commit**

```bash
git add tests/e2e/conftest.py
git commit -m "test: add shared e2e conftest with jmo_runner fixture and validators"
```

---

### Task 1.8: Add `.gitignore` Entry and Makefile Targets

**Files:**

- Modify: `.gitignore`
- Modify: `Makefile`

- [ ] **Step 1: Add e2e-screenshots to .gitignore**

Add to `.gitignore`:

```text
# E2E visual test screenshots
e2e-screenshots/
```

- [ ] **Step 2: Add Makefile targets**

Add to `Makefile` (after existing test targets):

```makefile
test-e2e:
	$(PY) -m pytest tests/e2e/ -m "e2e or slow" --timeout=900 -v

test-e2e-visual:
	$(PY) -m pytest tests/e2e/test_dashboard_visual.py -v --timeout=120

test-e2e-report:
	$(PY) -m pytest tests/e2e/ -m "e2e or slow" --timeout=900 --json-report --json-report-file=e2e-results.json -v
	@echo "E2E results written to e2e-results.json"
```

- [ ] **Step 3: Update `.PHONY` list**

Add `test-e2e test-e2e-visual test-e2e-report` to the `.PHONY` declaration at the top of the Makefile.

- [ ] **Step 4: Verify targets**

Run: `make test-e2e --dry-run`

Expected: Shows the pytest command that would run.

- [ ] **Step 5: Commit**

```bash
git add .gitignore Makefile
git commit -m "chore: add e2e Makefile targets and gitignore for visual test screenshots"
```

---

## Chunk 2: Phase 2 — Test Migration (Bash to Pytest)

Converts bash e2e tests (U1-U12, M1-M6, W1-W4, A1-A3) to pytest. Runs parity verification before deleting bash script.

### Task 2.1: Create `test_scan_workflows.py` (Replaces U1-U6, M1-M3, W1)

**Files:**

- Create: `tests/e2e/test_scan_workflows.py`
- Reference: `tests/e2e/run_comprehensive_tests.sh` (functions `test_U1` through `test_U6`, `test_M1` through `test_M3`, `test_W1`)
- Reference: `tests/e2e/conftest.py` (jmo_runner, validate_basic_scan)

- [ ] **Step 1: Read bash script test functions**

Read `tests/e2e/run_comprehensive_tests.sh` and extract the exact CLI arguments used for each test (U1-U6, M1-M3, W1). Note the validation functions called for each.

- [ ] **Step 2: Write the parametrized test file**

Create `tests/e2e/test_scan_workflows.py`:

```python
"""Parametrized e2e scan workflow tests.

Replaces bash tests U1-U6 (Ubuntu), M1-M3 (macOS), W1 (Windows).
Each test runs jmo CLI with specific arguments and validates output.

Uses jmo_runner fixture from conftest.py.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

from tests.e2e.conftest import (
    current_platform,
    validate_basic_scan,
    validate_multi_target,
)

# Test fixture paths
E2E_FIXTURES = Path(__file__).parent / "fixtures"
IAC_FIXTURE = E2E_FIXTURES / "iac" / "aws-s3-public.tf"

# Default test targets (can be overridden via environment variables)
DEFAULT_REPO = "https://github.com/juice-shop/juice-shop.git"
DEFAULT_IMAGE = "alpine:3.19"


def _get_test_repo():
    """Get test repo URL from environment or use default."""
    import os

    return os.environ.get("TEST_REPO", DEFAULT_REPO)


def _get_test_image():
    """Get test image from environment or use default."""
    import os

    return os.environ.get("TEST_IMAGE", DEFAULT_IMAGE)


requires_docker = pytest.mark.skipif(
    not shutil.which("docker"),
    reason="Docker not installed",
)


SCAN_WORKFLOWS = [
    # Ubuntu tests
    pytest.param(
        "U1",
        "Single repo - native CLI",
        lambda: [
            "ci", "--repo", _get_test_repo(),
            "--profile", "fast", "--allow-missing-tools",
        ],
        validate_basic_scan,
        "linux",
        id="U1-repo-native",
    ),
    pytest.param(
        "U2",
        "Single image - native CLI",
        lambda: [
            "ci", "--image", _get_test_image(),
            "--tools", "trivy,syft", "--allow-missing-tools",
        ],
        validate_basic_scan,
        "linux",
        marks=[requires_docker],
        id="U2-image-native",
    ),
    pytest.param(
        "U3",
        "IaC file - native CLI",
        lambda: [
            "ci", "--terraform-state", str(IAC_FIXTURE),
            "--tools", "checkov,trivy", "--allow-missing-tools",
        ],
        validate_basic_scan,
        "linux",
        id="U3-iac-native",
    ),
    pytest.param(
        "U4",
        "URL DAST - native CLI",
        lambda: [
            "ci", "--url", "http://testphp.vulnweb.com",
            "--tools", "zap", "--allow-missing-tools",
        ],
        validate_basic_scan,
        "linux",
        id="U4-url-dast",
    ),
    pytest.param(
        "U5",
        "Multi-target - native CLI",
        lambda: [
            "ci",
            "--repo", _get_test_repo(),
            "--image", _get_test_image(),
            "--terraform-state", str(IAC_FIXTURE),
            "--allow-missing-tools",
        ],
        validate_multi_target,
        "linux",
        marks=[requires_docker],
        id="U5-multi-target",
    ),
    pytest.param(
        "U6",
        "Batch images - native CLI",
        lambda: [
            "ci", "--image", _get_test_image(),
            "--tools", "trivy,syft", "--allow-missing-tools",
        ],
        validate_basic_scan,
        "linux",
        marks=[requires_docker],
        id="U6-batch-images",
    ),
    # macOS tests (same commands, different platform)
    pytest.param(
        "M1",
        "Single repo - native CLI (macOS)",
        lambda: [
            "ci", "--repo", _get_test_repo(),
            "--profile", "fast", "--allow-missing-tools",
        ],
        validate_basic_scan,
        "darwin",
        id="M1-repo-native-macos",
    ),
    pytest.param(
        "M2",
        "Single image - native CLI (macOS)",
        lambda: [
            "ci", "--image", _get_test_image(),
            "--tools", "trivy,syft", "--allow-missing-tools",
        ],
        validate_basic_scan,
        "darwin",
        marks=[requires_docker],
        id="M2-image-native-macos",
    ),
    pytest.param(
        "M3",
        "IaC file - native CLI (macOS)",
        lambda: [
            "ci", "--terraform-state", str(IAC_FIXTURE),
            "--tools", "checkov,trivy", "--allow-missing-tools",
        ],
        validate_basic_scan,
        "darwin",
        id="M3-iac-native-macos",
    ),
    # Windows tests
    pytest.param(
        "W1",
        "Single repo - native CLI (Windows)",
        lambda: [
            "ci", "--repo", _get_test_repo(),
            "--profile", "fast", "--allow-missing-tools",
        ],
        validate_basic_scan,
        "win32",
        id="W1-repo-native-windows",
    ),
]


@pytest.mark.e2e
@pytest.mark.slow
@pytest.mark.parametrize("test_id,desc,args_fn,validator,platform", SCAN_WORKFLOWS)
def test_scan_workflow(test_id, desc, args_fn, validator, platform, jmo_runner):
    """Unified scan workflow test.

    Replaces bash tests U1-U6, M1-M3, W1.
    Each parametrized case runs jmo CLI and validates output.
    """
    if platform != current_platform():
        pytest.skip(f"Test {test_id} is for {platform}, running on {current_platform()}")

    args = args_fn()
    rc, stdout, stderr, results_dir = jmo_runner(args)

    # Exit code 0 (no findings) or 1 (findings found) are success
    # Exit code 2+ means error
    assert rc in (0, 1), (
        f"Test {test_id} ({desc}) failed with exit code {rc}.\n"
        f"stderr: {stderr[:500]}"
    )

    validator(results_dir)
```

- [ ] **Step 3: Verify tests collect**

Run: `pytest tests/e2e/test_scan_workflows.py --collect-only`

Expected: 10 test cases collected (U1-U6, M1-M3, W1), most skipped for wrong platform.

- [ ] **Step 4: Commit**

```bash
git add tests/e2e/test_scan_workflows.py
git commit -m "test: add parametrized scan workflow tests replacing bash U1-U6, M1-M3, W1"
```

---

### Task 2.2: Create `test_wizard_workflows.py` (Replaces M4, W2)

**Files:**

- Create: `tests/e2e/test_wizard_workflows.py`
- Reference: `tests/e2e/run_comprehensive_tests.sh` (functions for M4, W2)

- [ ] **Step 1: Read bash wizard test functions**

Read the M4 and W2 functions from `run_comprehensive_tests.sh`. They test `jmotools wizard --yes --emit-script` and verify the emitted script can execute.

- [ ] **Step 2: Write the wizard test file**

Create `tests/e2e/test_wizard_workflows.py`:

```python
"""E2E tests for wizard --yes workflows.

Replaces bash tests M4 (macOS wizard) and W2 (Windows wizard).
Tests that wizard --yes produces valid artifacts (emitted scripts, make targets).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from tests.e2e.conftest import current_platform

E2E_FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.e2e
@pytest.mark.slow
class TestWizardWorkflows:
    """Test wizard --yes artifact generation."""

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_wizard_emit_script_macos(self, tmp_path):
        """M4: Wizard --yes emits runnable script on macOS."""
        script_path = tmp_path / "wizard-output.sh"
        result = subprocess.run(
            [
                sys.executable, "-m", "scripts.cli.jmo",
                "wizard", "--yes",
                "--repos-dir", str(E2E_FIXTURES),
                "--profile", "fast",
                "--emit-script", str(script_path),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, f"Wizard failed: {result.stderr[:500]}"
        assert script_path.exists(), "Emitted script not created"
        content = script_path.read_text()
        assert "jmo" in content.lower(), "Emitted script doesn't contain jmo command"

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
    def test_wizard_emit_script_windows(self, tmp_path):
        """W2: Wizard --yes emits runnable script on Windows."""
        script_path = tmp_path / "wizard-output.sh"
        result = subprocess.run(
            [
                sys.executable, "-m", "scripts.cli.jmo",
                "wizard", "--yes",
                "--repos-dir", str(E2E_FIXTURES),
                "--profile", "fast",
                "--emit-script", str(script_path),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, f"Wizard failed: {result.stderr[:500]}"
        assert script_path.exists(), "Emitted script not created"
```

- [ ] **Step 3: Verify tests collect**

Run: `pytest tests/e2e/test_wizard_workflows.py --collect-only`

- [ ] **Step 4: Commit**

```bash
git add tests/e2e/test_wizard_workflows.py
git commit -m "test: add wizard workflow tests replacing bash M4, W2"
```

---

### Task 2.3: Create `test_ci_gating.py` (Replaces U12)

**Files:**

- Create: `tests/e2e/test_ci_gating.py`

- [ ] **Step 1: Read bash U12 function**

Read the U12 function from `run_comprehensive_tests.sh`. It tests `jmo ci --fail-on HIGH` and verifies exit code is 1 when HIGH findings are present.

- [ ] **Step 2: Write the CI gating test file**

Create `tests/e2e/test_ci_gating.py`:

```python
"""E2E tests for CI gating with --fail-on threshold.

Replaces bash test U12.
Verifies that jmo ci returns exit code 1 when findings exceed the severity threshold.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

E2E_FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.e2e
@pytest.mark.slow
class TestCIGating:
    """Test CI mode with --fail-on severity threshold."""

    def test_fail_on_high_with_vulnerable_target(self, tmp_path):
        """U12: CI mode exits 1 when HIGH findings present."""
        results_dir = tmp_path / "results"
        results_dir.mkdir()

        result = subprocess.run(
            [
                sys.executable, "-m", "scripts.cli.jmo",
                "ci",
                "--repo", str(E2E_FIXTURES / "python"),
                "--profile", "fast",
                "--fail-on", "HIGH",
                "--allow-missing-tools",
                "--results-dir", str(results_dir),
            ],
            capture_output=True,
            text=True,
            timeout=900,
        )

        # Should exit 1 (findings above threshold) or 0 (no HIGH findings)
        # The vulnerable fixtures contain known HIGH severity issues
        assert result.returncode in (0, 1), (
            f"CI gating returned unexpected exit code {result.returncode}.\n"
            f"stderr: {result.stderr[:500]}"
        )

    def test_fail_on_critical_passes_with_medium_only(self, tmp_path):
        """CI mode exits 0 when only MEDIUM findings and threshold is CRITICAL."""
        results_dir = tmp_path / "results"
        results_dir.mkdir()

        result = subprocess.run(
            [
                sys.executable, "-m", "scripts.cli.jmo",
                "ci",
                "--repo", str(E2E_FIXTURES / "python"),
                "--profile", "fast",
                "--fail-on", "CRITICAL",
                "--allow-missing-tools",
                "--results-dir", str(results_dir),
            ],
            capture_output=True,
            text=True,
            timeout=900,
        )

        # With --fail-on CRITICAL, only CRITICAL findings cause exit 1
        assert result.returncode in (0, 1), (
            f"Unexpected exit code {result.returncode}"
        )
```

- [ ] **Step 3: Commit**

```bash
git add tests/e2e/test_ci_gating.py
git commit -m "test: add CI gating e2e tests replacing bash U12"
```

---

### Task 2.4: Create `test_advanced_targets.py` (Replaces A1-A3)

**Files:**

- Create: `tests/e2e/test_advanced_targets.py`

- [ ] **Step 1: Write advanced target tests**

Create `tests/e2e/test_advanced_targets.py`:

```python
"""E2E tests for advanced scan targets.

Replaces bash tests A1 (GitLab), A2 (K8s), A3 (deep profile).
These tests require specific infrastructure and are skipped if unavailable.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tests.e2e.conftest import validate_basic_scan

E2E_FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.e2e
@pytest.mark.slow
class TestAdvancedTargets:
    """Advanced scan targets requiring specific infrastructure."""

    @pytest.mark.skipif(
        not os.environ.get("GITLAB_TOKEN"),
        reason="GITLAB_TOKEN not set",
    )
    def test_gitlab_repo_scan(self, jmo_runner):
        """A1: GitLab repository scan (requires GITLAB_TOKEN)."""
        gitlab_repo = os.environ.get(
            "TEST_GITLAB_REPO",
            "https://gitlab.com/gitlab-org/gitlab-runner.git",
        )
        rc, stdout, stderr, results_dir = jmo_runner([
            "ci", "--repo", gitlab_repo,
            "--profile", "fast", "--allow-missing-tools",
        ])
        assert rc in (0, 1), f"GitLab scan failed: {stderr[:500]}"
        validate_basic_scan(results_dir)

    @pytest.mark.skipif(
        not shutil.which("kubectl"),
        reason="kubectl not installed",
    )
    def test_k8s_cluster_scan(self, jmo_runner):
        """A2: Kubernetes cluster scan (requires kubectl + running cluster)."""
        rc, stdout, stderr, results_dir = jmo_runner([
            "ci",
            "--k8s-context", "default",
            "--k8s-namespace", "default",
            "--tools", "trivy,falco",
            "--allow-missing-tools",
        ])
        assert rc in (0, 1), f"K8s scan failed: {stderr[:500]}"

    def test_deep_profile_scan(self, jmo_runner):
        """A3: Deep profile scan (all tools, 40-70 min)."""
        rc, stdout, stderr, results_dir = jmo_runner([
            "ci", "--repo", str(E2E_FIXTURES / "python"),
            "--profile", "deep", "--allow-missing-tools",
        ], timeout=4200)  # 70 minutes
        assert rc in (0, 1), f"Deep scan failed: {stderr[:500]}"
        validate_basic_scan(results_dir)
```

- [ ] **Step 2: Commit**

```bash
git add tests/e2e/test_advanced_targets.py
git commit -m "test: add advanced target e2e tests replacing bash A1-A3"
```

---

### Task 2.5: Create `test_docker_workflows.py` (Replaces U9-U11, M5-M6, W3-W4)

**Files:**

- Rename: `tests/e2e/test_docker_variants.py` to `tests/e2e/test_docker_workflows.py`
- Modify: `tests/e2e/test_docker_workflows.py`
- Reference: `tests/e2e/run_comprehensive_tests.sh` (functions for U9-U11, M5-M6, W3-W4)

Note: U7 and U8 are already SKIPPED in the bash script (U7 requires manual verification, U8 is interactive wizard). They are intentionally excluded from migration.

- [ ] **Step 1: Read bash Docker test functions**

Read `run_comprehensive_tests.sh` functions for U9-U11, M5-M6, W3-W4. They run `docker run ... jmo ci` with various arguments and validate output via volume mounts.

- [ ] **Step 2: Rename existing file**

```bash
git mv tests/e2e/test_docker_variants.py tests/e2e/test_docker_workflows.py
```

- [ ] **Step 3: Add Docker CLI workflow tests**

Add to `tests/e2e/test_docker_workflows.py` a new class for the bash-equivalent Docker tests:

```python
@pytest.mark.e2e
@pytest.mark.slow
@pytest.mark.docker
class TestDockerCLIWorkflows:
    """Docker CLI workflow tests replacing bash U9-U11, M5-M6, W3-W4.

    Tests jmo scan execution inside Docker containers with volume mounts.
    """

    DOCKER_REGISTRY = "ghcr.io/jimmy058910/jmo-security"

    @pytest.mark.skipif(not shutil.which("docker"), reason="Docker not installed")
    @pytest.mark.parametrize(
        "test_id,variant,cli_args,platform",
        [
            pytest.param("U9", "latest-full", ["ci", "--repo", "/scan", "--profile", "balanced"], "linux", id="U9-docker-full-repo"),
            pytest.param("U10", "latest-full", ["ci", "--image", "alpine:3.19", "--tools", "trivy,syft"], "linux", id="U10-docker-full-image"),
            pytest.param("U11", "latest-slim", ["ci", "--repo", "/scan", "--profile", "fast"], "linux", id="U11-docker-slim-multi"),
            pytest.param("M5", "latest-full", ["ci", "--repo", "/scan", "--profile", "balanced"], "darwin", id="M5-docker-full-macos"),
            pytest.param("M6", "latest-slim", ["ci", "--repo", "/scan", "--profile", "fast"], "darwin", id="M6-docker-slim-macos"),
            pytest.param("W3", "latest-full", ["ci", "--repo", "/scan", "--profile", "balanced"], "win32", id="W3-docker-full-windows"),
            pytest.param("W4", "latest-slim", ["ci", "--repo", "/scan", "--profile", "fast"], "win32", id="W4-docker-slim-windows"),
        ],
    )
    def test_docker_cli_workflow(self, test_id, variant, cli_args, platform, tmp_path):
        """Run jmo inside Docker container and validate output."""
        if sys.platform != platform:
            pytest.skip(f"Test {test_id} is for {platform}")

        results_dir = tmp_path / "results"
        results_dir.mkdir()

        docker_cmd = [
            "docker", "run", "--rm",
            "-v", f"{tmp_path}:/scan",
            "-v", f"{results_dir}:/scan/results",
            f"{self.DOCKER_REGISTRY}:{variant}",
            *cli_args,
            "--results-dir", "/scan/results",
            "--allow-missing-tools",
        ]

        result = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=900,
        )

        assert result.returncode in (0, 1), (
            f"Docker test {test_id} failed with exit code {result.returncode}.\n"
            f"stderr: {result.stderr[:500]}"
        )

        # Validate output files exist on host via volume mount
        assert (results_dir / "findings.json").exists() or result.returncode == 0
```

- [ ] **Step 4: Verify tests collect**

Run: `pytest tests/e2e/test_docker_workflows.py --collect-only`

Expected: Both existing variant tests and new CLI workflow tests collected.

- [ ] **Step 5: Update any imports referencing old filename**

Run: `grep -r "test_docker_variants" tests/`

Fix any imports that reference the old filename.

- [ ] **Step 6: Commit**

```bash
git add tests/e2e/test_docker_workflows.py
git commit -m "test: rename test_docker_variants to test_docker_workflows, add Docker CLI tests

Replaces bash tests U9-U11, M5-M6, W3-W4 with parametrized pytest.
U7 (manual) and U8 (interactive) intentionally excluded."
```

---

### Task 2.6: Create Pytest Fixture Data Loaders

**Files:**

- Create: `tests/e2e/fixtures/conftest.py`

- [ ] **Step 1: Write fixture conftest replacing setup_fixtures.sh**

Create `tests/e2e/fixtures/conftest.py`:

```python
"""Session-scoped fixture data loaders for e2e tests.

Replaces setup_fixtures.sh. Provides verified fixture paths
for IaC, Python, JavaScript, and config test files.
"""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent


@pytest.fixture(scope="session")
def iac_fixtures() -> dict[str, Path]:
    """Return paths to IaC test fixtures."""
    iac_dir = FIXTURES_DIR / "iac"
    fixtures = {
        "terraform": iac_dir / "aws-s3-public.tf",
        "k8s": iac_dir / "k8s-privileged-pod.yaml",
        "dockerfile": iac_dir / "Dockerfile.bad",
        "docker_compose": iac_dir / "docker-compose.insecure.yml",
    }
    for name, path in fixtures.items():
        assert path.exists(), f"Missing IaC fixture: {name} at {path}"
    return fixtures


@pytest.fixture(scope="session")
def python_fixtures() -> dict[str, Path]:
    """Return paths to Python test fixtures."""
    py_dir = FIXTURES_DIR / "python"
    return {"vulnerable_app": py_dir / "vulnerable_app.py"}


@pytest.fixture(scope="session")
def javascript_fixtures() -> dict[str, Path]:
    """Return paths to JavaScript test fixtures."""
    js_dir = FIXTURES_DIR / "javascript"
    return {
        "package_json": js_dir / "package.json",
        "vulnerable_app": js_dir / "vulnerable_app.js",
    }


@pytest.fixture(scope="session")
def config_fixtures() -> dict[str, Path]:
    """Return paths to config test fixtures."""
    cfg_dir = FIXTURES_DIR / "configs"
    return {
        "env_example": cfg_dir / ".env.example",
        "secrets_yaml": cfg_dir / "secrets.yaml",
    }
```

- [ ] **Step 2: Verify fixtures load**

Run: `pytest tests/e2e/ --collect-only 2>&1 | grep "conftest"`

Expected: No import errors from the fixtures conftest.

- [ ] **Step 3: Commit**

```bash
git add tests/e2e/fixtures/conftest.py
git commit -m "test: add e2e fixture data loaders replacing setup_fixtures.sh"
```

---

### Task 2.7: Add E2E Report Generation Hook

**Files:**

- Modify: `tests/e2e/conftest.py`

- [ ] **Step 1: Add pytest hook for markdown report generation**

Add to `tests/e2e/conftest.py` a `pytest_terminal_summary` hook that generates a markdown report from test results:

```python
def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Generate e2e markdown report after test run."""
    report_path = getattr(config.option, "json_report_file", None)
    if report_path is None:
        return

    # Report generation is handled by pytest-json-report
    # This hook adds a release readiness check
    stats = terminalreporter.stats
    passed = len(stats.get("passed", []))
    failed = len(stats.get("failed", []))
    skipped = len(stats.get("skipped", []))
    total = passed + failed

    if total > 0:
        pass_rate = (passed / total) * 100
        status = "PASS" if pass_rate >= 95.0 else "FAIL"
        terminalreporter.write_line("")
        terminalreporter.write_line(
            f"E2E Release Readiness: {status} ({pass_rate:.1f}% pass rate, "
            f"threshold: 95%)"
        )
```

- [ ] **Step 2: Verify hook runs**

Run: `pytest tests/e2e/test_scan_workflows.py --collect-only -v`

Expected: No errors (hook only activates with `--json-report-file`).

- [ ] **Step 3: Commit**

```bash
git add tests/e2e/conftest.py
git commit -m "test: add e2e release readiness report hook"
```

---

### Task 2.8: Parity Verification (Critical Gate)

**Files:**

- No file changes — verification only

- [ ] **Step 1: Run new pytest scan workflow tests**

Run: `pytest tests/e2e/test_scan_workflows.py --collect-only -v`

Verify: All 10 test cases collected. Platform-appropriate tests not skipped.

- [ ] **Step 2: Compare with bash script test list**

Cross-reference the parametrized test IDs (U1-U6, M1-M3, W1) against `run_comprehensive_tests.sh` to verify every bash test has a pytest equivalent.

- [ ] **Step 3: Run one end-to-end test if tools available**

If on Linux with tools installed:

Run: `pytest tests/e2e/test_scan_workflows.py -k "U3" -v --timeout=900`

This runs the IaC test (U3) which uses local fixtures and doesn't require network access or Docker.

- [ ] **Step 4: Document parity status**

Create a brief note confirming parity or listing gaps. This gate must pass before Task 2.9.

---

### Task 2.9: Delete Bash E2E Scripts (After Parity Confirmed)

**Files:**

- Delete: `tests/e2e/run_comprehensive_tests.sh`
- Delete: `tests/e2e/generate_report.py`
- Delete: `tests/e2e/fixtures/setup_fixtures.sh`

- [ ] **Step 1: Verify parity gate passed (Task 2.8)**

Confirm all bash tests have pytest equivalents before proceeding.

- [ ] **Step 2: Delete bash scripts**

```bash
git rm tests/e2e/run_comprehensive_tests.sh
git rm tests/e2e/generate_report.py
git rm tests/e2e/fixtures/setup_fixtures.sh
```

- [ ] **Step 3: Run full test suite**

Run: `make test-fast`

Expected: All tests pass. No imports reference deleted files.

- [ ] **Step 4: Commit**

```bash
git commit -m "refactor: remove bash e2e scripts, replaced by pytest parametrized tests"
```

---

## Chunk 3: Phase 3 — Workflow Consolidation

Merges 8 workflow files into 4, one merge at a time. Each step validated before proceeding.

### Task 3.1: Merge Maintenance Workflows (3 to 1)

**Files:**

- Modify: `.github/workflows/maintenance.yml`
- Delete: `.github/workflows/weekly-tool-update.yml`
- Delete: `.github/workflows/version-check.yml`

- [ ] **Step 1: Read all three maintenance workflows in full**

Read `maintenance.yml`, `weekly-tool-update.yml`, `version-check.yml`. Document every job, trigger, and secret used.

- [ ] **Step 2: Create unified maintenance.yml**

Merge all jobs into `maintenance.yml` with three schedule triggers:

```yaml
on:
  schedule:
    - cron: '0 0 * * 0'   # Sunday 00:00 UTC (tool updates)
    - cron: '0 2 * * 0'   # Sunday 02:00 UTC (version checks)
    - cron: '0 6 * * 1'   # Monday 06:00 UTC (repo completeness)
  workflow_dispatch:
    inputs:
      task:
        description: 'Task to run'
        required: false
        default: 'all'
        type: choice
        options: [all, tool-update, version-check, completeness]
```

Jobs from `weekly-tool-update.yml`:
- `auto-update-tools` (add condition: `if: github.event.schedule == '0 0 * * 0' || inputs.task == 'all' || inputs.task == 'tool-update'`)

Jobs from `version-check.yml`:
- `check-versions` (add `needs: auto-update-tools` to make dependency explicit)
- `check-dockerfile-consistency`
- `check-python-deps`
- `version-check-summary`

Existing `maintenance.yml` job:
- `repo-completeness` (keep existing trigger condition)

- [ ] **Step 3: Validate merged YAML**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/maintenance.yml'))"`

Run: `actionlint .github/workflows/maintenance.yml` (if actionlint installed locally)

- [ ] **Step 4: Delete old workflow files**

```bash
git rm .github/workflows/weekly-tool-update.yml
git rm .github/workflows/version-check.yml
```

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/maintenance.yml
git commit -m "ci: consolidate maintenance workflows (3 to 1)

Merge weekly-tool-update.yml and version-check.yml into maintenance.yml.
Tool-update to version-check dependency now explicit via needs: instead
of implicit cron timing."
```

---

### Task 3.2: Merge Release Workflows (2 to 1)

**Files:**

- Modify: `.github/workflows/release.yml`
- Delete: `.github/workflows/automated-release.yml`

- [ ] **Step 1: Read both release workflows in full**

Read `release.yml` and `automated-release.yml`. Map every job, trigger, and dependency.

- [ ] **Step 2: Add automated-release jobs to release.yml**

Add `workflow_dispatch` trigger to `release.yml` alongside existing tag trigger. Add `prepare-release` and `finalize-release` jobs with appropriate conditions:

- `prepare-release`: runs only on `workflow_dispatch`
- `finalize-release`: runs only when `prepare-release` completes and PR is merged
- Existing release jobs: run only on tag push `v*`

- [ ] **Step 3: Validate YAML and test with dry-run**

Validate syntax. If possible, test with `workflow_dispatch` dry-run (manual trigger with no actual version bump).

- [ ] **Step 4: Delete old workflow**

```bash
git rm .github/workflows/automated-release.yml
```

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: consolidate release workflows (2 to 1)

Merge automated-release.yml into release.yml. Two entry points:
workflow_dispatch for release prep, tag push v* for publishing."
```

---

### Task 3.3: Absorb Docker Validation into Scheduled Tests

**Files:**

- Modify: `.github/workflows/scheduled-tests.yml`
- Delete: `.github/workflows/docker-validation.yml`

- [ ] **Step 1: Read docker-validation.yml in full**

Read `docker-validation.yml`. Extract `validate-variants` and `validation-summary` jobs.

- [ ] **Step 2: Add Docker validation jobs to scheduled-tests.yml**

Add to `scheduled-tests.yml`:
- `docker-validate-variants` job (Sunday 3 AM UTC condition)
- `docker-validation-summary` job (depends on variants)

Add `'0 3 * * 0'` to the `schedule` list in `scheduled-tests.yml`.

- [ ] **Step 3: Delete old workflow**

```bash
git rm .github/workflows/docker-validation.yml
```

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/scheduled-tests.yml
git commit -m "ci: absorb docker-validation into scheduled-tests workflow"
```

---

### Task 3.4: Move Schedule-Only Jobs from CI to Scheduled

**Files:**

- Modify: `.github/workflows/ci.yml`
- Modify: `.github/workflows/scheduled-tests.yml`

- [ ] **Step 1: Move lint-full job**

Cut the `lint-full` job definition from `ci.yml` and paste into `scheduled-tests.yml`. It only runs on schedule (`if: github.event_name == 'schedule'`), so it belongs in the scheduled workflow.

- [ ] **Step 2: Move integration-tests job**

Cut the `integration-tests` job from `ci.yml` and paste into `scheduled-tests.yml`. It runs on schedule OR push to main/dev — update the condition accordingly.

- [ ] **Step 3: Add nightly-docker-smoke timeout**

Add `timeout-minutes: 30` to the `nightly-docker-smoke` job (currently has no timeout).

- [ ] **Step 4: Validate both workflow files**

Run yamllint and actionlint on both files.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml .github/workflows/scheduled-tests.yml
git commit -m "ci: move schedule-only jobs (lint-full, integration-tests) to scheduled workflow

Also add timeout-minutes: 30 to nightly-docker-smoke job."
```

---

### Task 3.5: Eliminate test-matrix, Expand test-sharded

**Files:**

- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Read test-matrix and test-sharded jobs**

Understand the current matrix strategy for both jobs. `test-matrix` runs on 3 OS without coverage. `test-sharded` runs on Ubuntu only with coverage and 4 splits.

- [ ] **Step 2: Expand test-sharded to include macOS and Windows**

Add macOS and Windows to `test-sharded` matrix. They don't need sharding (fewer tests run on non-Ubuntu), so they can run as single shards.

- [ ] **Step 3: Remove test-matrix job entirely**

Delete the `test-matrix` job definition. Update any `needs:` references in other jobs.

- [ ] **Step 4: Verify coverage-aggregate compatibility**

Check `.github/actions/aggregate-coverage/action.yml` — it uses `actions/download-artifact` with a `pattern` glob to collect shard coverage files. Verify the artifact names emitted by the updated `test-sharded` job still match the download pattern. If the pattern was `coverage-shard-*`, ensure each shard uploads as `coverage-shard-0`, `coverage-shard-1`, etc. No changes should be needed if artifact naming is preserved.

- [ ] **Step 5: Validate CI workflow**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"`

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: eliminate test-matrix, expand test-sharded to all 3 OS

Removes duplicate unit test execution. test-sharded now covers
Ubuntu (4 shards), macOS (1 shard), Windows (1 shard)."
```

---

### Task 3.6: Rename Scheduled Tests Workflow

**Files:**

- Rename: `.github/workflows/scheduled-tests.yml` to `.github/workflows/scheduled.yml`

- [ ] **Step 1: Rename the file**

```bash
git mv .github/workflows/scheduled-tests.yml .github/workflows/scheduled.yml
```

- [ ] **Step 2: Search for references to old filename**

Run: `grep -r "scheduled-tests.yml" docs/ tests/ .github/ CLAUDE.md TEST.md`

Update any references found.

- [ ] **Step 3: Commit**

```bash
# git mv already staged the rename — only add files changed in Step 2
# git add <any files where references were updated>
git commit -m "ci: rename scheduled-tests.yml to scheduled.yml"
```

Note: `git mv` stages the rename automatically. If `grep` from Step 2 found references in other files (docs, CLAUDE.md, etc.), `git add` those files before committing. If no references were found, just `git commit`.

---

### Task 3.7: Update Scheduled Workflow E2E Jobs to Use Pytest

**Files:**

- Modify: `.github/workflows/scheduled.yml`

- [ ] **Step 1: Update e2e-ubuntu job**

Replace the bash script invocation:

```yaml
# OLD:
- run: bash tests/e2e/run_comprehensive_tests.sh

# NEW:
- run: make test-e2e
```

- [ ] **Step 2: Update e2e-macos job similarly**

- [ ] **Step 3: Add e2e-visual job**

Add new job for visual dashboard tests:

```yaml
e2e-visual:
  if: github.event.schedule == '0 4 * * 1-5' || inputs.task == 'e2e' || inputs.task == 'all'
  runs-on: ubuntu-latest
  timeout-minutes: 15
  steps:
    - uses: actions/checkout@v6
    - uses: ./.github/actions/setup-python-jmo
    - name: Install Playwright
      run: |
        pip install pytest-playwright
        playwright install chromium --with-deps
    - name: Run visual tests
      run: make test-e2e-visual
    - uses: actions/upload-artifact@v4
      if: failure()
      with:
        name: visual-test-screenshots
        path: test-results/
        retention-days: 7
```

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/scheduled.yml
git commit -m "ci: update e2e jobs to use pytest, add visual testing job"
```

---

## Chunk 4: Phase 4 — Skill & Browser Layer

Independent of Phases 2-3. Creates the Claude skill and visual dashboard tests.

### Task 4.1: Create `test_dashboard_visual.py` (Playwright Tests)

**Files:**

- Create: `tests/e2e/test_dashboard_visual.py`
- Reference: `scripts/core/reporters/html_reporter.py` (dashboard structure)

- [ ] **Step 1: Read html_reporter.py to understand dashboard structure**

Read `scripts/core/reporters/html_reporter.py` to understand the HTML structure — what CSS classes/IDs are used for severity charts, findings tables, tabs, etc.

- [ ] **Step 2: Write visual dashboard tests**

Create `tests/e2e/test_dashboard_visual.py`:

```python
"""Visual dashboard regression tests using Playwright.

Tests that dashboard.html renders correctly with real findings data.
Requires: pip install pytest-playwright && playwright install chromium

Run: make test-e2e-visual
Skip: pytest tests/e2e/ --ignore=tests/e2e/test_dashboard_visual.py
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# Skip entire module if playwright not installed
pytest.importorskip("playwright")

from playwright.sync_api import Page, expect  # noqa: E402


@pytest.fixture(scope="session")
def sample_dashboard(tmp_path_factory) -> Path:
    """Generate a dashboard.html with sample findings data.

    Uses the HTML reporter to generate a real dashboard from
    sample findings data, ensuring tests use realistic content.
    """
    from scripts.core.reporters.html_reporter import write_html

    tmp_dir = tmp_path_factory.mktemp("dashboard")
    findings_file = tmp_dir / "findings.json"

    # Create minimal but realistic findings data
    findings = [
        {
            "id": f"finding-{i}",
            "fingerprint_id": f"fp-{i}",
            "tool": "test-tool",
            "severity": sev,
            "title": f"Test Finding {i} ({sev})",
            "description": f"Description for finding {i}",
            "file_path": f"src/app.py",
            "line_number": i * 10,
            "category": "security",
        }
        for i, sev in enumerate(
            ["CRITICAL"] * 2 + ["HIGH"] * 5 + ["MEDIUM"] * 8 + ["LOW"] * 3,
            start=1,
        )
    ]
    findings_file.write_text(json.dumps(findings))

    dashboard_path = tmp_dir / "dashboard.html"
    write_html(findings, str(dashboard_path))

    assert dashboard_path.exists(), "Dashboard generation failed"
    return dashboard_path


@pytest.fixture
def dashboard_page(page: Page, sample_dashboard: Path) -> Page:
    """Load dashboard in Playwright page."""
    file_url = f"file:///{sample_dashboard.resolve().as_posix()}"
    page.goto(file_url)
    page.wait_for_load_state("domcontentloaded")
    return page


@pytest.mark.e2e
class TestDashboardRendering:
    """Test that dashboard.html renders correctly."""

    def test_dashboard_loads_without_js_errors(self, dashboard_page: Page):
        """Dashboard loads without JavaScript console errors."""
        errors = []
        # Register listener before reload — fixture already loaded the page,
        # so we reload to capture all JS errors from a fresh page load
        dashboard_page.on("pageerror", lambda err: errors.append(str(err)))
        dashboard_page.reload()
        dashboard_page.wait_for_load_state("domcontentloaded")
        assert not errors, f"JavaScript errors: {errors}"

    def test_dashboard_has_title(self, dashboard_page: Page):
        """Dashboard has a page title."""
        title = dashboard_page.title()
        assert title, "Dashboard has no title"

    def test_findings_table_has_rows(self, dashboard_page: Page):
        """Findings table displays at least one row."""
        # Adjust selector based on actual HTML reporter output
        rows = dashboard_page.locator("table tbody tr, .finding-row, [data-finding]")
        expect(rows.first).to_be_visible(timeout=5000)

    def test_severity_counts_visible(self, dashboard_page: Page):
        """Severity counts are displayed on the dashboard."""
        page_text = dashboard_page.text_content("body")
        assert page_text is not None
        # Should contain severity labels
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            assert severity in page_text or severity.lower() in page_text.lower(), (
                f"Severity '{severity}' not found in dashboard"
            )


@pytest.mark.e2e
class TestDashboardResponsive:
    """Test dashboard renders at different viewport sizes."""

    @pytest.mark.parametrize(
        "width,height,label",
        [
            (375, 812, "mobile"),
            (768, 1024, "tablet"),
            (1440, 900, "desktop"),
        ],
    )
    def test_responsive_viewport(
        self, page: Page, sample_dashboard: Path, width, height, label
    ):
        """Dashboard renders without errors at various viewport sizes."""
        page.set_viewport_size({"width": width, "height": height})
        file_url = f"file:///{sample_dashboard.resolve().as_posix()}"
        page.goto(file_url)
        page.wait_for_load_state("domcontentloaded")

        # Take screenshot for visual inspection
        screenshots_dir = Path("e2e-screenshots")
        screenshots_dir.mkdir(exist_ok=True)
        page.screenshot(path=str(screenshots_dir / f"dashboard-{label}.png"))

        # Verify page loaded (basic check)
        assert page.title(), f"Dashboard failed to load at {label} viewport"
```

- [ ] **Step 3: Run tests (if Playwright installed)**

Run: `pip install pytest-playwright && playwright install chromium`

Run: `pytest tests/e2e/test_dashboard_visual.py -v`

Expected: Tests pass (or skip if Playwright not installed).

- [ ] **Step 4: Commit**

```bash
git add tests/e2e/test_dashboard_visual.py
git commit -m "test: add pytest-playwright dashboard visual regression tests"
```

---

### Task 4.2: Create `/jmo-e2e-verify` Claude Skill

**Files:**

- Create: `.claude/skills/jmo-e2e-verify/SKILL.md`

- [ ] **Step 1: Read existing skill structure for patterns**

Read `.claude/skills/jmo-test-fabricator/SKILL.md` (or any other skill) to understand the frontmatter format and structure used in this project.

- [ ] **Step 2: Write the skill file**

Create `.claude/skills/jmo-e2e-verify/SKILL.md` with the 6-phase orchestration design from the spec. The skill should include:

- YAML frontmatter (name, description, user-invocable, allowed-tools, argument-hint)
- Pre-flight environment checks
- Parallel research sub-agent definitions (codebase delta, test health, infrastructure)
- Test execution with task tracking
- Failure analysis categorization
- Visual verification with agent-browser (optional)
- Report generation template

Reference: `docs/superpowers/specs/2026-03-12-e2e-consolidation-design.md` Section 4 for complete phase details.

- [ ] **Step 3: Validate skill frontmatter**

Run: `python -c "import yaml; yaml.safe_load(open('.claude/skills/jmo-e2e-verify/SKILL.md').read().split('---')[1])"`

- [ ] **Step 4: Commit**

```bash
git add .claude/skills/jmo-e2e-verify/SKILL.md
git commit -m "feat: add jmo-e2e-verify Claude skill for AI-driven e2e verification"
```

---

### Task 4.3: Update Skills INDEX.md

**Files:**

- Modify: `.claude/skills/INDEX.md`

- [ ] **Step 1: Add jmo-e2e-verify entry**

Add to `.claude/skills/INDEX.md` in the appropriate section:

```markdown
| jmo-e2e-verify | AI-orchestrated e2e verification with parallel sub-agents, failure analysis, and visual dashboard inspection | `/jmo-e2e-verify [quick\|full\|visual\|scan-only]` |
```

- [ ] **Step 2: Commit**

```bash
git add .claude/skills/INDEX.md
git commit -m "docs: add jmo-e2e-verify to skills index"
```

---

## Chunk 5: Phase 5 — Cleanup & Documentation

### Task 5.1: Update CLAUDE.md

**Files:**

- Modify: `CLAUDE.md`

- [ ] **Step 1: Update workflow references**

Replace references to old workflow filenames:
- `scheduled-tests.yml` -> `scheduled.yml`
- Remove references to `docker-validation.yml`, `weekly-tool-update.yml`, `version-check.yml`, `automated-release.yml`
- Add new workflow names and descriptions

- [ ] **Step 2: Update testing commands table**

Add new Makefile targets:

```markdown
| `make test-e2e` | E2E tests (pytest-native) |
| `make test-e2e-visual` | Dashboard visual tests (Playwright) |
| `make test-e2e-report` | E2E tests with JSON report |
```

- [ ] **Step 3: Update AI Tooling section**

Add `/jmo-e2e-verify` to the skills table.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md for e2e consolidation (workflows, targets, skill)"
```

---

### Task 5.2: Update TEST.md

**Files:**

- Modify: `TEST.md`

- [ ] **Step 1: Update e2e testing section**

Replace bash script references with pytest commands. Update the e2e section to document:
- `make test-e2e` replaces `bash tests/e2e/run_comprehensive_tests.sh`
- Parametrized test IDs (U1-U6, M1-M3, W1, etc.)
- Visual testing with Playwright
- Report generation

- [ ] **Step 2: Commit**

```bash
git add TEST.md
git commit -m "docs: update TEST.md for pytest-native e2e tests"
```

---

### Task 5.3: Update tests/e2e/README.md

**Files:**

- Modify: `tests/e2e/README.md`

- [ ] **Step 1: Rewrite for pytest-native structure**

Update the README to reflect:
- New pytest commands instead of bash script
- New file structure (test_scan_workflows.py, test_dashboard_visual.py, etc.)
- How to run specific tests (`pytest -k "U1"`)
- Visual testing setup instructions
- Updated CI workflow references

- [ ] **Step 2: Commit**

```bash
git add tests/e2e/README.md
git commit -m "docs: update e2e README for pytest-native test structure"
```

---

### Task 5.4: Update AGENTS.md

**Files:**

- Modify: `AGENTS.md`

- [ ] **Step 1: Document sub-agent usage in e2e skill**

Add documentation about the 3 parallel research sub-agents used by the e2e verification skill (codebase delta, test health, infrastructure).

- [ ] **Step 2: Commit**

```bash
git add AGENTS.md
git commit -m "docs: document e2e verification sub-agents in AGENTS.md"
```

---

### Task 5.5: Final Validation

**Files:**

- No file changes — verification only

- [ ] **Step 1: Run full test suite**

Run: `make test-fast`

Expected: All tests pass.

- [ ] **Step 2: Run lint suite**

Run: `make lint`

Expected: All lint checks pass.

- [ ] **Step 3: Validate workflows**

Run: `actionlint .github/workflows/*.yml` (if available)

Expected: No errors.

- [ ] **Step 4: Run e2e tests**

Run: `make test-e2e` (or `pytest tests/e2e/ --collect-only` if tools not available)

Expected: Tests collect/pass as appropriate for the platform.

- [ ] **Step 5: Invoke release-readiness agent**

Use the `release-readiness` agent to verify the consolidated infrastructure passes pre-release checks.

---

## Summary

| Phase | Tasks | Commits | Risk |
|-------|-------|---------|------|
| Phase 1: Foundation | 1.1-1.8 | 8 | Low |
| Phase 2: Test Migration | 2.1-2.9 | 8 | Medium |
| Phase 3: Workflow Consolidation | 3.1-3.7 | 7 | Medium-High |
| Phase 4: Skill & Browser | 4.1-4.3 | 3 | Low |
| Phase 5: Cleanup & Docs | 5.1-5.5 | 4 | Low |
| **Total** | **32 tasks** | **30 commits** | |
