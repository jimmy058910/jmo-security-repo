# Implementation Plan - E2E Testing Suite


## Phase 1: Foundation & Fixtures

- [ ] Task: Create E2E directory structure (`tests/e2e/`) and configuration.
    - [ ] Sub-task: Create `tests/e2e/conftest.py` with base fixtures.
    - [ ] Sub-task: Update `pytest.ini` to include `e2e` marker configuration.

- [ ] Task: Create `tests/e2e/fixtures/vulnerable-repo` with multi-language samples.
    - [ ] Sub-task: Add Python sample (Bandit/Safety triggers).
    - [ ] Sub-task: Add JS sample (npm audit/ESLint triggers).
    - [ ] Sub-task: Add IaC sample (Terraform/K8s misconfigs).
    - [ ] Sub-task: Add Secrets sample (Fake API keys).

- [ ] Task: Conductor - User Manual Verification 'Foundation & Fixtures' (Protocol in workflow.md)


## Phase 2: CLI & Repo Scanning

- [ ] Task: Implement `test_cli_basics.py`.
    - [ ] Sub-task: Write Tests for `jmo --version`, `jmo --help`.
    - [ ] Sub-task: Implement Feature: Basic CLI smoke tests.

- [ ] Task: Implement `test_scan_repo.py`.
    - [ ] Sub-task: Write Tests for `jmo scan --target . --profile fast`.
    - [ ] Sub-task: Implement Feature: Repository scan verification.
    - [ ] Sub-task: Verify JSON output schema validity.

- [ ] Task: Conductor - User Manual Verification 'CLI & Repo Scanning' (Protocol in workflow.md)


## Phase 3: Advanced Scenarios & Outputs

- [ ] Task: Implement `test_profiles.py`.
    - [ ] Sub-task: Write Tests for `slim` and `balanced` profiles.
    - [ ] Sub-task: Implement Feature: Profile-specific tool execution verification.

- [ ] Task: Implement `test_outputs.py`.
    - [ ] Sub-task: Write Tests for HTML dashboard generation.
    - [ ] Sub-task: Implement Feature: HTML asset existence check.
    - [ ] Sub-task: Write Tests for SARIF output.
    - [ ] Sub-task: Implement Feature: SARIF schema validation.

- [ ] Task: Implement `test_error_handling.py`.
    - [ ] Sub-task: Write Tests for missing tool behavior.
    - [ ] Sub-task: Implement Feature: Graceful failure verification.

- [ ] Task: Conductor - User Manual Verification 'Advanced Scenarios & Outputs' (Protocol in workflow.md)


## Phase 4: CI Integration

- [ ] Task: Update GitHub Actions workflow (`.github/workflows/ci.yml`).
    - [ ] Sub-task: Add E2E job definition.
    - [ ] Sub-task: Configure artifact upload for E2E reports.

- [ ] Task: Verify Cross-Platform execution.
    - [ ] Sub-task: Validate on Windows runner.
    - [ ] Sub-task: Validate on Linux runner.

- [ ] Task: Conductor - User Manual Verification 'CI Integration' (Protocol in workflow.md)
