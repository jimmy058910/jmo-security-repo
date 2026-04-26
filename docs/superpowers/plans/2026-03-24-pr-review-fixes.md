# PR #223 Review Fixes Implementation Plan

> **STATUS: COMPLETED** — This plan was fully executed. Retained for historical reference.
>
> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all 16 issues identified by PR review agents (3 critical, 9 high/important, 4 medium).

**Architecture:** Three groups — test correctness fixes (issues #3, #9, #10, #11, #16), workflow error-handling hardening (issues #1, #2, #4, #5, #6, #7, #8, #12, #13, #14, #15), production code fix (issue #6-html).

**Tech Stack:** Python 3.12+, pytest, GitHub Actions YAML, bash

**Source:** PR review report from `pr-review-toolkit` agents (code-reviewer, pr-test-analyzer, silent-failure-hunter)

---

## Chunk 1: Test Correctness Fixes (Critical + Important)

### Task 1: Fix `validate_basic_scan` and `validate_multi_target` paths

**Files:**

- Modify: `tests/e2e/conftest.py:95-128`

- [ ] **Step 1: Fix paths in `validate_basic_scan`**

Change all three file checks from `results_dir / "file"` to `results_dir / "summaries" / "file"`:

```python
def validate_basic_scan(results_dir: Path) -> None:
    """Validate basic scan output files exist and are valid JSON."""
    summaries = results_dir / "summaries"
    findings_file = summaries / "findings.json"
    assert findings_file.exists(), f"findings.json not found in {summaries}"

    data = json.loads(findings_file.read_text())
    # v1.0.0: findings.json uses metadata wrapper {"meta": {...}, "findings": [...]}
    if isinstance(data, dict) and "findings" in data:
        findings = data["findings"]
    elif isinstance(data, list):
        findings = data
    else:
        raise AssertionError(f"findings.json has unexpected format: {type(data)}")
    assert isinstance(findings, list), "findings must be a list"

    summary_file = summaries / "SUMMARY.md"
    assert summary_file.exists(), f"SUMMARY.md not found in {summaries}"

    dashboard_file = summaries / "dashboard.html"
    assert dashboard_file.exists(), f"dashboard.html not found in {summaries}"
```

- [ ] **Step 2: Fix paths in `validate_multi_target`**

```python
def validate_multi_target(results_dir: Path) -> None:
    """Validate multi-target scan output."""
    validate_basic_scan(results_dir)

    summaries = results_dir / "summaries"
    findings_file = summaries / "findings.json"
    data = json.loads(findings_file.read_text())

    # Handle both wrapped and raw formats (same logic as validate_basic_scan)
    if isinstance(data, dict) and "findings" in data:
        findings = data["findings"]
    elif isinstance(data, list):
        findings = data
    else:
        raise AssertionError(f"findings.json has unexpected format: {type(data)}")

    if findings:
        fingerprints = [
            f.get("fingerprint_id") for f in findings if f.get("fingerprint_id")
        ]
        assert len(fingerprints) == len(
            set(fingerprints)
        ), "Duplicate fingerprint IDs found"
```

- [ ] **Step 3: Verify tests still collect**

Run: `pytest tests/e2e/test_scan_workflows.py --collect-only -q`

Expected: 10 tests collected.

- [ ] **Step 4: Commit**

```bash
git add tests/e2e/conftest.py
git commit -m "fix: correct validate_basic_scan paths to results/summaries/"
```

---

### Task 2: Fix CI gating test assertions

**Files:**

- Modify: `tests/e2e/test_ci_gating.py:51-83`

- [ ] **Step 1: Strengthen assertions**

The first test should verify that exit code is 0 or 1 (not 2+). The second test should assert `rc == 0` since `--fail-on CRITICAL` with only MEDIUM findings should pass:

```python
    def test_fail_on_high_with_vulnerable_target(self, tmp_path):
        """U12: CI mode exits 1 when HIGH findings present."""
        results_dir = tmp_path / "results"
        results_dir.mkdir()

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "scripts.cli.jmo",
                "ci",
                "--repo",
                str(E2E_FIXTURES / "python"),
                "--profile",
                "fast",
                "--fail-on",
                "HIGH",
                "--allow-missing-tools",
                "--results-dir",
                str(results_dir),
            ],
            capture_output=True,
            text=True,
            timeout=900,
        )

        # Exit code 2+ means error (not a gating decision)
        assert result.returncode in (0, 1), (
            f"CI gating returned unexpected exit code {result.returncode}.\n"
            f"stderr: {result.stderr[:500]}"
        )

        # If tools produced findings, verify gating behavior
        findings_file = results_dir / "summaries" / "findings.json"
        if findings_file.exists():
            data = json.loads(findings_file.read_text())
            findings = data.get("findings", data) if isinstance(data, dict) else data
            high_or_above = [
                f for f in findings
                if f.get("severity", "").upper() in ("HIGH", "CRITICAL")
            ]
            if high_or_above:
                assert result.returncode == 1, (
                    f"Found {len(high_or_above)} HIGH+ findings but exit code was 0"
                )

    def test_fail_on_critical_passes_with_medium_only(self, tmp_path):
        """CI mode exits 0 when only MEDIUM findings and threshold is CRITICAL."""
        results_dir = tmp_path / "results"
        results_dir.mkdir()

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "scripts.cli.jmo",
                "ci",
                "--repo",
                str(E2E_FIXTURES / "python"),
                "--profile",
                "fast",
                "--fail-on",
                "CRITICAL",
                "--allow-missing-tools",
                "--results-dir",
                str(results_dir),
            ],
            capture_output=True,
            text=True,
            timeout=900,
        )

        # With --fail-on CRITICAL and no CRITICAL findings, should exit 0
        # (exit 1 only if CRITICAL findings exist)
        assert result.returncode in (0, 1), (
            f"Unexpected exit code {result.returncode}"
        )

        # Verify the contract: if rc==1, there must be CRITICAL findings
        if result.returncode == 1:
            findings_file = results_dir / "summaries" / "findings.json"
            assert findings_file.exists(), "Exit 1 but no findings file"
            data = json.loads(findings_file.read_text())
            findings = data.get("findings", data) if isinstance(data, dict) else data
            critical = [
                f for f in findings if f.get("severity", "").upper() == "CRITICAL"
            ]
            assert critical, (
                "Exit code 1 with --fail-on CRITICAL but no CRITICAL findings found"
            )
```

- [ ] **Step 2: Add `import json` at top of file**

Add `import json` to the imports if not already present.

- [ ] **Step 3: Verify tests collect**

Run: `pytest tests/e2e/test_ci_gating.py --collect-only`

- [ ] **Step 4: Commit**

```bash
git add tests/e2e/test_ci_gating.py
git commit -m "fix: strengthen CI gating tests to verify actual gating contract"
```

---

### Task 3: Fix U6 to test `--images-file` batch scanning

**Files:**

- Modify: `tests/e2e/test_scan_workflows.py:132-147`

- [ ] **Step 1: Remove U6 from parametrized list**

Delete the U6 `pytest.param(...)` entry from `SCAN_WORKFLOWS` (it requires `tmp_path` which the parametrized test doesn't have access to).

- [ ] **Step 2: Add a standalone U6 test function**

Add after the `test_scan_workflow` function:

```python
@pytest.mark.e2e
@pytest.mark.slow
@requires_docker
def test_batch_images_file(jmo_runner, tmp_path):
    """U6: Batch image scan using --images-file (replaces single-image duplicate)."""
    if current_platform() != "linux":
        pytest.skip("U6 is for linux")

    images_file = tmp_path / "batch-images.txt"
    images_file.write_text(
        f"{_get_test_image()}\n"
        "nginx:alpine\n"
        "redis:alpine\n"
    )

    rc, stdout, stderr, results_dir = jmo_runner([
        "ci", "--images-file", str(images_file),
        "--tools", "trivy,syft", "--allow-missing-tools",
    ])

    assert rc in (0, 1), (
        f"U6 batch images failed with exit code {rc}.\n"
        f"stderr: {stderr[:500]}"
    )
    validate_basic_scan(results_dir)
```

- [ ] **Step 3: Verify tests collect**

Run: `pytest tests/e2e/test_scan_workflows.py --collect-only -q`

Expected: 9 parametrized + 1 standalone = 10 tests.

- [ ] **Step 4: Commit**

```bash
git add tests/e2e/test_scan_workflows.py
git commit -m "fix: U6 now tests --images-file batch scanning (was duplicate of U2)"
```

---

### Task 4: Add pytest-timeout to deep profile test

**Files:**

- Modify: `tests/e2e/test_advanced_targets.py:68`

- [ ] **Step 1: Add timeout decorator**

Add `@pytest.mark.timeout(4500)` to `test_deep_profile_scan`:

```python
    @pytest.mark.timeout(4500)  # 75 min — deep profile can take 40-70 min
    def test_deep_profile_scan(self, jmo_runner):
```

- [ ] **Step 2: Commit**

```bash
git add tests/e2e/test_advanced_targets.py
git commit -m "fix: add pytest-timeout(4500) to deep profile test to prevent early kill"
```

---

### Task 5: Improve wizard test assertions

**Files:**

- Modify: `tests/e2e/test_wizard_workflows.py`

- [ ] **Step 1: Strengthen wizard script assertions**

For both `test_wizard_emit_script_macos` and `test_wizard_emit_script_windows`, add stronger content checks:

After `assert script_path.exists()`, add:

```python
        content = script_path.read_text()
        # Script must contain actual jmo scan/ci command, not just a mention
        assert any(
            cmd in content for cmd in ["jmo scan", "jmo ci", "scripts.cli.jmo"]
        ), f"Emitted script doesn't contain a jmo scan command:\n{content[:200]}"
        # Script should reference the profile
        assert "fast" in content, "Emitted script doesn't reference the profile"
```

- [ ] **Step 2: Commit**

```bash
git add tests/e2e/test_wizard_workflows.py
git commit -m "fix: strengthen wizard test assertions to verify scan command in emitted script"
```

---

## Chunk 2: Workflow Error-Handling Hardening

### Task 6: Fix trufflehog-scan `|| true` masking real errors

**Files:**

- Modify: `.github/actions/trufflehog-scan/action.yml:29-52`

- [ ] **Step 1: Add post-install verification to Install step**

```yaml
    - name: Install TruffleHog
      shell: bash
      env:
        TRUFFLEHOG_VERSION: ${{ inputs.trufflehog-version }}
      run: |
        set -euo pipefail
        INSTALL_URL="https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh"
        curl -sSfL "$INSTALL_URL" | sh -s -- -b /usr/local/bin "v${TRUFFLEHOG_VERSION}"
        if ! command -v trufflehog >/dev/null 2>&1; then
          echo "::error::TruffleHog installation failed — binary not found after install"
          exit 1
        fi
        echo "TruffleHog $(trufflehog --version 2>&1 | head -1) installed successfully"
```

- [ ] **Step 2: Replace `|| true` with proper exit code handling in Run step**

```yaml
    - name: Run TruffleHog scan
      shell: bash
      env:
        SCAN_PATH: ${{ inputs.scan-path }}
        EXCLUDE_PATHS: ${{ inputs.exclude-paths }}
        FAIL_ON_VERIFIED: ${{ inputs.fail-on-verified }}
      run: |
        set -euo pipefail

        if ! trufflehog filesystem "$SCAN_PATH" \
          --json \
          --exclude-paths "$EXCLUDE_PATHS" \
          --only-verified > trufflehog-results.json 2>trufflehog-stderr.txt; then
          EXIT_CODE=$?
          echo "::error::TruffleHog exited with code ${EXIT_CODE}"
          cat trufflehog-stderr.txt >&2
          exit "${EXIT_CODE}"
        fi

        if [ ! -s trufflehog-results.json ]; then
          echo "TruffleHog scan complete. Verified secrets: 0"
          exit 0
        fi

        VERIFIED=$({ jq -r 'select(.Verified == true)' trufflehog-results.json || true; } | wc -l)

        if [ "$VERIFIED" -gt 0 ] && [ "$FAIL_ON_VERIFIED" = "true" ]; then
          echo "::error::Found $VERIFIED verified secrets! Review trufflehog-results.json"
          exit 1
        fi

        echo "TruffleHog scan complete. Verified secrets: $VERIFIED"
```

- [ ] **Step 3: Validate YAML**

Run: `python -c "import yaml; yaml.safe_load(open('.github/actions/trufflehog-scan/action.yml'))"`

- [ ] **Step 4: Commit**

```bash
git add .github/actions/trufflehog-scan/action.yml
git commit -m "fix: replace || true with proper error handling in trufflehog-scan action"
```

---

### Task 7: Fix notify-failure `2>/dev/null` hiding auth errors

**Files:**

- Modify: `.github/actions/notify-failure/action.yml`

- [ ] **Step 1: Remove `2>/dev/null` and add error logging**

Replace the `gh issue list` call to log errors instead of hiding them:

```bash
        # Log errors instead of suppressing — failure notification path must be transparent
        if ! EXISTING=$(gh issue list \
            --repo "$GITHUB_REPOSITORY" \
            --state open \
            --search "\"${TITLE}\" in:title" \
            --json number \
            --jq '.[0].number'); then
          echo "::warning::Could not query existing issues (gh issue list failed). Creating new issue."
          EXISTING=""
        fi

        if [ -n "$EXISTING" ] && [ "$EXISTING" != "null" ]; then
          echo "Adding comment to existing issue #${EXISTING}"
          gh issue comment "$EXISTING" --repo "$GITHUB_REPOSITORY" --body "$BODY"
        else
          echo "Creating new issue: ${TITLE}"
          gh issue create \
            --repo "$GITHUB_REPOSITORY" \
            --title "$TITLE" \
            --body "$BODY" \
            --label "$ISSUE_LABEL" \
            || echo "::error::Failed to create failure issue. Check token permissions (issues: write scope required)."
        fi
```

- [ ] **Step 2: Validate YAML**

Run: `python -c "import yaml; yaml.safe_load(open('.github/actions/notify-failure/action.yml'))"`

- [ ] **Step 3: Commit**

```bash
git add .github/actions/notify-failure/action.yml
git commit -m "fix: remove 2>/dev/null from notify-failure, log errors transparently"
```

---

### Task 8: Fix `changelog_entry` input injection in release.yml

**Files:**

- Modify: `.github/workflows/release.yml:131,191,214`

- [ ] **Step 1: Add `CHANGELOG_ENTRY` to env blocks**

Three steps in the `prepare-release` job use `${{ inputs.changelog_entry }}` inline in `run:` blocks. Add `CHANGELOG_ENTRY: ${{ inputs.changelog_entry }}` to the `env:` block of each step, then replace the inline expression with `"$CHANGELOG_ENTRY"`:

**Line 131** (Create changelog entry step): Replace `echo "${{ inputs.changelog_entry }}"` with `echo "$CHANGELOG_ENTRY"`

**Line 214** (Create PR body step): Same — replace `echo "${{ inputs.changelog_entry }}"` with `echo "$CHANGELOG_ENTRY"`

**Line 191** (Update commit message step): Replace `sed -i "s/\$CHANGELOG_ENTRY/${{ inputs.changelog_entry }}/g"` with a Python one-liner that avoids sed delimiter issues:

```yaml
      - name: Update commit message
        env:
          CHANGELOG_ENTRY: ${{ inputs.changelog_entry }}
        run: |
          python3 -c "
          import os, pathlib
          msg = pathlib.Path('commit_message.txt').read_text()
          entry = os.environ['CHANGELOG_ENTRY']
          msg = msg.replace('$CHANGELOG_ENTRY', entry)
          pathlib.Path('commit_message.txt').write_text(msg)
          "
```

Each of these steps already has a `run:` block — add `env: CHANGELOG_ENTRY: ...` to each one that uses the input.

- [ ] **Step 2: Validate YAML**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"`

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "fix: route changelog_entry through env var to prevent injection in sed"
```

---

### Task 9: Add missing `needs` to `e2e-summary` job

**Files:**

- Modify: `.github/workflows/scheduled.yml:822`

- [ ] **Step 1: Add `e2e-macos` and `tool-contract-tests` to needs**

```yaml
  e2e-summary:
    name: E2E Test Summary
    runs-on: ubuntu-latest
    needs: [e2e-ubuntu, e2e-macos, e2e-tool-integration, tool-contract-tests, e2e-visual]
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/scheduled.yml
git commit -m "fix: add e2e-macos and tool-contract-tests to e2e-summary needs"
```

---

### Task 10: Add placeholder validation to html_reporter fallback chain

**Files:**

- Modify: `scripts/core/reporters/html_reporter.py:55-59`

- [ ] **Step 1: Add warning log when using fallback HTML**

After the `else: _write_fallback_html(...)` branch, add a logging import and warning. Before the `if total <= INLINE_THRESHOLD:` block, add a placeholder check:

```python
    # Verify placeholder exists before attempting replacement
    placeholder = "window.__FINDINGS__ = []"
    if placeholder not in template:
        import logging

        logging.getLogger(__name__).warning(
            "Template does not contain expected placeholder '%s'. "
            "Dashboard may not display findings correctly.",
            placeholder,
        )
        _write_fallback_html(findings, p)
        return

    # Decide: Inline vs External mode
```

Also add a warning log to the fallback branch:

```python
        else:
            # Last resort: use simple fallback HTML
            import logging

            logging.getLogger(__name__).warning(
                "React dashboard build not found. "
                "Run 'npm run build' in scripts/dashboard/ for the interactive dashboard. "
                "Using fallback HTML."
            )
            _write_fallback_html(findings, p)
            return
```

- [ ] **Step 2: Commit**

```bash
git add scripts/core/reporters/html_reporter.py
git commit -m "fix: add placeholder validation and warning log to html_reporter fallback chain"
```

---

### Task 11: Remove redundant `|| true` from e2e test steps in scheduled.yml

**Files:**

- Modify: `.github/workflows/scheduled.yml:548,621`

Note: Line 915 (performance benchmarks) is handled separately in Task 14 to avoid overlapping edits.

- [ ] **Step 1: Remove `|| true` from e2e-ubuntu test step (line 548)**

Change:

```yaml
            2>&1 | tee "$RESULTS_DIR/test.log" || true
```

To:

```yaml
            2>&1 | tee "$RESULTS_DIR/test.log"
```

`continue-on-error: true` on the step already handles non-zero exit codes correctly while preserving `steps.<id>.outcome == 'failure'` for downstream checks.

- [ ] **Step 2: Same for e2e-macos test step (line 621)**

- [ ] **Step 3: Validate YAML**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/scheduled.yml'))"`

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/scheduled.yml
git commit -m "fix: remove redundant || true from e2e steps (continue-on-error suffices)"
```

---

### Task 12: Fix `version-check-summary` missing `check-python-deps` result

**Files:**

- Modify: `.github/workflows/maintenance.yml:380-392`

- [ ] **Step 1: Add missing result check**

After the `check-dockerfile-consistency` check, add:

```bash
          if [ "${{ needs.check-python-deps.result }}" == "failure" ]; then
            echo "::error::Python dependency check failed"
            exit 1
          fi
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/maintenance.yml
git commit -m "fix: add check-python-deps.result to version-check-summary"
```

---

### Task 13: Fix `update_versions.py || echo` swallowing failures

**Files:**

- Modify: `.github/workflows/maintenance.yml:250`

- [ ] **Step 1: Replace `|| echo` with proper error handling**

```yaml
      - name: Check for latest versions
        id: check
        run: |
          set -euo pipefail
          if ! python3 scripts/dev/update_versions.py --check-latest > version_check_output.txt 2>&1; then
            cat version_check_output.txt
            echo "::error::update_versions.py --check-latest failed"
            exit 1
          fi
          cat version_check_output.txt
          if grep -q "UPDATE AVAILABLE" version_check_output.txt; then
            echo "outdated=true" >> "$GITHUB_OUTPUT"
          fi
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/maintenance.yml
git commit -m "fix: replace || echo with proper error handling in version check"
```

---

### Task 14: Fix nightly performance test `|| echo` masking

**Files:**

- Modify: `.github/workflows/scheduled.yml:911-915`

- [ ] **Step 1: Replace `|| echo` with `continue-on-error`**

```yaml
      - name: Run performance benchmarks
        id: perf-tests
        continue-on-error: true
        run: |
          python3 -m pytest tests/performance/test_benchmarks.py \
            -v \
            --benchmark-only \
            --benchmark-json=baseline-results.json

      - name: Warn on performance regression
        if: steps.perf-tests.outcome == 'failure'
        run: |
          echo "::warning::Performance benchmarks failed. Review nightly logs for regressions."
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/scheduled.yml
git commit -m "fix: use continue-on-error for performance benchmarks instead of || echo"
```

---

### Task 15: Fix Docker validation `|| true` masking scan failures

**Files:**

- Modify: `.github/workflows/scheduled.yml:1034`

- [ ] **Step 1: Remove `|| true` and make results check a hard failure**

```yaml
      - name: Run scan
        run: |
          docker run --rm \
            -v /tmp/test-repo:/scan \
            -w /scan \
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ matrix.variant }} \
            scan --repo . --profile ${{ matrix.profile }} --results-dir /scan/results
        continue-on-error: true
        id: docker-scan

      - name: Verify scan results
        run: |
          if [ "${{ steps.docker-scan.outcome }}" == "failure" ]; then
            echo "::error::Docker scan for ${{ matrix.variant }} failed"
            exit 1
          fi
          if [ ! -d /tmp/test-repo/results ]; then
            echo "::error::Scan completed but produced no results directory"
            exit 1
          fi
          echo "Scan completed successfully"
          ls -la /tmp/test-repo/results
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/scheduled.yml
git commit -m "fix: replace || true with continue-on-error for Docker validation scan"
```

---

### Task 16: Fix inline trufflehog `|| true` in scheduled.yml

**Files:**

- Modify: `.github/workflows/scheduled.yml:108-110`

- [ ] **Step 1: Apply same fix as Task 6 to inline trufflehog call**

This is a duplicate of the `|| true` pattern at line 108 in `nightly-extended-tests`. Apply the same error-handling pattern from Task 6:

```yaml
      - name: Run security audit
        run: |
          set -euo pipefail
          if ! trufflehog filesystem . --json --exclude-paths .trufflehog-exclude.txt \
              --only-verified > trufflehog-results.json 2>trufflehog-stderr.txt; then
            EXIT_CODE=$?
            echo "::error::TruffleHog exited with code ${EXIT_CODE}"
            cat trufflehog-stderr.txt >&2
            exit "${EXIT_CODE}"
          fi

          if [ ! -s trufflehog-results.json ]; then
            echo "Security audit complete. Verified secrets: 0"
          else
            VERIFIED=$({ jq -r 'select(.Verified == true)' trufflehog-results.json || true; } | wc -l)
            if [ "$VERIFIED" -gt 0 ]; then
              echo "::error::Found $VERIFIED verified secrets!"
              exit 1
            fi
            echo "Security audit complete. Verified secrets: $VERIFIED"
          fi
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/scheduled.yml
git commit -m "fix: replace || true with proper error handling in inline trufflehog scan"
```

---

## Summary

| Phase | Tasks | Risk |
|-------|-------|------|
| Chunk 1: Test Correctness | 1-5 | Low (test-only changes) |
| Chunk 2: Workflow Hardening | 6-16 | Medium (CI workflow changes) |
| **Total** | **16 tasks** | |
