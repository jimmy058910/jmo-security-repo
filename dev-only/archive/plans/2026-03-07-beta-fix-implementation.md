# v1.0.0 Beta Fix Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Resolve all 20 blockers and 38 warnings from the v1.0.0 beta audit across 17 categories.

**Architecture:** Single-branch (dev) execution with 7 parallel streams. Each stream owns specific files — no two streams edit the same file. Phases ensure dependent streams run after their prerequisites.

**Tech Stack:** Python 3.12, Docker, GitHub Actions, pytest, Black/Ruff

**Design Doc:** [2026-03-07-beta-fix-design.md](2026-03-07-beta-fix-design.md)
**Audit Source:** [1.0.0-Beta-Fix.md](1.0.0-Beta-Fix.md)

---

## Phase Map

```text
Phase 1 (parallel):  S1-Docker  |  S2-Docs  |  S3-Code  |  S5-CI
Phase 2 (parallel):  S4-Tests
Phase 3 (serial):    S6-Code-Quality
Phase 4 (serial):    S7-Procedural (final cleanup + verify)
```

---

## Stream 1: Docker & Compose (Categories 1, 6, 8, 2.7)

**Files owned:** `Dockerfile`, `Dockerfile.fast`, `Dockerfile.slim`, `Dockerfile.balanced`, `docker-compose.yml`

### Task 1.1: Sync Dockerfile Versions via Script

**Files:**
- Run: `scripts/dev/update_versions.py`
- Verify: `Dockerfile:258`, `Dockerfile:261`, `Dockerfile:265`, `Dockerfile.balanced:191-193`, `Dockerfile.slim:162-163`

**Step 1: Run the version sync script**

Run: `python scripts/dev/update_versions.py --sync`
Expected: Script reports versions updated for yara-python, prowler, scancode-toolkit

**Step 2: Verify the sync worked**

Run: `grep -n "yara-python\|prowler\|scancode-toolkit" Dockerfile Dockerfile.balanced Dockerfile.slim`

Expected values after sync:
- yara-python: `4.5.4` (was 4.5.2 in all three)
- prowler: `5.18.2` (was 5.13.1 in all three)
- scancode-toolkit: `32.5.0` (was 32.4.1 in Dockerfile, 32.3.0 in Dockerfile.balanced)

If the script doesn't fix all of them, manually edit:
- `Dockerfile:258` — `yara-python==4.5.4`
- `Dockerfile:261` — `scancode-toolkit==32.5.0`
- `Dockerfile:265` — `prowler==5.18.2`
- `Dockerfile.balanced:191` — `yara-python==4.5.4`
- `Dockerfile.balanced:192` — `prowler==5.18.2`
- `Dockerfile.balanced:193` — `scancode-toolkit==32.5.0`
- `Dockerfile.slim:162` — `yara-python==4.5.4`
- `Dockerfile.slim:163` — `prowler==5.18.2`

### Task 1.2: Fix Ubuntu Version Comments in All 4 Dockerfiles

**Files:**
- Modify: `Dockerfile:2`, `Dockerfile.fast:2`, `Dockerfile.slim:2`, `Dockerfile.balanced:2`

**Step 1: Fix each Dockerfile header comment**

Replace "Ubuntu 22.04" with "Ubuntu 24.04" on line 2 of each file:

`Dockerfile:2` — change:
```text
# Base: Ubuntu 22.04 with 26 security tools pre-installed + OPA
```
to:
```text
# Base: Ubuntu 24.04 with 29 security tools pre-installed
```

`Dockerfile.fast:2` — change:
```text
# Base: Ubuntu 22.04 with 8 CI/CD gate tools + OPA for policy-as-code
```
to:
```text
# Base: Ubuntu 24.04 with 9 CI/CD gate tools (8 scanners + OPA)
```

`Dockerfile.slim:2` — change:
```text
# Base: Ubuntu 22.04 with 15 cloud-focused security tools + OPA
```
to:
```text
# Base: Ubuntu 24.04 with 14 cloud-focused security tools + OPA
```

`Dockerfile.balanced:2` — change:
```text
# Base: Ubuntu 22.04 with 19 production-ready security tools + OPA
```
to:
```text
# Base: Ubuntu 24.04 with 18 production-ready security tools + OPA
```

### Task 1.3: Fix Tool Count Comments in Main Dockerfile

**Files:**
- Modify: `Dockerfile:1`, `Dockerfile:3`, `Dockerfile:186`, `Dockerfile:357-358`

**Step 1: Fix line 1 header**

Change:
```text
# JMo Security Suite - All-in-One Docker Image (Full/Deep - v1.0.0)
```
Keep as-is (title is fine).

**Step 2: Fix line 3 tool count**

Change:
```text
# Size: ~1.9 GB (optimized) | Tools: 26 Docker-ready scanners | Multi-arch: amd64, arm64
```
to:
```text
# Size: ~1.9 GB (optimized) | Tools: 29 (26 Docker-ready + 3 manual) | Multi-arch: amd64, arm64
```

**Step 3: Fix line 186 LABEL**

Change:
```text
LABEL org.opencontainers.image.description="Terminal-first security audit toolkit with 27 pre-installed scanners + OPA policy engine + plugin system (v1.0.0)"
```
to:
```text
LABEL org.opencontainers.image.description="Terminal-first security audit toolkit with 29 tools (26 Docker-ready + OPA policy engine) + plugin system (v1.0.0)"
```

**Step 4: Fix lines 357-358 verify comment**

Change:
```text
# Verify all 27 tools are installed and accessible
RUN echo "=== Verifying all 27 tools ===" && \
```
to:
```text
# Verify all Docker-ready tools are installed and accessible
RUN echo "=== Verifying Docker-ready tools ===" && \
```

### Task 1.4: Fix docker-compose.yml (3 issues)

**Files:**
- Modify: `docker-compose.yml:8`, `docker-compose.yml:44`, `docker-compose.yml:66-81`

**Step 1: Remove deprecated version key (line 8)**

Delete the line:
```yaml
version: '3.8'
```

**Step 2: Fix --profile missing value (line 44)**

Change line 44-45 from:
```yaml
      - --profile
      - --human-logs
```
to:
```yaml
      - --profile
      - balanced
      - --human-logs
```

**Step 3: Replace alpine service with balanced variant (lines 66-81)**

Replace the entire `jmo-alpine` service:
```yaml
  # Alpine variant (minimal size)
  jmo-alpine:
    image: ghcr.io/jimmy058910/jmo-security:alpine
    volumes:
      - .:/scan:ro
      - ./results:/scan/results
    command:
      - scan
      - --repo
      - /scan
      - --results
      - /scan/results
      - --profile
      - fast
    environment:
      - PYTHONUNBUFFERED=1
```
with:
```yaml
  # Balanced variant (recommended for most use cases)
  jmo-balanced:
    image: ghcr.io/jimmy058910/jmo-security:balanced
    volumes:
      - .:/scan:ro
      - ./results:/scan/results
    command:
      - scan
      - --repo
      - /scan
      - --results
      - /scan/results
      - --profile
      - balanced
    environment:
      - PYTHONUNBUFFERED=1
```

**Step 5: Commit**

```bash
git add Dockerfile Dockerfile.fast Dockerfile.slim Dockerfile.balanced docker-compose.yml
git commit -m "fix(docker): sync versions, fix comments, fix docker-compose issues

- Sync yara-python (4.5.4), prowler (5.18.2), scancode-toolkit (32.5.0)
- Fix Ubuntu 22.04 -> 24.04 in header comments (all 4 Dockerfiles)
- Fix tool count comments in main Dockerfile
- Fix docker-compose: add missing --profile value, replace :alpine with :balanced, remove deprecated version key"
```

---

## Stream 2: Documentation (Categories 2.1-2.6, 3, 4, 5, 14.1)

**Files owned:** `README.md`, `CLAUDE.md`, `docs/PROFILES_AND_TOOLS.md`, `docs/DOCKER_README.md`, `docs/CLI_REFERENCE.md`, `docs/USER_GUIDE.md`, `docs/RESULTS_GUIDE.md`, `CHANGELOG.md`, `docs/index.md`, `docs/RELEASE.md`, `docs/internal/TESTING_MATRIX.md`

### Task 2.1: Fix README.md Tool Counts and Tool Table

**Files:**
- Modify: `README.md:80`, `README.md:82-94`, `README.md:104`, `README.md:107`, `README.md:362`

**Step 1: Fix scanner count (line 80)**

Change:
```text
28 scanners across 11 categories:
```
to:
```text
29 tools across 12 categories:
```

**Step 2: Fix tool table (lines 82-94)**

Replace the tool table with updated version. Key changes:
- SCA row: Remove OSV-Scanner (ghost tool, no adapter exists)
- Add new row for Policy: OPA
- Add ShellCheck to a category (Shell row or merge with existing)

Change:
```markdown
| Category | Tools |
|----------|-------|
| **Secrets** | TruffleHog (verified), Nosey Parker, Semgrep-Secrets |
| **SAST** | Semgrep, Bandit, Gosec, Horusec |
| **SBOM** | Syft, CDXgen, ScanCode |
| **SCA** | Trivy, Grype, OSV-Scanner, Dependency-Check |
| **IaC** | Checkov, Checkov-CICD |
| **Cloud/CSPM** | Prowler, Kubescape |
| **DAST** | OWASP ZAP, Nuclei |
| **Dockerfile** | Hadolint |
| **Malware** | YARA |
| **System** | Lynis |
| **Runtime** | Trivy-RBAC, Falco, AFL++ |
```
to:
```markdown
| Category | Tools |
|----------|-------|
| **Secrets** | TruffleHog (verified), Nosey Parker, Semgrep-Secrets |
| **SAST** | Semgrep, Bandit, Gosec, Horusec |
| **SBOM** | Syft, CDXgen, ScanCode |
| **SCA** | Trivy, Grype, Dependency-Check |
| **IaC** | Checkov, Checkov-CICD |
| **Cloud/CSPM** | Prowler, Kubescape |
| **DAST** | OWASP ZAP, Nuclei, Akto |
| **Dockerfile/Shell** | Hadolint, ShellCheck |
| **Malware** | YARA |
| **Mobile** | MobSF |
| **System** | Lynis |
| **Policy** | OPA |
| **Runtime** | Trivy-RBAC, Falco, AFL++ |
```

**Step 3: Fix profile tool counts (lines 104, 107)**

Change line 104: fast profile tools `8` -> `9`
Change line 107: deep profile tools `28` -> `29`

**Step 4: Fix "Last Updated" date (line 362)**

Change:
```text
**Last Updated:** December 2025
```
to:
```text
**Last Updated:** March 2026
```

### Task 2.2: Fix CLAUDE.md Tool Count

**Files:**
- Modify: `CLAUDE.md:287`

**Step 1: Fix deep profile count**

Change:
```text
| `deep` | 28 | 40-70 min | Compliance audits, pentests | `:deep` (default) |
```
to:
```text
| `deep` | 29 | 40-70 min | Compliance audits, pentests | `:deep` (default) |
```

### Task 2.3: Fix PROFILES_AND_TOOLS.md (Counts + YAML Lists)

**Files:**
- Modify: `docs/PROFILES_AND_TOOLS.md` at lines 31, 48, 72, 92, 104, 126, 152, 154, 190, 753

**Step 1: Fix quick reference table (line 31)**

Change: `| **deep** | 28 |` -> `| **deep** | 29 |`

**Step 2: Fix section headers**

- Line 48: `### Fast Profile (8 tools)` -> `### Fast Profile (9 tools)`
- Line 72: `### Deep Profile (28 tools)` -> `### Deep Profile (29 tools)`
- Line 92: `### Fast Profile (8 tools)` -> `### Fast Profile (9 tools)`
- Line 154: `### Deep Profile (28 tools)` -> `### Deep Profile (29 tools)`

**Step 3: Add OPA to all 4 YAML profile lists**

Fast profile (after line 103, add before closing ```):
```yaml
  - opa           # Policy-as-code engine (Open Policy Agent)
```

Slim profile (after line 125, before the Note comment):
```yaml
  - opa           # Policy-as-code engine (Open Policy Agent)
```

Balanced profile (after line 151, before the Note comment):
```yaml
  - opa           # Policy-as-code engine (Open Policy Agent)
```

Deep profile (after line 189, before closing ```):
```yaml
  - opa           # Policy-as-code engine (Open Policy Agent)
```

**Step 4: Fix consistency matrix (line 753)**

Change: `# deep: 28 tools` -> `# deep: 29 tools`

Also fix the slim comment count if it says 13: should be 14.
Also fix balanced comment count if it says 17: should be 18.

### Task 2.4: Fix DOCKER_README.md Tool Counts

**Files:**
- Modify: `docs/DOCKER_README.md` at lines 299, 314, 419, 449, 469

**Step 1: Fix all 5 locations**

- Line 299: `- 28 tools, 40-70 min scans` -> `- 29 tools, 40-70 min scans`
- Line 314: `- 8 tools, 5-10 min scans` -> `- 9 tools, 5-10 min scans`
- Line 419: `# Fast - Quick validation (8 tools)` -> `# Fast - Quick validation (9 tools)`
- Line 449: `trufflehog, semgrep, syft, trivy, checkov, hadolint, nuclei, shellcheck (8 tools)` -> `trufflehog, semgrep, syft, trivy, checkov, hadolint, nuclei, shellcheck, opa (9 tools)`
- Line 469: `All 28 tools (25 Docker-ready + 3 manual installation)` -> `All 29 tools (26 Docker-ready + 3 manual installation)`

**Step 2: Fix dependency-check profile misassignment (line 459)**

Find where dependency-check is listed in balanced profile section and remove it (it's deep-only).

### Task 2.5: Fix CLI_REFERENCE.md Tool Count

**Files:**
- Modify: `docs/CLI_REFERENCE.md:18`

**Step 1: Fix jmo full tool count**

Change:
```text
| `jmo full` | Comprehensive audit (28 tools, 40-70 min) |
```
to:
```text
| `jmo full` | Comprehensive audit (29 tools, 40-70 min) |
```

### Task 2.6: Fix Version References in Example JSON

**Files:**
- Modify: `docs/USER_GUIDE.md:835`, `docs/RESULTS_GUIDE.md:1408`

**Step 1: Fix USER_GUIDE.md**

Change line 835:
```json
    "jmo_version": "0.9.0",
```
to:
```json
    "jmo_version": "1.0.0",
```

**Step 2: Fix RESULTS_GUIDE.md**

Change line 1408:
```json
    "jmo_version": "0.9.0",
```
to:
```json
    "jmo_version": "1.0.0",
```

### Task 2.7: Fix CHANGELOG Placeholder Date

**Files:**
- Modify: `CHANGELOG.md:268`

**Step 1: Fix placeholder**

Change:
```text
## 0.9.0 (2025-11-XX)
```
to:
```text
## 0.9.0 (2025-11-04)
```

(Use November 4 based on the example timestamps in the JSON docs, or check git history for actual date.)

### Task 2.8: Remove OSV-Scanner Ghost Reference from docs/index.md

**Files:**
- Modify: `docs/index.md:151`

**Step 1: Remove OSV-Scanner from SCA row**

Change:
```text
| SCA | Trivy, Grype, OSV-Scanner, Dependency-Check |
```
to:
```text
| SCA | Trivy, Grype, Dependency-Check |
```

### Task 2.9: Fix Broken Internal Links

**Files:**
- Modify: `docs/RELEASE.md:158`, `docs/internal/TESTING_MATRIX.md:24`, `docs/internal/TESTING_MATRIX.md:391`

**Step 1: Fix RELEASE.md broken link**

Change:
```text
**Documentation:** See [dev-only/README_CONSISTENCY.md](../dev-only/README_CONSISTENCY.md) for complete guide.
```
to:
```text
**Documentation:** See [dev-only/archive/README_CONSISTENCY.md](../dev-only/archive/README_CONSISTENCY.md) for complete guide.
```

**Step 2: Fix TESTING_MATRIX.md link at line 24**

Change:
```text
> **Canonical source:** [PROFILES_AND_TOOLS.md](PROFILES_AND_TOOLS.md)
```
to:
```text
> **Canonical source:** [PROFILES_AND_TOOLS.md](../PROFILES_AND_TOOLS.md)
```

**Step 3: Fix TESTING_MATRIX.md link at line 391**

Change:
```text
**Maintainer:** See [CONTRIBUTING.md](../CONTRIBUTING.md)
```
to:
```text
**Maintainer:** See [CONTRIBUTING.md](../../CONTRIBUTING.md)
```

### Task 2.10: Commit Documentation Fixes

```bash
git add README.md CLAUDE.md CHANGELOG.md docs/PROFILES_AND_TOOLS.md docs/DOCKER_README.md docs/CLI_REFERENCE.md docs/USER_GUIDE.md docs/RESULTS_GUIDE.md docs/index.md docs/RELEASE.md docs/internal/TESTING_MATRIX.md
git commit -m "docs: fix tool counts, version refs, ghost tools, and broken links

- Update tool counts: fast=9, deep=29 across all docs (OPA added to all profiles)
- Remove OSV-Scanner ghost reference (no adapter exists)
- Fix jmo_version 0.9.0 -> 1.0.0 in example JSON
- Fix CHANGELOG 0.9.0 placeholder date
- Add OPA to all 4 YAML profile lists in PROFILES_AND_TOOLS.md
- Fix dependency-check profile assignment (deep-only)
- Fix 3 broken internal links (RELEASE.md, TESTING_MATRIX.md)
- Update README Last Updated to March 2026"
```

---

## Stream 3: Code Fixes (Categories 9.1, 9.3, 10.1-10.4, 14.2)

**Files owned:** `scripts/core/history_db.py`, `scripts/core/reporters/html_reporter.py`, `scripts/core/reporters/sarif_reporter.py`, `scripts/cli/wizard_flows/tool_checker.py`, `scripts/jmo_mcp/jmo_server.py`, plus 13 files with `shutil.which()` calls

### Task 3.1: Replace shutil.which() with tool_exists()

**Files:**
- Modify: 13 files (32 occurrences total across `scripts/`)

The wrapper `tool_exists()` lives at `scripts/core/tool_utils.py:128`. It checks PATH + JMo installation paths and provides logging.

**Important:** NOT all `shutil.which()` calls should be replaced. The ones in `tool_utils.py` itself (which defines `tool_exists()`) and `find_tool()` must stay — they ARE the implementation. Also, `scripts/dev/test_wizard_tools.py` is a dev script, not production code.

**Step 1: Identify which calls to replace**

Replace in these files (production code that should use the wrapper):
- `scripts/cli/jmo.py` (2 calls)
- `scripts/cli/build_commands.py` (1 call)
- `scripts/cli/tool_manager.py` (5 calls)
- `scripts/cli/tool_installer.py` (9 calls)
- `scripts/cli/installers/npm_installer.py` (3 calls)
- `scripts/cli/installers/binary_installer.py` (2 calls)
- `scripts/cli/wizard_flows/validators.py` (2 calls)
- `scripts/cli/wizard_flows/target_configurators.py` (1 call)
- `scripts/core/exceptions.py` (2 calls)
- `scripts/core/validators/scan_validator.py` (1 call)
- `scripts/core/validators/platform_validator.py` (2 calls)

**Do NOT replace:**
- `scripts/core/tool_utils.py` — this IS the implementation of `tool_exists()`
- `scripts/dev/test_wizard_tools.py` — dev-only script

**Step 2: For each file, add import and replace calls**

Pattern: Replace `shutil.which("tool_name")` with the appropriate form.

CAUTION: `shutil.which()` returns a path string or None. `tool_exists()` returns a boolean. Some call sites use the return value as a path (e.g., `path = shutil.which("tool")`). For those, use `find_tool("tool")` from `scripts/core/tool_utils.py` instead.

Review each call site:
- If used as a boolean check (`if shutil.which("x"):`) -> use `tool_exists("x")`
- If used to get the path (`path = shutil.which("x")`) -> use `find_tool("x")`

Add import at top of each modified file:
```python
from scripts.core.tool_utils import tool_exists, find_tool
```

**Step 3: Run tests**

Run: `pytest tests/ -x -q --timeout=30 -k "not docker and not real_scan"`
Expected: All pass (no functional changes)

### Task 3.2: Route get_query_plan() Through _validate_readonly_query()

**Files:**
- Modify: `scripts/core/history_db.py:1925-1941`

**Step 1: Replace manual validation with existing function**

The function at line 1925-1941 has inline validation (SELECT prefix check, semicolon check). Replace with the more comprehensive `_validate_readonly_query()` from line 3634.

Change lines 1925-1941 from:
```python
    # Validate query is SELECT-only (prevent injection in diagnostic tool)
    query_stripped = query.strip().upper()
    if not query_stripped.startswith("SELECT") and not query_stripped.startswith(
        "EXPLAIN"
    ):
        raise ValueError("get_query_plan() only supports SELECT queries")

    # Security: Reject semicolons and compound statements to prevent SQL injection
    # via f-string interpolation into EXPLAIN QUERY PLAN. Even though SQLite's
    # execute() only runs the first statement, defense-in-depth matters.
    if ";" in query:
        raise ValueError(
            "get_query_plan() does not allow semicolons (compound statements)"
        )

    cursor = conn.cursor()
    cursor.execute(f"EXPLAIN QUERY PLAN {query}")  # nosec B608 - query validated above
```
to:
```python
    # Security: Route through comprehensive query validator (CWE-89 defense-in-depth)
    _validate_readonly_query(query)

    cursor = conn.cursor()
    cursor.execute(f"EXPLAIN QUERY PLAN {query}")  # nosec B608 - validated by _validate_readonly_query()
```

**Step 2: Run related tests**

Run: `pytest tests/ -x -q -k "history_db or query_plan"`
Expected: All pass

### Task 3.3: Add HTML Escape to Fallback Reporter

**Files:**
- Modify: `scripts/core/reporters/html_reporter.py:118,164`

**Step 1: Add escape import and apply**

At top of function `_write_fallback_html` (line 108), the `total` variable is `len(findings)` which is always an integer. For defense-in-depth consistency, escape it.

Find the function and check if `_escape_html` is already defined in this file. If not, use `html.escape` from stdlib.

Add import at top of file (if not already present):
```python
import html
```

Change line 164:
```python
        <p><strong>Total Findings:</strong> {total}</p>
```
to:
```python
        <p><strong>Total Findings:</strong> {html.escape(str(total))}</p>
```

### Task 3.4: Add Safety Comment to shlex.split() Usage

**Files:**
- Modify: `scripts/cli/wizard_flows/tool_checker.py:988`

**Step 1: Add comment documenting internal-only usage**

Change:
```python
                    proc_result = subprocess.run(
                        shlex.split(sub_cmd),
```
to:
```python
                    # Safety: sub_cmd is internally generated by _build_check_commands(),
                    # not from user input. shlex.split() is safe here.
                    proc_result = subprocess.run(
                        shlex.split(sub_cmd),
```

### Task 3.5: Add Security TODO to MCP apply_fix() Stub

**Files:**
- Modify: `scripts/jmo_mcp/jmo_server.py:276`

**Step 1: Add security implementation notes**

Add after the docstring (before the function body):

```python
    # TODO(security): When implementing apply_fix(), add these controls:
    #   1. Directory traversal validation on patch paths (CWE-22)
    #   2. Backup-before-apply with rollback on failure
    #   3. Run tests after applying patch, rollback if tests fail
    #   4. Validate patch doesn't modify files outside project root
    #   5. Rate limit to prevent rapid-fire patch application
```

### Task 3.6: Update SARIF Reporter Version

**Files:**
- Modify: `scripts/core/reporters/sarif_reporter.py:151`

**Step 1: Update default version**

Change:
```python
    version = "0.4.0"  # Default
```
to:
```python
    version = "1.0.0"  # Default
```

### Task 3.7: Investigate Path Traversal Pattern (Cat 9.3)

**Files:**
- Check: `scripts/core/validators/release_validator.py:842`

**Step 1: Verify this is the validator's own check pattern**

The `no-path-traversal` validator at line 842 uses `re.compile(r'["\']\.\./')` to DETECT path traversal patterns in the codebase. This is a false positive — the validator itself contains the pattern it's searching for.

Confirm by reading the code. If it's indeed the validator's own regex, no action needed. Document in commit message.

### Task 3.8: Commit Code Fixes

```bash
git add scripts/
git commit -m "fix: security hardening and code consistency improvements

- Replace 27 raw shutil.which() calls with tool_exists()/find_tool() wrapper
- Route get_query_plan() through _validate_readonly_query() (CWE-89)
- Add html.escape() to fallback HTML reporter for defense-in-depth
- Add safety comments to shlex.split() and apply_fix() stub
- Update SARIF reporter default version to 1.0.0
- Cat 9.3: path traversal pattern is validator's own regex (false positive)"
```

---

## Stream 4: Tests & Coverage (Categories 11, 16)

**Files owned:** `tests/` directory (new and modified test files)

### Task 4.1: Create test_install_config.py

**Files:**
- Create: `tests/unit/test_install_config.py`
- Reference: `scripts/core/install_config.py`

**Step 1: Read install_config.py to understand what to test**

Read the module to identify public functions/constants.

**Step 2: Write tests**

Create tests for:
- Tool URL constants are valid (not empty, proper format)
- Timeout values are reasonable (positive integers)
- Isolated tool list contains expected tools
- Tool configuration dictionaries have required keys

```python
"""Tests for scripts/core/install_config.py — tool installation configuration."""

import pytest
from scripts.core.install_config import (
    TOOL_INSTALL_URLS,
    TOOL_TIMEOUTS,
    ISOLATED_VENV_TOOLS,
)


class TestToolInstallUrls:
    """Test tool installation URL configuration."""

    def test_urls_not_empty(self):
        assert len(TOOL_INSTALL_URLS) > 0

    def test_all_urls_are_strings(self):
        for tool, url in TOOL_INSTALL_URLS.items():
            assert isinstance(url, str), f"{tool} URL is not a string"
            assert len(url) > 0, f"{tool} has empty URL"


class TestToolTimeouts:
    """Test tool timeout configuration."""

    def test_timeouts_are_positive(self):
        for tool, timeout in TOOL_TIMEOUTS.items():
            assert timeout > 0, f"{tool} has non-positive timeout: {timeout}"


class TestIsolatedVenvTools:
    """Test isolated venv tool list."""

    def test_isolated_tools_is_list(self):
        assert isinstance(ISOLATED_VENV_TOOLS, (list, set, tuple))

    def test_isolated_tools_not_empty(self):
        assert len(ISOLATED_VENV_TOOLS) > 0
```

**Step 3: Run test**

Run: `pytest tests/unit/test_install_config.py -v`
Expected: All pass

### Task 4.2: Create test_unicode_utils.py

**Files:**
- Create: `tests/unit/test_unicode_utils.py`
- Reference: `scripts/core/unicode_utils.py`

**Step 1: Read unicode_utils.py to understand what to test**

**Step 2: Write tests for public functions**

Test Unicode handling edge cases: empty strings, ASCII-only, mixed Unicode, emoji, CJK characters.

**Step 3: Run test**

Run: `pytest tests/unit/test_unicode_utils.py -v`
Expected: All pass

### Task 4.3: Create test_progress_ui.py

**Files:**
- Create: `tests/unit/test_progress_ui.py`
- Reference: `scripts/cli/ui/progress.py`

**Step 1: Read progress.py**

**Step 2: Write tests for progress tracker UI components**

Test initialization, updates, and completion callbacks with mock output.

**Step 3: Run test**

Run: `pytest tests/unit/test_progress_ui.py -v`
Expected: All pass

### Task 4.4: Create test_config_models.py

**Files:**
- Create: `tests/unit/test_config_models.py`
- Reference: `scripts/cli/wizard_flows/config_models.py`

**Step 1: Read config_models.py**

**Step 2: Write tests for dataclass/model validation**

Test default values, field validation, serialization.

**Step 3: Run test**

Run: `pytest tests/unit/test_config_models.py -v`
Expected: All pass

### Task 4.5: Investigate test_no_github_tokens_in_code

**Files:**
- Check: The test that scans for GitHub tokens in source code

**Step 1: Find and read the test**

Run: `grep -rn "test_no_github_tokens_in_code" tests/`

**Step 2: Determine if requirements-dev.txt changes triggered it**

The deps-compile changes may have introduced a string that matches the token pattern. If so, add requirements-dev.txt to the exclusion list in the test.

**Step 3: Fix if needed**

If it's a false positive from requirements-dev.txt, add it to the ignore list. If it's a real token, address immediately.

### Task 4.6: Investigate and Fix Remaining Test Failures

**Files:**
- Check: `test_path_normalization_cross_platform`, `test_bad_jmo_threads_fallback`, `test_allow_missing_tools_stubs_all`

**Step 1: Run each failing test individually to get error details**

```bash
pytest tests/ -k "test_path_normalization_cross_platform" -v --tb=long
pytest tests/ -k "test_bad_jmo_threads_fallback" -v --tb=long
pytest tests/ -k "test_allow_missing_tools_stubs_all" -v --tb=long
```

**Step 2: Fix based on error output**

Common patterns:
- Path normalization: Use `pathlib.Path` consistently, check for Windows backslash issues
- Env variable fallback: Ensure mock properly patches `os.environ`
- Missing tools stubs: Ensure `tool_exists` and `find_tool` are both mocked

**Step 3: Add proper skip markers for infra-dependent tests**

For Docker-dependent and real-tool tests (Categories 16.1, 16.2), ensure they have appropriate skip markers:

```python
@pytest.mark.skipif(
    not shutil.which("docker"),
    reason="Docker not available"
)
```

### Task 4.7: Commit Test Improvements

```bash
git add tests/
git commit -m "test: add dedicated test files for coverage gaps and fix test failures

- Add test_install_config.py for install configuration
- Add test_unicode_utils.py for Unicode handling
- Add test_progress_ui.py for progress tracker UI
- Add test_config_models.py for wizard config models
- Fix test_no_github_tokens_in_code false positive
- Fix cross-platform path normalization test
- Fix environment variable fallback test
- Add skip markers for Docker/tool-dependent tests"
```

---

## Stream 5: CI/CD (Categories 13.1-13.2)

**Files owned:** `.github/workflows/ci.yml`

### Task 5.1: Add TruffleHog to CI Push/PR Workflow

**Files:**
- Modify: `.github/workflows/ci.yml` (add step to `quick-checks` job)

**Step 1: Add TruffleHog step after the existing checks**

Add after the `guardrails_check.sh` step (around line 69), before import direction check:

```yaml
      - name: "Secrets scan (TruffleHog)"
        run: |
          curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
          trufflehog filesystem . --json --exclude-paths .trufflehog-exclude.txt --only-verified > trufflehog-results.json || true
          VERIFIED=$(jq -r 'select(.Verified == true)' trufflehog-results.json 2>/dev/null | wc -l || echo "0")
          if [ "$VERIFIED" -gt 0 ]; then
            echo "::error::Found $VERIFIED verified secrets! Review trufflehog-results.json"
            exit 1
          fi
```

Note: We use `--only-verified` to keep CI fast (only flag confirmed-real secrets, not patterns).

### Task 5.2: Add Critical Integration Tests to PR (Optional)

**Files:**
- Modify: `.github/workflows/ci.yml:531-534`

**Step 1: Evaluate scope**

The integration tests at line 531 currently have `if: github.event_name == 'schedule'`. Adding them to every PR would slow CI significantly since they require tool installation.

Instead of running full integration tests, add a lighter-weight dedup accuracy test that uses mocked tool output:

Change the condition to also run on `push` to `main` and `dev`:

```yaml
    if: github.event_name == 'schedule' || (github.event_name == 'push' && (github.ref == 'refs/heads/main' || github.ref == 'refs/heads/dev'))
```

This runs integration tests on nightly + pushes to main/dev (not every PR, which would be too slow).

### Task 5.3: Commit CI Changes

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add TruffleHog secrets scan to push/PR workflow

- Add verified secrets scanning to quick-checks job
- Uses --only-verified flag for fast CI execution
- Expand integration tests to run on main/dev pushes (not just nightly)"
```

---

## Stream 6: Code Quality (Categories 12.3, 12.4, 12.6)

**Files owned:** `scripts/cli/jmo.py`, `scripts/core/generate_dashboard.py`, `scripts/core/email_service.py`, `scripts/core/developer_attribution.py`, `scripts/core/history_migrations.py`, `scripts/core/attestation/tamper_detector.py`, `scripts/cli/wizard_flows/tool_checker.py`

**Note:** This stream runs AFTER Stream 3 completes (shares some files).

### Task 6.1: Add Return Type Hints to Public Functions

**Files:**
- Modify: `scripts/cli/jmo.py` (27 functions), `scripts/core/generate_dashboard.py` (7), `scripts/cli/wizard_flows/tool_checker.py` (3)

**Step 1: Add type hints to jmo.py parser helper functions**

The 27 functions are `_add_*_args` helpers that modify an `argparse.ArgumentParser`. They all return `None`.

Pattern:
```python
# Before:
def _add_scan_args(parser):

# After:
def _add_scan_args(parser: argparse.ArgumentParser) -> None:
```

Apply this pattern to all 27 `_add_*_args` functions.

**Step 2: Add type hints to generate_dashboard.py**

Read the file, identify the 7 functions, add appropriate return types.

**Step 3: Add type hints to tool_checker.py**

Read the file, identify the 3 functions, add appropriate return types.

**Step 4: Run formatter and tests**

Run: `make fmt && pytest tests/ -x -q --timeout=30 -k "not docker"`
Expected: All pass (type hints are non-functional changes)

### Task 6.2: Guard print() Statements in scripts/core/

**Files:**
- Modify: `scripts/core/email_service.py`, `scripts/core/developer_attribution.py`, `scripts/core/generate_dashboard.py`, `scripts/core/history_migrations.py`, `scripts/core/attestation/tamper_detector.py`

**Step 1: For each file, check if print() calls are already inside `if __name__ == "__main__":`**

Most are already in `__main__` blocks (per the audit: email_service has 15 in test harness). For those already guarded, no change needed.

For any print() calls NOT in `__main__` blocks, replace with logger calls:

```python
# Before:
print(f"Processing {item}")

# After:
logger.info(f"Processing {item}")
```

Ensure `logger = logging.getLogger(__name__)` exists at module top.

**Step 2: Run tests**

Run: `pytest tests/ -x -q -k "email_service or developer_attribution or generate_dashboard or history_migrations or tamper_detector"`
Expected: All pass

### Task 6.3: Add Comments to Broad except Exception Clauses

**Files:**
- Modify: Files listed in audit (31 occurrences across scripts/)

**Step 1: Add rationale comments to each broad except**

For each `except Exception:` block, add a brief comment explaining why it's acceptable:

```python
# Before:
except Exception:
    pass

# After:
except Exception:  # Acceptable: graceful degradation for optional telemetry
    pass
```

Common rationale categories:
- "graceful degradation for optional feature"
- "callback protection — must not crash main flow"
- "transaction rollback safety — re-raises after cleanup"
- "version detection fallback — tool may not be installed"
- "terminal width detection — safe default on failure"

**Step 2: Verify no functional changes**

Run: `make fmt && make lint`
Expected: Clean

### Task 6.4: Create GitHub Issues for Deferred Refactoring

**Step 1: Create issues for Cat 12.1, 12.2, 12.5**

```bash
gh issue create --title "refactor: decompose jmo.py (3,803 lines) into subcommand modules" \
  --label "tech-debt" --label "refactoring" \
  --body "Extract 22 subcommand handlers from scripts/cli/jmo.py into dedicated modules under scripts/cli/commands/. See docs/plans/2026-03-07-beta-fix-design.md for context."

gh issue create --title "refactor: decompose history_db.py (3,209 lines) into focused modules" \
  --label "tech-debt" --label "refactoring" \
  --body "Split scripts/core/history_db.py into query builders, migrations, encryption, and core DB modules. See docs/plans/2026-03-07-beta-fix-design.md."

gh issue create --title "refactor: extract WizardConfig dataclass from run_wizard() 21 params" \
  --label "tech-debt" --label "refactoring" \
  --body "Group the 21 optional parameters of run_wizard() (scripts/cli/wizard.py:815) into a WizardConfig dataclass for cleaner API."

gh issue create --title "refactor: decompose tool_installer.py (2,634 lines) and tool_manager.py (1,892 lines)" \
  --label "tech-debt" --label "refactoring" \
  --body "Further decompose large CLI modules. See docs/plans/2026-03-07-beta-fix-design.md."
```

### Task 6.5: Commit Code Quality Improvements

```bash
git add scripts/
git commit -m "refactor: add type hints, guard print statements, document except clauses

- Add return type annotations to 37 public functions (jmo.py, generate_dashboard.py, tool_checker.py)
- Guard print() statements in scripts/core/ with __main__ checks or replace with logger
- Add rationale comments to 31 broad except Exception clauses
- Deferred: file decomposition tracked in GitHub issues"
```

---

## Stream 7: Procedural & Cleanup (Categories 7, 13.3, 15, 17)

**Runs last after all other streams complete.**

### Task 7.1: Handle requirements-dev.txt

**Files:**
- Commit: `requirements-dev.txt`

**Step 1: Commit the existing changes**

The file adds `colorama==0.4.6` and `pywin32==311` as transitive dependencies. These are legitimate deps from the compile hook.

```bash
git add requirements-dev.txt
git commit -m "chore(deps): update requirements-dev.txt with transitive dependencies"
```

### Task 7.2: Verify Bearer 2.0.0 and Document EOL

**Files:**
- Modify: `versions.yaml` (add comment)

**Step 1: Check if Bearer 2.0.0 exists**

```bash
curl -s https://api.github.com/repos/Bearer/bearer/releases/latest | jq '.tag_name'
```

If 2.0.0 doesn't exist as a release, update versions.yaml to the latest available version.

**Step 2: Document Bearer EOL status**

Add comment to versions.yaml above the bearer entry:

```yaml
  bearer:
    # NOTE: Bearer project is archived (EOL). Pinned at last release.
    # Evaluate replacement when this becomes a compatibility issue.
    version: 2.0.0
```

### Task 7.3: Document deps-compile Conflicts

**Files:**
- Create or modify: `.claude/known-issues.md`

**Step 1: Document the 10 dependency conflicts**

Add a section documenting that these conflicts exist in the flat requirements-dev.txt but don't affect runtime (tools run in isolated venvs).

### Task 7.4: Document Sigstore OIDC Known Limitation

**Files:**
- Modify: `.claude/known-issues.md` (same file as 7.3)

**Step 1: Add Sigstore OIDC section**

```markdown
## Sigstore OIDC Signing (P2)

CLI infrastructure for Sigstore OIDC signing exists but the browser-based OIDC flow
is not implemented. Attestation signing is deferred to a future release.

Status: CLI flags present, signing non-functional without OIDC implementation.
```

### Task 7.5: Run Full Verification

**Step 1: Format and lint**

```bash
make fmt && make lint
```
Expected: Clean

**Step 2: Run full test suite**

```bash
make test-fast
```
Expected: All unit/adapter/core tests pass (integration/Docker tests may skip)

**Step 3: Run validation**

```bash
jmo validate -v
```
Expected: 253/253 pass (0 warnings)

**Step 4: Verify coverage**

```bash
pytest tests/ --cov=scripts --cov-fail-under=85 -n auto -q
```
Expected: Coverage >= 85%

### Task 7.6: Commit Plan Docs and Final Cleanup

```bash
git add docs/plans/ .claude/known-issues.md versions.yaml
git commit -m "docs: add beta fix plans and known issues documentation

- Add beta fix design and implementation plan
- Document deps-compile conflicts as known non-blocking issue
- Document Sigstore OIDC limitation (P2)
- Document Bearer EOL status in versions.yaml"
```

---

## Execution Summary

| Stream | Tasks | Est. Edits | Key Files |
|--------|-------|-----------|-----------|
| S1: Docker | 4 | ~20 | 5 files |
| S2: Docs | 10 | ~35 | 11 files |
| S3: Code | 8 | ~45 | 15+ files |
| S4: Tests | 7 | ~200+ (new test code) | 6+ files |
| S5: CI | 3 | ~15 | 1 file |
| S6: Quality | 5 | ~80 | 7 files |
| S7: Procedural | 6 | ~10 | 3 files |
| **Total** | **43 tasks** | **~405 edits** | **~48 files** |

## Post-Completion Checklist

- [ ] All 7 streams committed
- [ ] `make fmt && make lint` passes
- [ ] `make test-fast` passes (unit/adapter/core)
- [ ] `jmo validate -v` shows improvement over baseline (target: 253/253)
- [ ] Coverage >= 85%
- [ ] 4 GitHub issues created for deferred refactoring
- [ ] Design doc and plan doc committed
- [ ] Ready for PR: dev -> main
