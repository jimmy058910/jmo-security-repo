# Bearer Removal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cleanly remove the EOL Bearer CLI tool from all 7 layers of the JMo Security codebase and create a reusable Tool Removal Guide for future EOL removals.

**Architecture:** Bottom-up removal — tests first (prevent import errors), then core code, CLI, Docker, config, docs. Each phase ends with a test run to catch breakage early. The Tool Removal Guide is written last, informed by the real removal experience.

**Tech Stack:** Python 3.12+, pytest, Docker, YAML, Markdown

**Target Release:** v1.0.1

---

### Task 1: Delete Bearer Test File and Update Shared Test Parameterizations

**Files:**
- Delete: `tests/adapters/test_bearer_adapter.py`
- Modify: `tests/adapters/test_adapter_malformed.py:54-58`
- Modify: `tests/integration/test_tool_smoke.py:233-247`
- Modify: `tests/unit/test_tool_installer_urls.py:167-182,322-337`
- Modify: `tests/cli/test_tool_manager.py:1351,1414,1454,1462`
- Modify: `tests/core/test_tool_registry.py:213`

- [ ] **Step 1: Delete the bearer adapter test file**

```bash
rm tests/adapters/test_bearer_adapter.py
```

- [ ] **Step 2: Remove BearerAdapter from shared malformed test**

In `tests/adapters/test_adapter_malformed.py`, remove the bearer entry from the `ALL_ADAPTERS` list and its import:

Remove from imports (near top of file):
```python
from scripts.core.adapters.bearer_adapter import BearerAdapter
```

Remove from list (line 58):
```python
    ("bearer", BearerAdapter),
```

- [ ] **Step 3: Remove bearer smoke test config**

In `tests/integration/test_tool_smoke.py`, remove lines 233-247:

```python
    "bearer": ToolSmokeConfig(
        name="bearer",
        timeout=180,
        min_findings=0,  # Findings vary - just check tool runs
        command_template=[
            "bearer",
            "scan",
            "{target}",
            "--format",
            "json",
            "--output",
            "{output}",
        ],
        description="Data privacy scanner",
    ),
```

- [ ] **Step 4: Remove bearer URL tests**

In `tests/unit/test_tool_installer_urls.py`, remove both test methods:

Remove `test_bearer_url_x86_64` (lines 167-182):
```python
    def test_bearer_url_x86_64(self):
        """Test bearer URL for x86_64 Linux."""
        url = BINARY_URLS["bearer"]["default"].format(
            version="1.51.1",
            os="Linux",
            os_lower="linux",
            arch="x86_64",
            arch_amd="amd64",
            arch_aarch="x86_64",
            trivy_arch="64bit",
            rust_arch="x86_64-unknown-linux-gnu",
        )
        assert url == (
            "https://github.com/Bearer/bearer/releases/download/v1.51.1/"
            "bearer_1.51.1_linux_amd64.tar.gz"
        )
```

Remove `test_bearer_url_windows` (lines 322-337):
```python
    def test_bearer_url_windows(self):
        """Test bearer URL for Windows (.zip format)."""
        url = BINARY_URLS["bearer"]["windows"].format(
            version="1.51.1",
            os="Windows",
            os_lower="windows",
            arch="x86_64",
            arch_amd="amd64",
            arch_aarch="x86_64",
            trivy_arch="64bit",
            rust_arch="x86_64-pc-windows-msvc",
        )
        assert url == (
            "https://github.com/Bearer/bearer/releases/download/v1.51.1/"
            "bearer_1.51.1_windows_amd64.zip"
        )
```

- [ ] **Step 5: Update tool manager test mock data**

In `tests/cli/test_tool_manager.py`, update 4 locations:

Line 1351 — change `not_installed=["bearer"]` to `not_installed=[]`:
```python
            not_installed=[],
```

Line 1414 — change `not_installed=["bearer"]` to `not_installed=[]`:
```python
            not_installed=[],
```

Line 1454 — remove "bearer" from the list:
```python
            return_value=["trivy", "semgrep", "checkov"],
```

Line 1462 — remove "bearer" from the dict value list:
```python
                    {"fast": ["trivy", "semgrep", "checkov", "falco"]},
```

- [ ] **Step 6: Update tool registry test comment**

In `tests/core/test_tool_registry.py`, update the comment at line 213:

Old:
```python
        # Windows should have fewer (missing falco, afl++, noseyparker, bearer)
```

New:
```python
        # Windows should have fewer (missing falco, afl++, noseyparker)
```

- [ ] **Step 7: Run tests to verify no import errors**

```bash
make test-fast
```

Expected: All tests pass. Bearer-specific tests no longer exist. No `ImportError` or `ModuleNotFoundError` for bearer_adapter.

- [ ] **Step 8: Commit**

```bash
git add tests/adapters/test_bearer_adapter.py tests/adapters/test_adapter_malformed.py tests/integration/test_tool_smoke.py tests/unit/test_tool_installer_urls.py tests/cli/test_tool_manager.py tests/core/test_tool_registry.py
git commit -m "test(bearer): remove bearer adapter tests and test references

Part of bearer EOL removal for v1.0.1. Removes:
- test_bearer_adapter.py (22 tests)
- Bearer entries from shared parameterized tests
- Bearer smoke test config
- Bearer URL validation tests
- Bearer references in tool manager test mocks

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Delete Bearer Adapter and Remove from Core Code

**Files:**
- Delete: `scripts/core/adapters/bearer_adapter.py`
- Modify: `scripts/core/constants.py:78,138,220,241,269`
- Modify: `scripts/core/tool_registry.py:55,75,102,298-303`
- Modify: `scripts/core/rule_equivalence.py:164,170,177,182`
- Modify: `scripts/core/install_config.py:147-151`
- Modify: `scripts/dev/generate_comprehensive_test_data.py:53`

- [ ] **Step 1: Delete the bearer adapter file**

```bash
rm scripts/core/adapters/bearer_adapter.py
```

- [ ] **Step 2: Remove TOOL_BEARER constant and all profile list references**

In `scripts/core/constants.py`, make these edits:

Remove line 78 (constant definition):
```python
TOOL_BEARER = "bearer"
```

Remove line 138 (from ALL_TOOLS):
```python
    TOOL_BEARER,
```

Remove line 220 (from PROFILE_SLIM_TOOLS) and update count comment:
```python
    TOOL_BEARER,
```
Change `]  # 14 tools` to `]  # 13 tools`

Remove line 241 (from PROFILE_BALANCED_TOOLS) and update count comment:
```python
    TOOL_BEARER,
```
Change `]  # 18 tools` to `]  # 17 tools`

Remove line 269 (from PROFILE_DEEP_TOOLS) and update count comment:
```python
    TOOL_BEARER,
```
Change `]  # 29 tools` to `]  # 28 tools`

- [ ] **Step 3: Remove bearer from tool_registry.py profile lists and platform restrictions**

In `scripts/core/tool_registry.py`:

Remove `"bearer",` from `slim` list (line 55) and update comment to `# 13 tools`:
```python
        "bearer",
```

Remove `"bearer",` from `balanced` list (line 75) and update comment to `# 17 tools`:
```python
        "bearer",
```

Remove `"bearer",` from `deep` list (line 102) and update comment to `# 28 tools`:
```python
        "bearer",
```

Remove the platform restrictions entry (lines 298-303):
```python
    "bearer": {
        "platforms": ["linux", "macos"],
        "docker_image": "bearer/bearer",
        "reason": "Go binary not available for Windows",
        "workarounds": ["docker", "wsl2"],
    },
```

- [ ] **Step 4: Remove bearer from rule equivalence mappings**

In `scripts/core/rule_equivalence.py`, remove these 4 tuples:

Line 164:
```python
        ("bearer", "python_sql_injection"),
```

Line 170:
```python
        ("bearer", "javascript_xss"),
```

Line 177:
```python
        ("bearer", "python_os_command_injection"),
```

Line 182:
```python
        ("bearer", "python_path_traversal"),
```

- [ ] **Step 5: Remove bearer from install_config.py**

In `scripts/core/install_config.py`, remove lines 147-151:
```python
    "bearer": {
        "windows": "https://github.com/Bearer/bearer/releases/download/v{version}/bearer_{version}_windows_{arch_amd}.zip",
        "default":  "https://github.com/Bearer/bearer/releases/download/v{version}/bearer_{version}_{os_lower}_{arch_amd}.tar.gz",
    },
```

- [ ] **Step 6: Remove bearer from test data generator**

In `scripts/dev/generate_comprehensive_test_data.py`, remove line 53:
```python
    "bearer": {"type": "privacy", "weight": 0.03},
```

- [ ] **Step 7: Run tests**

```bash
make test-fast
```

Expected: All tests pass. No references to `bearer_adapter` or `TOOL_BEARER` remain in production code.

- [ ] **Step 8: Commit**

```bash
git add scripts/core/adapters/bearer_adapter.py scripts/core/constants.py scripts/core/tool_registry.py scripts/core/rule_equivalence.py scripts/core/install_config.py scripts/dev/generate_comprehensive_test_data.py
git commit -m "refactor(core): remove bearer adapter and core references

Remove Bearer CLI (EOL) from:
- Adapter plugin (bearer_adapter.py deleted)
- Tool constants and all 3 profile lists (slim: 13, balanced: 17, deep: 28)
- Platform restrictions registry
- Rule equivalence mappings (4 groups still have semgrep+bandit coverage)
- Binary download URLs
- Test data generator weights

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Remove Bearer from CLI Code

**Files:**
- Modify: `scripts/cli/scan_jobs/repository_scanner.py:28,863-892`
- Modify: `scripts/cli/tool_manager.py:88,141,321-327,420-424`
- Modify: `scripts/cli/tool_installer.py:437-444`
- Modify: `scripts/cli/wizard_flows/profile_config.py:84`
- Modify: `scripts/cli/wizard_flows/tool_checker.py:204,229`

- [ ] **Step 1: Remove bearer scan block from repository_scanner.py**

Remove the docstring entry at line 28:
```python
18. Bearer: Data security and privacy scanner
```
Renumber subsequent tools (19 → 18, 20 → 19, etc.).

Remove the entire scan block at lines 863-892:
```python
    # Bearer: Data security and privacy scanner
    if "bearer" in tools:
        bearer_out = out_dir / "bearer.json"
        bearer_path = _find_tool("bearer")
        if bearer_path:
            bearer_flags = get_tool_flags("bearer")
            bearer_cmd = [
                bearer_path,
                "scan",
                str(repo),
                "--format",
                "json",
                "--output",
                str(bearer_out),
                *bearer_flags,
            ]
            tool_defs.append(
                ToolDefinition(
                    name="bearer",
                    command=bearer_cmd,
                    output_file=bearer_out,
                    timeout=get_tool_timeout("bearer", timeout),
                    retries=retries,
                    ok_return_codes=(0, 1),
                    capture_stdout=False,
                )
            )
        elif allow_missing_tools:
            _write_stub("bearer", bearer_out)
            statuses["bearer"] = True
```

- [ ] **Step 2: Remove bearer from tool_manager.py**

Remove from VERSION_PATTERNS dict (line 88):
```python
    "bearer": re.compile(r"Version:\s*v?(\d+\.\d+\.\d+)"),
```

Remove from VERSION_COMMANDS dict (line 141):
```python
    "bearer": ["bearer", "version"],
```

Remove from INSTALL_INSTRUCTIONS dict (lines 321-328):
```python
    "bearer": {
        "install": {
            "linux": "curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh",
            "macos": "brew install bearer/tap/bearer",
            "windows": "iwr -useb https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.ps1 | iex",
        },
        "jmo_install": "jmo tools install bearer",
    },
```

Remove from PLATFORM_RESTRICTIONS dict (lines 420-425):
```python
    "bearer": {
        "windows": (
            "No Windows binaries available (use Docker or WSL)",
            "https://github.com/Bearer/bearer",
        ),
    },
```

- [ ] **Step 3: Clear bearer from EOL_TOOLS dict (keep structure)**

In `scripts/cli/tool_installer.py`, change the `EOL_TOOLS` dict to be empty but keep the infrastructure:

Old (lines 437-442):
```python
        EOL_TOOLS = {
            "bearer": (
                "Bearer project is archived (EOL). v2.0.1 is the final release. "
                "Consider Semgrep privacy rules (p/privacy, p/owasp-top-10) as a replacement."
            ),
        }
```

New:
```python
        EOL_TOOLS: dict[str, str] = {
            # Add tools here as they reach end-of-life, before full removal.
            # Format: "tool_name": "Deprecation message for users"
        }
```

- [ ] **Step 4: Remove bearer from wizard flows**

In `scripts/cli/wizard_flows/profile_config.py`, remove line 84:
```python
    "bearer": 50,
```

In `scripts/cli/wizard_flows/tool_checker.py`, remove line 204:
```python
        "bearer": "No official Windows binary",
```

Remove `"bearer"` from `WINDOWS_INCOMPATIBLE_TOOLS` set (line 229):
```python
    "bearer",
```

- [ ] **Step 5: Run tests**

```bash
make test-fast
```

Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
git add scripts/cli/scan_jobs/repository_scanner.py scripts/cli/tool_manager.py scripts/cli/tool_installer.py scripts/cli/wizard_flows/profile_config.py scripts/cli/wizard_flows/tool_checker.py
git commit -m "refactor(cli): remove bearer from scanner, tool manager, and wizard

Remove Bearer CLI (EOL) from:
- Repository scanner scan block and docstring
- Tool manager version patterns, commands, install instructions, platform restrictions
- Tool installer EOL_TOOLS entry (dict kept as infrastructure)
- Wizard profile scan time estimates
- Windows incompatible tools list

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Remove Bearer from Dockerfiles

**Files:**
- Modify: `Dockerfile:131-137,302,320,387`
- Modify: `Dockerfile.balanced:97-103,220,235,279`
- Modify: `Dockerfile.slim:78-84,180,194,234`

- [ ] **Step 1: Remove bearer from Dockerfile (deep variant)**

Remove download block (lines 131-137):
```dockerfile
# Download Bearer (Data Privacy + SAST)
RUN BEARER_VERSION="2.0.1" && \
    BEARER_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/bearer/bearer/releases/download/v${BEARER_VERSION}/bearer_${BEARER_VERSION}_linux_${BEARER_ARCH}.tar.gz" \
    -o /tmp/bearer.tar.gz && \
    tar -xzf /tmp/bearer.tar.gz -C /usr/local/bin bearer && \
    chmod +x /usr/local/bin/bearer
```

Remove COPY statement (line 302):
```dockerfile
COPY --from=builder /usr/local/bin/bearer /usr/local/bin/bearer
```

Remove from chmod block (line 320):
```dockerfile
    /usr/local/bin/bearer \
```

Remove from smoke test (line 387):
```dockerfile
    bearer version && \
```

- [ ] **Step 2: Remove bearer from Dockerfile.balanced**

Remove download block (lines 97-103):
```dockerfile
# Download Bearer (Data Privacy + SAST)
RUN BEARER_VERSION="2.0.1" && \
    BEARER_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/bearer/bearer/releases/download/v${BEARER_VERSION}/bearer_${BEARER_VERSION}_linux_${BEARER_ARCH}.tar.gz" \
    -o /tmp/bearer.tar.gz && \
    tar -xzf /tmp/bearer.tar.gz -C /usr/local/bin bearer && \
    chmod +x /usr/local/bin/bearer
```

Remove COPY statement (line 220):
```dockerfile
COPY --from=builder /usr/local/bin/bearer /usr/local/bin/bearer
```

Remove from chmod block (line 235):
```dockerfile
    /usr/local/bin/bearer \
```

Remove from smoke test (line 279):
```dockerfile
    bearer version && \
```

- [ ] **Step 3: Remove bearer from Dockerfile.slim**

Remove download block (lines 78-84):
```dockerfile
# Download Bearer (Data Privacy)
RUN BEARER_VERSION="2.0.1" && \
    BEARER_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -sSL "https://github.com/bearer/bearer/releases/download/v${BEARER_VERSION}/bearer_${BEARER_VERSION}_linux_${BEARER_ARCH}.tar.gz" \
    -o /tmp/bearer.tar.gz && \
    tar -xzf /tmp/bearer.tar.gz -C /usr/local/bin bearer && \
    chmod +x /usr/local/bin/bearer
```

Remove COPY statement (line 180):
```dockerfile
COPY --from=builder /usr/local/bin/bearer /usr/local/bin/bearer
```

Remove from chmod block (line 194):
```dockerfile
    /usr/local/bin/bearer \
```

Remove from smoke test (line 234):
```dockerfile
    bearer version && \
```

- [ ] **Step 4: Commit**

```bash
git add Dockerfile Dockerfile.balanced Dockerfile.slim
git commit -m "ci(docker): remove bearer from slim, balanced, and deep Dockerfiles

Remove Bearer CLI (EOL) download, COPY, chmod, and smoke test
from all 3 Dockerfile variants. Dockerfile.fast was never affected.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Remove Bearer from versions.yaml

**Files:**
- Modify: `versions.yaml:199-212,377,655-661`

- [ ] **Step 1: Remove bearer tool block**

Remove lines 199-212:
```yaml
  bearer:
    # NOTE: Bearer project is archived (EOL). v2.0.1 is the FINAL release.
    # No further updates will be published. Consider Semgrep privacy rules
    # (p/privacy, p/owasp-top-10) as a replacement when issues arise.
    version: 2.0.1
    github_repo: Bearer/bearer
    description: Data security and privacy scanner (GDPR/CCPA)
    release_pattern: bearer_linux_{arch}
    architectures:
      amd64: amd64
      arm64: arm64
    update_check: gh api repos/Bearer/bearer/releases/latest
    critical: false
    notes: v1.0.0 - Data privacy and sensitive data flows
```

- [ ] **Step 2: Remove bearer from non_critical_tools update group**

Remove line 377:
```yaml
    - bearer
```

- [ ] **Step 3: Remove bearer version history entry**

Remove lines 655-661:
```yaml
- date: '2025-11-17'
  action: Updated bearer
  tools_updated:
  - tool: bearer
    old_version: 1.50.0
    new_version: 1.51.1
  updated_by: update_versions.py
```

- [ ] **Step 4: Run tests to confirm no YAML parsing issues**

```bash
make test-fast
```

Expected: All tests pass. No tool registry or version lookup failures.

- [ ] **Step 5: Commit**

```bash
git add versions.yaml
git commit -m "chore(config): remove bearer from versions.yaml

Remove tool definition, update schedule group membership,
and version history entry for EOL Bearer CLI.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Update Documentation — Primary Docs

**Files:**
- Modify: `CLAUDE.md:7,13(profile counts)`
- Modify: `CONTRIBUTING.md:35-38`
- Modify: `README.md:13`
- Modify: `PRODUCT_DEFINITION.md:158`
- Modify: `DOCKER_HUB_README.md:32`
- Modify: `CHANGELOG.md` (add v1.0.1 section)
- Modify: `docs/PROFILES_AND_TOOLS.md:62,125,147,172,216,303,305,426,501,537`
- Modify: `docs/DOCKER_README.md:395,459`
- Modify: `docs/USER_GUIDE.md:368`
- Modify: `docs/CLI_REFERENCE.md:226,385`

- [ ] **Step 1: Update CLAUDE.md**

Line 7 — change `28+` to `27+`:
```text
JMo Security is a terminal-first security audit toolkit orchestrating 27+ scanners with unified CLI, normalized outputs, and HTML dashboard.
```

Update profile table (around line 13):
- `slim` | 13 | 12-18 min
- `balanced` | 17 | 18-25 min
- `deep` | 28 | 40-70 min

Also update the "28 adapter files" reference in the Architecture section to `27 adapter files`.

- [ ] **Step 2: Update CONTRIBUTING.md**

Line 35-38 — update profile table:
- `slim` | 13
- `balanced` | 17
- (deep already says 28 which is now correct)

Line 24 — update install command comment if it mentions tool count:
```bash
jmo tools install --profile balanced   # Install security tools (17 tools)
```

- [ ] **Step 3: Update README.md**

Line 13:
```text
**v1.0.0** | A terminal-first security audit toolkit orchestrating 27 scanners with unified CLI, normalized outputs, and interactive HTML dashboard.
```

- [ ] **Step 4: Update PRODUCT_DEFINITION.md**

Line 158 — remove Bearer from SAST list:
```text
| **SAST** | Semgrep, Horusec, Bandit, Gosec | Language depth vs. breadth trade-offs |
```

- [ ] **Step 5: Update DOCKER_HUB_README.md**

Line 32 — update tool count from 28 to 27 and remove "License (Bearer)" from the tool list. Recategorize or remove that category:
```text
- 🔐 **27 Security Tools** (24 Docker-ready + 3 manual): Secrets (TruffleHog, Nosey Parker, Semgrep-Secrets), SAST (Semgrep, Bandit, Gosec, Horusec), SBOM (Syft, CDXgen, ScanCode), SCA (Trivy, Grype, Dependency-Check), IaC (Checkov, Checkov-CICD), Cloud (Prowler, Kubescape), DAST (ZAP, Nuclei, Akto*), Dockerfile (Hadolint), Mobile (MobSF*), Malware (YARA), System (Lynis), Runtime (Trivy-RBAC, Falco), Fuzzing (AFL++*) |*Manual install required
```

- [ ] **Step 6: Update docs/PROFILES_AND_TOOLS.md**

This file has the most bearer references. Make these edits:

Line 62 — remove bearer mention from slim description:
```text
**Tools included:** Fast profile + cloud security (Prowler, Kubescape), additional SCA (Grype), and multi-language SAST (Horusec).
```

Line 125 — remove bearer from slim tool list:
```text
  - bearer          # Data privacy/SAST (GDPR/CCPA) [EOL: project archived, v2.0.1 final]
```

Line 147 — remove bearer from balanced tool list:
```text
  - bearer
```

Line 172 — remove bearer from deep tool list:
```text
  - bearer
```

Line 216 — remove bearer row from tool matrix:
```text
| Bearer | slim+ | 12+ languages (privacy focus) |
```

Line 303 — remove bearer row from SAST comparison table:
```text
| **Bearer** | Data privacy focus (GDPR/CCPA, PII exposure) | 12+ languages |
```

Line 305 — update SAST rationale paragraph to remove bearer mention.

Line 426 — remove `bearer (EOL)` from SAST tool group:
```text
| SAST | semgrep, bandit, gosec, horusec |
```

Line 501 — remove bearer cross-reference row:
```text
| bearer | ✅ | - | - | - | ✅ | - |
```

Line 537 — remove bearer from legacy version table:
```text
| 4 | Bearer | 1.51.1 | slim+ | binary | No |
```

Update all tool counts in section headers (slim: 14→13, balanced: 18→17, deep: 29→28).

- [ ] **Step 7: Update docs/DOCKER_README.md**

Line 395 — remove bearer row:
```text
| **Bearer** | Security + Privacy | Data flow, OWASP risks |
```

Line 459 — update balanced description:
```text
**Tools:** Fast + prowler, kubescape, grype, horusec, zap, scancode, cdxgen, gosec (17 tools)
```

- [ ] **Step 8: Update docs/USER_GUIDE.md**

Line 368 — remove bearer:
```text
**Slim profile adds:** prowler, kubescape, grype, horusec, dependency-check
```

- [ ] **Step 9: Update docs/CLI_REFERENCE.md**

Line 226 — remove `bearer` from tool list output example.

Line 385 — remove bearer from platform-skipped example:
```text
  🚫 1 platform-skipped (bearer - Windows not supported)
```
Update to show a different tool or remove the example line.

- [ ] **Step 10: Add CHANGELOG.md entry**

Add a new v1.0.1 section at the top (after line 3):

```markdown
## [1.0.1] - 2026-04-XX

### Removed

- **Bearer CLI** - Removed EOL Bearer security/privacy scanner (v2.0.1 final, project acquired by Cycode)
  - Bearer's SAST security findings (SQLi, XSS, command injection, path traversal) are already covered by Semgrep
  - Bearer's unique PII data-flow tracking has no open-source CLI replacement; gap documented
  - Profile tool counts updated: slim (14→13), balanced (18→17), deep (29→28)
  - Removed from: adapter, constants, profiles, scanner, tool manager, wizard, 3 Dockerfiles, versions.yaml

### Added

- **Tool Removal Guide** (`docs/TOOL_REMOVAL_GUIDE.md`) - Reusable 7-layer checklist for removing EOL tools
```

- [ ] **Step 11: Commit**

```bash
git add CLAUDE.md CONTRIBUTING.md README.md PRODUCT_DEFINITION.md DOCKER_HUB_README.md CHANGELOG.md docs/PROFILES_AND_TOOLS.md docs/DOCKER_README.md docs/USER_GUIDE.md docs/CLI_REFERENCE.md
git commit -m "docs: update all documentation for bearer removal

Update tool counts (slim: 13, balanced: 17, deep: 28) and remove
bearer references across 10 documentation files. Add v1.0.1
CHANGELOG section documenting the removal.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: Update Documentation — Secondary Docs

**Files:**
- Modify: `docs/MANUAL_INSTALLATION.md:217-230,290,306`
- Modify: `docs/USAGE_MATRIX.md:321,370,376`
- Modify: `docs/internal/TESTING_MATRIX.md:32,40,72,194,273`
- Modify: `docs/internal/BUILD_OPTIMIZATION.md:132-134,197`
- Modify: `docs/examples/custom-policy-examples.md:322,348`
- Modify: `packaging/docker/legacy/README.md:61`
- Modify: `packaging/winget/manifests/j/jmo/jmo-security/1.0.0/jmo.jmo-security.locale.en-US.yaml:106`

- [ ] **Step 1: Update docs/MANUAL_INSTALLATION.md**

Remove the entire Bearer install section (lines 217-230):
````markdown
**Bearer** (Privacy/PII scanning - Linux/macOS only):

```bash
# macOS
brew install bearer/tap/bearer

# Linux
curl -sfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh | sh

# Windows: Use Docker
docker run --rm -v "$PWD:/scan" bearer/bearer scan /scan
```

> **Note:** Bearer is not available natively on Windows. Use Docker mode or WSL2 for full support.
````

Remove bearer row from platform support table (line 290):
```text
| Bearer | ✅ | ✅ | ❌ | ✅ |
```

Remove bearer from Windows-incompatible list (line 306):
```text
> ~ bearer: Go binary not available for Windows
```

- [ ] **Step 2: Update docs/USAGE_MATRIX.md**

Remove bearer row (line 321):
```text
| **bearer** | Data privacy SAST | Repos | N/A | ~15-20% |
```

Remove `bearer` from slim profile tool list (line 370):
```yaml
    tools: [trufflehog, semgrep, syft, trivy, checkov, hadolint, nuclei, shellcheck,
            prowler, kubescape, grype, horusec, dependency-check]
```

Remove `bearer` from balanced profile tool list (line 376):
```yaml
    tools: [trufflehog, semgrep, syft, trivy, checkov, hadolint, nuclei, shellcheck,
            prowler, kubescape, grype, horusec, dependency-check,
            zap, scancode, cdxgen, gosec]
```

- [ ] **Step 3: Update docs/internal/TESTING_MATRIX.md**

Remove bearer from all 5 locations (lines 32, 40, 72, 194, 273). Update tool counts in surrounding text.

- [ ] **Step 4: Update docs/internal/BUILD_OPTIMIZATION.md**

Remove bearer download example (lines 132-134) and install line (197).

- [ ] **Step 5: Update docs/examples/custom-policy-examples.md**

Line 322 — remove bearer from comment:
```python
    # Check license field (from scancode or custom scanners)
```

Line 348 — update example command:
```bash
jmo scan --repo . --profile-name deep  # Includes scancode
```

- [ ] **Step 6: Update packaging files**

`packaging/docker/legacy/README.md` line 61 — remove bearer from table:
```text
| License | - | - | - |
```

`packaging/winget/.../locale.en-US.yaml` line 106 — remove bearer from slim description:
```yaml
  - slim: 13 tools (fast + prowler, kubescape, grype, horusec, dependency-check)
```

- [ ] **Step 7: Commit**

```bash
git add docs/MANUAL_INSTALLATION.md docs/USAGE_MATRIX.md docs/internal/TESTING_MATRIX.md docs/internal/BUILD_OPTIMIZATION.md docs/examples/custom-policy-examples.md packaging/docker/legacy/README.md packaging/winget/manifests/j/jmo/jmo-security/1.0.0/jmo.jmo-security.locale.en-US.yaml
git commit -m "docs: remove bearer from secondary docs and packaging manifests

Update manual installation, usage matrix, testing matrix,
build optimization, policy examples, and packaging manifests.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Create Tool Removal Guide

**Files:**
- Create: `docs/TOOL_REMOVAL_GUIDE.md`

- [ ] **Step 1: Write the Tool Removal Guide**

Create `docs/TOOL_REMOVAL_GUIDE.md`:

````markdown
# Tool Removal Guide

How to cleanly remove a security tool from JMo Security. This 7-layer checklist ensures no orphaned references remain. Based on the Bearer CLI removal (v1.0.1).

## When to Remove a Tool

- **Project archived/EOL** with no further rule updates (stale scanners create false confidence)
- **Acquired and folded** into a commercial product with no maintained OSS edition
- **Superseded** by another tool already in JMo with equivalent coverage
- **Persistent reliability issues** with no fix path

**Before removing:** Confirm there is no drop-in open-source CLI replacement. As an orchestrator, JMo can only wrap tools that exist as standalone binaries.

## Pre-Removal

1. Confirm EOL status: check GitHub repo, releases page, announcements
2. Identify coverage gap: is another tool in JMo already covering this tool's findings?
3. Search for replacement candidates: same niche, wrappable CLI, actively maintained
4. Write a design spec: `docs/superpowers/specs/YYYY-MM-DD-<tool>-removal-design.md`
5. Document decision rationale in CHANGELOG.md

## Removal Checklist (7 Layers)

Work bottom-up: tests first, then code, then Docker/config/docs. Run `make test-fast` after each code layer.

### Layer 1: Core Code

- [ ] Delete adapter: `scripts/core/adapters/<tool>_adapter.py`
- [ ] Remove `TOOL_<NAME>` constant from `scripts/core/constants.py`
- [ ] Remove from `ALL_TOOLS` list in `scripts/core/constants.py`
- [ ] Remove from `PROFILE_*_TOOLS` lists in `scripts/core/constants.py` (update count comments)
- [ ] Remove from `PROFILE_TOOLS` dict in `scripts/core/tool_registry.py` (update count comments)
- [ ] Remove from `PLATFORM_RESTRICTIONS` dict in `scripts/core/tool_registry.py` (if present)
- [ ] Remove from rule equivalence groups in `scripts/core/rule_equivalence.py` (if present)
- [ ] Remove from `BINARY_URLS` in `scripts/core/install_config.py` (if present)
- [ ] Remove from `ISOLATED_TOOLS` in `scripts/core/install_config.py` (if present)
- [ ] Remove from `scripts/dev/generate_comprehensive_test_data.py` tool weights

### Layer 2: CLI Code

- [ ] Remove scan block from `scripts/cli/scan_jobs/<scanner_type>_scanner.py`
- [ ] Update scanner docstring tool numbering
- [ ] Remove from `VERSION_PATTERNS` in `scripts/cli/tool_manager.py`
- [ ] Remove from `VERSION_COMMANDS` in `scripts/cli/tool_manager.py`
- [ ] Remove from `INSTALL_INSTRUCTIONS` in `scripts/cli/tool_manager.py`
- [ ] Remove from `PLATFORM_RESTRICTIONS` in `scripts/cli/tool_manager.py`
- [ ] Remove from `EOL_TOOLS` in `scripts/cli/tool_installer.py` (if still present)
- [ ] Remove from `scripts/cli/wizard_flows/profile_config.py` scan time estimates
- [ ] Remove from `scripts/cli/wizard_flows/tool_checker.py` (windows_reasons + WINDOWS_INCOMPATIBLE_TOOLS)

### Layer 3: Tests

- [ ] Delete adapter test: `tests/adapters/test_<tool>_adapter.py`
- [ ] Remove from `ALL_ADAPTERS` in `tests/adapters/test_adapter_malformed.py`
- [ ] Remove smoke config from `tests/integration/test_tool_smoke.py`
- [ ] Remove URL tests from `tests/unit/test_tool_installer_urls.py`
- [ ] Update mock data in `tests/cli/test_tool_manager.py`
- [ ] Update count assertions/comments in `tests/core/test_tool_registry.py`

### Layer 4: Docker

For each Dockerfile variant that includes the tool:
- [ ] Remove download/install RUN block
- [ ] Remove COPY statement (multi-stage builds)
- [ ] Remove from chmod PATH-verification block
- [ ] Remove from smoke test command chain

Check which variants: `grep -l "<tool>" Dockerfile*`

### Layer 5: Configuration

- [ ] Remove tool block from `versions.yaml`
- [ ] Remove from update schedule group in `versions.yaml`
- [ ] Remove from version history in `versions.yaml`
- [ ] Remove any per-tool config from `jmo.yml` profiles

### Layer 6: Documentation

Primary docs:
- [ ] `CLAUDE.md` — scanner count, profile tool counts, adapter count
- [ ] `CONTRIBUTING.md` — profile table tool counts
- [ ] `README.md` — scanner count
- [ ] `PRODUCT_DEFINITION.md` — tool categorization table
- [ ] `DOCKER_HUB_README.md` — tool count and list
- [ ] `CHANGELOG.md` — add removal entry under target version
- [ ] `docs/PROFILES_AND_TOOLS.md` — tool lists, matrix, cross-reference, SAST rationale
- [ ] `docs/DOCKER_README.md` — tool table, profile descriptions
- [ ] `docs/USER_GUIDE.md` — profile descriptions
- [ ] `docs/CLI_REFERENCE.md` — tool list examples, platform-skipped examples

Secondary docs:
- [ ] `docs/MANUAL_INSTALLATION.md` — install instructions, platform table, Windows notes
- [ ] `docs/USAGE_MATRIX.md` — tool role table, profile tool lists
- [ ] `docs/internal/TESTING_MATRIX.md` — test matrix
- [ ] `docs/internal/BUILD_OPTIMIZATION.md` — build examples
- [ ] `docs/examples/custom-policy-examples.md` — example policies
- [ ] `packaging/docker/legacy/README.md` — legacy Docker table
- [ ] `packaging/winget/.../locale.en-US.yaml` — WinGet manifest description

### Layer 7: Verify

- [ ] `make test-fast` passes
- [ ] `make lint` passes
- [ ] Grep confirms no orphaned references:
  ```bash
  grep -ri "<tool_name>" scripts/ tests/ --include="*.py" | grep -v "Bearer "  # Exclude HTTP Bearer auth
  ```
- [ ] Profile counts match across: constants.py, tool_registry.py, CLAUDE.md, CONTRIBUTING.md, PROFILES_AND_TOOLS.md, DOCKER_README.md

## False Positives to Ignore

Some tool names overlap with other concepts. Common false positives:

| Tool Name | False Positive Context | Why It's Safe |
|-----------|----------------------|---------------|
| bearer | HTTP `Authorization: Bearer <token>` | Authentication scheme, not the tool |
| trivy | Other security contexts mentioning "trivy" | Check if it's the tool or a typo |
| bandit | "bandit" in non-security contexts | Check surrounding context |

## Worked Example: Bearer CLI (v1.0.1)

Bearer (data privacy/SAST scanner) was removed in v1.0.1 after Cycode acquired the project and released v2.0.1 as the final open-source version.

- **Coverage gap:** Bearer's SAST findings were already covered by Semgrep `auto`. The unique PII data-flow tracking has no OSS CLI replacement.
- **Profile impact:** slim (14→13), balanced (18→17), deep (29→28)
- **Files touched:** ~30 files across all 7 layers
- **Design spec:** `docs/superpowers/specs/2026-04-03-bearer-removal-design.md`
- **Implementation plan:** `docs/superpowers/plans/2026-04-03-bearer-removal.md`
````

- [ ] **Step 2: Run lint on the new file**

```bash
make lint
```

- [ ] **Step 3: Commit**

```bash
git add docs/TOOL_REMOVAL_GUIDE.md
git commit -m "docs: add Tool Removal Guide for future EOL tool removals

7-layer checklist covering core code, CLI, tests, Docker, config,
documentation, and verification. Includes Bearer as worked example.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

---

### Task 9: Final Verification

**Files:** None (verification only)

- [ ] **Step 1: Run full test suite with coverage**

```bash
make test-fast
```

Expected: All tests pass. No bearer-related failures.

- [ ] **Step 2: Run linter**

```bash
make lint
```

Expected: Clean.

- [ ] **Step 3: Grep for orphaned bearer references**

```bash
grep -ri "bearer" scripts/ tests/ --include="*.py" | grep -v "Bearer " | grep -v "bearer_token" | grep -v "Authorization"
```

Expected: No results (all remaining "bearer" references are HTTP Bearer auth, not the tool).

- [ ] **Step 4: Verify profile counts match across sources**

```bash
python -c "
from scripts.core.tool_registry import PROFILE_TOOLS
for p, tools in PROFILE_TOOLS.items():
    print(f'{p}: {len(tools)} tools')
    assert 'bearer' not in tools, f'bearer still in {p}!'
print('All profiles clean.')
"
```

Expected output:
```text
fast: 9 tools
slim: 13 tools
balanced: 17 tools
deep: 28 tools
All profiles clean.
```

- [ ] **Step 5: Final commit (if any verification fixes needed)**

Only if verification revealed issues. Otherwise, no commit needed.
