# Detailed Phase Guide

Full instructions for each of the 10 phases in the adapter generation workflow. For a compact overview, see the main [SKILL.md](../SKILL.md).

---

## Phase 0: Memory Query

Check if tool patterns already exist in memory cache. See [memory-integration.md](./memory-integration.md) for full details.

---

## Phase 1: Research Tool Output Format

**Purpose:** Understand tool's JSON structure

**Actions:**
1. Search for official documentation: "{tool} JSON output format"
2. Check GitHub repos: "{tool} sample output"
3. Review existing plugin adapters for similar tools
4. Document schema structure, exit codes, field mappings

**Output:**
- JSON schema understanding
- Exit code mappings (0/1/2)
- Field mappings (vulnerabilities, secrets, misconfigs)

**Memory Integration:**
- Compare discovered format with memory (if exists)
- Note discrepancies (tool version changes?)

---

## Phase 2: Create Plugin Adapter

**Purpose:** Map tool JSON to CommonFinding schema using plugin architecture

**File:** `scripts/core/adapters/{tool}_adapter.py`

Use the template at [templates/adapter-template.py](../templates/adapter-template.py).

**Key Requirements:**
1. `@adapter_plugin` decorator (auto-registers)
2. Inherits `AdapterPlugin` base class
3. Returns `Finding` objects (dataclass, not dicts)
4. Uses `self.get_fingerprint()` helper (inherited)
5. Metadata property (required by base class)
6. Method named `parse()` (base class contract)

**Plugin Metadata Fields:**
- `name`: Plugin identifier (must match JSON filename)
- `version`: Adapter version (not tool version)
- `tool_name`: Security tool name
- `schema_version`: CommonFinding schema version (1.2.0)
- `output_format`: Tool output format ("json", "ndjson", "xml")
- `exit_codes`: Tool exit code meanings

---

## Phase 3: Write Tests

**Purpose:** Achieve >=85% coverage with realistic fixtures

**File:** `tests/adapters/test_{tool}_adapter.py`

Use the template at [templates/test-template.py](../templates/test-template.py).

**Key Differences from v2.x:**
- Import adapter class: `from ... import {Tool}Adapter`
- Instantiate adapter: `adapter = {Tool}Adapter()`
- Call `.parse()` method (not `load_{tool}()` function)
- Assert `Finding` objects: `isinstance(f, Finding)`
- Test plugin metadata: `adapter.metadata`

---

## Phase 4: CLI Integration (REMOVED in v3.0.0)

**This phase is no longer needed.** Plugin auto-discovery eliminates manual imports.

**OLD (v2.3.0):**
```python
# Manual imports in normalize_and_report.py
from scripts.core.adapters.{tool}_adapter import load_{tool}
{tool}_findings = load_{tool}(target / "{tool}.json")
all_findings.extend({tool}_findings)
```

**NEW (v3.0.0):**
```python
# NO MANUAL IMPORTS NEEDED!
# Plugins auto-discovered via discover_adapters()
plugin_count = discover_adapters()
registry = get_plugin_registry()

for tool_output in target.glob("*.json"):
    tool_name = tool_output.stem
    plugin_class = registry.get(tool_name)
    if plugin_class:
        adapter = plugin_class()
        findings.extend(adapter.parse(tool_output))
```

Skip directly to Phase 5.

---

## Phase 5: Update Configuration

**File:** `jmo.yml`

**Add {tool} to profiles:**

```yaml
profiles:
  fast:
    # Add if fast enough (<5 min)
    tools: [trufflehog, semgrep, trivy, checkov]

  balanced:
    # Add here
    tools: [trufflehog, semgrep, syft, trivy, checkov,
            hadolint, zap, nuclei, {tool}]

  deep:
    tools: [trufflehog, noseyparker, semgrep, bandit, syft, trivy,
            checkov, hadolint, zap, nuclei, {tool}, falco, afl++]

per_tool:
  {tool}:
    flags: ["--json"]  # From memory: Required flag
    timeout: 600  # From memory: Common pitfall (large repos timeout)
```

**Profile Selection Guidelines:**

| Profile | Criteria | Examples |
|---------|----------|----------|
| **fast** | <5 min, core capability, <10% false positives | trufflehog, semgrep, trivy |
| **balanced** | Production-ready, SAST/DAST/SCA/IaC/CSPM | prowler, kubescape, akto |
| **deep** | Specialized, >10 min, fuzzing, runtime, mobile | mobsf, lynis, afl++ |

---

## Phase 6: Update Documentation

**Files to Update:**
1. **README.md** - Add {tool} to supported tools list
2. **QUICKSTART.md** - Add {tool} scan example (if commonly used)
3. **docs/USER_GUIDE.md** - Add {tool} configuration section
4. **CLAUDE.md** - Update tool count and category list
5. **CHANGELOG.md** - Document feature addition

---

## Phase 6.5: Docker, Wizard, and Installation Integration

**CRITICAL:** This phase is STILL REQUIRED for plugin-based adapters.

**Why:** Plugin system only affects adapters (Python code). Docker images still need binary installation, wizard profiles still need tool selection, installation scripts still need tool downloads.

**Sub-Phases:**
1. **Version Tracking** (`versions.yaml`) - Add tool version
2. **Local Installation** (`scripts/dev/install_tools.sh`) - Add install script
3. **Docker Integration** (3 Dockerfiles) - Add tool to all variants
4. **Wizard Profiles** (`scripts/cli/wizard.py`) - Add to appropriate profiles
5. **Verify Parity** - Check consistency across all integration points

---

## Phase 7: Write Integration Tests

**File:** `tests/integration/test_{tool}_integration.py`

**Purpose:** End-to-end test of {tool} in scan workflow.

```python
"""Integration tests for {tool} scanner (v3.0.0)."""

import pytest
import json
from pathlib import Path
from scripts.cli.jmo import cmd_scan, cmd_report, parse_args


def test_{tool}_scan_integration(tmp_path, sample_repo):
    """Test {tool} in full scan workflow with plugin architecture."""
    # Arrange
    results_dir = tmp_path / "results"
    args = parse_args([
        "scan",
        "--repo", str(sample_repo),
        "--tools", "{tool}",
        "--results-dir", str(results_dir),
        "--allow-missing-tools"
    ])

    # Act: Scan
    rc_scan = cmd_scan(args)
    assert rc_scan == 0
    tool_output = results_dir / "individual-repos" / sample_repo.name / "{tool}.json"
    assert tool_output.exists()

    # Act: Report (tests plugin auto-discovery)
    args_report = parse_args([
        "report",
        str(results_dir),
        "--outputs", "json,md"
    ])
    rc_report = cmd_report(args_report)
    assert rc_report == 0

    # Verify: {tool} findings in unified output
    findings_file = results_dir / "summaries" / "findings.json"
    assert findings_file.exists()
    findings = json.loads(findings_file.read_text())
    {tool}_findings = [f for f in findings if f["tool"]["name"] == "{tool}"]
    assert len({tool}_findings) > 0

    for finding in {tool}_findings:
        assert finding["schemaVersion"] == "1.2.0"
        assert "id" in finding
        assert "ruleId" in finding
        assert "severity" in finding


def test_{tool}_plugin_discovery():
    """Test {tool} adapter is discovered by plugin system (v3.0.0)."""
    from scripts.core.plugin_loader import discover_adapters, get_plugin_registry

    count = discover_adapters()
    assert count > 0

    registry = get_plugin_registry()
    adapter_class = registry.get("{tool}")
    assert adapter_class is not None

    adapter = adapter_class()
    assert adapter.metadata.name == "{tool}"
    assert adapter.metadata.tool_name == "{tool}"
```

---

## Phase 8: Store Memory

See [memory-integration.md](./memory-integration.md) for full details on storing learned patterns.

---

## Phase 9: Run Validation Suite

**Checklist:**
- [ ] Tests pass: `pytest tests/adapters/test_{tool}_adapter.py -v`
- [ ] Coverage >=85%: `pytest tests/adapters/test_{tool}_adapter.py --cov=scripts.core.adapters.{tool}_adapter --cov-report=term-missing`
- [ ] Integration test passes: `pytest tests/integration/test_{tool}_integration.py -v`
- [ ] Plugin discovery works: Verify adapter auto-loaded
- [ ] Linting clean: `ruff check scripts/core/adapters/{tool}_adapter.py`
- [ ] Formatting clean: `black scripts/core/adapters/{tool}_adapter.py`
- [ ] Type checking: `mypy scripts/core/adapters/{tool}_adapter.py` (if enabled)
- [ ] Documentation lint: `markdownlint README.md QUICKSTART.md docs/USER_GUIDE.md`
- [ ] Memory stored: Verify `.jmo/memory/adapters/{tool}.json` exists

**Commands:**

```bash
# Run all validations
make test
make lint
make pre-commit-run

# Verify plugin discovery
python3 -c "
from scripts.core.plugin_loader import discover_adapters, get_plugin_registry
count = discover_adapters()
print(f'Discovered {count} plugins')
registry = get_plugin_registry()
adapter = registry.get('{tool}')
print(f'{tool} adapter: {adapter}')
"

# Verify memory file
cat .jmo/memory/adapters/{tool}.json | jq .
```

---

## Phase 10: Create Pull Request

**PR Title:** `feat(adapters): add {tool} scanner support (v3.0.0 plugin)`

**PR Description Template:**

```markdown
## Summary

Add support for {tool} scanner using v3.0.0 plugin architecture.

## Changes

- **Adapter:** `scripts/core/adapters/{tool}_adapter.py`
  (plugin-based, 150 lines, 87% coverage)
- **Tests:** `tests/adapters/test_{tool}_adapter.py` (8 tests, all passing)
- **Integration:** `tests/integration/test_{tool}_integration.py` (end-to-end test)
- **Config:** Added {tool} to `balanced` and `deep` profiles
- **Docs:** Updated README.md, QUICKSTART.md, USER_GUIDE.md, CLAUDE.md
- **Memory:** Stored patterns in `.jmo/memory/adapters/{tool}.json`

## Plugin Architecture (v3.0.0)

This adapter uses the v0.9.0 plugin architecture:
- `@adapter_plugin` decorator for auto-discovery
- Inherits `AdapterPlugin` base class
- Returns `Finding` objects (not dicts)
- No manual imports needed (auto-loaded)

## Test Coverage

tests/adapters/test_{tool}_adapter.py::test_{tool}_adapter_high_severity PASSED
tests/adapters/test_{tool}_adapter.py::test_{tool}_adapter_clean PASSED
tests/adapters/test_{tool}_adapter.py::test_{tool}_adapter_malformed PASSED
tests/adapters/test_{tool}_adapter.py::test_{tool}_adapter_missing_file PASSED
tests/adapters/test_{tool}_adapter.py::test_{tool}_severity_mapping PASSED
tests/adapters/test_{tool}_adapter.py::test_{tool}_plugin_metadata PASSED
tests/adapters/test_{tool}_adapter.py::test_{tool}_finding_objects_not_dicts PASSED

Coverage: 87% (130/150 lines)

## Example Usage

jmo scan --profile balanced --repo ./my-project --tools {tool}
cat results/summaries/findings.json | jq '.[] | select(.tool.name == "{tool}")'

## Checklist

- [x] Tests pass (>=85% coverage)
- [x] Linting clean (ruff, black, mypy)
- [x] Plugin auto-discovery works
- [x] Documentation updated
- [x] Memory stored for reuse
- [x] Integration test added
```
