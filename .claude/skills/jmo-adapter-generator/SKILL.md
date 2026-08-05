---
name: jmo-adapter-generator
description: Generate new security tool adapters with plugin architecture, tests, and CLI integration. Use when adding a new scanner tool to JMo Security.
argument-hint: <tool-name>
user-invocable: true
context: fork
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

## Execution

Generate adapter for: **$ARGUMENTS**

**Current adapter count:**
!ls scripts/core/adapters/*_adapter.py 2>/dev/null | wc -l

---

## Purpose

**Approach:** Generate adapters that are correct and complete on the first pass. Verify every field mapping against the CommonFinding schema before declaring done.

---

## Breaking Changes (v3.0.0)

**Plugin Architecture (v0.9.0):** Class-based adapters with `@adapter_plugin` decorator replaced function-based `load_{tool}()` pattern. Adapters return `Finding` objects (not dicts) and are auto-discovered -- no manual imports in normalize_and_report.py.

**v1.0.0 Tool Expansion:** 16 new tools added (12 to 28 total), 5 new categories (Cloud CSPM, Mobile SAST, CI/CD Security, License, System Hardening), 3 new target types.

**Migration at a glance:**

```python
# OLD: Function-based
def load_snyk(path: Path) -> List[Dict[str, Any]]: ...

# NEW: Plugin-based
@adapter_plugin(PluginMetadata(name="snyk", ...))
class SnykAdapter(AdapterPlugin):
    def parse(self, output_path: Path) -> List[Finding]: ...
```

---

## Skill Workflow (10 Phases)

> Full step-by-step instructions: [references/detailed-phase-guide.md](references/detailed-phase-guide.md)

### Phase 0: Memory Query

Check `.jmo/memory/adapters/{tool}.json` for cached patterns. Memory hit saves 30-45 min of research. See [references/memory-integration.md](references/memory-integration.md).

### Phase 1: Research Tool Output Format

Search official docs and GitHub for JSON schema, exit codes, and field mappings. Compare with memory if available.

### Phase 2: Create Plugin Adapter

**File:** `scripts/core/adapters/{tool}_adapter.py`

Use the full template at [templates/adapter-template.py](templates/adapter-template.py). Key requirements:

- `@adapter_plugin` decorator with `PluginMetadata` (auto-registers)
- Inherits `AdapterPlugin`, implements `parse()` returning `List[Finding]`
- Uses `self.get_fingerprint()` for deterministic IDs
- `name` in metadata must match `{tool}.json` filename
- Adapters do NOT handle compliance enrichment (centralized in normalize_and_report.py)

### Phase 3: Write Tests

**File:** `tests/adapters/test_{tool}_adapter.py`

Use the full template at [templates/test-template.py](templates/test-template.py). Must achieve >=85% coverage. Key patterns:

- Instantiate `{Tool}Adapter()`, call `.parse()`, assert `Finding` objects
- Test fixtures: high severity, clean scan, malformed JSON, missing file
- Verify severity mapping, plugin metadata, fingerprint generation

### Phase 4: CLI Integration -- REMOVED

Auto-discovery via `discover_adapters()` eliminates manual imports. Skip to Phase 5.

### Phase 5: Update Configuration

Add `{tool}` to appropriate profiles in `jmo.yml` and set per-tool flags/timeout. Profile criteria: fast (<5 min), balanced (production-ready), deep (specialized).

### Phase 6: Update Documentation

Update README.md, QUICKSTART.md, docs/USER_GUIDE.md, CLAUDE.md, CHANGELOG.md with the new tool.

### Phase 6.5: Docker, Wizard, and Installation Integration

Still required -- plugin system only affects Python adapters. Update: `versions.yaml`, install scripts, 3 Dockerfiles, wizard profiles. Verify parity across all integration points.

### Phase 7: Write Integration Tests

**File:** `tests/integration/test_{tool}_integration.py`

End-to-end test: scan with tool, generate report, verify findings in unified output with v1.2.0 schema. Also test plugin discovery via `get_plugin_registry()`.

### Phase 8: Store Memory

Persist tool patterns, exit codes, pitfalls, and test fixtures to `.jmo/memory/adapters/{tool}.json`. See [references/memory-integration.md](references/memory-integration.md).

### Phase 9: Run Validation Suite

Run `make test && make lint && make pre-commit-run`. Verify plugin discovery, coverage >=85%, memory file exists. Full checklist in [references/detailed-phase-guide.md](references/detailed-phase-guide.md#phase-9-run-validation-suite).

### Phase 10: Create Pull Request

PR title: `feat(adapters): add {tool} scanner support (v3.0.0 plugin)`. Include adapter, tests, integration tests, config, docs, and memory in the changeset. Full PR template in [references/detailed-phase-guide.md](references/detailed-phase-guide.md#phase-10-create-pull-request).

---

## Real-World Examples

See [examples/new-tool-examples.md](examples/new-tool-examples.md) for complete adapter implementations:

1. **Prowler** (Cloud CSPM) -- AWS/Azure/GCP auditing, 400+ compliance checks
2. **MobSF** (Mobile SAST) -- iOS/Android static analysis, OWASP Mobile Top 10
3. **Checkov** (CI/CD Security) -- GitHub Actions/GitLab CI scanning with CI/CD tagging
4. **ScanCode** (License Compliance) -- OSS license detection, risky license flagging
5. **Lynis** (System Hardening) -- Text log parsing, warning/suggestion extraction

---

## Success Criteria

- [ ] Plugin adapter created with `@adapter_plugin` decorator
- [ ] Tests pass with >=85% coverage
- [ ] Plugin auto-discovery works (no manual imports)
- [ ] Tests use `adapter.parse()` method (not `load_{tool}()`)
- [ ] Tests verify `Finding` objects (not dicts)
- [ ] Configuration updated (jmo.yml profiles)
- [ ] Documentation updated (README, QUICKSTART, USER_GUIDE)
- [ ] Docker/Wizard/Installation integration complete
- [ ] Integration test passes (end-to-end)
- [ ] Memory stored for reuse
- [ ] All validation checks pass
