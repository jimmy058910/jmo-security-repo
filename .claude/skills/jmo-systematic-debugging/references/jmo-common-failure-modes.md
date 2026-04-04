# JMo Security Common Failure Modes

Catalog of frequent issues with systematic debugging approaches for each.

---

## 1. Empty findings.json despite tool output

**Symptoms:**

- `trivy.json` has 50 vulnerabilities
- `findings.json` has 0 findings
- No errors in logs

**Phase 1 Investigation:**

```bash
# Check adapter parsing
python3 -c "
from scripts.core.adapters.trivy_adapter import load_trivy
findings = load_trivy('results/individual-repos/test-repo/trivy.json')
print(f'Adapter returned {len(findings)} findings')
"
```

**Common root causes:**

1. **Adapter field mapping:** Tool output structure changed, adapter expects old format
2. **Schema validation:** Adapter returns findings but missing required CommonFinding fields
3. **Fingerprint collision:** All findings have identical ID, deduplicated to 1

**Phase 2 Pattern:**

- Compare tool output against adapter expectations
- Check recent tool version changes in `versions.yaml`
- Review adapter's field extraction logic line-by-line

**Phase 3 Hypothesis:**

- "Tool outputs 'Level' but adapter checks 'Severity'" (field name change)
- "Adapter returns empty list due to missing 'Results' key" (structure change)

**Phase 4 Fix:**

- Update adapter field mapping: `item.get("Severity") or item.get("Level")`
- Add test case with new tool output format

---

## 2. Tool times out in CI but works locally

**Symptoms:**

- Local scan: trivy completes in 30 seconds
- CI scan: trivy times out after 600 seconds
- Same repo, same tool version

**Phase 1 Investigation:**

```bash
# Check tool versions
cat versions.yaml | grep "trivy:"
trivy --version  # Local
# In CI: Add step to print trivy --version

# Check timeout configuration
grep -r "timeout.*600" jmo.yml scripts/cli/
```

**Common root causes:**

1. **Tool version mismatch:** CI uses older trivy with slower CVE database
2. **Resource constraints:** CI runner has 2 CPU cores vs local 8 cores
3. **Network latency:** CI downloads CVE database slower than local cache

**Phase 2 Pattern:**

- Compare tool versions (local vs CI)
- Check CI runner specs (CPU, memory, network)
- Review timeout settings (global vs per-tool)

**Phase 3 Hypothesis:**

- "CI uses trivy 0.50 (slow), local uses 0.68 (fast)" (version mismatch)
- "Timeout 600s insufficient for CI's 2-core runner" (resource constraint)

**Phase 4 Fix:**

- Update Dockerfile to use trivy 0.68 from `versions.yaml`
- Add per-tool timeout override: `trivy: { timeout: 900 }` in `jmo.yml`
- Add test: Verify CI trivy version matches `versions.yaml`

---

## 3. One target type works, others fail

**Symptoms:**

- Repos: trivy scan succeeds, findings in `findings.json`
- Images: trivy scan succeeds, NO findings in `findings.json`
- Same tool, same adapter

**Phase 1 Investigation:**

```bash
# Check directory structure
ls -lah results/individual-repos/test-repo/trivy.json  # 45KB
ls -lah results/individual-images/nginx_latest/trivy.json  # 0 bytes OR missing

# Check normalize_and_report.py
grep -n "individual-images" scripts/core/normalize_and_report.py
# Line found? If not, directory not scanned
```

**Common root causes:**

1. **Missing directory in aggregation:** `normalize_and_report.py` doesn't scan `individual-images/`
2. **Exit code handling:** Image scans return different exit codes than repo scans
3. **Output file not created:** Scan job doesn't write output file correctly

**Phase 2 Pattern:**

- Compare scan job implementations: `repository_scanner.py` vs `image_scanner.py`
- Check `target_dirs` list in `normalize_and_report.py`
- Verify output file creation in scan job

**Phase 3 Hypothesis:**

- "`target_dirs` missing `individual-images/`" (aggregation gap)
- "Image scan writes to wrong directory" (scan job bug)

**Phase 4 Fix:**

- Add `results_dir / "individual-images"` to `target_dirs` list
- Add test: Verify all 6 target directories scanned
- Update documentation: CLAUDE.md results directory layout

---

## 4. Tests pass locally, fail in CI

**Symptoms:**

- Local: `pytest tests/ -v` -- all pass
- CI: `pytest tests/ -v` -- 3 failures in adapter tests

**Phase 1 Investigation:**

```bash
# Check Python versions
python3 --version  # Local
# CI: Check .github/workflows/ci.yml matrix

# Check dependency versions
pip list | grep pytest
# CI: Check requirements-dev.txt vs pip list

# Check test isolation
pytest tests/adapters/test_trivy_adapter.py -v  # Pass?
pytest tests/ -v  # Fail?
# If so: test pollution from other tests
```

**Common root causes:**

1. **Dependency version mismatch:** Local has pytest 8.0, CI has pytest 7.4
2. **Test pollution:** Tests depend on execution order or shared state
3. **Path assumptions:** Tests assume files exist that don't in CI environment

**Phase 2 Pattern:**

- Compare local vs CI environments (Python, deps, OS)
- Check test fixtures: Do they use `/tmp/` paths? (macOS vs Linux)
- Review test setup/teardown: Proper cleanup?

**Phase 3 Hypothesis:**

- "Tests assume `/tmp/` exists, CI uses `$RUNNER_TEMP`" (path assumption)
- "Tests leave fixtures in `/tmp/`, next test uses stale data" (test pollution)

**Phase 4 Fix:**

- Use `tmp_path` fixture instead of hardcoded `/tmp/` paths
- Add cleanup in teardown: `shutil.rmtree(tmp_path, ignore_errors=True)`
- Run tests with `--randomly` to catch order dependencies

---

## 5. Pre-commit hooks fail on CI but pass locally

**Symptoms:**

- Local: `pre-commit run --all-files` -- all pass
- CI: pre-commit job -- markdownlint fails

**Phase 1 Investigation:**

```bash
# Check pre-commit versions
pre-commit --version  # Local
# CI: Check .github/workflows/ci.yml

# Run specific hook
pre-commit run markdownlint --all-files

# Check hook configuration
cat .pre-commit-config.yaml | grep -A 5 "markdownlint"
```

**Common root causes:**

1. **Hook version mismatch:** Local uses cached old version, CI uses latest
2. **File not tracked:** Local has `.gitignore` files, CI doesn't see them
3. **Config mismatch:** Local has `.markdownlint.json`, CI doesn't

**Phase 2 Pattern:**

- Compare hook versions: `pre-commit run --all-files --verbose`
- Check files being linted: `pre-commit run markdownlint --all-files --verbose`
- Review hook config: `.markdownlint.json`, `.pre-commit-config.yaml`

**Phase 3 Hypothesis:**

- "Local markdownlint v0.33, CI v0.39 (stricter rules)" (version mismatch)
- "CI lints dev-only/ files, local .gitignore hides them" (file tracking)

**Phase 4 Fix:**

- Run `pre-commit autoupdate` to sync versions
- Commit `.markdownlint.json` if missing
- Add `exclude: ^dev-only/` to `.pre-commit-config.yaml`
