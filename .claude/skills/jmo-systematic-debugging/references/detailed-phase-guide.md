# Detailed Phase Guide

Full instructions for each of the 4 debugging phases with JMo-specific examples, commands, and patterns.

---

## Phase 1: Root Cause Investigation (Detailed)

**BEFORE attempting ANY fix:**

### Step 1: Read Error Messages Carefully

- Don't skip past errors or warnings
- They often contain the exact solution
- Read stack traces completely
- Note line numbers, file paths, error codes

**JMo-specific error patterns:**

```python
# Adapter parse errors
AdapterParseException: "Invalid JSON in trivy output"
# Check: Is raw tool JSON valid? Use `jq . < tool.json`

# Schema validation errors
"Missing required field 'ruleId' in finding"
# Check: Adapter mapping logic, does tool output have this field?

# Subprocess errors
"Tool 'semgrep' failed with exit code 2"
# Check: OK exit codes in jmo.py, per-tool overrides in jmo.yml
```

### Step 2: Reproduce Consistently

- Can you trigger it reliably?
- What are the exact steps?
- Does it happen every time?
- If not reproducible, gather more data -- don't guess

**JMo-specific reproduction steps:**

```bash
# Isolate scan phase failure
python3 scripts/cli/jmo.py scan --repo ./test-repo --tools trivy --results-dir /tmp/debug-scan

# Isolate report phase failure
python3 scripts/cli/jmo.py report /tmp/debug-scan --human-logs

# Isolate adapter parsing
python3 -c "
from scripts.core.adapters.trivy_adapter import load_trivy
findings = load_trivy('/tmp/debug-scan/individual-repos/test-repo/trivy.json')
print(f'Loaded {len(findings)} findings')
"

# Test single tool in isolation
trivy fs -f json . -o /tmp/trivy-debug.json && \
python3 -c "from scripts.core.adapters.trivy_adapter import load_trivy; \
print(load_trivy('/tmp/trivy-debug.json'))"
```

### Step 3: Check Recent Changes

- What changed that could cause this?
- Git diff, recent commits
- New dependencies, config changes
- Environmental differences

**JMo-specific change categories:**

- **Adapter changes:** Modified field mappings, exit code handling
- **Tool version changes:** Tool output format changed (check `versions.yaml`)
- **Profile changes:** New tools added, timeout adjustments
- **Multi-target changes:** New target type added, directory structure changed
- **Compliance changes:** New framework mappings, CWE updates

### Step 4: Gather Evidence in Multi-Component Systems

**WHEN system has multiple components (CI -> build -> signing, API -> service -> database):**

Add diagnostic instrumentation BEFORE proposing fixes:

```text
For EACH component boundary:
  - Log what data enters component
  - Log what data exits component
  - Verify environment/config propagation
  - Check state at each layer

Run once to gather evidence showing WHERE it breaks
THEN analyze evidence to identify failing component
THEN investigate that specific component
```

**Example (multi-layer system):**

```bash
# Layer 1: Workflow
echo "=== Secrets available in workflow: ==="
echo "IDENTITY: ${IDENTITY:+SET}${IDENTITY:-UNSET}"

# Layer 2: Build script
echo "=== Env vars in build script: ==="
env | grep IDENTITY || echo "IDENTITY not in environment"

# Layer 3: Signing script
echo "=== Keychain state: ==="
security list-keychains
security find-identity -v

# Layer 4: Actual signing
codesign --sign "$IDENTITY" --verbose=4 "$APP"
```

**This reveals:** Which layer fails (secrets -> workflow OK, workflow -> build FAIL)

**JMo-specific component boundaries:**

```text
Boundary 1: CLI -> Tool Subprocess
- Check: Tool invocation (command, flags, environment)
- Check: Exit codes, stdout/stderr
- Check: Output file created and non-empty

Boundary 2: Tool Output File -> Adapter Parsing
- Check: JSON validity (jq . < tool.json)
- Check: Expected tool output structure (Results array, etc.)
- Check: Adapter field mapping logic

Boundary 3: Adapter -> normalize_and_report.py
- Check: Findings list returned from adapter
- Check: CommonFinding schema compliance
- Check: Fingerprint generation

Boundary 4: Aggregation -> Reporters
- Check: Deduplication by fingerprint ID
- Check: Compliance enrichment
- Check: Output file generation (findings.json, dashboard.html)
```

### Step 5: Trace Data Flow

**WHEN error is deep in call stack:**

**JMo-specific data flow tracing:**

```text
User -> jmo.py scan -> ScanOrchestrator -> scan_repository()
    -> subprocess.run(["trivy", ...]) -> trivy.json written
    -> jmo.py report -> normalize_and_report.py -> gather_results()
    -> load_trivy(trivy.json) -> List[CommonFinding]
    -> Deduplication -> Compliance enrichment
    -> write_json(findings.json) + write_markdown(SUMMARY.md)
```

**Backward tracing example:**

```text
Problem: findings.json has 0 findings but trivy.json has 50 vulnerabilities

Step 1: Where does findings.json get populated?
-> write_json() in basic_reporter.py

Step 2: What calls write_json()?
-> normalize_and_report.py:main() passes findings list

Step 3: Where does findings list come from?
-> gather_results() aggregates from all adapters

Step 4: What does load_trivy() return?
-> Add debug: print(f"Trivy findings: {len(findings_chunk)}")
-> If 50: Problem is in gather_results aggregation
-> If 0: Problem is in load_trivy parsing

Step 5: If load_trivy returns 0:
-> Check: Does trivy.json have expected structure?
-> Check: Is "Results" key present? data.get("Results")
-> Check: Are vulnerabilities being extracted? r.get("Vulnerabilities")
-> Root cause likely: Tool output format changed, adapter needs update
```

**Quick version:**

- Where does bad value originate?
- What called this with bad value?
- Keep tracing up until you find the source
- Fix at source, not at symptom

---

## Phase 2: Pattern Analysis (Detailed)

**Find the pattern before fixing.**

### Step 1: Find Working Examples in JMo Codebase

**For adapter issues:**

```bash
# Compare working adapter against broken one
# Example: semgrep_adapter works, snyk_adapter broken

# 1. Compare adapter structure
diff -u scripts/core/adapters/semgrep_adapter.py \
        scripts/core/adapters/snyk_adapter.py

# 2. Check tool output structure similarity
jq . results/individual-repos/test-repo/semgrep.json | head -30
jq . results/individual-repos/test-repo/snyk.json | head -30

# 3. Compare test patterns
diff -u tests/adapters/test_semgrep_adapter.py \
        tests/adapters/test_snyk_adapter.py
```

**For scan job issues:**

```bash
# Compare working scan job against broken one
# Example: scan_repository() works, scan_image() broken

# Check: scan_jobs/*.py implementations
# Pattern: All follow _iter_*() -> job_*() -> ThreadPoolExecutor
grep -A 20 "def job_repository" scripts/cli/scan_jobs/repository_scanner.py
grep -A 20 "def job_image" scripts/cli/scan_jobs/image_scanner.py
```

**For multi-target issues:**

```bash
# If one target type works but another doesn't
# Example: repos work, images fail

# 1. Check directory structure
ls -lah results/individual-repos/test-repo/  # Has trivy.json
ls -lah results/individual-images/nginx/     # Empty or missing trivy.json?

# 2. Check normalize_and_report.py aggregation
grep -A 10 "individual-repos" scripts/core/normalize_and_report.py
grep -A 10 "individual-images" scripts/core/normalize_and_report.py
# Should be identical patterns
```

### Step 2: Compare Against Reference Implementations

**JMo-specific references:**

- **Adapter pattern:** `scripts/core/adapters/trivy_adapter.py` (most comprehensive)
- **Test pattern:** `tests/adapters/test_trivy_adapter.py` (5 categories)
- **Scan job pattern:** `scripts/cli/scan_jobs/repository_scanner.py` (12 tools)
- **Exit code handling:** Check CLAUDE.md "Tool Invocation" section
- **CommonFinding schema:** `docs/schemas/common_finding.v1.json`

**Read completely before implementing:**

```python
# WRONG: Skim trivy_adapter, copy-paste structure
# RIGHT: Read trivy_adapter line by line, understand:
# - How does it handle missing fields? (item.get("X") or "default")
# - How does it normalize severity? (normalize_severity() function)
# - How does it generate fingerprints? (fingerprint() function)
# - What does it do with raw tool data? (Embeds in finding["raw"])
```

### Step 3: Identify Differences Between Working and Broken

**Systematic comparison checklist:**

```text
- [ ] Exit codes: Does tool use different codes than expected?
- [ ] JSON structure: Does tool output have different top-level keys?
- [ ] Field names: Are field names different? (e.g., "Severity" vs "Level")
- [ ] Nested vs flat: Is data nested differently? (Results[0].Vulnerabilities vs Vulnerabilities)
- [ ] Array vs object: Is field an array when expecting object, or vice versa?
- [ ] Empty handling: How does tool represent "no findings"? ([] vs null vs missing key)
- [ ] Tool version: Did tool version change? Check versions.yaml
```

**Example difference investigation:**

```bash
# Why does trivy work for repos but not images?

# Compare tool invocations
grep "trivy fs" scripts/cli/scan_jobs/repository_scanner.py
# trivy fs -f json . -o results/trivy.json

grep "trivy image" scripts/cli/scan_jobs/image_scanner.py
# trivy image -f json nginx:latest -o results/trivy.json

# Compare outputs
jq '.Results[0] | keys' results/repos/test-repo/trivy.json
jq '.Results[0] | keys' results/images/nginx/trivy.json
# Are keys identical? If not, adapter may need conditional logic
```

### Step 4: Understand Dependencies

**JMo-specific dependency checks:**

```bash
# Tool availability
make verify-env  # Shows installed tools

# Tool versions (critical for output format compatibility)
cat versions.yaml | grep -A 2 "trivy:"
trivy --version  # Does local version match versions.yaml?

# Configuration dependencies
cat jmo.yml | grep -A 10 "balanced:"  # Profile config
cat jmo.yml | grep -A 5 "per_tool:"    # Per-tool overrides

# Python dependencies
pip list | grep -E "(pytest|black|ruff)"  # Dev deps
python3 -c "import yaml; print('PyYAML OK')"  # Optional dep

# Environment assumptions
env | grep JMO_  # JMo-specific env vars
# JMO_THREADS, JMO_PROFILE, JMO_TELEMETRY_DISABLE, etc.
```

---

## Phase 3: Hypothesis and Testing (Detailed)

**Scientific method.**

### Step 1: Form Single Hypothesis

- State clearly: "I think X is the root cause because Y"
- Write it down
- Be specific, not vague

**JMo-specific hypothesis examples:**

```text
GOOD: "I think trivy returns exit code 1 when it finds vulnerabilities,
      and jmo.py treats exit code 1 as failure, so findings are never
      written to the output file."

BAD:  "There's something wrong with the trivy integration."

GOOD: "I think the adapter expects 'Severity' field but the tool outputs
      'Level' field, so normalize_severity() returns None and the finding
      is skipped."

BAD:  "The adapter isn't parsing the JSON correctly."

GOOD: "I think normalize_and_report.py only scans individual-repos/
      directory and doesn't scan individual-images/, so image findings
      never make it to findings.json."

BAD:  "Multi-target scanning isn't working."
```

### Step 2: Test Minimally

- Make the SMALLEST possible change to test hypothesis
- One variable at a time
- Don't fix multiple things at once

**Test 1: Exit code hypothesis**

```bash
# Hypothesis: Tool returns exit code 1, treated as failure
# Minimal test: Add exit code 1 to OK list

# BEFORE (in jmo.py or scan_jobs/*.py)
ok_rcs = (0,)

# AFTER (minimal change)
ok_rcs = (0, 1)

# Run single tool scan
python3 scripts/cli/jmo.py scan --repo ./test-repo --tools trivy --results-dir /tmp/test

# Verify: Does trivy.json exist and contain findings?
ls -lah /tmp/test/individual-repos/test-repo/trivy.json
jq '.Results | length' /tmp/test/individual-repos/test-repo/trivy.json
```

**Test 2: Field mapping hypothesis**

```python
# Hypothesis: Tool outputs "Level" not "Severity"
# Minimal test: Change field name in adapter

# BEFORE (in tool_adapter.py)
severity = item.get("Severity")

# AFTER (minimal change)
severity = item.get("Level")  # Changed field name

# Run adapter test
pytest tests/adapters/test_tool_adapter.py::test_basic_parsing -v

# Verify: Does finding have correct severity?
```

**Test 3: Directory scanning hypothesis**

```python
# Hypothesis: normalize_and_report.py missing individual-images/ directory
# Minimal test: Add directory to scan list

# BEFORE (in normalize_and_report.py)
target_dirs = [
    results_dir / "individual-repos",
]

# AFTER (minimal change)
target_dirs = [
    results_dir / "individual-repos",
    results_dir / "individual-images",  # Added
]

# Run report phase
python3 scripts/cli/jmo.py report /tmp/test

# Verify: Are image findings now in findings.json?
jq '[.[] | select(.location.path | contains("nginx"))] | length' \
   /tmp/test/summaries/findings.json
```

### Step 3: Verify Before Continuing

- Did it work? Yes -> Phase 4
- Didn't work? Form NEW hypothesis
- DON'T add more fixes on top

**JMo-specific verification commands:**

```bash
# Verify scan phase
ls -lah results/individual-*/*/tool.json  # Output files created?
jq . results/individual-repos/test-repo/trivy.json  # Valid JSON?

# Verify adapter parsing
python3 -c "
from scripts.core.adapters.trivy_adapter import load_trivy
findings = load_trivy('results/individual-repos/test-repo/trivy.json')
print(f'Parsed {len(findings)} findings')
if findings: print(f'Sample: {findings[0]}')
"

# Verify report phase
jq 'length' results/summaries/findings.json  # Expected count?
grep -c "HIGH" results/summaries/SUMMARY.md  # Expected severity breakdown?

# Verify tests
pytest tests/adapters/test_trivy_adapter.py -v  # All pass?
pytest --cov=scripts/core/adapters/trivy_adapter --cov-report=term  # >=85%?
```

### Step 4: When You Don't Know

- Say "I don't understand X"
- Don't pretend to know
- Ask for help
- Research more

**JMo-specific research resources:**

- Tool documentation: Check tool's GitHub repo, official docs
- Example outputs: Run tool locally, inspect JSON structure
- JMo patterns: Read CLAUDE.md, check similar adapters
- Test examples: Review tests/adapters/ for patterns
- Skills: Use jmo-adapter-generator, jmo-test-fabricator skills

---

## Phase 4: Implementation (Detailed)

**Fix the root cause, not the symptom.**

### Step 1: Create Failing Test Case

- Simplest possible reproduction
- Automated test if possible
- One-off test script if no framework
- MUST have before fixing

**For adapter bugs:**

```python
# File: tests/adapters/test_tool_adapter.py
def test_field_mapping_bug_regression():
    """Regression test for bug where 'Level' field not recognized."""
    json_data = {
        "Results": [{
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2024-1234",
                "Level": "HIGH",  # Tool outputs "Level" not "Severity"
                "Title": "Test vulnerability",
            }]
        }]
    }

    tmp_path = Path("/tmp/test_tool_output.json")
    tmp_path.write_text(json.dumps(json_data))

    findings = load_tool(tmp_path)

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"  # FAILS before fix
```

**For scan job bugs:**

```python
# File: tests/integration/test_multi_target.py
def test_image_scanning_creates_output():
    """Regression test for image scan not creating output files."""
    result = subprocess.run([
        "python3", "scripts/cli/jmo.py", "scan",
        "--image", "nginx:latest",
        "--tools", "trivy",
        "--results-dir", "/tmp/test-scan"
    ], capture_output=True)

    out_file = Path("/tmp/test-scan/individual-images/nginx_latest/trivy.json")
    assert out_file.exists()  # FAILS before fix
    assert out_file.stat().st_size > 0
```

**For CI bugs:**

```yaml
# File: .github/workflows/ci.yml (add test job)
test-trivy-version:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Verify trivy version matches versions.yaml
      run: |
        EXPECTED=$(yq .tools.trivy.version versions.yaml)
        ACTUAL=$(trivy --version | grep -oP '\d+\.\d+\.\d+')
        echo "Expected: $EXPECTED, Actual: $ACTUAL"
        test "$EXPECTED" = "$ACTUAL"  # FAILS if mismatch
```

### Step 2: Implement Single Fix

- Address the root cause identified
- ONE change at a time
- No "while I'm here" improvements
- No bundled refactoring

**Fix 1: Adapter field mapping**

```python
# File: scripts/core/adapters/tool_adapter.py
# ROOT CAUSE: Tool outputs "Level" not "Severity"
# FIX: Check both field names

# BEFORE (symptom fix - would miss other fields)
severity = item.get("Severity")

# AFTER (root cause fix)
severity = item.get("Severity") or item.get("Level") or "UNKNOWN"
```

**Fix 2: Exit code handling**

```python
# File: scripts/cli/scan_jobs/image_scanner.py
# ROOT CAUSE: Trivy returns exit code 1 when findings exist
# FIX: Add exit code 1 to OK list for trivy

# BEFORE
if tool == "trivy":
    cmd = ["trivy", "image", "-f", "json", image, "-o", str(out)]
    rc, _, _, used = _run_cmd(cmd, timeout, retries)

# AFTER (add ok_rcs parameter)
if tool == "trivy":
    cmd = ["trivy", "image", "-f", "json", image, "-o", str(out)]
    rc, _, _, used = _run_cmd(cmd, timeout, retries, ok_rcs=(0, 1))
```

**Fix 3: Multi-target aggregation**

```python
# File: scripts/core/normalize_and_report.py
# ROOT CAUSE: Missing individual-images/ in target_dirs list
# FIX: Add all 6 target directories

# BEFORE (missing images, iac, web, gitlab, k8s)
target_dirs = [
    results_dir / "individual-repos",
]

# AFTER
target_dirs = [
    results_dir / "individual-repos",
    results_dir / "individual-images",
    results_dir / "individual-iac",
    results_dir / "individual-web",
    results_dir / "individual-gitlab",
    results_dir / "individual-k8s",
]
```

### Step 3: Verify Fix

- Test passes now?
- No other tests broken?
- Issue actually resolved?

**JMo-specific verification checklist:**

```bash
# 1. Run new test
pytest tests/adapters/test_tool_adapter.py::test_field_mapping_bug_regression -v
# MUST pass

# 2. Run all adapter tests
pytest tests/adapters/ -v
# NO new failures

# 3. Run integration tests
pytest tests/integration/ -v
# NO new failures

# 4. Check coverage
pytest --cov=scripts/core/adapters/tool_adapter --cov-fail-under=85
# MUST be >=85%

# 5. Run pre-commit hooks
pre-commit run --all-files
# MUST pass (no ruff, black, markdownlint failures)

# 6. Test end-to-end
python3 scripts/cli/jmo.py scan --repo ./test-repo --tools trivy
python3 scripts/cli/jmo.py report ./results
# Check findings.json has expected findings

# 7. Verify fix in original failure scenario
# Re-run exact command that failed originally
# MUST succeed now
```

### Step 4: If Fix Doesn't Work

- STOP
- Count: How many fixes have you tried?
- If < 3: Return to Phase 1, re-analyze with new information
- **If >= 3: STOP and question the architecture (Step 5 below)**
- DON'T attempt Fix #4 without architectural discussion

**JMo-specific: When to question architecture:**

```text
Example: Adding new tool adapter requires 5+ files changed
- jmo.py: Add tool invocation
- scan_jobs/repository_scanner.py: Add tool to job_repository
- normalize_and_report.py: Import adapter, add to loader loop
- jmo.yml: Add tool to profiles
- Multiple test files

-> This suggests: Plugin architecture needed
-> Alternative: Auto-discovery of adapters, config-driven tool registration
```

### Step 5: If 3+ Fixes Failed -- Question Architecture

**Pattern indicating architectural problem:**

- Each fix reveals new shared state/coupling/problem in different place
- Fixes require "massive refactoring" to implement
- Each fix creates new symptoms elsewhere

**JMo-specific architectural smells:**

- **Adapter coupling:** Tool adapters depend on normalize_and_report.py structure
- **Scan job duplication:** Each target type has similar but duplicated scan logic
- **Configuration sprawl:** jmo.yml, per_tool overrides, CLI args all interact
- **Test brittleness:** Tool version changes break 20+ test fixtures

**STOP and question fundamentals:**

- Is this pattern fundamentally sound?
- Are we "sticking with it through sheer inertia"?
- Should we refactor architecture vs. continue fixing symptoms?

**Discuss with user before attempting more fixes:**

- "I've tried 3 fixes, each reveals new coupling. Should we refactor?"
- "This suggests a plugin architecture would be better. Thoughts?"
- "The root issue seems architectural, not a simple bug."

This is NOT a failed hypothesis -- this is a wrong architecture.
