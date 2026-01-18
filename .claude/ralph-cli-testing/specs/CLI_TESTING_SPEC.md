# CLI Testing Specification

Complete specification for JMo Security CLI testing scenarios.

## Test Categories Overview

| Category | ID Prefix | Tests | Description |
|----------|-----------|-------|-------------|
| Help/Version | HV | 8 | Version and help outputs |
| Tool Management | TM | 8 | `tools check/list/outdated/debug` |
| Tool Installation | TI | 5 | Actual tool installation (slow) |
| Scan Execution | SC | 5 | Actual scan execution (slow) |
| Adapters | AD | 3 | `adapters list/validate` |
| Report | RP | 6 | Report generation formats |
| History | HS | 4 | `history list/show/stats/query` |
| Trends | TR | 4 | `trends analyze/score/insights` |
| Diff | DF | 6 | Scan comparison commands |
| Policy | PL | 4 | Policy validation commands |
| CI Mode | CI | 2 | CI/CD integration |
| **Total** | | **55** | |

---

## HV: Help and Version (8 tests)

### HV-001: Version Output
```bash
jmo --version
```
**Expected:**
- Exit code: 0
- stdout contains: "JMo Security v" or version pattern `\d+\.\d+\.\d+`
- stderr: empty or warnings only

### HV-002: Main Help
```bash
jmo --help
```
**Expected:**
- Exit code: 0
- stdout contains: "scan", "report", "tools", "history"
- Shows command groups

### HV-003: Scan Help
```bash
jmo scan --help
```
**Expected:**
- Exit code: 0
- stdout contains: "--repo", "--profile", "--results-dir"

### HV-004: Report Help
```bash
jmo report --help
```
**Expected:**
- Exit code: 0
- stdout contains: "--format", "json", "html", "sarif"

### HV-005: Tools Help
```bash
jmo tools --help
```
**Expected:**
- Exit code: 0
- stdout contains: "check", "list", "install"

### HV-006: History Help
```bash
jmo history --help
```
**Expected:**
- Exit code: 0
- stdout contains: "list", "show", "stats"

### HV-007: Diff Help
```bash
jmo diff --help
```
**Expected:**
- Exit code: 0
- stdout contains: "--format", "--severity"

### HV-008: Policy Help
```bash
jmo policy --help
```
**Expected:**
- Exit code: 0
- stdout contains: "list", "validate", "test"

---

## TM: Tool Management (8 tests)

### TM-001: Tools Check (Default)
```bash
jmo tools check
```
**Expected:**
- Exit code: 0 (even if tools missing)
- stdout: table with tool names and status
- Contains: tool names like "trivy", "bandit", "semgrep"

### TM-002: Tools Check JSON Output
```bash
jmo tools check --json
```
**Expected:**
- Exit code: 0
- stdout: valid JSON
- JSON has "tools" array with "name" and "status" fields

### TM-003: Tools Check Profile
```bash
jmo tools check --profile fast
```
**Expected:**
- Exit code: 0
- Shows only tools in "fast" profile
- Fewer tools than default

### TM-004: Tools List
```bash
jmo tools list
```
**Expected:**
- Exit code: 0
- Lists all supported tools
- Shows categories

### TM-005: Tools List by Category
```bash
jmo tools list --category sast
```
**Expected:**
- Exit code: 0
- Shows only SAST tools
- Contains: semgrep, bandit

### TM-006: Tools Install Dry-Run
```bash
jmo tools install --profile fast --dry-run
```
**Expected:**
- Exit code: 0
- stdout contains: "Would install" or "Dry run"
- No actual installation occurs

### TM-007: Tools Outdated
```bash
jmo tools outdated
```
**Expected:**
- Exit code: 0
- Shows tools with newer versions available
- May be empty if all up-to-date

### TM-008: Tools Debug
```bash
jmo tools debug trivy
```
**Expected:**
- Exit code: 0 (even if tool not installed)
- Shows installation paths, version detection info
- Diagnostic information

---

## TI: Tool Installation (5 tests) - ACTUAL INSTALLATION

**Note:** These tests perform actual installations. Run sparingly.

### TI-001: Install Dry-Run Verification
```bash
jmo tools install --profile fast --yes --dry-run
```
**Expected:**
- Exit code: 0
- Lists tools that would be installed
- No files modified

### TI-002: Install Fast Profile
```bash
jmo tools install --profile fast --yes
```
**Expected:**
- Exit code: 0 or 1 (some tools may fail on Windows)
- Progress output during installation
- At least some tools installed

**Platform Notes:**
- Windows: 4 tools always fail (falco, afl++, mobsf, akto)
- Check `jmo tools check --profile fast` after install

### TI-003: Verify Installation
```bash
jmo tools check --profile fast --json
```
**Expected (after TI-002):**
- Exit code: 0
- JSON shows some tools with "status": "OK"
- Windows: minimum 4 tools OK (trivy, bandit, gitleaks, hadolint)
- Linux: minimum 6 tools OK

### TI-004: Debug Single Tool
```bash
jmo tools debug <installed_tool>
```
**Expected:**
- Exit code: 0
- Shows version information
- Shows installation path

### TI-005: Clean Isolated Venvs
```bash
jmo tools clean --force
```
**Expected:**
- Exit code: 0
- Removes isolated venv directories
- Output confirms cleanup

---

## SC: Scan Execution (5 tests) - ACTUAL SCANS

**Note:** These tests run actual scans. Use `tests/fixtures/samples/` as target.

### SC-001: Scan Python Fixture
```bash
jmo scan --repo tests/fixtures/samples/python-vulnerable \
    --results-dir <temp_dir>/results \
    --profile-name fast \
    --allow-missing-tools \
    --human-logs
```
**Expected:**
- Exit code: 0
- Creates `<temp_dir>/results/summaries/findings.json`
- findings.json has valid CommonFinding v1.2.0 format

### SC-002: Profile Shortcut Scan
```bash
jmo fast tests/fixtures/samples/python-vulnerable \
    --results-dir <temp_dir>/results \
    --allow-missing-tools
```
**Expected:**
- Exit code: 0
- Creates findings.json
- Uses fast profile tools

### SC-003: Verify Findings Schema
**After SC-001 or SC-002:**
```python
findings = json.load(open("<temp_dir>/results/summaries/findings.json"))
assert findings["meta"]["schema_version"] == "1.2.0"
assert "findings" in findings
```
**Expected:**
- Schema version is "1.2.0"
- Meta section present
- Findings array present

### SC-004: Verify Dashboard Generated
**After SC-001:**
```bash
ls <temp_dir>/results/summaries/dashboard.html
```
**Expected:**
- File exists
- Valid HTML structure
- Contains finding data

### SC-005: Container Image Scan (Optional)
```bash
jmo scan --image python:3.11-slim \
    --results-dir <temp_dir>/results \
    --allow-missing-tools \
    --timeout 120
```
**Expected:**
- Exit code: 0 (or skip if Docker unavailable)
- Creates findings if trivy installed
- Graceful skip if Docker not running

---

## AD: Adapters (3 tests)

### AD-001: Adapters List
```bash
jmo adapters list
```
**Expected:**
- Exit code: 0
- Lists all registered adapters
- Contains: semgrep, trivy, bandit, etc.

### AD-002: Adapters List JSON
```bash
jmo adapters list --json
```
**Expected:**
- Exit code: 0
- Valid JSON output
- Array of adapter objects with name, tool_name

### AD-003: Adapters Validate
```bash
jmo adapters validate
```
**Expected:**
- Exit code: 0
- Validates all adapter registrations
- Reports any issues

---

## RP: Report Generation (6 tests)

**Prerequisite:** results-baseline fixtures

### RP-001: Report JSON Format
```bash
jmo report <fixtures>/results-baseline --format json
```
**Expected:**
- Exit code: 0
- Outputs valid JSON to stdout or file
- Contains findings array

### RP-002: Report Markdown Format
```bash
jmo report <fixtures>/results-baseline --format md
```
**Expected:**
- Exit code: 0
- Contains markdown headers (#, ##)
- Lists findings by severity

### RP-003: Report HTML Format
```bash
jmo report <fixtures>/results-baseline --format html
```
**Expected:**
- Exit code: 0
- Generates dashboard.html
- Valid HTML structure

### RP-004: Report SARIF Format
```bash
jmo report <fixtures>/results-baseline --format sarif
```
**Expected:**
- Exit code: 0
- Valid SARIF JSON
- Contains "$schema" with SARIF reference

### RP-005: Report CSV Format
```bash
jmo report <fixtures>/results-baseline --format csv
```
**Expected:**
- Exit code: 0
- CSV with headers
- One row per finding

### RP-006: Report Fail-On Threshold
```bash
jmo report <fixtures>/results-baseline --fail-on HIGH
```
**Expected:**
- Exit code: 1 (baseline has HIGH findings)
- Output shows threshold exceeded

---

## HS: History Commands (4 tests)

**Prerequisite:** test-history.db fixture

### HS-001: History List
```bash
JMO_HISTORY_DB=<fixtures>/test-history.db jmo history list
```
**Expected:**
- Exit code: 0
- Lists 5 scans
- Shows timestamp, profile, finding counts

### HS-002: History Show
```bash
JMO_HISTORY_DB=<fixtures>/test-history.db jmo history show <scan_id>
```
**Expected:**
- Exit code: 0
- Shows scan details
- Lists findings summary

### HS-003: History Stats
```bash
JMO_HISTORY_DB=<fixtures>/test-history.db jmo history stats
```
**Expected:**
- Exit code: 0
- Shows aggregate statistics
- Total scans, findings

### HS-004: History Query
```bash
JMO_HISTORY_DB=<fixtures>/test-history.db jmo history query --severity CRITICAL
```
**Expected:**
- Exit code: 0
- Filters findings by severity
- Returns only CRITICAL findings

---

## TR: Trends Commands (4 tests)

**Prerequisite:** test-history.db fixture with 5+ scans

### TR-001: Trends Analyze
```bash
JMO_HISTORY_DB=<fixtures>/test-history.db jmo trends analyze
```
**Expected:**
- Exit code: 0
- Shows trend direction (improving/worsening)
- Statistical summary

### TR-002: Trends Score
```bash
JMO_HISTORY_DB=<fixtures>/test-history.db jmo trends score
```
**Expected:**
- Exit code: 0
- Shows security score
- Score between 0-100

### TR-003: Trends Insights
```bash
JMO_HISTORY_DB=<fixtures>/test-history.db jmo trends insights
```
**Expected:**
- Exit code: 0
- Provides actionable insights
- Based on historical data

### TR-004: Trends Explain
```bash
JMO_HISTORY_DB=<fixtures>/test-history.db jmo trends explain
```
**Expected:**
- Exit code: 0
- Explains trend methodology
- Mann-Kendall test description

---

## DF: Diff Commands (6 tests)

**Prerequisite:** results-baseline and results-current fixtures

### DF-001: Diff Basic
```bash
jmo diff <fixtures>/results-baseline <fixtures>/results-current
```
**Expected:**
- Exit code: 0
- Shows added/removed findings
- 3 removed (baseline 12-14), 5 added

### DF-002: Diff JSON Format
```bash
jmo diff <fixtures>/results-baseline <fixtures>/results-current --format json
```
**Expected:**
- Exit code: 0
- Valid JSON output
- Contains "added", "removed", "unchanged" arrays

### DF-003: Diff Markdown Format
```bash
jmo diff <fixtures>/results-baseline <fixtures>/results-current --format md
```
**Expected:**
- Exit code: 0
- Markdown headers
- +/- notation for changes

### DF-004: Diff Severity Filter
```bash
jmo diff <fixtures>/results-baseline <fixtures>/results-current --severity CRITICAL,HIGH
```
**Expected:**
- Exit code: 0
- Only shows CRITICAL and HIGH findings
- Filters out MEDIUM/LOW/INFO

### DF-005: Diff Tool Filter
```bash
jmo diff <fixtures>/results-baseline <fixtures>/results-current --tool semgrep
```
**Expected:**
- Exit code: 0
- Only shows semgrep findings
- Filters out other tools

### DF-006: Diff Only New
```bash
jmo diff <fixtures>/results-baseline <fixtures>/results-current --only new
```
**Expected:**
- Exit code: 0
- Shows only added findings
- 5 new findings

---

## PL: Policy Commands (4 tests)

### PL-001: Policy List
```bash
jmo policy list
```
**Expected:**
- Exit code: 0
- Lists available policies
- Shows built-in policies

### PL-002: Policy Validate
```bash
jmo policy validate jmo.suppress.yml
```
**Expected:**
- Exit code: 0 (valid) or 1 (invalid)
- Validates policy file syntax
- Reports errors if any

### PL-003: Policy Test
```bash
jmo policy test <fixtures>/results-baseline --policy jmo.suppress.yml
```
**Expected:**
- Exit code: 0
- Shows which findings would be suppressed
- Summary of policy application

### PL-004: Policy Show
```bash
jmo policy show <policy_name>
```
**Expected:**
- Exit code: 0
- Shows policy details
- Documentation of rules

---

## CI: CI Mode (2 tests)

**Prerequisite:** results fixtures

### CI-001: CI Mode Fail-On CRITICAL
```bash
jmo ci --results-dir <fixtures>/results-baseline --fail-on CRITICAL
```
**Expected:**
- Exit code: 1 (baseline has CRITICAL findings)
- Machine-readable output
- Summary of threshold violations

### CI-002: CI Mode Fail-On INFO
```bash
jmo ci --results-dir <fixtures>/results-baseline --fail-on INFO
```
**Expected:**
- Exit code: 1 (any severity triggers)
- All findings count as failures
- Complete summary

---

## Platform-Specific Considerations

### Windows

| Tool | Status | Test Handling |
|------|--------|---------------|
| falco | Never works | `@skip_on_windows` |
| afl++ | Never works | `@skip_on_windows` |
| mobsf | Never works | `@skip_on_windows` |
| akto | Never works | `@skip_on_windows` |
| lynis | May fail | Try, skip on failure |
| noseyparker | May fail | Try, document result |

### Expected Tool Counts by Platform

| Platform | Min Tools | Max Tools |
|----------|-----------|-----------|
| Windows | 16 | 24 |
| Linux | 24 | 28 |
| macOS | 20 | 26 |

---

## Test Execution Order

1. **Phase 0**: HV tests (no prerequisites)
2. **Phase 1**: TM tests (no external dependencies)
3. **Phase 2**: TI tests (actual installation)
4. **Phase 3**: AD tests (no prerequisites)
5. **Phase 4**: SC tests (actual scans, needs fixtures)
6. **Phase 5**: RP, HS, TR, DF, PL tests (fixture-based)
7. **Phase 6**: CI tests (integration)

---

## Fixture Dependencies

| Test Category | Required Fixtures |
|--------------|-------------------|
| HV, TM, AD | None |
| TI | None (creates state) |
| SC | tests/fixtures/samples/ |
| RP | results-baseline/ |
| HS, TR | test-history.db |
| DF | results-baseline/, results-current/ |
| PL | jmo.suppress.yml, results |
| CI | Any results directory |
