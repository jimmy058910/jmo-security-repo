# Document Update Templates

Detailed templates for each type of documentation update in JMo Security.
Referenced from the main [SKILL.md](../SKILL.md).

## 1. New Tool Adapter

**Files to update:**

- README.md: Add tool to "Supported Tools" table
- QUICKSTART.md: Add example **only if** tool in fast/balanced profile
- CHANGELOG.md: Add to `[Unreleased]` -> `### Added`
- docs/index.md: Update tool count if mentioned
- DOCKER_HUB_README.md: Update tool count and tool list in features section
- .github/workflows/release.yml: Update short-description tool count if total changes
- docs/USER_GUIDE.md: Only if tool has unique config options or flags
- CLAUDE.md: Only if adapter pattern significantly differs

**Example: Adding Snyk Adapter**

**README.md** (tool table):

```markdown
| Tool | Category | Description | Profile |
|------|----------|-------------|---------|
| trufflehog | Secrets | Verified secrets scanning | fast, balanced, deep |
| semgrep | SAST | Multi-language static analysis | fast, balanced, deep |
| snyk | SCA | Dependency vulnerability scanning with fix suggestions | balanced, deep |
```

**QUICKSTART.md** (after "Basic Scanning" section):

````markdown
### Dependency Scanning with Snyk

Scan for known vulnerabilities in package dependencies:

```bash
# Balanced profile includes Snyk
jmo scan --profile balanced --repos-dir ~/repos

# Run Snyk explicitly
jmo scan --repo ./myapp --tools snyk --results-dir results
```
````

**CHANGELOG.md** (top of file, `[Unreleased]` section):

```markdown
## [Unreleased]

### Added

- **Snyk adapter**: Scan for dependency vulnerabilities in package manifests
  - Detects CVEs with CVSS scoring
  - Provides upgrade path remediation
  - Maps to OWASP Top 10 (A06:2021 - Vulnerable Components)
  - Available in balanced and deep profiles
```

**docs/USER_GUIDE.md** (only if Snyk has unique config like auth token):

```yaml
per_tool:
  snyk:
    flags:
      - --auth=token
      - --severity-threshold=high
    timeout: 900
```

## 2. New CLI Flag

**Files to update:**

- docs/USER_GUIDE.md: Update CLI synopsis section
- QUICKSTART.md: Update only if flag affects basic workflow
- CHANGELOG.md: Add to `[Unreleased]` -> `### Added` or `### Changed`
- README.md: Only if major feature flag (e.g., `--wizard`, `--ci`)

**Example: Adding `--output-dir` Flag**

**docs/USER_GUIDE.md** (CLI Synopsis section):

```bash
jmo scan [OPTIONS]

Output:
  --results-dir PATH      # Results directory (default: ./results)
  --output-dir PATH       # Alternative to --results-dir (alias)
```

**CHANGELOG.md**:

```markdown
### Added

- **`--output-dir` flag**: Alias for `--results-dir` for consistency with other tools
```

## 3. New Target Type (Major Feature)

**Files to update:**

- README.md: Add to target types table, update examples
- QUICKSTART.md: Add target type section with examples
- docs/USER_GUIDE.md: CLI synopsis, new target type section, multi-target examples
- CHANGELOG.md: Add to `[Unreleased]` -> `### Added` (detailed description)
- CLAUDE.md: Update architecture section, directory structure, tool assignment table
- docs/index.md: Update quick links, feature highlights
- docs/examples/: Add example workflow if complex

**Example: Adding AWS Account Scanning**

**README.md** (Target Types section):

```markdown
## Multi-Target Scanning (v0.6.0+)

| Target Type | CLI Flags | Tools | Example |
|-------------|-----------|-------|---------|
| Repositories | `--repo`, `--repos-dir` | trufflehog, semgrep | `jmo scan --repo ./myapp` |
| Container Images | `--image` | trivy, syft | `jmo scan --image nginx:latest` |
| AWS Accounts | `--aws-account` | prowler, scoutsuite | `jmo scan --aws-account 123456789012` |
```

**docs/USER_GUIDE.md** (comprehensive new section):

````markdown
### AWS Account Scanning (v0.7.0+)

#### Prerequisites

1. AWS Credentials: Configure via AWS CLI or environment variables
2. IAM Permissions: Scanning account needs SecurityAudit policy
3. Tools: Install Prowler and/or ScoutSuite

#### CLI Options

```bash
jmo scan --aws-account ACCOUNT_ID [OPTIONS]

AWS Target Options:
  --aws-account ID          # Single AWS account ID (12 digits)
  --aws-accounts-file FILE  # File with account IDs (one per line)
  --aws-region REGION       # AWS region (default: us-east-1)
  --aws-profile PROFILE     # AWS CLI profile name
```

#### Results Structure

```text
results/individual-aws-accounts/
  123456789012/
    prowler.json
    scoutsuite.json
```
````

**CLAUDE.md** (Architecture section):

```markdown
### Multi-Target Scanning Architecture

**Tool Assignments by Target Type:**

| Target Type | Primary Tools | Secondary Tools |
|-------------|---------------|-----------------|
| Repositories | trufflehog, semgrep | trivy, noseyparker, bandit |
| Container Images | trivy, syft | - |
| AWS Accounts | prowler, scoutsuite | - |
```

## 4. Breaking Change

**Files to update:**

- CHANGELOG.md: Add to `[Unreleased]` -> `### BREAKING CHANGES` (top of section)
- CHANGELOG.md: Add migration guide with before/after examples
- All affected docs: Update examples, add deprecation notices
- docs/USER_GUIDE.md: Update troubleshooting section
- README.md: Add prominent notice if breaking change affects Quick Start

**Example: Renaming `--results` to `--results-dir`**

**CHANGELOG.md** (top of [Unreleased]):

````markdown
## [Unreleased]

### BREAKING CHANGES

- **Renamed `--results` flag to `--results-dir`** for clarity and consistency
  - **Old:** `jmo scan --repo ./app --results ./output`
  - **New:** `jmo scan --repo ./app --results-dir ./output`
  - **Migration:** Update all scripts/CI pipelines to use `--results-dir`
  - **Compatibility:** `--results` deprecated but supported until v0.7.0 (shows warning)

**Migration Guide:**

```bash
# Before (deprecated)
jmo scan --repo ./myapp --results ./scan-results

# After (current)
jmo scan --repo ./myapp --results-dir ./scan-results

# Batch migration for scripts: list first, review, then edit only that list.
# Never `find ... -exec sed -i` across a tree -- it rewrites every match in
# every file it reaches, including unrelated prose and vendored code, with no
# preview and no undo.
grep -rl -- '--results ' --include='*.sh' . > /tmp/to-migrate.txt
$EDITOR /tmp/to-migrate.txt            # drop anything that should not change
xargs -a /tmp/to-migrate.txt sed -i.bak -- 's/--results /--results-dir /g'
```

> Two traps in that `sed`. `-i` alone is GNU-only — BSD/macOS `sed` reads the
> next argument as the suffix and silently eats your next filename, so pass an
> explicit suffix (`-i.bak`). And on Windows checkouts `sed -i` rewrites the
> whole file's line endings, turning a one-line change into a whole-file diff;
> prefer a scripted edit that writes bytes, and verify with
> `git diff --numstat` against `git diff --ignore-cr-at-eol --numstat`.
>
> The `--results` → `--results-dir` rename above is an **illustrative example**
> of how to document a breaking change, not a live deprecation. JMo's real flag
> is `--results-dir`; `--results` still resolves to it today only because
> argparse accepts unambiguous prefixes.

**Deprecation Timeline:**

- v0.6.0: `--results` deprecated (warning shown)
- v0.6.x: Both flags supported
- v0.7.0: `--results` removed entirely
````

## 5. New Output Format/Reporter

**Files to update:**

- README.md: Add to output formats list
- QUICKSTART.md: Add example of using new format
- docs/USER_GUIDE.md: Document format details, config options
- CHANGELOG.md: Add to `[Unreleased]` -> `### Added`
- docs/RESULTS_GUIDE.md: Add example output if visual format

**Example: Adding CSV Reporter**

**README.md** (Output Formats section):

```markdown
| Format | File | Purpose |
|--------|------|---------|
| JSON | `findings.json` | Machine-readable, complete findings |
| CSV | `findings.csv` | Spreadsheet import, pivot tables |
| SARIF | `findings.sarif` | GitHub/GitLab code scanning |
```

**docs/USER_GUIDE.md**:

````markdown
### CSV Reporter (v0.6.0+)

**CSV Structure:**

| Column | Description |
|--------|-------------|
| id | Fingerprint ID |
| tool | Tool name |
| severity | CRITICAL/HIGH/MEDIUM/LOW/INFO |
| path | File path |
| message | Finding description |

**Configuration:**

```yaml
outputs: [csv]  # CSV only
# Or via CLI
jmo report ./results --outputs csv
```

**Limitations:**

- Nested structures flattened to comma-separated strings
- `raw` field excluded (too large for CSV)
````

## 6. Bug Fix (User-Facing)

**Files to update:**

- CHANGELOG.md: Add to `[Unreleased]` -> `### Fixed`
- docs/USER_GUIDE.md: Update troubleshooting if fix affects common issues

**Example: Fixing TruffleHog NDJSON Parsing**

```markdown
### Fixed

- **TruffleHog NDJSON parsing**: Fixed adapter to handle newline-delimited JSON format
  - Previously only parsed JSON arrays, causing missed findings
  - Now supports: JSON arrays, NDJSON, single JSON objects, nested arrays
  - No user action required; findings will appear in next scan
```

## 7. Profile Changes (Tool Additions/Removals)

**Files to update:**

- README.md: Update tool table with profile assignments
- QUICKSTART.md: Update profile descriptions
- docs/USER_GUIDE.md: Update profile reference table
- CHANGELOG.md: Add to `[Unreleased]` -> `### Changed`
- CLAUDE.md: Update profile descriptions if significant change

**Example: Moving Checkov from balanced to deep**

```markdown
### Changed

- **Checkov moved from balanced to deep profile**: Improves balanced scan time from 20 min to 15 min
  - Rationale: Checkov IaC scanning adds 5 min overhead
  - Impact: Balanced profile users no longer get IaC scanning by default
  - Workaround: Explicitly enable: `jmo scan --profile-name balanced --tools checkov`
```

## 8. Docker Image Changes

**Files to update:**

- docs/DOCKER_README.md: Update image variants table, examples
- README.md: Update Docker Quick Start if variant added/removed
- CHANGELOG.md: Add to `[Unreleased]` -> `### Added` or `### Changed`
- docs/examples/github-actions-docker.yml: Update CI examples

**Example: Adding Alpine Variant**

```markdown
## Image Variants

| Variant | Size | Tools Included | Use Case |
|---------|------|----------------|----------|
| `full` | ~2.5 GB | All 14 tools | Complete scanning |
| `slim` | ~800 MB | 8 core tools | CI/CD |
| `alpine` | ~400 MB | 6 essential tools | Minimal footprint |
```

## 9. Tool Count Changes (Critical for Docker Hub)

**CRITICAL: Tool count must be consistent across ALL documentation.**

**Files to update when tool count changes:**

- DOCKER_HUB_README.md: Update tool count in image variants table AND features list
- .github/workflows/release.yml: Update short-description tool count
- README.md: Update tool count references
- QUICKSTART.md: Update profile descriptions if tool counts mentioned
- docs/index.md: Update quick links tool count
- CLAUDE.md: Update "Supported Tools" section
- CHANGELOG.md: Document tool additions/removals with rationale

**Why This Matters:**

- Docker Hub is public-facing -- outdated tool counts damage credibility
- Automated sync via release.yml -- both README and short-description must match
- User confusion -- inconsistent counts across docs creates trust issues
- Search visibility -- Docker Hub short-description affects discoverability

**Verification Checklist:**

A checklist you have to eyeball is not a check. Each step below **exits
non-zero** when it fails, so the block can be pasted whole and trusted.

```bash
#!/usr/bin/env bash
set -euo pipefail

# 1. Both counts come from the single source of truth -- NOT from jmo.yml.
#    jmo.yml's `deep:` profile carries no `tools:` key at all (it says so in a
#    comment); a grep for one there silently returns 0 and every later
#    comparison then "passes" against nothing.
#
#    There are SEVERAL legitimate numbers -- one per profile, plus the unique
#    catalogue total. Asserting against only one of them flags correct files:
#    measured, a deep-only check reported 16 false positives, because 9 / 13 /
#    17 are simply fast / slim / balanced.
VALID=$(python - <<'PY'
from scripts.core.tool_registry import PROFILE_TOOLS
counts = {len(v) for v in PROFILE_TOOLS.values()}
counts.add(len({t for v in PROFILE_TOOLS.values() for t in v}))
print(" ".join(str(c) for c in sorted(counts)))
PY
)
echo "legitimate tool counts: $VALID"

# 2. Every stated count must be one of them. A number that is no longer any
#    profile's size is stale by construction -- no judgement needed.
fail=0
for f in DOCKER_HUB_README.md README.md docs/PROFILES_AND_TOOLS.md \
         .github/workflows/release.yml; do
  [ -f "$f" ] || { echo "MISSING: $f"; fail=1; continue; }
  while IFS= read -r hit; do
    n=$(printf '%s' "${hit#*:}" | grep -oE '^[0-9]+')
    case " $VALID " in
      *" $n "*) ;;
      *) echo "STALE in $f:$hit"; fail=1 ;;
    esac
  done < <(grep -noE "[0-9]+ tools" "$f" || true)
done

exit "$fail"
```

> **Which of the live numbers a file should use is a judgement the script cannot
> make** — it only proves the number is still one of them. Confirm the *sense*
> yourself: `README.md`'s "29 tools across 12 categories" is the catalogue and
> is correct; a profile comparison table saying 29 would be wrong.
>
> Do not add `jmo.yml` expecting a tool list. Profile membership lives in
> `scripts/core/tool_registry.py:PROFILE_TOOLS`; `jmo.yml` sets only per-profile
> `threads`/`timeout`/`retries`/`policy`. Its inline comment naming a count is
> prose, and prose drifts — at the time of writing it says 29 for `deep`, which
> is the catalogue number, while `PROFILE_TOOLS["deep"]` holds 28.
