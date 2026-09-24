# Document Update Templates

Detailed templates for each type of documentation update in JMo Security.
Referenced from the main [SKILL.md](../SKILL.md).

## 1. New Tool Adapter

**Files to update:**

- README.md: Add tool to "Supported Tools" table
- docs/TOOLS.md: Add the tool to the matrix, with when it runs and its target types
- QUICKSTART.md: Add example **only if** the tool joins `TOOL_MATRIX` (the default list)
- CHANGELOG.md: Add to `[Unreleased]` -> `### Added`
- docs/index.md: Update tool count if mentioned
- DOCKER_HUB_README.md: Update tool count and tool list in features section
- .github/workflows/release.yml: Update short-description tool count if total changes
- docs/USER_GUIDE.md: Only if tool has unique config options or flags
- CLAUDE.md: Only if adapter pattern significantly differs

**Example: Adding Snyk Adapter**

**README.md** (tool table):

```markdown
| Tool | Category | Description |
|------|----------|-------------|
| trufflehog | Secrets | Verified secrets scanning |
| semgrep | SAST | Multi-language static analysis |
| snyk | SCA | Dependency vulnerability scanning with fix suggestions |
```

**QUICKSTART.md** (after "Basic Scanning" section):

````markdown
### Dependency Scanning with Snyk

Scan for known vulnerabilities in package dependencies:

```bash
# Snyk is in the default tool matrix
jmo scan --repos-dir ~/repos

# Run Snyk alone
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
  - Runs by default on repository targets; narrow with `--tools` or `--skip-tools`
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
| AWS Accounts | `--aws-account` | scoutsuite | `jmo scan --aws-account 123456789012` |
```

> AWS account scanning is a **hypothetical** target type here, used only to show
> the shape of the update. JMo has no cloud-account scanner; `--aws-account` does
> not exist.

**docs/USER_GUIDE.md** (comprehensive new section):

````markdown
### AWS Account Scanning (v0.7.0+)

#### Prerequisites

1. AWS Credentials: Configure via AWS CLI or environment variables
2. IAM Permissions: Scanning account needs SecurityAudit policy
3. Tools: Install ScoutSuite

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
    scoutsuite.json
```
````

**CLAUDE.md** (Architecture section):

```markdown
### Multi-Target Scanning Architecture

**Tool Assignments by Target Type:**

| Target Type | Primary Tools | Secondary Tools |
|-------------|---------------|-----------------|
| Repositories | trufflehog, semgrep | syft, trivy, checkov |
| Container Images | trivy, syft | - |
| AWS Accounts | scoutsuite | - |
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

## 7. Docker Image Changes

There is **one** image, built from `Dockerfile` and published as
`ghcr.io/jimmy058910/jmo-security:latest` and `:<version>` (Docker Hub:
`jmogaming/jmo-security`). It carries every scanner in `TOOL_MATRIX` plus the
opa policy engine. Never document a per-variant tag: none is built, and
`tests/unit/test_docker_tag_pattern_drift.py` fails on the old suffixed form.

**Files to update:**

- docs/DOCKER_README.md: Update what the image carries, its size, examples
- DOCKER_HUB_README.md: Update the image description (synced by release.yml)
- README.md: Update Docker Quick Start if the image name or tags change
- CHANGELOG.md: Add to `[Unreleased]` -> `### Added` or `### Changed`
- docs/examples/github-actions-docker.yml: Update CI examples

**Example: A scanner joins the image**

```markdown
### Changed

- **Docker image**: now carries Snyk, so `docker run ... tools check` inside the
  container lists it as ready. State the measured size change, if any.
```

## 8. Tool Count Changes (Critical for Docker Hub)

**CRITICAL: Tool count must be consistent across ALL documentation.**

**Files to update when tool count changes:**

- docs/TOOLS.md: Update the tool matrix and the "Removed in v2.0.0" list if a tool leaves
- DOCKER_HUB_README.md: Update tool count in the description AND features list
- .github/workflows/release.yml: Update short-description tool count
- README.md: Update tool count references
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

# 1. The count comes from the single source of truth -- NOT from jmo.yml and
#    not from another doc. TOOL_MATRIX is the tuple `jmo scan` considers when
#    nothing narrows the list; there is exactly one legitimate number.
N=$(python -c "from scripts.core.tool_registry import TOOL_MATRIX; print(len(TOOL_MATRIX))")
echo "tool count: $N"

# 2. Every stated count must equal it. A number that is not the matrix size is
#    stale by construction -- no judgement needed.
fail=0
for f in DOCKER_HUB_README.md README.md docs/TOOLS.md \
         .github/workflows/release.yml; do
  [ -f "$f" ] || { echo "MISSING: $f"; fail=1; continue; }
  while IFS= read -r hit; do
    n=$(printf '%s' "${hit#*:}" | grep -oE '^[0-9]+')
    [ "$n" = "$N" ] || { echo "STALE in $f:$hit"; fail=1; }
  done < <(grep -noE "[0-9]+ (tools|scanners)" "$f" || true)
done

exit "$fail"
```

> **Count scanners, not adapters or installed binaries.** Three numbers look
> alike and only one is the tool count:
>
> - `len(TOOL_MATRIX)` is the scanner count every doc states.
> - The adapters on disk are more than that: `scripts/core/adapters/` also holds
>   SARIF bindings that are not wired into scans yet.
> - opa is installed and baked into the image, but it is the policy engine
>   (`POLICY_ENGINE`), not a scanner, so it is never counted.
>
> Do not add `jmo.yml` expecting a tool list. It has no top-level `tools:` key
> by default; a user adds one only to narrow the matrix.
> `tests/unit/test_tool_catalogue_count_claims.py` checks the same claims in CI;
> the script above is the quick local version.
