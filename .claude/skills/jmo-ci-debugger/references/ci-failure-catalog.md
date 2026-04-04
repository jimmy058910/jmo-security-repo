# CI Failure Catalog

Complete reference of all 17 documented CI failure patterns with detailed symptoms, root causes, and proven fixes.

---

## 1. Docker Tag Extraction Issues

**Symptoms:**

```text
Error: invalid reference format: v0.5.0
Error: tag contains 'v' prefix when it shouldn't
Error: docker pull failed: manifest not found for v0.5.0
```

**Root Cause:**

Manually constructing tags from `github.ref_name` includes the 'v' prefix from Git tags:

- Git tag: `v0.5.0`
- `github.ref_name`: `v0.5.0` (includes 'v')
- Docker expects: `0.5.0` (no 'v')

**Where This Occurs:**

- release.yml, lines ~80-120
- Docker image testing steps
- Multi-arch build tagging

**Wrong Approach:**

```yaml
- name: Extract tag (INCORRECT)
  run: |
    # This includes the 'v' prefix
    TAG=${GITHUB_REF#refs/tags/}  # v0.5.0
    echo "TAG=$TAG" >> $GITHUB_ENV

- name: Test image (FAILS)
  run: |
    # Tries to pull ghcr.io/org/repo:v0.5.0 which doesn't exist
    docker run --rm ghcr.io/${{ github.repository }}:${{ env.TAG }} --help
```

**Correct Approach:**

```yaml
- name: Docker metadata
  id: meta
  uses: docker/metadata-action@v5
  with:
    images: ghcr.io/${{ github.repository }}
    tags: |
      type=semver,pattern={{version}}        # Strips 'v' automatically
      type=semver,pattern={{major}}.{{minor}}
      type=raw,value=latest,enable={{is_default_branch}}

- name: Extract tag for testing
  run: |
    # Extract first tag from metadata-action output (no 'v')
    TEST_TAG=$(echo "${{ steps.meta.outputs.tags }}" | head -n1 | cut -d':' -f2)
    echo "TEST_TAG=$TEST_TAG" >> $GITHUB_ENV
    echo "Testing with tag: $TEST_TAG"

- name: Test image (WORKS)
  run: |
    # Pulls ghcr.io/org/repo:0.5.0 (correct)
    docker run --rm ghcr.io/${{ github.repository }}:${{ env.TEST_TAG }} --help
```

**Why This Works:**

- `metadata-action` follows Docker Hub conventions (no 'v' prefix)
- Automatically handles version extraction from Git tags
- Consistent across all Docker registries (ghcr.io, Docker Hub, ECR)

**Testing Locally:**

```bash
# Simulate GitHub Actions environment
export GITHUB_REF=refs/tags/v0.5.0
export GITHUB_REF_NAME=v0.5.0

# Wrong: includes 'v'
TAG=${GITHUB_REF#refs/tags/}
echo $TAG  # v0.5.0

# Correct: strips 'v'
TAG=${GITHUB_REF#refs/tags/v}
echo $TAG  # 0.5.0

# Or use metadata-action in your workflow
```

**Related Issues:**

- If multi-arch build fails, check tag format in build-push-action
- If image push succeeds but pull fails, tag mismatch between build and test

---

## 2. Actionlint Parameter Errors

**Symptoms:**

```text
Error: Unexpected input(s) 'fail_on_error', valid inputs are ['github_token', 'fail_level', ...]
Error: fail_on_error is not a valid input for reviewdog/action-actionlint@v1
```

**Root Cause:**

Using deprecated or incorrect parameter names from outdated action documentation.

**Where This Occurs:**

- ci.yml, quick-checks job, actionlint step

**Wrong Approach:**

```yaml
- name: Run actionlint (INCORRECT)
  uses: reviewdog/action-actionlint@v1
  with:
    fail_on_error: true  # Not supported by v1
    reporter: github-pr-check
```

**Correct Approach:**

```yaml
- name: Run actionlint (CORRECT)
  uses: reviewdog/action-actionlint@v1
  with:
    fail_level: error  # Correct parameter
    reporter: github-pr-check
    filter_mode: nofilter
    actionlint_flags: ""
```

**Valid Parameters (reviewdog/action-actionlint@v1):**

- `fail_level`: `error`, `warning`, `any`, `none` (default: none)
- `reporter`: `github-pr-check`, `github-check`, `github-pr-review`
- `filter_mode`: `added`, `diff_context`, `file`, `nofilter`
- `actionlint_flags`: Additional flags for actionlint binary

### Alternative: Run actionlint directly

```yaml
- name: Run actionlint (Direct)
  run: |
    # Install actionlint
    bash <(curl https://raw.githubusercontent.com/rhysd/actionlint/main/scripts/download-actionlint.bash)

    # Run with custom flags
    ./actionlint -color -verbose
```

**Testing Locally:**

```bash
# Install actionlint
brew install actionlint  # macOS
# Or download binary from https://github.com/rhysd/actionlint/releases

# Validate workflows
actionlint .github/workflows/*.yml

# Check specific file
actionlint .github/workflows/ci.yml -verbose
```

**Common Actionlint Errors and Fixes:**

| Error | Cause | Fix |
|-------|-------|-----|
| `unknown property "fail_on_error"` | Wrong parameter | Use `fail_level: error` |
| `workflow command is disabled` | Deprecated syntax | Use environment files |
| `invalid input "on"` | YAML syntax error | Quote `"on"` keyword |
| `unknown event "push"` | Typo in trigger | Check event names |

---

## 3. Docker Image Testing Command Errors

**Symptoms:**

```text
Error: unknown flag: --version
jmo: error: unrecognized arguments: --version
Container exited with non-zero code: 2
```

**Root Cause:**

JMo CLI doesn't support top-level `--version` flag. Version is embedded in package metadata, not exposed as CLI flag.

**Where This Occurs:**

- release.yml, docker-build job, testing step after image push

**Wrong Approach:**

```yaml
- name: Test Docker image (INCORRECT)
  run: |
    docker run --rm ghcr.io/${{ github.repository }}:${{ env.TEST_TAG }} --version
    # jmo doesn't have --version flag
```

**Correct Approach:**

```yaml
- name: Test Docker image (CORRECT)
  run: |
    # Test 1: Main help works
    docker run --rm ghcr.io/${{ github.repository }}:${{ env.TEST_TAG }} --help

    # Test 2: Subcommand help works
    docker run --rm ghcr.io/${{ github.repository }}:${{ env.TEST_TAG }} scan --help

    # Test 3: CI command syntax
    docker run --rm ghcr.io/${{ github.repository }}:${{ env.TEST_TAG }} ci --help

    # Test 4: Tools are accessible (for full variant)
    docker run --rm --entrypoint sh ghcr.io/${{ github.repository }}:${{ env.TEST_TAG }} \
      -c "trufflehog --version && semgrep --version && trivy --version"
```

**Why This Works:**

- `--help` is universally supported
- Tests CLI is functional without needing actual scan
- Verifies entrypoint and command parsing
- Tool checks validate image variant completeness

### Alternative: Check Python Package Version

```yaml
- name: Get version from package
  run: |
    docker run --rm --entrypoint python ghcr.io/${{ github.repository }}:${{ env.TEST_TAG }} \
      -c "import importlib.metadata; print(importlib.metadata.version('jmo-security'))"
```

**Testing Locally:**

```bash
# Build image
docker build -t jmo-test:local .

# Test help (should work)
docker run --rm jmo-test:local --help

# Test version (will fail)
docker run --rm jmo-test:local --version

# Test subcommand
docker run --rm jmo-test:local scan --help

# Check tools
docker run --rm --entrypoint sh jmo-test:local -c "which trufflehog semgrep trivy"
```

---

## 4. SARIF Upload Permission Errors

**Symptoms:**

```text
Error: Resource not accessible by integration
Error: refusing to allow GitHub App to create or update workflow without security-events write permission
HttpError: Resource not accessible by integration
```

**Root Cause:**

Missing `security-events: write` permission in workflow permissions block. GitHub Security tab requires this permission to accept SARIF uploads.

**Where This Occurs:**

- release.yml, docker-scan job
- Any workflow using `github/codeql-action/upload-sarif@v3`

**Wrong Approach:**

```yaml
name: Release

on:
  push:
    tags: ["v*"]

# Missing security-events permission
permissions:
  contents: read
  packages: write

jobs:
  docker-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'image'
          format: 'sarif'
          output: 'trivy-results.sarif'

      - name: Upload SARIF (FAILS)
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'trivy-results.sarif'
```

**Correct Approach:**

```yaml
name: Release

on:
  push:
    tags: ["v*"]

# Add security-events permission
permissions:
  contents: read
  packages: write
  security-events: write  # Required for SARIF upload

jobs:
  docker-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'image'
          image-ref: 'ghcr.io/${{ github.repository }}:${{ env.TEST_TAG }}'
          format: 'sarif'
          output: 'trivy-results.sarif'

      - name: Upload SARIF (WORKS)
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: 'trivy-results.sarif'
          category: 'container-scan'
```

**Permission Scopes:**

| Permission | Level | Purpose |
|------------|-------|---------|
| `contents` | read | Checkout code |
| `packages` | write | Push Docker images to ghcr.io |
| `security-events` | write | Upload SARIF to Security tab |
| `id-token` | write | OIDC token for Trusted Publishers |
| `pull-requests` | write | Comment on PRs with results |

**GitHub Security Tab Setup:**

1. Go to repo Settings -> Security -> Code scanning
2. Set up GitHub Advanced Security (if private repo)
3. Configure code scanning to accept SARIF uploads
4. Verify permission in workflow: `security-events: write`

**Testing Locally:**

You can't test SARIF upload locally, but you can validate the SARIF file:

```bash
# Install SARIF validator
npm install -g @microsoft/sarif-multitool

# Validate SARIF file
sarif-multitool validate trivy-results.sarif

# View SARIF results
cat trivy-results.sarif | jq '.runs[0].results[] | {ruleId, message}'
```

**Troubleshooting:**

- If upload succeeds but no results in Security tab: Check SARIF format version (must be 2.1.0)
- If "Resource not accessible" persists: Check if GitHub Advanced Security is enabled for private repos
- If upload intermittently fails: Add retry logic with `continue-on-error: true`

---

## 5. Docker Hub README Sync Issues

**Symptoms:**

```text
Error: Not found
Error: Authentication failed
Error: API rate limit exceeded
Error: unexpected status: 401 Unauthorized
```

**Root Cause:**

1. Using outdated action version (v3 -> v4)
2. Missing required secrets/variables
3. Missing repository variable gate
4. Incorrect Docker Hub token permissions

**Where This Occurs:**

- release.yml, docker-hub-readme job

**Wrong Approach:**

```yaml
jobs:
  docker-hub-readme:
    runs-on: ubuntu-latest
    steps:
      # Old version, no gating, missing variables
      - uses: peter-evans/dockerhub-description@v3
        with:
          username: ${{ secrets.DOCKERHUB_USERNAME }}
          password: ${{ secrets.DOCKERHUB_PASSWORD }}  # Should be TOKEN
          repository: myorg/myrepo  # Hardcoded
```

**Correct Approach:**

```yaml
jobs:
  docker-hub-readme:
    runs-on: ubuntu-latest
    # Gate with repository variable
    if: startsWith(github.ref, 'refs/tags/v') && vars.DOCKERHUB_ENABLED == 'true'
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      # Current version with proper auth
      - name: Sync README to Docker Hub
        uses: peter-evans/dockerhub-description@v4
        with:
          username: ${{ secrets.DOCKERHUB_USERNAME }}
          password: ${{ secrets.DOCKERHUB_TOKEN }}  # PAT, not password
          repository: ${{ secrets.DOCKERHUB_REPOSITORY }}
          readme-filepath: ./docs/DOCKER_README.md  # Optional: custom README
          short-description: 'JMo Security - Multi-tool security audit suite'
```

**Setup Requirements:**

**1. Create Docker Hub Access Token:**

```bash
# Go to Docker Hub -> Account Settings -> Security -> Access Tokens
# Create new token with scopes:
- Read
- Write
- Delete (required for README updates)

# Name: github-actions-readme-sync
# Copy token (shown once)
```

**2. Add GitHub Secrets:**

```bash
# In GitHub repo: Settings -> Secrets and variables -> Actions

# Add secrets:
DOCKERHUB_USERNAME=your-docker-username
DOCKERHUB_TOKEN=dckr_pat_xxxxxxxxxxxxxxxxxxxxx  # From step 1
DOCKERHUB_REPOSITORY=your-docker-username/repo-name

# Add variable (not secret):
DOCKERHUB_ENABLED=true  # Repository variable
```

**3. Verify Token Permissions:**

```bash
# Test token locally
TOKEN="dckr_pat_xxxxxxxxxxxxxxxxxxxxx"
curl -u "username:$TOKEN" https://hub.docker.com/v2/users/login/

# Should return: {"token": "..."}
# If error 401: Token expired or wrong permissions
```

**Why Use Variable Gate?**

```yaml
if: vars.DOCKERHUB_ENABLED == 'true'
```

Benefits:

- Disable Docker Hub sync without modifying workflow
- Useful for forks (don't have Docker Hub access)
- Prevents errors in environments without secrets configured
- Can enable/disable per repository without code changes

### Alternative: Skip Docker Hub Sync

If you don't use Docker Hub (only ghcr.io), remove the job entirely.

**Testing Locally:**

```bash
# Test README update (requires token)
docker run --rm \
  -e DOCKERHUB_USERNAME=your-username \
  -e DOCKERHUB_PASSWORD=your-token \
  -e DOCKERHUB_REPOSITORY=your-username/repo \
  -v $(pwd):/workspace \
  peterevans/dockerhub-description:4 \
  --readme /workspace/README.md
```

---

## 6. Dependabot PR Cascading Failures

**Symptoms:**

```text
Error: ModuleNotFoundError: No module named 'scripts.core.compliance_frameworks'
Error: ImportError while importing test module
Error: Cannot import scripts.core.exceptions
All 13 Dependabot PRs failing with same error
```

**Root Cause:**

Dependabot creates PRs based on the `main` branch **at the time the PR is created**. If you push a commit with new Python modules **after** Dependabot creates PRs, those PRs will be missing the new files and fail with `ModuleNotFoundError`.

**Real-World Example (Oct 19, 2025):**

- **11:19 PM EDT:** Dependabot creates 13 PRs based on `main` branch
- **11:46 PM EDT:** Developer pushes commit adding `compliance_frameworks.py` and 16 other modules
- **Result:** All 13 Dependabot PRs fail because they're based on old `main` without the new modules

**Where This Occurs:**

- Any Dependabot PR (Python packages, GitHub Actions, Docker base images)
- Test failures in CI test-matrix job
- Import errors during test collection

**Wrong Approach:**

```bash
# Manually rebasing each PR individually
git fetch origin pull/68/head:pr-68
git checkout pr-68
git rebase main
git push --force-with-lease
# Repeat for all 13 PRs... Time-consuming, error-prone
```

**Correct Approach:**

Use Dependabot's built-in rebase command:

```bash
# Option 1: Trigger rebase via GitHub CLI (fastest)
for pr in 68 67 66 65 64 63 62 61 60 59 58 57 56; do
  gh pr comment $pr --repo jimmy058910/jmo-security-repo --body "@dependabot rebase"
done

# Option 2: Comment on PRs manually in GitHub UI
# Navigate to each PR and comment: @dependabot rebase
```

**Why This Works:**

- Dependabot automatically rebases PR against current `main` (includes new modules)
- Preserves PR history and metadata
- No manual git operations needed
- Works even with merge conflicts (Dependabot handles them)

**Verification:**

```bash
# Monitor rebase progress (PRs will show "updated" status)
gh pr list --repo jimmy058910/jmo-security-repo --author app/dependabot --state open

# Check CI status after rebases
gh pr checks 68 --repo jimmy058910/jmo-security-repo

# Verify specific failure is resolved
gh run view <run-id> --log-failed | grep -i "modulenotfound"
```

**Prevention Strategy (Three Layers):**

### Layer 1: Pre-push Git Hook (Automatic)

Install a pre-push hook that validates before every push:

```bash
# .git/hooks/pre-push (already installed in JMo Security)
#!/bin/bash
echo "Running pre-push checks..."

# Check for untracked Python modules
untracked=$(git ls-files --others --exclude-standard scripts/ | grep "\.py$" || true)
if [ -n "$untracked" ]; then
  echo "ERROR: Untracked Python files found in scripts/:"
  echo "$untracked"
  echo "Fix: Run 'git add scripts/' before pushing"
  exit 1
fi

# Validate critical module imports
for module in compliance_frameworks exceptions tool_runner constants; do
  if ! python3 -c "import scripts.core.$module" 2>/dev/null; then
    echo "ERROR: Cannot import scripts.core.$module"
    exit 1
  fi
done

echo "Pre-push checks passed!"
```

### Layer 2: Dependabot Schedule Configuration

Configure Dependabot to run at predictable times (already configured in `.github/dependabot.yml`):

```yaml
# Run weekly Monday 9 AM UTC (after weekend development settles)
schedule:
  interval: "weekly"
  day: "monday"
  time: "09:00"
```

### Layer 3: Contributor Documentation

Document commit guidelines in `CONTRIBUTING.md`.

**Manual Validation (before committing):**

```bash
# Check for untracked files in scripts/
git status scripts/

# Add all new modules
git add scripts/

# Verify imports work
python3 -c "import scripts.core.your_new_module"
```

### Fallback: Close and Recreate PRs

If rebases fail or take too long:

```bash
# Close all Dependabot PRs with explanation
for pr in 68 67 66 65 64 63 62 61 60 59 58 57 56; do
  gh pr close $pr --repo jimmy058910/jmo-security-repo --comment \
    "@dependabot recreate

This PR was created before critical fixes were merged to main.
Closing to trigger recreation with updated base.

Root cause: ModuleNotFoundError (fixed in main)
Resolution: Dependabot will auto-recreate within 24 hours."
done
```

**Dependabot will automatically recreate PRs within 1-24 hours using current `main` as base.**

**Troubleshooting:**

**Q: Rebase succeeded but tests still failing?**

```bash
# Check if main branch has other issues
gh run list --workflow=CI --branch=main --limit 5

# If main is failing, fix main first
git checkout main
make test  # Fix any failures
git push
```

**Q: Some PRs rebased successfully, others failed?**

```bash
# Check which PRs have merge conflicts
gh pr list --author app/dependabot --state open --json number,mergeable

# For conflicted PRs, close and recreate
gh pr close <number> --comment "@dependabot recreate"
```

**Q: Want to prevent this entirely?**

```bash
# Use branch protection rules (Settings -> Branches -> main)
# Require status checks to pass before merging:
- CI / Quick checks
- CI / Test ubuntu-latest / Python 3.11
- CI / Test macos-latest / Python 3.11

# This prevents broken commits from reaching main
# BUT: May slow down your development velocity
```

**Time Savings:**

- **Manual rebase approach:** 2-4 hours (13 PRs x 10-20 min each)
- **Dependabot rebase command:** 5 minutes (comment on all PRs, wait for automation)
- **Pre-push hook prevention:** 0 hours (issue never occurs)

**Related Documentation:**

- Pre-push hook: `.git/hooks/pre-push` (installed automatically)
- Commit guidelines: [CONTRIBUTING.md#commit-guidelines-and-pre-push-validation](../../CONTRIBUTING.md#commit-guidelines-and-pre-push-validation)
- Dependabot config: [.github/dependabot.yml](../../.github/dependabot.yml)

---

## 7. Markdownlint Failures (Documentation)

**Symptoms:**

```text
markdownlint.........................................................Failed
MD036/no-emphasis-as-heading: Emphasis used instead of a heading
MD032/blanks-around-lists: Lists should be surrounded by blank lines
MD040/fenced-code-language: Code fence should have language specified
MD031/fenced-code-fence: Fenced code blocks should be surrounded by blank lines
```

**Root Cause:**

Documentation doesn't follow markdown linting rules, causing accessibility and compatibility issues.

**Where This Occurs:**

- ci.yml, lint-full job (nightly)
- Pre-commit hooks (local)
- Any markdown file (README, CHANGELOG, docs/*)

**Common Violations:**

### MD036: Emphasis as Heading

**Wrong:**

```markdown
**Installation**

Follow these steps...

**Configuration**

Edit the config file...
```

**Correct:**

```markdown
## Installation

Follow these steps...

## Configuration

Edit the config file...
```

**Why:** Screen readers announce heading levels for navigation. Emphasis (bold) doesn't provide semantic structure.

### MD032: Blank Lines Around Lists

**Wrong:**

```markdown
Prerequisites:
- Python 3.10+
- Docker installed
- Git configured
Run the following command...
```

**Correct:**

```markdown
Prerequisites:

- Python 3.10+
- Docker installed
- Git configured

Run the following command...
```

**Why:** Inconsistent rendering across markdown parsers (GitHub, GitLab, VSCode, etc.).

### MD040: Code Fence Language

**Wrong:**

````markdown
Install the package:
```

pip install jmo-security

```text
````

**Correct:**

````markdown
Install the package:

```bash
pip install jmo-security
```
````

**Why:** No syntax highlighting, screen readers can't identify code language, copy-paste unreliable.

### MD031: Blank Lines Around Code Fences

**Wrong:**

````markdown
Run this command:
```bash
jmo scan --repo ./app
```
This will scan the app.
````

**Correct:**

````markdown
Run this command:

```bash
jmo scan --repo ./app
```

This will scan the app.
````

**Fixing Workflow:**

```bash
# 1. Check single file
pre-commit run markdownlint --files docs/USER_GUIDE.md

# 2. See all violations
pre-commit run markdownlint --all-files --show-diff-on-failure

# 3. Auto-fix some issues (not all)
npx markdownlint-cli --fix "**/*.md"

# 4. Manually fix remaining issues
vim docs/USER_GUIDE.md

# 5. Verify fixes
pre-commit run markdownlint --all-files

# 6. Commit only after passing
git add docs/USER_GUIDE.md
git commit -m "docs: fix markdownlint violations"
```

**Configuration (.markdownlint.yaml):**

```yaml
# Relaxed rules for JMo Security
MD013: false  # Line length (disabled for long URLs/tables)
MD033: false  # Inline HTML (allowed for badges)
MD041: false  # First line heading (not all files need it)

# Strict rules (enforce)
MD036: true   # No emphasis as headings
MD032: true   # Blank lines around lists
MD040: true   # Code fence language required
MD031: true   # Blank lines around code fences
```

**CRITICAL PRINCIPLE:**

**Fix ALL violations found, not just new ones.**

If markdownlint shows 10 violations (3 new + 7 old), fix all 10. See [jmo-documentation-updater skill](../jmo-documentation-updater/SKILL.md#technical-debt-principle) for rationale.

---

## 8. Pre-commit Hook Failures in CI

**Symptoms:**

```text
ruff....................................Failed
black...................................Failed
shellcheck..............................Failed
detect-private-key......................Failed
```

**Root Cause:**

Local changes didn't pass pre-commit before push, or pre-commit hooks are outdated.

**Where This Occurs:**

- ci.yml, lint-full job
- Local development before commit

**Prevention:**

```bash
# Install pre-commit hooks (one-time setup)
make pre-commit-install

# This installs git hooks that run on every commit
# Hooks automatically run before commit completes
```

**Quick Fix in CI:**

If CI fails but you need to push a hotfix:

```bash
# 1. Run pre-commit locally
pre-commit run --all-files

# 2. Auto-fix formatting
make fmt  # Runs black, ruff format, shfmt

# 3. Fix remaining issues manually
vim scripts/cli/jmo.py

# 4. Re-run pre-commit
pre-commit run --all-files

# 5. Commit and push
git add .
git commit -m "fix: resolve pre-commit violations"
git push
```

**Common Violations:**

| Hook | Error | Fix |
|------|-------|-----|
| **ruff** | `F401: imported but unused` | Remove unused imports |
| **black** | `would reformat file.py` | Run `black file.py` |
| **shellcheck** | `SC2086: Quote variables` | Add quotes: `"$var"` |
| **detect-private-key** | `Potential private key` | Move to env var or .gitignore |
| **check-yaml** | `Invalid YAML syntax` | Fix indentation, quotes |
| **end-of-file-fixer** | `No newline at end of file` | Add newline |

**Bypassing Pre-commit (Emergency Only):**

```bash
# Skip pre-commit hooks (NOT RECOMMENDED)
git commit --no-verify -m "emergency hotfix"

# CI will still fail - fix violations after push
```

---

## 9. Test Coverage Below Threshold

**Symptoms:**

```text
FAILED tests/adapters/test_snyk_adapter.py::test_snyk_basic
=============================== Coverage =============================
TOTAL                        1234    245     82%
FAILED: Coverage of 82% is below threshold of 85%
```

**Root Cause:**

New code not sufficiently tested, or tests don't cover all branches.

**Where This Occurs:**

- ci.yml, test-matrix job
- pytest with `--cov-fail-under=85`

**Quick Diagnosis:**

```bash
# Run tests with coverage report
pytest --cov --cov-report=term-missing

# Output shows uncovered lines:
scripts/core/adapters/snyk_adapter.py    45-52, 67, 89-91    76%
#                                        ^ these lines not covered
```

**Fix Strategy:**

1. **Add missing test cases** (see jmo-test-fabricator skill)
2. **Test edge cases:** empty files, malformed JSON, missing fields
3. **Test error paths:** exceptions, timeouts, missing tools
4. **Test v1.1.0/v1.2.0 features:** risk, context, compliance

**Example Fix:**

```python
# tests/adapters/test_snyk_adapter.py

# Missing test for empty file (line 45-52)
def test_snyk_empty_file(tmp_path: Path):
    """Test handling of empty file."""
    p = tmp_path / "empty.json"
    p.write_text("", encoding="utf-8")
    assert load_snyk(p) == []  # Now covers lines 45-52

# Missing test for malformed JSON (line 67)
def test_snyk_malformed_json(tmp_path: Path):
    """Test handling of malformed JSON."""
    p = tmp_path / "bad.json"
    p.write_text("{not json}", encoding="utf-8")
    assert load_snyk(p) == []  # Now covers line 67

# Missing test for nested arrays (line 89-91)
def test_snyk_nested_arrays(tmp_path: Path):
    """Test handling of nested vulnerability arrays."""
    sample = {"vulnerabilities": [[{"id": "SNYK-001"}]]}
    # ... covers lines 89-91
```

**Coverage Best Practices:**

- **Aim for >90%:** Gives buffer below 85% threshold
- **Test all error paths:** Not just happy path
- **Use coverage report:** `--cov-report=html` for visual coverage map
- **Don't skip tests:** Avoid `@pytest.mark.skip` without good reason

---

## 10. Requirements Drift

**Symptoms:**

```text
Error: requirements-dev.txt does not match requirements-dev.in
Error: requirements-dev.txt is out of date (run: make deps-compile)
```

**Root Cause:**

`requirements-dev.in` was edited but not recompiled to `requirements-dev.txt`.

**Where This Occurs:**

- ci.yml, quick-checks job
- Dependency management workflow

**Fix:**

```bash
# Recompile requirements
make deps-compile

# This runs: pip-compile requirements-dev.in -o requirements-dev.txt

# Verify changes
git diff requirements-dev.txt

# Commit both files
git add requirements-dev.in requirements-dev.txt
git commit -m "build(deps): update test dependencies"
```

**Why This Check Exists:**

- Ensures deterministic builds (same versions every time)
- Prevents "works on my machine" issues
- Locks transitive dependencies (dependencies of dependencies)
- CI validates lock file is up-to-date

**Dependency Update Workflow:**

```bash
# 1. Edit source file
echo "pytest>=8.0.0" >> requirements-dev.in

# 2. Compile to lock file
make deps-compile

# 3. Sync to environment
make deps-sync  # or make uv-sync (faster)

# 4. Test changes
make test

# 5. Commit both files
git add requirements-dev.in requirements-dev.txt
git commit -m "build(deps): upgrade pytest to 8.0.0"
```

---

## 11. YAML Syntax Errors

**Symptoms:**

```text
yamllint: error: syntax error: expected <block end>, but found '<block mapping start>'
Error: workflow is invalid
actionlint: invalid YAML syntax
```

**Root Cause:**

Invalid YAML syntax (indentation, quotes, anchors, etc.).

**Where This Occurs:**

- ci.yml, quick-checks job (yamllint step)
- Any `.yml` or `.yaml` file

**Common YAML Mistakes:**

### 1. Mixed Tabs/Spaces

**Wrong:**

```yaml
jobs:
  test:
    runs-on: ubuntu-latest  # Tab
    steps:  # 2 spaces
```

**Correct:**

```yaml
jobs:
  test:
    runs-on: ubuntu-latest  # 2 spaces consistently
    steps:
```

### 2. Missing Quotes Around Special Characters

**Wrong:**

```yaml
env:
  MESSAGE: Hello: World  # Colon unquoted
  PATH: /usr/bin:/usr/local/bin  # Multiple colons
```

**Correct:**

```yaml
env:
  MESSAGE: "Hello: World"  # Quote strings with colons
  PATH: "/usr/bin:/usr/local/bin"
```

### 3. Incorrect Indentation

**Wrong:**

```yaml
jobs:
  test:
  runs-on: ubuntu-latest  # Should be indented
    steps:
      - name: Test
      run: echo "test"  # Should be indented more
```

**Correct:**

```yaml
jobs:
  test:
    runs-on: ubuntu-latest  # 2 spaces
    steps:
      - name: Test
        run: echo "test"  # 4 spaces under list item
```

**Validation Workflow:**

```bash
# 1. Check YAML syntax
yamllint .github/workflows/*.yml

# 2. Validate with Python (detects syntax errors)
python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"

# 3. Validate GitHub Actions specifically
actionlint .github/workflows/*.yml

# 4. Fix errors
vim .github/workflows/ci.yml

# 5. Re-validate
yamllint .github/workflows/ci.yml && actionlint .github/workflows/ci.yml
```

**Yamllint Configuration (.yamllint.yaml):**

```yaml
extends: default

rules:
  line-length:
    max: 120  # Allow longer lines for URLs
    allow-non-breakable-words: true
    allow-non-breakable-inline-mappings: true

  indentation:
    spaces: 2  # Consistent 2-space indentation
    indent-sequences: true

  comments:
    min-spaces-from-content: 2
```

---

## 12. Branch Protection and Direct Push Failures

**Symptoms:**

```text
remote: error: GH013: Repository rule violations found for refs/heads/main.
remote: - Required status check "quick-checks" is expected.
remote: - Required status check "Test ubuntu-latest / Python 3.11" is expected.
error: failed to push some refs to 'https://github.com/jimmy058910/jmo-security-repo.git'
```

**Root Cause:**

Branch protection rules require passing CI checks before merging to `main`. Direct pushes to `main` are blocked unless all required status checks pass.

**Where This Occurs:**

- Any attempt to push directly to protected branches
- Applies to all workflows (ci.yml, release.yml)
- Affects both manual pushes and automated workflows

**Branch Protection Configuration (JMo Security):**

```yaml
# Settings -> Branches -> main -> Branch protection rules
Required status checks:
  - quick-checks
  - Test ubuntu-latest / Python 3.11
  - Lint (quick checks)

Settings:
  Require status checks to pass before merging
  Require branches to be up to date before merging
  Allow force pushes (disabled for safety)
  Allow deletions (disabled for safety)
```

**Wrong Approach:**

```bash
# Try to push directly to main (FAILS)
git checkout main
git commit -m "fix: urgent hotfix"
git push origin main
# remote: error: GH013: Repository rule violations found
```

**Correct Approach:**

Use feature branches and pull requests:

```bash
# 1. Create feature branch
git checkout -b fix/urgent-issue

# 2. Make changes and commit
git add .
git commit -m "fix: resolve urgent issue"

# 3. Push feature branch (no branch protection)
git push origin fix/urgent-issue

# 4. Create pull request
gh pr create --title "Fix urgent issue" --body "Resolves issue XYZ"

# 5. Wait for CI checks to pass
gh pr checks --watch

# 6. Merge when green
gh pr merge --merge  # or --squash, --rebase
```

**Emergency Bypass (Repository Admin Only):**

If you have repository admin rights and need emergency access:

```bash
# Option 1: Temporarily disable branch protection
# GitHub UI: Settings -> Branches -> main -> Edit -> Temporarily disable

# Push fix
git push origin main

# Re-enable protection immediately after
# GitHub UI: Settings -> Branches -> main -> Edit -> Re-enable

# USE SPARINGLY - bypasses all safety checks
```

**Workflow for CI Fixes:**

When CI is broken and you need to fix it:

```bash
# 1. Create fix branch from current main
git checkout main
git pull
git checkout -b fix/ci-broken

# 2. Apply fix
git checkout origin/main -- requirements-dev.txt
git add requirements-dev.txt
git commit -m "fix(ci): remove absolute paths from requirements-dev.txt"

# 3. Push to fix branch
git push origin fix/ci-broken

# 4. Create PR
gh pr create --title "Fix CI: requirements-dev.txt absolute paths" \
  --body "Fixes recurring deps-compile freshness check failure."

# 5. Monitor PR checks
gh pr checks --watch

# 6. Merge when green
gh pr merge --squash
```

**Testing Locally Before PR:**

```bash
# Pre-flight checklist (prevents PR failures)
make pre-commit-run  # All pre-commit hooks
make test           # Tests with coverage >=85%
make lint           # Additional linting

# Check for common issues
grep -E "/home/|/Users/" requirements-dev.txt  # Absolute paths?
git status scripts/  # Untracked Python files?

# Workflow-specific checks
yamllint .github/workflows/*.yml
actionlint .github/workflows/*.yml
```

**Prevention Best Practices:**

1. **Always use feature branches** - Never commit directly to main locally
2. **Test locally first** - Run full pre-flight checklist before pushing
3. **Create PR immediately** - Don't wait until "ready" - use draft PRs
4. **Monitor CI actively** - Use `gh pr checks --watch` for real-time feedback
5. **Document branch strategy** - Add to CONTRIBUTING.md for collaborators

---

## 13. GitHub Rulesets Requiring Commit Statuses (Not Check Runs)

**Symptoms:**

```text
PR shows "waiting for status to be reported" for required check
All GitHub Actions checks show SUCCESS
Merge button remains disabled: "Some checks haven't completed yet"
Manual merge attempt: "Required status check was not set by the expected GitHub app"
```

**Root Cause:**

GitHub has **two separate status systems**:

1. **Check Runs API** (modern) - Used by GitHub Actions workflows
2. **Commit Status API** (legacy) - Required by some GitHub Rulesets

When a **GitHub Ruleset** is configured to require a specific status check by context name, it expects a **commit status** (legacy API), not a **check run**. GitHub Actions creates check runs by default, not commit statuses.

**Where This Occurs:**

- Repositories using GitHub Rulesets instead of branch protection rules
- Rulesets configured with `required_status_checks` by context name
- Any workflow where ruleset expects commit status but CI creates check run

**Diagnosis Commands:**

```bash
# 1. Check if rulesets are in use (vs. branch protection)
gh api repos/OWNER/REPO/rulesets --jq '.[] | {id, name, enforcement}'

# 2. Get required status checks from ruleset
gh api repos/OWNER/REPO/rulesets/RULESET_ID --jq '.rules[] | select(.type == "required_status_checks") | .parameters.required_status_checks[]'

# 3. Check commit status API (different from check runs)
gh api repos/OWNER/REPO/commits/COMMIT_SHA/status --jq '{state, statuses: [.statuses[] | {context, state}]}'
# Returns: {"state":"pending","statuses":[]}  <- No commit statuses!

# 4. Check check runs API (GitHub Actions)
gh api repos/OWNER/REPO/commits/COMMIT_SHA/check-runs --jq '.check_runs[] | {name, status, conclusion}'
# Returns: All checks show "completed" and "success"

# 5. Compare: Ruleset expects commit status, but only check runs exist
```

**Wrong Approach (Manual Fix):**

```bash
# Manually creating commit status works but isn't sustainable
gh api repos/OWNER/REPO/statuses/COMMIT_SHA \
  -X POST \
  -f state=success \
  -f context="quick-checks" \
  -f description="All CI checks passed"

# This works ONCE but doesn't fix future PRs
```

**Correct Approach (Permanent Fix):**

Add commit status creation to your workflow:

```yaml
# .github/workflows/ci.yml
jobs:
  quick-checks:
    name: Quick checks
    runs-on: ubuntu-latest
    steps:
      # ... existing validation steps ...

      # Create commit status for ruleset compatibility
      # GitHub Rulesets may require commit statuses (legacy API) instead of check runs
      - name: Create commit status
        if: always()
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.repos.createCommitStatus({
              owner: context.repo.owner,
              repo: context.repo.repo,
              sha: context.sha,
              state: '${{ job.status }}' === 'success' ? 'success' : 'failure',
              context: 'quick-checks',
              description: 'CI checks ' + ('${{ job.status }}' === 'success' ? 'passed' : 'failed')
            });
```

**Why This Works:**

- `if: always()` ensures status is created even if job fails
- `${{ job.status }}` evaluates to 'success', 'failure', 'cancelled', or 'skipped'
- `context: 'quick-checks'` matches the ruleset requirement exactly
- Creates **both** check run (automatic) and commit status (explicit)

**Key Differences: Check Runs vs. Commit Statuses:**

| Aspect | Check Runs (Modern) | Commit Statuses (Legacy) |
|--------|-------------------|------------------------|
| **API Endpoint** | `/repos/{owner}/{repo}/check-runs` | `/repos/{owner}/{repo}/statuses/{sha}` |
| **Created By** | GitHub Actions (automatic) | Manual API call or external CI |
| **Identifier** | Name (e.g., "Quick checks") | Context (e.g., "quick-checks") |
| **Ruleset Support** | Not directly supported | Required by rulesets |
| **UI Display** | Shows in "Checks" tab | Shows as status badge |
| **Conclusion** | SUCCESS, FAILURE, SKIPPED, etc. | success, failure, error, pending |

**Alternative Solution: Update Ruleset to Use Check Runs:**

If you have repository admin access, update the ruleset:

```bash
# Get current ruleset configuration
gh api repos/OWNER/REPO/rulesets/RULESET_ID > ruleset.json

# Edit ruleset.json to change from commit status to check run
# Change:
#   "required_status_checks": [{"context": "quick-checks", "integration_id": 15368}]
# To:
#   "required_status_checks": [{"context": "Quick checks", "integration_id": null}]
# Note: Check runs use the job NAME, not context

# Update ruleset
gh api repos/OWNER/REPO/rulesets/RULESET_ID -X PUT --input ruleset.json
```

**However, updating workflows is preferred** because:

- Works with any ruleset configuration
- Backwards compatible with branch protection rules
- Doesn't require admin access
- Creates both check runs and commit statuses (best of both worlds)

**Verification:**

```bash
# After adding commit status step to workflow:
# 1. Push commit
git commit -m "test"
git push

# 2. Wait for CI to complete (2-3 min)

# 3. Verify commit status was created
gh api repos/OWNER/REPO/commits/$(git rev-parse HEAD)/status --jq '.statuses[] | {context, state}'
# Should show: {"context":"quick-checks","state":"success"}

# 4. Verify PR is mergeable
gh pr view PR_NUMBER --json mergeable,mergeStateStatus
# Should show: {"mergeable":true,"mergeStateStatus":"CLEAN"}
```

**Prevention:**

1. **Always create commit statuses** in GitHub Actions workflows for critical jobs
2. **Test merge button** in PRs during workflow development
3. **Document ruleset requirements** in repository documentation
4. **Use consistent context names** between workflow job names and status contexts

---

## 14. Nightly Lint-Full Cascading Failures (Multiple Tool Errors)

**Symptoms:**

```text
lint-full job failed with multiple categories:
- actionlint: shellcheck warnings (SC2086, SC2129, SC2252)
- markdownlint: MD032, MD034, MD040 violations (8 files, 13 issues)
- mypy: unused type:ignore, missing type annotations (6 files, 13 errors)
- deps-compile: pip version incompatibility
```

**Root Cause:**

Accumulated technical debt from changes that pass individual pre-commit hooks but fail comprehensive lint-full. Common when:

1. Changes pushed without running `pre-commit run --all-files`
2. Pre-commit hooks outdated or not installed locally
3. Tool version updates introduce stricter checks
4. Pip/dependency version mismatch between local and CI

**Where This Occurs:**

- Nightly scheduled runs (lint-full job at 6 AM UTC)
- After dependency updates or tool version bumps
- When multiple contributors push without comprehensive local testing

**Systematic Fix Approach:**

**Step 1: Diagnose All Failures**

```bash
# Fetch failed run logs
gh run view <run-id> --log-failed | grep -E "Failed|error:" > failures.txt

# Categorize failures
echo "=== Actionlint ==="
grep "actionlint" failures.txt

echo "=== Markdownlint ==="
grep "markdownlint" failures.txt

echo "=== Mypy ==="
grep "mypy" failures.txt

echo "=== Deps-compile ==="
grep "deps-compile\|pip-compile" failures.txt
```

**Step 2: Fix in Order (Dependencies Matter)**

Fix in this order because deps-compile blocks other tools:

1. **deps-compile first** (blocks pip installs for other tools):

   ```bash
   # Check pip version locally
   pip --version

   # If 25.3+, CI workflows need pin updates
   # Edit .github/workflows/ci.yml (all 3 install steps):
   python -m pip install --upgrade 'pip<25.3'

   # Recompile locally to verify
   make deps-compile
   ```

2. **actionlint shellcheck warnings**:

   ```bash
   # Run locally to see all warnings
   pre-commit run actionlint --all-files

   # Common fixes:
   # - Quote variables: $VAR -> "$VAR"
   # - Group redirects: { echo "a"; echo "b"; } >> file
   # - Fix || vs && logic (SC2252)
   # - Disable false positives: # shellcheck disable=SC2252
   ```

3. **mypy type errors**:

   ```bash
   # Run locally
   pre-commit run mypy --all-files

   # Common fixes:
   # - Remove unused type:ignore comments
   # - Add explicit types: data: dict[str, Any] = json.loads(...)
   # - Fix None vs Type: obj or {} instead of obj
   # - Import Any: from typing import Any, Dict, List, Optional
   ```

4. **markdownlint violations**:

   ```bash
   # Run locally
   pre-commit run markdownlint --all-files

   # CRITICAL: Fix ALL violations found (not just new ones)
   # This is the Technical Debt Principle from CLAUDE.md

   # Common patterns:
   # - MD032: Add blank lines before/after lists
   # - MD034: Wrap URLs: https://url -> <https://url>
   # - MD040: Add language: ``` -> ```bash or ```text
   ```

**Step 3: Apply Technical Debt Principle**

**CRITICAL PRINCIPLE: Fix ALL violations found, not just new ones.**

```bash
# Wrong: Fix only your 3 new violations
pre-commit run markdownlint --files docs/NEW_FILE.md

# Correct: Fix ALL 13 violations across all 8 files
pre-commit run markdownlint --all-files
# Must show: "Passed" for all files before committing
```

**Step 4: Test Comprehensively**

```bash
# Must pass ALL hooks
pre-commit run --all-files

# Verify specific tools individually
pre-commit run actionlint --all-files
pre-commit run markdownlint --all-files
pre-commit run mypy --all-files
make deps-compile && git diff requirements-dev.txt  # Should be clean
```

**Prevention Strategies:**

1. **Local Pre-Commit Discipline:** Install hooks, run `pre-commit run --all-files` before every push
2. **Enhanced Pre-Push Hook:** Add mypy and markdownlint checks on staged files
3. **Weekly Maintenance Routine:** Update hooks monthly, fix violations proactively
4. **CI Workflow Enhancement:** Add "Lint Preview" to quick-checks job

**Time Investment:**

- **Diagnosis:** 5 minutes
- **Fix execution:** 30-45 minutes (all 4 categories)
- **Testing:** 5 minutes
- **Total:** 40-55 minutes

---

## 15. Ruff Linting Failures After Black Formatting (Cascading Cleanup)

**Symptoms:**

1. **Black formatting passes** - `pre-commit run black --all-files` returns "Passed"
2. **Ruff linting fails immediately after** - CI "Lint (quick checks)" job fails with F401/F541/F403 violations
3. **Errors appear in files you just formatted** - Black created "clean" formatting that exposed underlying issues
4. **Multiple files affected** - Not isolated to one file

**Error Pattern:**

```text
CI: Lint (quick checks) -- Failed

ruff check scripts/ tests/
F401 [*] `scripts.core.config.load_config` imported but unused
  --> scripts/cli/wizard.py:28:33

F541 [*] f-string without any placeholders
   --> scripts/core/adapters/mobsf_adapter.py:211:39

Found 7 errors (7 fixable with --fix).
```

**Root Cause:**

**Black and Ruff have different scopes:**

- **Black**: Auto-formatter that handles line length, indentation, quotes, trailing commas. Does NOT remove unused imports or optimize f-strings.
- **Ruff**: Comprehensive linter that checks code quality beyond formatting (F401: Unused imports, F541: f-strings without placeholders, F403: Star imports, F811: Redefined imports).

**This is NOT a Black bug** - it's working as designed. Black formats, Ruff enforces quality.

**Correct Approach:**

```bash
# Step 1: Run Black first (formatting baseline)
pre-commit run black --all-files

# Step 2: Run Ruff immediately after (catch quality issues)
ruff check scripts/ tests/ --fix

# Step 3: Review auto-fixes (Ruff applies most fixes automatically)
git diff

# Step 4: Manually fix remaining violations (if any)

# Step 5: Verify all checks pass
pre-commit run --all-files

# Step 6: Commit with comprehensive message
git add .
git commit -m "style: format with Black and fix ruff violations"
```

**Common Violations After Black Formatting:**

1. **F401: Unused imports (most common)** - Remove unused import lines
2. **F541: f-string without placeholders** - Remove f-prefix from strings
3. **F403: Star imports** - Replace with explicit imports
4. **F811: Redefined imports** - Combine duplicate imports

**Prevention: Pre-Commit Hook Order**

Edit `.pre-commit-config.yaml` to enforce Black -> Ruff order:

```yaml
repos:
  # Step 1: Format code (Black)
  - repo: https://github.com/psf/black
    hooks:
      - id: black

  # Step 2: Lint code (Ruff) -- RUNS AFTER BLACK
  - repo: https://github.com/astral-sh/ruff-pre-commit
    hooks:
      - id: ruff
        args: [--fix, --exit-non-zero-on-fix]
```

**Time Investment:** 5-10 minutes (diagnosis + auto-fix + review)

---

## 16. Platform-Specific Test Threshold Failures (Floating-Point Precision)

**Symptoms:**

1. **Floating-point precision differences** - Same test passes on Ubuntu but fails on macOS (or vice versa)
2. **Python version variations** - Same code returns slightly different values
3. **Performance timing variations** - Hardware differences cause <10% timing variations
4. **Multiple platform failures** - Not isolated to one OS/Python version

**Error Pattern:**

```text
FAILED tests/unit/test_dedup_enhanced.py::test_message_jargon_variations - assert 0.5 <= 0.48888888888888893
FAILED tests/unit/test_dedup_enhanced.py::test_message_with_cwe_cve - assert 0.664069264069264 >= 0.75
FAILED tests/performance/test_history_db_perf.py::test_query_10k_scans_fast - AssertionError: Took 0.528s, expected <0.5s
```

**Root Cause:**

**Floating-point arithmetic is NOT deterministic across platforms:**

- **Different CPU architectures**: x86_64 (Ubuntu) vs ARM64 (macOS M1/M2) use different floating-point units
- **Compiler optimizations**: GCC vs Clang optimize float operations differently
- **Library implementations**: rapidfuzz C extensions compiled with different flags
- **Python versions**: 3.10 vs 3.11 vs 3.12 have different float handling
- **Hardware timing**: CI runners have different CPU speeds

**Correct Approach:**

```bash
# Step 1: Identify the pattern from ALL failing platforms
gh run view <run-id> --log-failed | grep -E "assert|FAILED" | grep -E "test_name"

# Step 2: Find the MINIMUM or MAXIMUM value across ALL platforms
# For lower bounds: Use minimum value - 5% buffer
# For upper bounds: Use maximum value + 5% buffer

# Step 3: Update test with relaxed threshold + comment
```

**Common Library-Specific Issues:**

| Library | Symptom | Fix |
|---------|---------|-----|
| **rapidfuzz** | Fuzzy string matching returns 0.47 vs 0.49 across platforms | Relax bounds by 5-10% |
| **numpy** | Array operations differ at 1e-15 precision | Use `np.isclose()` with `atol=1e-12` |
| **scipy** | Statistical tests vary slightly | Use 95% confidence intervals |
| **time.time()** | Performance benchmarks vary +/-10% across hardware | Add 20% buffer to timing assertions |

**Prevention Strategies:**

1. **Use Relative Comparisons:** `pytest.approx(0.75, rel=0.05)` instead of exact equality
2. **Test Ranges, Not Exact Values:** `assert 95.0 <= score <= 105.0`
3. **Use Platform-Specific Tolerances:** Different buffers for macOS vs Ubuntu
4. **Document Expected Ranges in Test Docstrings**

**Buffer Guidelines:**

- **Floating-point similarity**: 5-10% buffer
- **Performance timing**: 20-30% buffer
- **Statistical tests**: Use confidence intervals (95% or 99%)
- **Exact values**: Use `pytest.approx(rel=0.01)` for 1% tolerance

**Time Investment:** 20-30 minutes per occurrence

---

## 17. React Dashboard Build FileNotFoundError (Test Environment)

**Symptoms:**

1. Tests calling `write_html()` fail with `FileNotFoundError`
2. Error mentions "React dashboard build not found"
3. Tests pass locally but fail in CI (or vice versa)
4. Multiple test files fail with same error

**Error Pattern:**

```text
FAILED tests/reporters/test_html_security.py::test_xss_prevention - FileNotFoundError: React dashboard build not found at /path/to/scripts/dashboard/dist/index.html
FAILED tests/reporters/test_yaml_html_reporters.py::test_write_html - FileNotFoundError: React dashboard build not found
FAILED tests/unit/test_signal_handling.py::test_cmd_scan_signal_stop - FileNotFoundError: React dashboard build not found
```

**Root Cause:**

The `html_reporter.py` has a dual check for skipping React build validation:

```python
skip_react_check = (
    os.getenv("SKIP_REACT_BUILD_CHECK", "false").lower() == "true"
    or os.getenv("CI", "false").lower() == "true"
)
```

- **GitHub Actions sets `CI=true` automatically** - tests pass
- **Local development has no `CI` variable** - tests fail unless explicitly set
- **Test files missing the `SKIP_REACT_BUILD_CHECK` fixture** - inconsistent behavior

**Correct Approach:**

Add a module-level autouse fixture to ensure consistent behavior across all environments:

```python
import os
import pytest

@pytest.fixture(autouse=True)
def skip_react_build_check():
    """Skip React build check for all tests in this file (CI compatibility)."""
    os.environ["SKIP_REACT_BUILD_CHECK"] = "true"
    yield
    os.environ.pop("SKIP_REACT_BUILD_CHECK", None)


def test_write_html(tmp_path):
    # Now works in both CI and local development
    write_html(findings, tmp_path / "dashboard.html")
```

**Why This Works:**

1. **`autouse=True`** - Automatically applies to ALL tests in the file
2. **`yield` pattern** - Proper setup/teardown, cleans up after each test
3. **Module-level scope** - Only defined once, applies to entire file
4. **Environment isolation** - No leakage between test files

**Files That Need This Fixture:**

Any test file that calls `write_html()` directly or indirectly:

- `tests/reporters/test_html_reporter.py` - Has fixture + explicit test for enforcement
- `tests/reporters/test_yaml_html_reporters.py` - Needs fixture
- `tests/reporters/test_html_security.py` - Needs fixture
- `tests/unit/test_signal_handling.py` - Needs fixture (calls `cmd_scan` which may trigger reporting)

**Prevention Strategies:**

1. **Always add fixture to new test files calling `write_html()`**
2. **Check for fixture when copying test patterns from other files**
3. **Run tests locally with `unset CI` to catch missing fixtures**

**Time Investment:** 5-10 minutes per occurrence
