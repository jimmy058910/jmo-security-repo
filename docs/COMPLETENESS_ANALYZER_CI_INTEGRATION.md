# Repository Completeness Analyzer - CI/CD Integration Guide

This guide explains how to integrate the repository completeness analyzer into your CI/CD pipeline to automatically detect documentation-code drift and enforce documentation quality on pull requests.

## Table of Contents

- [Overview](#overview)
- [GitHub Actions Integration](#github-actions-integration)
  - [Basic PR Check](#basic-pr-check)
  - [PR Comment Automation](#pr-comment-automation)
  - [Blocking PRs with Critical Issues](#blocking-prs-with-critical-issues)
  - [Full Featured Workflow](#full-featured-workflow)
- [GitLab CI Integration](#gitlab-ci-integration)
- [Local Pre-Commit Hook](#local-pre-commit-hook)
- [Configuration Options](#configuration-options)
- [Interpreting Results](#interpreting-results)
- [Best Practices](#best-practices)

---

## Overview

The completeness analyzer detects:
- Undocumented features (Python APIs not in docs)
- Documentation-code drift (features in docs but changed in code)
- Missing documentation
- Configuration inconsistencies
- Test coverage gaps

**CI/CD integration benefits:**
- Prevents documentation debt from accumulating
- Catches drift before merge
- Provides actionable feedback to contributors
- Maintains documentation quality at scale

---

## GitHub Actions Integration

### Basic PR Check

**File:** `.github/workflows/completeness-check.yml`

This workflow runs the analyzer on every PR and fails if CRITICAL issues are found.

```yaml
name: Documentation Completeness Check

on:
  pull_request:
    branches: [main, dev]
    paths:
      - 'scripts/**/*.py'
      - 'docs/**/*.md'
      - 'README.md'
      - 'CLAUDE.md'
      - 'jmo.yml'

jobs:
  analyze-completeness:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for git blame attribution

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements-dev.txt

      - name: Run completeness analyzer
        id: analyze
        run: |
          python3 scripts/dev/analyze_repo_completeness.py
          echo "analysis_complete=true" >> $GITHUB_OUTPUT

      - name: Upload analysis report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: completeness-analysis
          path: dev-only/REPO_COMPLETENESS_ANALYSIS.json
          retention-days: 30

      - name: Check for CRITICAL issues
        run: |
          python3 << 'EOF'
          import json
          from pathlib import Path

          report = json.loads(Path("dev-only/REPO_COMPLETENESS_ANALYSIS.json").read_text())

          critical_issues = [
              rec for rec in report["findings"]["recommendations"]
              if rec["priority"] == "CRITICAL"
          ]

          if critical_issues:
              print("❌ CRITICAL documentation issues found:")
              print()
              for issue in critical_issues:
                  print(f"  [{issue['priority']}] {issue['action']}")
                  print(f"       → {issue['details']} ({issue['count']} items)")
                  print()
              print("Please fix CRITICAL issues before merging.")
              exit(1)
          else:
              print("✅ No CRITICAL documentation issues found.")
          EOF
```

**Triggers:**
- Runs on PRs targeting `main` or `dev`
- Only when Python code or documentation changes

**Behavior:**
- ✅ Passes if no CRITICAL issues
- ❌ Fails if CRITICAL issues found (blocks merge if branch protection enabled)
- 📊 Uploads full report as artifact

---

### PR Comment Automation

**File:** `.github/workflows/completeness-comment.yml`

This workflow posts a detailed comment on the PR with analysis results.

```yaml
name: Post Completeness Analysis

on:
  pull_request:
    branches: [main, dev]
    paths:
      - 'scripts/**/*.py'
      - 'docs/**/*.md'
      - 'README.md'
      - 'CLAUDE.md'

permissions:
  pull-requests: write
  contents: read

jobs:
  analyze-and-comment:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install -r requirements-dev.txt

      - name: Run completeness analyzer
        run: python3 scripts/dev/analyze_repo_completeness.py

      - name: Generate PR comment
        id: generate-comment
        run: |
          python3 << 'EOF'
          import json
          from pathlib import Path

          report = json.loads(Path("dev-only/REPO_COMPLETENESS_ANALYSIS.json").read_text())
          stats = report["statistics"]
          findings = report["findings"]

          # Count by priority
          priority_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
          for rec in findings["recommendations"]:
              priority_counts[rec["priority"]] += 1

          # Generate markdown comment
          comment = f"""## 📊 Documentation Completeness Analysis

          ### Statistics
          - Python files analyzed: **{stats['total_python_files']}**
          - Total functions: **{stats['total_functions']}**
          - Total classes: **{stats['total_classes']}**

          ### Findings Summary
          | Category | Count |
          |----------|-------|
          | Undocumented features | {len(findings['undocumented_features'])} |
          | Doc-code drift issues | {len(findings['doc_code_drift'])} |
          | Missing docs | {len(findings['missing_docs'])} |
          | Inconsistencies | {len(findings['inconsistencies'])} |
          | Config drift | {len(findings['config_drift'])} |
          | Test gaps | {len(findings['test_gaps'])} |

          ### Recommendations by Priority
          | Priority | Count |
          |----------|-------|
          | 🔴 CRITICAL | {priority_counts['CRITICAL']} |
          | 🟠 HIGH | {priority_counts['HIGH']} |
          | 🟡 MEDIUM | {priority_counts['MEDIUM']} |
          | 🔵 LOW | {priority_counts['LOW']} |
          """

          # Add CRITICAL issues if any
          critical_recs = [r for r in findings['recommendations'] if r['priority'] == 'CRITICAL']
          if critical_recs:
              comment += "\n\n### ❌ CRITICAL Issues (Must Fix Before Merge)\n\n"
              for rec in critical_recs:
                  comment += f"- **{rec['action']}**\n"
                  comment += f"  - {rec['details']} ({rec['count']} items)\n\n"

          # Add HIGH issues if any
          high_recs = [r for r in findings['recommendations'] if r['priority'] == 'HIGH']
          if high_recs:
              comment += "\n\n### ⚠️ HIGH Priority Issues (Recommended to Fix)\n\n"
              for rec in high_recs[:5]:  # Limit to 5
                  comment += f"- **{rec['action']}**\n"
                  comment += f"  - {rec['details']} ({rec['count']} items)\n\n"
              if len(high_recs) > 5:
                  comment += f"<details><summary>Show {len(high_recs) - 5} more HIGH priority issues</summary>\n\n"
                  for rec in high_recs[5:]:
                      comment += f"- **{rec['action']}**\n"
                      comment += f"  - {rec['details']} ({rec['count']} items)\n\n"
                  comment += "</details>\n\n"

          # Footer
          comment += "\n\n---\n"
          comment += "_📄 Full report available in workflow artifacts_\n"
          comment += f"_🤖 Analyzed by [Repository Completeness Analyzer](../blob/dev/scripts/dev/analyze_repo_completeness.py)_"

          # Save to file for PR comment action
          Path("pr-comment.md").write_text(comment)
          print("Comment generated successfully")
          EOF

      - name: Post PR comment
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const comment = fs.readFileSync('pr-comment.md', 'utf8');

            // Find existing bot comment
            const { data: comments } = await github.rest.issues.listComments({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
            });

            const botComment = comments.find(comment =>
              comment.user.type === 'Bot' &&
              comment.body.includes('Documentation Completeness Analysis')
            );

            if (botComment) {
              // Update existing comment
              await github.rest.issues.updateComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                comment_id: botComment.id,
                body: comment
              });
            } else {
              // Create new comment
              await github.rest.issues.createComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                issue_number: context.issue.number,
                body: comment
              });
            }

      - name: Upload analysis report
        uses: actions/upload-artifact@v4
        with:
          name: completeness-analysis
          path: dev-only/REPO_COMPLETENESS_ANALYSIS.json
          retention-days: 30
```

**Features:**
- ✅ Posts formatted comment with summary
- 🔄 Updates existing comment on new commits (avoids spam)
- 📊 Shows CRITICAL/HIGH issues inline
- 🔗 Links to full report in artifacts

**Example PR Comment:**

```markdown
## 📊 Documentation Completeness Analysis

### Statistics
- Python files analyzed: **87**
- Total functions: **342**
- Total classes: **45**

### Findings Summary
| Category | Count |
|----------|-------|
| Undocumented features | 12 |
| Doc-code drift issues | 5 |
| Missing docs | 8 |
| Inconsistencies | 3 |
| Config drift | 2 |
| Test gaps | 7 |

### Recommendations by Priority
| Priority | Count |
|----------|-------|
| 🔴 CRITICAL | 2 |
| 🟠 HIGH | 5 |
| 🟡 MEDIUM | 8 |
| 🔵 LOW | 3 |

### ❌ CRITICAL Issues (Must Fix Before Merge)

- **Update CLI command documentation**
  - 2 new commands added but not documented in USER_GUIDE.md (2 items)

- **Fix documentation inconsistencies**
  - CLAUDE.md and README.md have conflicting information about feature X (1 item)

---
_📄 Full report available in workflow artifacts_
_🤖 Analyzed by Repository Completeness Analyzer_
```

---

### Blocking PRs with Critical Issues

**File:** `.github/workflows/completeness-gate.yml`

This workflow uses GitHub's status checks to block merging PRs with CRITICAL issues.

```yaml
name: Documentation Quality Gate

on:
  pull_request:
    branches: [main, dev]
    paths:
      - 'scripts/**/*.py'
      - 'docs/**/*.md'
      - 'README.md'
      - 'CLAUDE.md'
      - 'jmo.yml'

jobs:
  quality-gate:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install -r requirements-dev.txt

      - name: Run completeness analyzer
        run: python3 scripts/dev/analyze_repo_completeness.py

      - name: Evaluate quality gate
        id: gate
        run: |
          python3 << 'EOF'
          import json
          import sys
          from pathlib import Path

          report = json.loads(Path("dev-only/REPO_COMPLETENESS_ANALYSIS.json").read_text())

          # Quality gate thresholds
          MAX_CRITICAL = 0  # Block if any CRITICAL issues
          MAX_HIGH = 10     # Block if more than 10 HIGH issues
          MAX_TOTAL = 50    # Block if more than 50 total issues

          recommendations = report["findings"]["recommendations"]

          critical_count = sum(1 for r in recommendations if r["priority"] == "CRITICAL")
          high_count = sum(1 for r in recommendations if r["priority"] == "HIGH")
          total_count = len(recommendations)

          print(f"Quality Gate Check:")
          print(f"  CRITICAL issues: {critical_count} (max: {MAX_CRITICAL})")
          print(f"  HIGH issues: {high_count} (max: {MAX_HIGH})")
          print(f"  Total issues: {total_count} (max: {MAX_TOTAL})")
          print()

          failed = False

          if critical_count > MAX_CRITICAL:
              print(f"❌ FAILED: {critical_count} CRITICAL issues found (max: {MAX_CRITICAL})")
              failed = True

          if high_count > MAX_HIGH:
              print(f"❌ FAILED: {high_count} HIGH issues found (max: {MAX_HIGH})")
              failed = True

          if total_count > MAX_TOTAL:
              print(f"❌ FAILED: {total_count} total issues found (max: {MAX_TOTAL})")
              failed = True

          if failed:
              print()
              print("Quality gate FAILED. Please address issues before merging.")
              sys.exit(1)
          else:
              print("✅ Quality gate PASSED")
          EOF

      - name: Set status
        if: always()
        uses: actions/github-script@v7
        with:
          script: |
            const status = '${{ steps.gate.outcome }}' === 'success' ? 'success' : 'failure';
            const description = status === 'success'
              ? 'Documentation quality gate passed'
              : 'Documentation quality gate failed - see details';

            await github.rest.repos.createCommitStatus({
              owner: context.repo.owner,
              repo: context.repo.repo,
              sha: context.payload.pull_request.head.sha,
              state: status,
              target_url: `${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`,
              description: description,
              context: 'Documentation Quality Gate'
            });
```

**Configuration:**
- `MAX_CRITICAL = 0` - Blocks any CRITICAL issues
- `MAX_HIGH = 10` - Allows up to 10 HIGH priority issues
- `MAX_TOTAL = 50` - Allows up to 50 total issues

**Branch Protection Setup:**

1. Go to **Settings → Branches → Branch protection rules**
2. Add rule for `main` (or `dev`)
3. Enable: **Require status checks to pass before merging**
4. Select: **Documentation Quality Gate**
5. Save

Now PRs with CRITICAL issues cannot be merged until fixed.

---

### Full Featured Workflow

**File:** `.github/workflows/completeness-full.yml`

Combines all features: check + comment + gate + trend tracking.

```yaml
name: Documentation Completeness (Full)

on:
  pull_request:
    branches: [main, dev]
    paths:
      - 'scripts/**/*.py'
      - 'docs/**/*.md'
      - 'README.md'
      - 'CLAUDE.md'
      - 'jmo.yml'

permissions:
  pull-requests: write
  contents: read
  statuses: write

jobs:
  completeness-analysis:
    runs-on: ubuntu-latest

    outputs:
      critical-count: ${{ steps.analyze.outputs.critical-count }}
      high-count: ${{ steps.analyze.outputs.high-count }}
      status: ${{ steps.gate.outputs.status }}

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'

      - name: Install dependencies
        run: pip install -r requirements-dev.txt

      - name: Run completeness analyzer
        id: analyze
        run: |
          python3 scripts/dev/analyze_repo_completeness.py

          # Extract counts for job outputs
          python3 << 'EOF'
          import json
          import os
          from pathlib import Path

          report = json.loads(Path("dev-only/REPO_COMPLETENESS_ANALYSIS.json").read_text())
          recommendations = report["findings"]["recommendations"]

          critical_count = sum(1 for r in recommendations if r["priority"] == "CRITICAL")
          high_count = sum(1 for r in recommendations if r["priority"] == "HIGH")

          with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
              f.write(f"critical-count={critical_count}\n")
              f.write(f"high-count={high_count}\n")
          EOF

      - name: Generate PR comment
        run: |
          python3 scripts/dev/generate_completeness_comment.py \
            --input dev-only/REPO_COMPLETENESS_ANALYSIS.json \
            --output pr-comment.md

      - name: Post or update PR comment
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const comment = fs.readFileSync('pr-comment.md', 'utf8');

            const { data: comments } = await github.rest.issues.listComments({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
            });

            const botComment = comments.find(c =>
              c.user.type === 'Bot' &&
              c.body.includes('Documentation Completeness Analysis')
            );

            if (botComment) {
              await github.rest.issues.updateComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                comment_id: botComment.id,
                body: comment
              });
            } else {
              await github.rest.issues.createComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                issue_number: context.issue.number,
                body: comment
              });
            }

      - name: Quality gate evaluation
        id: gate
        run: |
          python3 << 'EOF'
          import json
          import os
          import sys
          from pathlib import Path

          report = json.loads(Path("dev-only/REPO_COMPLETENESS_ANALYSIS.json").read_text())
          recommendations = report["findings"]["recommendations"]

          critical_count = sum(1 for r in recommendations if r["priority"] == "CRITICAL")
          high_count = sum(1 for r in recommendations if r["priority"] == "HIGH")

          # Quality gate thresholds
          MAX_CRITICAL = 0
          MAX_HIGH = 10

          status = "success"

          if critical_count > MAX_CRITICAL:
              print(f"❌ Quality gate FAILED: {critical_count} CRITICAL issues (max: {MAX_CRITICAL})")
              status = "failure"
          elif high_count > MAX_HIGH:
              print(f"⚠️ Quality gate WARNING: {high_count} HIGH issues (max: {MAX_HIGH})")
              status = "failure"
          else:
              print(f"✅ Quality gate PASSED")

          with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
              f.write(f"status={status}\n")

          if status == "failure":
              sys.exit(1)
          EOF

      - name: Upload analysis report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: completeness-analysis-${{ github.event.pull_request.number }}
          path: dev-only/REPO_COMPLETENESS_ANALYSIS.json
          retention-days: 90

      - name: Track trends
        if: github.event.pull_request.base.ref == 'main'
        run: |
          # Store historical data for trend analysis
          mkdir -p .github/completeness-history
          cp dev-only/REPO_COMPLETENESS_ANALYSIS.json \
             .github/completeness-history/pr-${{ github.event.pull_request.number }}.json

      - name: Set commit status
        if: always()
        uses: actions/github-script@v7
        with:
          script: |
            const status = '${{ steps.gate.outputs.status }}';
            const criticalCount = '${{ steps.analyze.outputs.critical-count }}';
            const highCount = '${{ steps.analyze.outputs.high-count }}';

            const description = status === 'success'
              ? `Quality gate passed (${criticalCount} critical, ${highCount} high)`
              : `Quality gate failed (${criticalCount} critical, ${highCount} high)`;

            await github.rest.repos.createCommitStatus({
              owner: context.repo.owner,
              repo: context.repo.repo,
              sha: context.payload.pull_request.head.sha,
              state: status,
              target_url: `${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`,
              description: description,
              context: 'Documentation Quality Gate'
            });
```

**Features:**
- ✅ Runs analyzer
- 💬 Posts PR comment with results
- 🚫 Blocks PRs with CRITICAL issues
- 📈 Tracks trends over time
- 📊 Sets commit status
- 📦 Uploads artifacts

---

## GitLab CI Integration

**File:** `.gitlab-ci.yml`

```yaml
stages:
  - analyze
  - report
  - gate

completeness-analyze:
  stage: analyze
  image: python:3.11
  before_script:
    - pip install -r requirements-dev.txt
  script:
    - python3 scripts/dev/analyze_repo_completeness.py
  artifacts:
    paths:
      - dev-only/REPO_COMPLETENESS_ANALYSIS.json
    expire_in: 30 days
  only:
    - merge_requests
  changes:
    - scripts/**/*.py
    - docs/**/*.md
    - README.md
    - CLAUDE.md

completeness-comment:
  stage: report
  image: python:3.11
  dependencies:
    - completeness-analyze
  script:
    - |
      python3 << 'EOF'
      import json
      import os
      from pathlib import Path

      report = json.loads(Path("dev-only/REPO_COMPLETENESS_ANALYSIS.json").read_text())

      # Generate markdown comment
      comment = "## Documentation Completeness Analysis\n\n"
      # ... (same as GitHub Actions example)

      # Post to MR via GitLab API
      import requests

      gitlab_api = os.environ['CI_API_V4_URL']
      project_id = os.environ['CI_PROJECT_ID']
      mr_iid = os.environ['CI_MERGE_REQUEST_IID']
      token = os.environ['GITLAB_TOKEN']

      url = f"{gitlab_api}/projects/{project_id}/merge_requests/{mr_iid}/notes"
      headers = {"PRIVATE-TOKEN": token}
      data = {"body": comment}

      requests.post(url, headers=headers, json=data)
      EOF
  only:
    - merge_requests
  variables:
    GITLAB_TOKEN: $GITLAB_TOKEN  # Set in CI/CD settings

completeness-gate:
  stage: gate
  image: python:3.11
  dependencies:
    - completeness-analyze
  script:
    - |
      python3 << 'EOF'
      import json
      import sys
      from pathlib import Path

      report = json.loads(Path("dev-only/REPO_COMPLETENESS_ANALYSIS.json").read_text())
      recommendations = report["findings"]["recommendations"]

      critical_count = sum(1 for r in recommendations if r["priority"] == "CRITICAL")

      if critical_count > 0:
          print(f"❌ Quality gate FAILED: {critical_count} CRITICAL issues")
          sys.exit(1)
      else:
          print("✅ Quality gate PASSED")
      EOF
  only:
    - merge_requests
```

---

## Local Pre-Commit Hook

**File:** `.pre-commit-config.yaml`

Add to existing pre-commit configuration:

```yaml
repos:
  # ... existing hooks ...

  - repo: local
    hooks:
      - id: completeness-check
        name: Documentation Completeness Check
        entry: python3 scripts/dev/analyze_repo_completeness.py
        language: system
        pass_filenames: false
        files: '^(scripts/.*\.py|docs/.*\.md|README\.md|CLAUDE\.md)$'
        always_run: false  # Only run when relevant files change
```

**Install:**
```bash
pre-commit install
```

**Usage:**
```bash
# Runs automatically on git commit when relevant files change
git commit -m "feat: add new feature"

# Or run manually
pre-commit run completeness-check --all-files
```

---

## Configuration Options

### Customizing Quality Gates

Edit thresholds in workflow files:

```python
# Quality gate thresholds
MAX_CRITICAL = 0   # Change to allow some CRITICAL issues
MAX_HIGH = 10      # Adjust based on project size
MAX_MEDIUM = 30    # Add MEDIUM threshold
MAX_TOTAL = 50     # Overall issue limit
```

### Customizing Analyzer Behavior

Modify `scripts/dev/analyze_repo_completeness.py`:

```python
class RepositoryAnalyzer:
    def __init__(self, repo_root: Path):
        self.repo_root = repo_root

        # Customize exclusions
        self.exclude_patterns = [
            "tests/*",       # Exclude test files
            "scripts/dev/*", # Exclude dev scripts
            "*_test.py",     # Exclude test files by naming
        ]

        # Customize priority thresholds
        self.priority_thresholds = {
            "CRITICAL": lambda count: count > 0,          # Any undocumented CLI commands
            "HIGH": lambda count: count > 5,              # More than 5 missing docstrings
            "MEDIUM": lambda count: count > 10,           # More than 10 test gaps
            "LOW": lambda count: count > 20,              # More than 20 minor issues
        }
```

---

## Interpreting Results

### Priority Levels

| Priority | Severity | Examples | Action Required |
|----------|----------|----------|-----------------|
| **CRITICAL** | Blocking | Undocumented CLI commands, major inconsistencies | Fix before merge |
| **HIGH** | Important | Missing function docstrings, outdated examples | Fix soon (within sprint) |
| **MEDIUM** | Nice to have | Test coverage gaps, minor drift | Fix eventually |
| **LOW** | Optional | Style inconsistencies, minor improvements | Low priority |

### Finding Categories

**Undocumented Features:**
- Public APIs (functions, classes) not mentioned in docs
- New CLI commands without documentation
- **Fix:** Add docstrings + update USER_GUIDE.md

**Doc-Code Drift:**
- Documentation describes feature differently than implementation
- Examples in docs use outdated API
- **Fix:** Update documentation to match current code

**Missing Documentation:**
- Modules without README
- CLI commands without help text
- Configuration options without examples
- **Fix:** Add missing documentation files

**Configuration Drift:**
- jmo.yml examples don't match actual usage
- Documented flags not in current CLI
- **Fix:** Synchronize config examples with code

**Test Gaps:**
- Features without test coverage
- Untested code paths
- **Fix:** Write tests or document why untested

---

## Best Practices

### 1. **Run Locally Before Pushing**

```bash
# Check before creating PR
make analyze-completeness

# Review output
cat dev-only/REPO_COMPLETENESS_ANALYSIS.json | jq '.findings.recommendations[] | select(.priority == "CRITICAL")'
```

### 2. **Address Issues by Priority**

Workflow:
1. Fix all **CRITICAL** issues (blocks merge)
2. Fix **HIGH** issues before next release
3. Track **MEDIUM/LOW** issues in backlog

### 3. **Update Documentation Incrementally**

Don't try to fix everything at once:
- Fix issues related to your PR
- Leave other issues for separate PRs
- Track improvements over time

### 4. **Use Analyzer for Code Review**

Reviewers can check:
```bash
# Download artifact from PR
gh run download <run-id> -n completeness-analysis

# Review findings
cat REPO_COMPLETENESS_ANALYSIS.json | jq '.findings'
```

### 5. **Monitor Trends Over Time**

Track metrics across PRs:
```bash
# Store historical data
mkdir -p .github/completeness-history
cp dev-only/REPO_COMPLETENESS_ANALYSIS.json \
   .github/completeness-history/$(date +%Y-%m-%d).json

# Plot trends
python3 scripts/dev/plot_completeness_trends.py
```

### 6. **Customize for Your Project**

Adjust thresholds based on:
- Project size (large projects = higher thresholds)
- Team size (small teams = lower thresholds)
- Maturity (mature projects = stricter gates)

### 7. **Integrate with Other Tools**

Combine with:
- **Codecov:** Link test gaps to coverage reports
- **SonarQube:** Align with code quality metrics
- **Dependabot:** Check docs when dependencies update

---

## Example: Full Integration

**Step-by-step setup:**

1. **Add workflow file:**
   ```bash
   cp docs/examples/completeness-full.yml .github/workflows/
   ```

2. **Enable branch protection:**
   - Settings → Branches → Add rule
   - Require status checks: **Documentation Quality Gate**

3. **Configure thresholds:**
   - Edit workflow: Adjust MAX_CRITICAL, MAX_HIGH
   - Commit changes

4. **Test on PR:**
   ```bash
   git checkout -b test-completeness
   # Make changes to docs or code
   git commit -m "test: completeness integration"
   git push origin test-completeness
   # Open PR, observe workflow
   ```

5. **Iterate based on feedback:**
   - Review PR comments
   - Adjust thresholds if too strict/lenient
   - Add custom exclusions if needed

---

## Troubleshooting

**Issue:** Workflow fails with "Python module not found"
- **Fix:** Ensure `requirements-dev.txt` is committed and up-to-date

**Issue:** PR comment not posted
- **Fix:** Check `pull-requests: write` permission in workflow

**Issue:** Quality gate too strict
- **Fix:** Adjust MAX_CRITICAL/MAX_HIGH thresholds

**Issue:** Analyzer runs on every file change
- **Fix:** Add `paths` filter to only trigger on relevant files

**Issue:** False positives in findings
- **Fix:** Customize `exclude_patterns` in analyzer or add exceptions

---

## Next Steps

1. **Start with basic PR check** (non-blocking)
2. **Add PR comments** for visibility
3. **Enable quality gate** once team is comfortable
4. **Track trends** for continuous improvement
5. **Customize** based on team feedback

For questions or issues, open a GitHub discussion or issue.

---

**Documentation Quality Gate keeps your docs in sync with your code! 📚✨**
