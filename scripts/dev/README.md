# JMo Security Development Tools

This directory contains development and maintenance utilities for the JMo Security project.

## Available Tools

### Repository Completeness Analyzer

**File:** `analyze_repo_completeness.py`

**Purpose:** Detects documentation-code drift and helps contributors find areas needing attention.

**Usage:**

```bash
python3 scripts/dev/analyze_repo_completeness.py

# Or via Makefile:
make analyze-completeness
```

**Output:** `dev-only/REPO_COMPLETENESS_ANALYSIS.json`

**What it checks:**

- **Undocumented features** - Python APIs extracted via AST parsing but not mentioned in documentation
- **Doc-code drift** - Features documented but implementation has changed
- **Missing documentation** - Modules, functions, or CLI commands without docs
- **Configuration inconsistencies** - `jmo.yml` examples vs actual usage patterns
- **Test coverage gaps** - Features without corresponding test suites
- **Documentation inconsistencies** - Conflicts between CLAUDE.md, README.md, and USER_GUIDE.md

**For contributors:**

Run this analyzer before submitting PRs to ensure your changes are properly documented. The tool generates a prioritized list of recommendations (CRITICAL/HIGH/MEDIUM/LOW) to guide documentation updates.

**Example output:**

```
📊 ANALYSIS COMPLETE
================================================================================

📈 Statistics:
  - Python files analyzed: 87
  - Total functions: 342
  - Total classes: 45

🔍 Findings Summary:
  - Undocumented features: 12
  - Doc-code drift issues: 5
  - Missing docs: 8
  - Inconsistencies: 3
  - Config drift: 2
  - Test gaps: 7

💡 Recommendations: 15

  [CRITICAL] Update documentation for new CLI commands
       → 3 commands added but not documented (3 items)

  [HIGH] Add missing function docstrings
       → Public APIs need documentation (8 items)

📄 Full report written to: dev-only/REPO_COMPLETENESS_ANALYSIS.json
```

**Integration into workflow:**

1. **Before submitting PR:**
   ```bash
   make analyze-completeness
   # Review CRITICAL/HIGH priority items
   # Update docs as needed
   ```

2. **Weekly maintenance:**
   - Run analyzer to catch accumulated drift
   - Address high-priority items first
   - Use `jmo-documentation-updater` skill for systematic fixes

3. **Future: CI/CD integration:**
   - Could be added to GitHub Actions to run on PRs
   - Automatically comment on PRs with drift warnings
   - Prevent merging PRs with CRITICAL documentation gaps

---

### Tool Installation Scripts

**File:** `install_tools.sh`

Installs external security scanning tools (semgrep, trivy, checkov, etc.) based on platform detection (Linux/macOS/WSL).

**Usage:**

```bash
make tools
```

---

### Version Management

**File:** `update_versions.py`

Manages tool versions across the project using `versions.yaml` as the single source of truth. See [docs/VERSION_MANAGEMENT.md](../../docs/VERSION_MANAGEMENT.md) for complete guide.

**Usage:**

```bash
# Check current versions
python3 scripts/dev/update_versions.py --report

# Check for available updates
python3 scripts/dev/update_versions.py --check-latest

# Update a specific tool
python3 scripts/dev/update_versions.py --tool trivy --version 0.68.0

# Sync all Dockerfiles with versions.yaml
python3 scripts/dev/update_versions.py --sync
```

---

## Contributing

If you create a new development tool:

1. Add it to this README with usage instructions
2. Add a Makefile target if appropriate
3. Document any dependencies or requirements
4. Include example output if helpful
5. Tag it with `dev-only/` output if it generates local files

For questions or suggestions, open an issue or discussion on GitHub.
