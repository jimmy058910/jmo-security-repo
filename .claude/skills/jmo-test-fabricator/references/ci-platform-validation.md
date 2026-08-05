# CI/CD and Platform Validation Patterns

## CI/CD Documentation Patterns

Create CI/CD examples and documentation for different platforms.

### When to Create CI Examples

Create CI/CD examples when:

- Adding support for new CI platform (GitLab CI, Jenkins, CircleCI, etc.)
- Documenting multi-target scanning workflows
- Showing profile-based configuration in CI
- Demonstrating failure thresholds (--fail-on)

### GitLab CI Example Structure

```yaml
# docs/examples/.gitlab-ci.yml
variables:
  JMO_PROFILE: "balanced"
  JMO_FAIL_ON: "HIGH"

stages:
  - security
  - compliance

.jmo_scan_template:
  image: jimmy058910/jmo-security:slim
  artifacts:
    when: always
    paths:
      - results/
    reports:
      sast: results/summaries/findings.sarif
    expire_in: 30 days

security:scan:
  extends: .jmo_scan_template
  stage: security
  script:
    - jmo scan --repo . --profile-name ${JMO_PROFILE} --results-dir results
    - jmo report results --fail-on ${JMO_FAIL_ON}
```

### Jenkins Example Structure

```groovy
// docs/examples/Jenkinsfile
pipeline {
    agent any
    environment {
        JMO_IMAGE = 'jimmy058910/jmo-security:slim'
    }
    stages {
        stage('Security Scan') {
            agent {
                docker {
                    image "${JMO_IMAGE}"
                    args '-v $WORKSPACE:/workspace'
                }
            }
            steps {
                sh 'jmo scan --repo . --results-dir results'
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'results/**/*'
            publishHTML([reportDir: 'results/summaries', reportFiles: 'dashboard.html'])
        }
    }
}
```

### Quick Start Documentation Pattern

When adding CI examples, also add quick start section to USER_GUIDE.md:

```markdown
#### [Platform] Quick Start

**See [docs/examples/[file]] for complete configuration.**

Quick example:

[Minimal 15-20 line example with inline comments]

**Key features:**

- Docker-based scanning (zero installation)
- Profile-based configuration
- Artifact archiving
- Multi-target support
```

### CI Example Validation Checklist

- [ ] YAML/Groovy syntax valid (yamllint, groovylint)
- [ ] All paths use environment variables (no hardcoded paths)
- [ ] Examples tested locally before committing
- [ ] Quick start added to USER_GUIDE.md
- [ ] Markdownlint passes on all docs

---

## Platform Validation Documentation Patterns

Create manual validation checklists for platform-specific testing.

### When to Create Validation Checklists

Create manual validation checklists for:

- Platform-specific testing (WSL, macOS, Windows)
- Docker variant testing (full/slim/alpine)
- Installation validation (pip, Docker, native tools)
- Performance comparison baselines

### Checklist Structure Template

````markdown
## [Platform] Validation

**Frequency:** [Every release / Every minor release / Quarterly]

**Environment:** [Platform requirements]

### [Platform] Prerequisites

1. **[Requirement 1]:**

   ```bash
   # Installation command
   ```

1. **[Requirement 2]:**

   ```bash
   # Verification command
   # Expected output
   ```

### Test Cases ([Platform])

#### TC[N]: [Test Name]

**Goal:** [What this test validates]

```bash
# Step-by-step commands with expected outputs
```

**Success Criteria:**

- [ ] [Criterion 1]
- [ ] [Criterion 2]

**Known Issues:**

- [Issue description and workaround]

### [Platform] Validation Summary

**Checklist Completion:**

- [ ] TC1: [Name]
- [ ] TC2: [Name]

**Issues Found:**

- Issue 1: [Description]

**Sign-Off:**

- Tester: [Name]
- Date: [YYYY-MM-DD]
- [Platform-specific version info]

### [Platform] Troubleshooting

**Problem:** [Common issue]

**Solution:** [Fix or workaround]
````

### Real-World Example: WSL Validation

````markdown
## WSL (Windows Subsystem for Linux) Validation

**Frequency:** Every minor release (vX.Y.0)

**Environment:** Windows 10/11 with WSL2

### WSL Prerequisites

1. **WSL2 Installation:**

   ```bash
   # Enable WSL2
   wsl --install

   # Verify version
   wsl --list --verbose
   # Expected: VERSION = 2
   ```

#### TC1: Installation Validation

**Goal:** Verify JMo installs correctly in WSL

```bash
# Install in WSL
pip install jmo-security

# Verify installation
jmo --help
# Expected: jmo CLI help output
```

**Success Criteria:**

- [ ] pip install succeeds
- [ ] jmo command available
- [ ] No DLL load errors
````

---

## Integration with CI/CD

### GitHub Actions Workflow

```yaml
# .github/workflows/ci.yml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - name: Install dependencies
        run: |
          pip install -e ".[dev]"
      - name: Run tests with coverage
        run: |
          pytest tests/adapters/ \
            --cov=scripts/core/adapters \
            --cov-fail-under=85 \
            --cov-report=term-missing
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: pytest-adapter-coverage
        name: Pytest Adapter Coverage
        entry: pytest tests/adapters/ --cov=scripts/core/adapters --cov-fail-under=85
        language: system
        pass_filenames: false
        always_run: true
```

### CI-Specific Test Considerations

**Skip Slow Tests in PR Checks:**

```yaml
# .github/workflows/ci.yml
- name: Fast tests (PR checks)
  run: pytest tests/unit tests/adapters -m "not slow"

- name: Full tests (nightly)
  if: github.event_name == 'schedule'
  run: pytest tests/ --timeout=600
```

**Mark Slow Tests:**

```python
@pytest.mark.slow
def test_deep_profile_full_scan(tmp_path):
    """Complete deep profile scan (30-60s)."""
    # Only runs in nightly CI, skipped in PR checks
```
