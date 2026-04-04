# Installation and Configuration Reference

Tool installation configuration, version pinning patterns, and Dockerfile patterns for CI.

---

## Tool Version Pinning

### GitHub Actions

```yaml
# Pin action versions to specific commits for security
- uses: actions/checkout@v4          # Major version pin (recommended)
- uses: docker/metadata-action@v5     # Semver tag
- uses: actions/github-script@v7      # For custom scripts

# Pin pip version to avoid breaking changes
- run: python -m pip install --upgrade 'pip<25.3'
```

### Pre-commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/psf/black
    rev: 24.10.0     # Pin to exact version
    hooks:
      - id: black

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.7.4      # Pin to exact version
    hooks:
      - id: ruff
        args: [--fix, --exit-non-zero-on-fix]
```

### Python Dependencies

```bash
# requirements-dev.in - specify minimum versions
pytest>=8.0.0
pytest-cov>=4.1.0
black>=24.0.0
ruff>=0.7.0

# Compile to lock file (deterministic)
make deps-compile
# Produces requirements-dev.txt with exact pinned versions
```

---

## Dockerfile Patterns

### Multi-Stage Builds

```dockerfile
# Stage 1: Build
FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements*.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Stage 2: Runtime
FROM python:3.12-slim AS runtime
WORKDIR /scan
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY . .
```

### Ubuntu 24.04 Specifics

```dockerfile
# PEP 668: All pip install needs --break-system-packages
RUN pip install --break-system-packages -r requirements.txt

# DON'T upgrade pip on Ubuntu 24.04 (causes RECORD file error)
# RUN pip install --upgrade pip  # BAD - causes "Cannot uninstall pip"

# UID 1000 conflict: Ubuntu 24.04 pre-creates 'ubuntu' user
RUN userdel -r ubuntu && useradd -u 1000 jmo
```

### Tool Installation in Docker

```dockerfile
# Shellcheck: Use GitHub releases binary (not apt)
RUN set -eux && \
    SHELLCHECK_VERSION="v0.10.0" && \
    curl -fsSL "https://github.com/koalaman/shellcheck/releases/download/${SHELLCHECK_VERSION}/shellcheck-${SHELLCHECK_VERSION}.linux.x86_64.tar.xz" \
    | tar -xJf - --strip-components=1 -C /usr/local/bin shellcheck-${SHELLCHECK_VERSION}/shellcheck

# Note: fast/slim/balanced Dockerfiles need xz-utils for .tar.xz extraction
# deep variant has it via build-essential transitive dependency
RUN apt-get install -y --no-install-recommends xz-utils
```

---

## CI Workflow Configuration

### ci.yml Job Dependencies

```yaml
jobs:
  quick-checks:      # 2-3 min - runs first
    ...

  test-matrix:       # 10-15 min - waits for quick-checks
    needs: quick-checks
    strategy:
      fail-fast: true
      matrix:
        os: [ubuntu-latest, macos-latest]
        python-version: ["3.10", "3.11", "3.12"]

  lint-full:         # 5-10 min - nightly only
    if: github.event_name == 'schedule'
    ...
```

### release.yml Docker Tags

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
```

### Permissions Block

```yaml
permissions:
  contents: read          # Checkout code
  packages: write         # Push Docker images to ghcr.io
  security-events: write  # Upload SARIF to Security tab
  id-token: write         # OIDC token for Trusted Publishers
  pull-requests: write    # Comment on PRs with results
```

---

## Local Tool Installation

```bash
# Install actionlint
brew install actionlint  # macOS
# Or download from https://github.com/rhysd/actionlint/releases

# Install yamllint
pip install yamllint

# Install markdownlint
npm install -g markdownlint-cli

# Install shellcheck
brew install shellcheck  # macOS
# Or download from https://github.com/koalaman/shellcheck/releases

# Validate workflows
actionlint .github/workflows/*.yml
yamllint .github/workflows/*.yml
```
