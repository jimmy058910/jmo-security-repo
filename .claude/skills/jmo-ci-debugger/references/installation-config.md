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
# pyproject.toml [dependency-groups] dev - specify minimum versions
pytest>=8.0.0
pytest-cov>=4.1.0
black>=24.0.0
ruff>=0.7.0

# Compile to lock file (deterministic)
make deps-lock
# Produces uv.lock with exact pinned versions (universal, all platforms)
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

Two rules, both learned the hard way (see `.claude/rules/docker.rules.md`,
"Download Hardening Convention"):

1. **Install the extractor before the extraction.** `tar -xJf` shells out to
   `xz`; on a slim base that package is absent, so an extraction step placed
   above the `apt-get install` fails every build.
2. **Never pipe a download straight into `tar`.** `curl` without `-f` exits 0 on
   an HTTP error page, and the pipe hands that HTML to `tar` — the
   "not in gzip format" cycle that broke v1.0.3 nightly smoke tests repeatedly.
   Download to a file, verify, then extract.

```dockerfile
# xz-utils goes in the base package layer, well before any .tar.xz download.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Shellcheck: GitHub releases binary (not apt).
# The version literal is owned by versions.yaml -- never hand-edit it here or in
# a Dockerfile; run `python scripts/dev/update_versions.py --sync`.
RUN SHELLCHECK_VERSION="<from versions.yaml>" && \
    SHELLCHECK_ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "aarch64" || echo "x86_64") && \
    curl -fsSL --retry 3 --retry-delay 5 --retry-all-errors \
      --connect-timeout 30 --max-time 600 \
      "https://github.com/koalaman/shellcheck/releases/download/v${SHELLCHECK_VERSION}/shellcheck-v${SHELLCHECK_VERSION}.linux.${SHELLCHECK_ARCH}.tar.xz" \
      -o /tmp/shellcheck.tar.xz && \
    xz -t /tmp/shellcheck.tar.xz && \
    tar -xJf /tmp/shellcheck.tar.xz -C /tmp && \
    mv /tmp/shellcheck-v${SHELLCHECK_VERSION}/shellcheck /usr/local/bin/shellcheck && \
    chmod +x /usr/local/bin/shellcheck
```

**All four** `Dockerfile.*` variants install `xz-utils` explicitly in that base
layer (`Dockerfile.fast:18`, `.slim:18`, `.balanced:18`, `.deep:19`) — including
`deep`, which does **not** get it transitively from `build-essential`. Read the
real files rather than copying this snippet; they are the source of truth for
the pinned versions and the arch handling.

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

**Declaring any `permissions` block sets every scope you do not list to `none`.**
It is not additive on top of the defaults, so an omission silently removes access
rather than inheriting it — the usual symptom is a 403 from one API call in an
otherwise green job. Grant per job, not workflow-wide, and list only what that
job calls:

```yaml
permissions:
  contents: read          # Checkout code
  packages: write         # Push Docker images to ghcr.io
  security-events: write  # Upload SARIF to Security tab
  id-token: write         # OIDC token for Trusted Publishers
  pull-requests: write    # Comment on PRs with results
  statuses: write         # ONLY if the job calls createCommitStatus (see catalog #13)
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
