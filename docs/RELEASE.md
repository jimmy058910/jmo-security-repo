# Release Guide

Remember to update CHANGELOG.md with user-facing changes.

This project publishes to PyPI via GitHub Actions on git tags of the form `v*` using Trusted Publishers (OIDC).

## Prerequisites

- **No PyPI API token required!** This repo uses Trusted Publishers (OIDC) for tokenless publishing.
- Ensure the repository is configured as a Trusted Publisher in PyPI settings (one-time setup).
- Ensure tests are green and coverage passes locally (≥85% required).
- Update `CHANGELOG.md` with all user-facing changes from the "Unreleased" section.

## Pre-Release Checklist

**🔴 CRITICAL FIRST STEP: Update ALL security tools to latest versions**

1. **Update ALL security tools (MANDATORY - enforced by CI):**

   ```bash
   # Check for available updates
   python3 scripts/dev/update_versions.py --check-latest

   # If updates found, update all tools
   python3 scripts/dev/update_versions.py --update-all  # Update versions.yaml
   python3 scripts/dev/update_versions.py --sync         # Sync Dockerfiles

   # Commit tool updates
   git add versions.yaml Dockerfile* scripts/dev/install_tools.sh
   git commit -m "deps(tools): update all to latest before vX.Y.Z

   Updated all security tools before release vX.Y.Z:
   - semgrep, checkov, trivy, trufflehog, syft, etc.

   See: python3 scripts/dev/update_versions.py --report"

   # Verify all tools current
   python3 scripts/dev/update_versions.py --check-latest
   # Expected output: [ok] All tools are up to date
   ```

   **Why this matters:**
   - Outdated tools miss security vulnerabilities (semgrep 41 versions behind = 200+ missing rules)
   - Users expect latest security tools in fresh releases
   - CI will BLOCK release if tools are outdated (pre-release-check job)

2. **Run full test suite locally:**

   ```bash
   make test
   # or
   pytest -q --maxfail=1 --disable-warnings --cov=. --cov-report=term-missing --cov-fail-under=85
   ```

3. **Verify linting and formatting:**

   ```bash
   make lint
   make fmt
   make pre-commit-run
   ```

4. **Review documentation:**
   - CHANGELOG.md updated with "Unreleased" changes moved to new version section
   - README.md reflects latest features
   - QUICKSTART.md is up-to-date
   - docs/USER_GUIDE.md includes new features

5. **Validate README consistency (PyPI + Docker Hub sync check):**

   ```bash
   make validate-readme
   ```

   **Why:** PyPI and Docker Hub render READMEs from uploaded packages/API, not from GitHub. This check detects:
   - **PyPI:** Missing/outdated badges, Docker namespace mismatches, stale content
   - **Docker Hub:** Old namespace in DOCKER_HUB_README.md, outdated versions, sync configuration issues
   - **GHCR:** Auto-syncs from GitHub (no check needed)

   **Fix:** If inconsistencies found:
   - **PyPI issues:** Resolved automatically when you publish the new release (uses current README.md)
   - **Docker Hub issues:** Update DOCKER_HUB_README.md before release, ensure DOCKERHUB_ENABLED=true

   **Documentation:** See [dev-only/README_CONSISTENCY.md](../dev-only/README_CONSISTENCY.md) for complete guide.

5. **Verify CI is green:**
   - Check GitHub Actions: all tests passing on ubuntu-latest and macos-latest
   - Coverage uploaded to Codecov successfully

## WSL (Windows Subsystem for Linux) Validation

**Frequency:** Every minor release (vX.Y.0)

**Environment:** WSL2 with Ubuntu 22.04 or later

### WSL Prerequisites

1. **WSL2 Installation:**

   ```powershell
   # Windows PowerShell (Administrator)
   wsl --install Ubuntu-22.04
   wsl --set-default-version 2
   ```

2. **Docker Desktop Integration:**
   - Install Docker Desktop for Windows
   - Enable "Use WSL 2 based engine" in settings
   - Enable "Ubuntu-22.04" in Resources → WSL Integration

3. **Git Configuration:**

   ```bash
   # Inside WSL
   git config --global core.autocrlf input  # Prevent CRLF issues
   ```

### Test Cases

#### TC1: Installation

**Goal:** Verify JMo Security installs correctly in WSL

```bash
# Clone repo to WSL filesystem (NOT /mnt/c/)
cd ~
git clone https://github.com/jimmy058910/jmo-security-repo.git
cd jmo-security-repo

# Install dev dependencies
make dev-deps

# Install external tools
make tools

# Verify environment
make verify-env
```

**Success Criteria:**

- [ ] All dependencies install without errors
- [ ] `make verify-env` shows all tools detected
- [ ] No path-related errors (e.g., "cannot find /mnt/c/...")

**Known Issues:**

- WSL1 not supported (must use WSL2)
- File permissions may require `chmod +x scripts/cli/*.py`
- Windows paths (`C:\...`) not supported; use WSL paths (`/home/...`)

#### TC2: Basic Scan

**Goal:** Verify native CLI scanning works

```bash
# Run fast profile scan
jmotools fast --repo .

# Verify results generated
ls -lh results/summaries/
cat results/summaries/SUMMARY.md
```

**Success Criteria:**

- [ ] Scan completes without path errors
- [ ] Results written to `results/summaries/`
- [ ] `dashboard.html` opens in Windows browser

**Troubleshooting:**

```bash
# If path errors occur, check line endings
file scripts/cli/jmo.py  # Should show "ASCII text" (NOT "with CRLF")

# Fix line endings if needed
find . -name "*.py" -exec dos2unix {} \;
```

#### TC3: Docker Mode

**Goal:** Verify Docker integration works

```bash
# Test Docker connectivity
docker run --rm hello-world

# Run scan in Docker
docker run --rm -v $(pwd):/repo jmo-security:latest scan --repo /repo --profile-name fast
```

**Success Criteria:**

- [ ] Docker daemon accessible from WSL
- [ ] Volume mount works (`/repo` accessible inside container)
- [ ] Results written back to WSL filesystem

**Known Issues:**

- Docker Desktop must be running in Windows
- Volume mounts may be slow (WSL filesystem I/O)
- Use WSL paths, not Windows paths (`/home/...` not `/mnt/c/...`)

#### TC4: Line Endings

**Goal:** Verify CRLF handling doesn't break scripts

```bash
# Check Git config
git config --get core.autocrlf  # Should be "input" or "false" (NOT "true")

# Verify Python scripts have LF endings
file scripts/cli/jmo.py  # Should show "ASCII text"

# Verify shell scripts have LF endings
file scripts/dev/install_tools.sh  # Should show "Bourne-Again shell script"
```

**Success Criteria:**

- [ ] No CRLF line endings in Python or shell scripts
- [ ] Scripts execute without `^M` errors

**Fix If Needed:**

```bash
# Configure Git to not convert line endings
git config --global core.autocrlf input

# Re-checkout repository
git checkout --force

# Verify fixed
file scripts/cli/jmo.py
```

#### TC5: Results Accessibility

**Goal:** Verify results accessible from Windows

```bash
# Generate dashboard
jmotools fast --repo .

# Open dashboard in Windows browser
# Option 1: Use WSL path in Windows browser
explorer.exe results/summaries/dashboard.html

# Option 2: Copy to Windows filesystem
cp results/summaries/dashboard.html /mnt/c/Users/$(whoami)/Desktop/

# Open from Desktop in Windows browser
```

**Success Criteria:**

- [ ] Dashboard opens in Windows browser
- [ ] Interactive features work (filtering, sorting)
- [ ] No path-related errors in browser console

#### TC6: Symlinks

**Goal:** Verify symlink handling works

```bash
# Create symlink to config
ln -s jmo.yml jmo-link.yml

# Run scan using symlinked config
jmo scan --config jmo-link.yml --repo . --results-dir ./results-symlink-test

# Verify results generated
ls results-symlink-test/
```

**Success Criteria:**

- [ ] Symlinks resolve correctly
- [ ] No "cannot find file" errors
- [ ] Results written to expected directory

#### TC7: Performance Comparison

**Goal:** Verify WSL performance comparable to native Linux

```bash
# Time a fast scan
time jmotools fast --repo .

# Expected: Within 20% of native Linux performance
# Fast profile: 5-8 minutes (WSL should be 6-10 minutes)
```

**Success Criteria:**

- [ ] Scan duration within 20% of native Linux
- [ ] No excessive disk I/O delays

**Known Issues:**

- WSL2 I/O may be slower for large repositories
- Recommend cloning to WSL filesystem (`/home/...`) not Windows (`/mnt/c/...`)

### WSL Validation Summary

**Checklist Completion:**

- [ ] TC1: Installation (✅ / ❌)
- [ ] TC2: Basic Scan (✅ / ❌)
- [ ] TC3: Docker Mode (✅ / ❌)
- [ ] TC4: Line Endings (✅ / ❌)
- [ ] TC5: Results Accessibility (✅ / ❌)
- [ ] TC6: Symlinks (✅ / ❌)
- [ ] TC7: Performance (✅ / ❌)

**Issues Found:**

- Issue 1: [Description]
- Issue 2: [Description]

**Resolution:**

- All issues resolved: ✅ / ❌
- Blocked issues documented in ROADMAP.md: ✅ / ❌

**Sign-Off:**

- Tester: [Name]
- Date: [YYYY-MM-DD]
- WSL Version: [Output of `wsl --version`]
- Ubuntu Version: [Output of `lsb_release -a`]
- Docker Desktop Version: [Output of `docker --version`]

### WSL Troubleshooting Guide

**Problem:** "cannot find /mnt/c/..." errors

**Solution:** Clone repo to WSL filesystem (`/home/...`), not Windows filesystem

**Problem:** "^M: bad interpreter" errors

**Solution:** Fix line endings:

```bash
git config --global core.autocrlf input
git checkout --force
dos2unix scripts/**/*.sh
```

**Problem:** Docker volume mounts not working

**Solution:** Verify Docker Desktop WSL integration enabled for Ubuntu distribution

**Problem:** Slow I/O performance

**Solution:** Use WSL filesystem (`/home/...`), not Windows filesystem (`/mnt/c/...`)

**Problem:** `explorer.exe` not opening files

**Solution:** Use full Windows path or copy to Windows filesystem first:

```bash
cp results/summaries/dashboard.html /mnt/c/Users/$(whoami)/Desktop/
```

## macOS Docker Validation

**Frequency:** Every minor release (vX.Y.0)

**Environment:** macOS 12+ with Docker Desktop

### macOS Prerequisites

1. **Docker Desktop Installation:**

   ```bash
   # Install via Homebrew
   brew install --cask docker

   # Or download from https://www.docker.com/products/docker-desktop
   ```

2. **Docker Daemon Running:**

   ```bash
   # Verify Docker is running
   docker info

   # Expected: Server version, OS/Arch: linux/arm64 or linux/amd64
   ```

### Test Cases (macOS Docker)

#### TC1: Docker Image Availability

**Goal:** Verify Docker images work on macOS

```bash
# Pull jmo-security image
docker pull jmogaming/jmo-security:latest

# Test basic help command
docker run --rm jmogaming/jmo-security:latest --help

# Expected: jmo CLI help output
```

**Success Criteria:**

- [ ] Image pulls successfully
- [ ] Help command works
- [ ] No platform warnings (should work on both Intel and Apple Silicon)

#### TC2: Volume Mount Handling

**Goal:** Verify macOS volume mounts work correctly

```bash
# Create test repository
mkdir -p ~/tmp/jmo-test
cd ~/tmp/jmo-test
echo "# Test" > README.md

# Run scan with volume mount
docker run --rm \
  -v $(pwd):/repo \
  jmogaming/jmo-security:latest \
  scan --repo /repo --profile-name fast --allow-missing-tools

# Verify results created
ls results/
```

**Success Criteria:**

- [ ] Volume mount works (`/repo` accessible inside container)
- [ ] Results written back to macOS filesystem
- [ ] No permission errors

**Known Issues:**

- Docker Desktop on Apple Silicon may show platform warnings (safe to ignore)
- Volume mounts from `/Users/...` work, `/tmp` may have permission issues

#### TC3: Network Access

**Goal:** Verify container can access internet (for tool updates)

```bash
# Test network access
docker run --rm jimmy058910/jmo-security:latest bash -c "curl -I https://github.com"

# Expected: HTTP 200 response
```

**Success Criteria:**

- [ ] Container has internet access
- [ ] DNS resolution works
- [ ] No proxy configuration needed

#### TC4: Performance Comparison

**Goal:** Verify macOS Docker performance is acceptable

```bash
# Time a fast scan
time docker run --rm \
  -v $(pwd):/repo \
  jmogaming/jmo-security:latest \
  scan --repo /repo --profile-name fast --allow-missing-tools

# Expected: Within 30% of Linux Docker performance
```

**Success Criteria:**

- [ ] Scan duration within 30% of Linux baseline
- [ ] No excessive disk I/O delays

**Known Issues:**

- Apple Silicon (M1/M2/M3) may be faster than Intel for some operations
- Docker Desktop may be slower than native Linux (expected)

#### TC5: Multi-Variant Testing

**Goal:** Verify all Docker image variants work on macOS

```bash
# Test full variant
docker run --rm jmogaming/jmo-security:latest --help

# Test slim variant
docker run --rm jmogaming/jmo-security:slim --help

# Test alpine variant
docker run --rm jmogaming/jmo-security:alpine --help
```

**Success Criteria:**

- [ ] All 3 variants work
- [ ] No platform-specific errors
- [ ] Help commands succeed for all variants

### macOS Validation Summary

**Checklist Completion:**

- [ ] TC1: Image Availability (✅ / ❌)
- [ ] TC2: Volume Mounts (✅ / ❌)
- [ ] TC3: Network Access (✅ / ❌)
- [ ] TC4: Performance (✅ / ❌)
- [ ] TC5: Multi-Variant (✅ / ❌)

**Issues Found:**

- Issue 1: [Description]
- Issue 2: [Description]

**Sign-Off:**

- Tester: [Name]
- Date: [YYYY-MM-DD]
- macOS Version: [Output of `sw_vers`]
- Docker Desktop Version: [Output of `docker --version`]
- Architecture: [Intel / Apple Silicon]

### macOS Troubleshooting

**Problem:** "no matching manifest for platform" error

**Solution:** Docker image may not support Apple Silicon, use Rosetta:

```bash
docker run --rm --platform linux/amd64 jmogaming/jmo-security:latest --help
```

**Problem:** Permission denied on volume mounts

**Solution:** Grant Docker Desktop access to `/Users` in macOS Privacy settings

**Problem:** Slow performance

**Solution:** Ensure "Use Virtualization Framework" enabled in Docker Desktop settings

## Step-by-Step Release Process

1. **Bump version in `pyproject.toml`** (for example, `0.4.0`):

   ```toml
   [project]
   name = "jmo-security"
   version = "0.4.0"  # Update this line
   ```

2. **Update CHANGELOG.md:**
   - Move "Unreleased" section content to a new version section:

     ```markdown
     ## 0.4.0 (2025-10-15)

     Highlights:

     - [Content from Unreleased section]

     ## Unreleased

     [Empty for now]
     ```

3. **Commit the version bump and changelog:**

   ```bash
   git add pyproject.toml CHANGELOG.md
   git commit -m "release: v0.4.0"
   ```

4. **Create and push the tag:**

   ```bash
   git tag v0.4.0
   git push origin main
   git push origin v0.4.0
   ```

5. **Monitor the Release workflow:**
   - Go to Actions tab in GitHub
   - The `Release (PyPI)` workflow will automatically:
     - Build the package
     - Publish to PyPI using Trusted Publishers (OIDC)
     - No token/secret required!

6. **Verify the release:**

   ```bash
   # Wait a few minutes for PyPI to update, then:
   pip install --upgrade jmo-security==0.4.0
   jmo --version
   jmo --help
   jmotools --help
   ```

## Troubleshooting

**Problem:** Release workflow fails with "Trusted Publisher authentication failed"

- **Solution:** Verify the repository is configured as a Trusted Publisher in PyPI settings
- **Check:** <https://pypi.org/manage/account/publishing/> (must match org/repo/workflow)

**Problem:** Tests fail in CI but pass locally

- **Solution:** Check matrix differences (Ubuntu vs macOS, Python 3.10 vs 3.11 vs 3.12)
- **Check:** Run `make test` with different Python versions locally

**Problem:** Coverage below 85%

- **Solution:** Add tests for uncovered code paths
- **Check:** Run `pytest --cov=. --cov-report=term-missing` to see gaps

## Notes

- The package exposes the `jmo` and `jmotools` console scripts.
- Coverage reports are uploaded to Codecov as part of the tests workflow (tokenless OIDC).
- License is defined via SPDX string in `pyproject.toml` and the `LICENSE` file is included in the distribution.
- CI enforces: tests passing, coverage ≥85%, pre-commit checks, reproducible dev deps.

## Post-Release

1. **Announce the release:**
   - Update project homepage (jmotools.com) if applicable
   - Post to relevant communities/channels
   - Tweet/share on social media

2. **Monitor for issues:**
   - Watch GitHub issues for bug reports
   - Check PyPI download stats
   - Monitor Codecov for coverage trends

---

**Documentation Hub:** [docs/index.md](index.md) | **Project Home:** [README.md](../README.md)
