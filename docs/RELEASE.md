# Release Guide

Remember to update CHANGELOG.md with user-facing changes.

This project publishes to PyPI via GitHub Actions on git tags of the form `v*` using Trusted Publishers (OIDC).

## Prerequisites

- **No PyPI API token required!** This repo uses Trusted Publishers (OIDC) for tokenless publishing.
- Ensure the repository is configured as a Trusted Publisher in PyPI settings (one-time setup).
- Ensure tests are green and coverage passes locally (≥85% required).
- Update `CHANGELOG.md` with all user-facing changes from the "Unreleased" section.

## Pre-Release Checklist

1. **Run full test suite locally:**

   ```bash
   make test
   # or
   pytest -q --maxfail=1 --disable-warnings --cov=. --cov-report=term-missing --cov-fail-under=85
   ```

2. **Verify linting and formatting:**

   ```bash
   make lint
   make fmt
   make pre-commit-run
   ```

3. **Review documentation:**
   - CHANGELOG.md updated with "Unreleased" changes moved to new version section
   - README.md reflects latest features
   - QUICKSTART.md is up-to-date
   - docs/USER_GUIDE.md includes new features

4. **Verify CI is green:**
   - Check GitHub Actions: all tests passing on ubuntu-latest and macos-latest
   - Coverage uploaded to Codecov successfully

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
- **Check:** https://pypi.org/manage/account/publishing/ (must match org/repo/workflow)

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
