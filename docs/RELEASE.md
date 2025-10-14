# Release Guide

Remember to update CHANGELOG.md with user-facing changes.

This project publishes to PyPI via GitHub Actions on git tags of the form `v*`.

## Prerequisites
- Ensure `secrets.PYPI_API_TOKEN` is configured in the GitHub repo settings.
- Ensure tests are green and coverage passes locally.
- Update `CHANGELOG.md` as needed.

## Step-by-step
1. Bump version in `pyproject.toml` (for example, `0.3.3`).
2. Commit the version bump and any related changes.
3. Create and push a tag: `git tag v0.3.3 && git push origin v0.3.3`.
4. The `Release (PyPI)` workflow builds and publishes the package.
5. Verify from a clean environment: `pip install jmo-security==0.3.3` then `jmo --help`.

## Notes
- The package exposes the `jmo` and `jmotools` console scripts.
- Coverage reports are uploaded to Codecov as part of the tests workflow.
- License is defined via SPDX string in `pyproject.toml` and the `LICENSE` file is included in the distribution.
