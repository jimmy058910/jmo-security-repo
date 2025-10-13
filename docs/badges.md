# Badges (snippet)

Copy/paste into README once CI is finalized.

```
[![Tests](https://github.com/jimmy058910/jmo-security-repo/actions/workflows/tests.yml/badge.svg)](https://github.com/jimmy058910/jmo-security-repo/actions/workflows/tests.yml)
[![codecov](https://codecov.io/gh/jimmy058910/jmo-security-repo/branch/main/graph/badge.svg?token=)](https://codecov.io/gh/jimmy058910/jmo-security-repo)
[![PyPI - Version](https://img.shields.io/pypi/v/jmo-security)](https://pypi.org/project/jmo-security/)
```

Notes:
- Coverage badge now uses Codecov. You may need to enable the repository on Codecov and optionally set CODECOV_TOKEN in repo secrets (not required for public repos with GitHub Actions, but recommended for stability).
- Alternative (Coveralls):
	- Add to CI: `pip install coveralls` and run `coverage xml` + `coveralls` or use `coverallsapp/github-action@v2`.
	- Badge example: `![Coveralls](https://coveralls.io/repos/github/<owner>/<repo>/badge.svg?branch=main)` linking to `https://coveralls.io/github/<owner>/<repo>?branch=main`.
- Tests badge links to GitHub Actions workflow.
- PyPI badge links to the published package (adjust if unpublished).
