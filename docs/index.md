# JMO Security Suite — Documentation

[![Tests](https://github.com/jimmy058910/jmo-security-repo/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/jimmy058910/jmo-security-repo/actions/workflows/tests.yml?query=branch%3Amain)
[![codecov](https://codecov.io/gh/jimmy058910/jmo-security-repo/branch/main/graph/badge.svg)](https://app.codecov.io/gh/jimmy058910/jmo-security-repo)

Welcome! This is the one-stop index for docs. Start with the User Guide, or jump to examples, screenshots, or schemas.

- User Guide: [USER_GUIDE.md](USER_GUIDE.md)
- Quick Start: [../QUICKSTART.md](../QUICKSTART.md)
- Examples: [examples/README.md](examples/README.md)
- Screenshots: [screenshots/README.md](screenshots/README.md)
- CommonFinding Schema: [schemas/common_finding.v1.json](schemas/common_finding.v1.json)
- Roadmap: [../ROADMAP.md](../ROADMAP.md)
 - HTML Dashboard details: [User Guide — SARIF and HTML dashboard](USER_GUIDE.md#sarif-and-html-dashboard)
 - Support the project: https://ko-fi.com/jmogaming

## What’s in this toolkit

- Orchestrates secrets, SAST (Semgrep, Bandit), SBOM, IaC, Dockerfile scanners via a unified CLI
- Normalizes outputs into a CommonFinding schema for consistent reporting
- Ships human-friendly HTML and machine-friendly JSON/YAML/SARIF
- Supports profiles, per-tool flags/timeouts, retries, include/exclude, and suppression

## Start here

1) Verify environment
```bash
make verify-env
```

2) Run a quick scan
```bash
jmo ci --repos-dir ~/repos --profile-name fast --fail-on HIGH --profile --human-logs
```

3) Open the dashboard (results/summaries/dashboard.html)
	- Learn more about features and profiling: [User Guide — SARIF and HTML dashboard](USER_GUIDE.md#sarif-and-html-dashboard)

Note: CI runs on ubuntu-latest and macos-latest across Python 3.10, 3.11, and 3.12, with concurrency and job timeouts to keep runs fast and reliable.

## WSL quick install checklist

If you're on Windows Subsystem for Linux (WSL), this gets you to green fast:

- Use WSL2 with Ubuntu 20.04+ (22.04+ recommended)
- Update core packages: `sudo apt-get update -y && sudo apt-get install -y build-essential git jq python3 python3-pip`
- Verify environment and get tool hints: `make verify-env`
- Optional curated tools install/upgrade: `make tools` and `make tools-upgrade`
- Nosey Parker (native, recommended on WSL): see [User Guide — Nosey Parker on WSL](USER_GUIDE.md#nosey-parker-on-wsl-native-recommended-and-auto-fallback-docker)
- Ensure `~/.local/bin` is on PATH (for user-local tools): `echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc`

## Key docs

- Configuration reference: see [USER_GUIDE.md](USER_GUIDE.md#configuration-jmoyml)
- Suppressions: see [USER_GUIDE.md](USER_GUIDE.md#suppressions)
- CLI synopsis: see [USER_GUIDE.md](USER_GUIDE.md#reference-cli-synopsis)

## Contributing and releases

- Tests: [../TEST.md](../TEST.md)
- Release notes: [../RELEASE_NOTES.md](../RELEASE_NOTES.md)
- License: [../LICENSE](../LICENSE)

## FAQ

Q: Tools not found or partial toolchain installed?
- A: Run `make verify-env` for OS-aware hints. You can also run with `--allow-missing-tools` to generate empty stubs and still exercise the pipeline.

Q: No repositories detected when using `--repos-dir`?
- A: Only immediate subfolders are considered repos. Ensure each contains a `.git` folder or pass `--repo` for a single path, or `--targets` file.

Q: YAML output missing?
- A: Install `pyyaml` to enable the YAML reporter. Otherwise JSON/MD/HTML still work; see [User Guide — Troubleshooting](USER_GUIDE.md#troubleshooting).

Q: Scans are slow on large directories?
- A: Use the `fast` profile, increase `threads`, and consult `timings.json` by running `jmo report --profile`. See [User Guide — Configuration](USER_GUIDE.md#configuration-jmoyml).

Q: How do I suppress false positives?
- A: Create a `jmo.suppress.yml` as described in [User Guide — Suppressions](USER_GUIDE.md#suppressions). A summary is written to `SUPPRESSIONS.md` during report/ci.
