# Troubleshooting

Common problems and fixes, organized by symptom. Each entry follows a **symptom → cause → fix** pattern so you can search for what you see.

For questions that aren't problems (e.g., "should I use pip or Docker?"), see [FAQ.md](FAQ.md).

## Installation

### "Tool not found" or "command not found: gitleaks"

**Symptom:** A scan reports a specific tool isn't installed, even though `pip install jmo-security` succeeded.

**Cause:** `jmo-security` the CLI is separate from the 28 underlying scanners. pip doesn't install them automatically.

**Fix:**

```bash
jmo tools check                         # list missing tools
jmo tools install --profile balanced    # install all tools for your profile
jmo tools install gitleaks              # install one specific tool
```

Docker users don't hit this — all scanners are pre-installed in the image.

### `jmo tools install` fails with pip conflicts

**Symptom:** Installing a pip-based tool fails because its dependencies conflict with another installed Python package.

**Cause:** Some tools (e.g., `scancode-toolkit`) pin old versions of packages you may have installed elsewhere. JMo isolates these in dedicated venvs, but a previous install may have leaked.

**Fix:**

```bash
jmo tools clean --force        # remove isolated venvs
jmo tools install <tool>       # reinstall fresh
```

### Permission denied on shell scripts

**Symptom:** `bash: ./scripts/foo.sh: Permission denied` after cloning.

**Cause:** The execute bit is lost on some clones (especially on Windows-to-Unix transfer).

**Fix:**

```bash
find scripts -type f -name "*.sh" -exec chmod +x {} +
```

---

## Scanning

### Scan hangs indefinitely

**Symptom:** A scan doesn't complete; CPU usage drops to zero.

**Causes and fixes:**

1. **Tool waiting on a prompt:** Some tools (older versions) prompt for input. Run the failing tool manually with `-v` to see if it's asking something. Report via Issues if so.
2. **Docker daemon unreachable:** Tools that use Docker (e.g., Trivy with image scans) may hang if Docker isn't running. `docker info` to check.
3. **Large network downloads:** Trivy/Grype fetch vulnerability DBs on first run (~50–100 MB). Wait it out once; subsequent runs are cached.

Set a per-scan timeout:

```bash
jmo scan --repo . --timeout 1800    # 30-minute hard limit
```

### "SQLite database is locked"

**Symptom:** Scan fails to write history with "database is locked".

**Cause:** Another JMo process has the DB open, or a previous scan crashed without releasing the lock.

**Fix:**

```bash
jmo history vacuum    # rebuilds the DB, releases stale locks
```

If the problem persists, rename `.jmo/history.db` to `.jmo/history.db.old` and re-run — a fresh DB will initialize.

### Scan finds nothing / zero findings

**Symptom:** Scan exits 0 with "0 findings" on code you know has issues.

**Causes:**

1. **Wrong profile:** `--profile-name fast` excludes SAST scanners. Try `--profile-name balanced` or `--profile-name deep`.
2. **Target misidentified:** If JMo treats your directory as non-scannable, check `jmo scan --repo . --human-logs` for detection output.
3. **Suppression rules:** Check `jmo.suppress.yml` at your repo root for accidental over-suppression.

---

## Docker

### "Permission denied" mounting a volume

**Symptom:** `docker run -v $(pwd):/scan ...` fails with permission errors on the results directory.

**Cause:** The container runs as a non-root user by default; your host's `./results` directory is owned by root or a different UID.

**Fix:**

```bash
mkdir -p results .jmo
chmod 777 results .jmo   # permissive; restrict in production
```

Or run as your host UID:

```bash
docker run --rm -u "$(id -u):$(id -g)" -v "$(pwd):/scan" ghcr.io/jimmy058910/jmo-security:latest ...
```

### History doesn't persist between Docker runs

**Symptom:** `jmo history list` is empty inside the container, even though you ran scans earlier.

**Cause:** The `.jmo/` directory lives inside the ephemeral container filesystem and disappears with `--rm`.

**Fix:** Mount `.jmo/` explicitly:

```bash
docker run --rm \
  -v "$(pwd)/.jmo:/scan/.jmo" \
  -v "$(pwd):/scan" \
  ghcr.io/jimmy058910/jmo-security:v1.0.1 scan --repo /scan
```

### arm64 image is missing a tool

**Symptom:** On Apple Silicon or ARM servers, `jmo tools check` shows a tool as missing that exists on amd64.

**Cause:** A handful of tools don't publish arm64 binaries upstream. Notably, `scancode-toolkit` skips arm64 because `extractcode-7z` has no `linux/aarch64` wheel.

**Fix:** Accept the gap or fall back to amd64 emulation via `--platform linux/amd64` (slower). See [docs/PLATFORM_NOTES.md](PLATFORM_NOTES.md) for per-tool arm64 status.

---

## CI/CD

### CI fails with "quick-checks" badge verification error

**Symptom:** A release-prep PR fails `verify_badges.sh` with "Version mismatch: Local 1.0.X, PyPI 1.0.Y".

**Cause:** `verify_badges.sh` blocks when local pyproject is ahead of PyPI. For release-prep branches, this is expected.

**Fix:** Branch names matching `release/v*`, `chore/release-v*`, `feature/*`, `refactor/*`, `hotfix/*`, `dependabot/*`, or branch `dev` automatically bypass the check. If your branch doesn't match, add its prefix to the allowlist at `scripts/dev/verify_badges.sh:100`.

### Scheduled e2e jobs fail silently with "no test results"

**Symptom:** GitHub Actions scheduled workflow completes but `pytest-json-report` produces empty output.

**Cause:** Missing dev-dependency install step. `pytest-json-report` isn't in the runtime image.

**Fix:** Add to your workflow job:

```yaml
- name: Install dev dependencies
  run: pip install -r requirements-dev.txt
```

Compare against the `e2e-tool-integration` job pattern in `.github/workflows/scheduled.yml`.

### Docker amd64 build fails with apt-get errors

**Symptom:** Release pipeline Docker build fails with `Connection failed [IP: ...]` or `W: Some index files failed to download`.

**Cause:** Transient Ubuntu mirror outage. Not your code.

**Fix:** Re-run failed jobs:

```bash
gh run rerun <run-id> --failed --repo jimmy058910/jmo-security-repo
```

Usually resolves on retry within 5–10 minutes.

---

## Windows

### Tools report "command not found" on native Windows

**Symptom:** `jmo tools check` says a tool is installed but scans report it as missing.

**Cause:** The tool installed via chocolatey/scoop adds to PATH in a new shell only. Current shell didn't pick up the update.

**Fix:** Close and reopen your terminal. Or run `refreshenv` (chocolatey helper).

### ZAP fails to start on Windows

**Symptom:** ZAP DAST scan fails immediately on launch.

**Cause:** ZAP requires Java 17+ and a GUI subsystem on Windows even in headless mode.

**Fix:** Install Java 17: `choco install openjdk17` (or `winget install EclipseAdoptium.Temurin.17.JDK`). For headless CI, prefer running ZAP through Docker.

### Line ending issues (pre-commit fails)

**Symptom:** `pre-commit` reports "mixed line endings" on files you didn't touch.

**Fix:**

```bash
git config core.autocrlf false
```

See [packaging/WINDOWS_COMPATIBILITY.md](../packaging/WINDOWS_COMPATIBILITY.md) for more Windows-specific guidance.

---

## Output and reports

### Dashboard HTML shows "No data" in browser

**Symptom:** `open results/summaries/dashboard.html` loads but the charts are empty.

**Cause:** The dashboard expects `dashboard-data.json` in the same directory. If you moved `dashboard.html` alone, data loading breaks.

**Fix:** Keep `dashboard.html` and `dashboard-data.json` together, or use the path-aware serving mode:

```bash
python -m http.server 8080 -d results/summaries/
# open http://localhost:8080/dashboard.html
```

### SARIF upload to GitHub fails with "Invalid SARIF"

**Symptom:** `github/codeql-action/upload-sarif@v3` rejects the SARIF file.

**Cause:** Usually the SARIF file is truncated (scan was killed mid-write) or contains adapter-emitted findings that don't round-trip through the schema validator.

**Fix:**

```bash
python -m json.tool results/summaries/findings.sarif > /dev/null    # validate JSON
jmo scan ... --strict-schema                                        # re-run with schema enforcement
```

If validation passes locally but GitHub rejects it, open an Issue with the full SARIF and the GitHub error.

---

## Still stuck?

1. **Check your version:** `jmo --version` — is it current?
2. **Check the CHANGELOG** — recent fixes may match your symptom.
3. **Search existing Issues:** [github.com/jimmy058910/jmo-security-repo/issues](https://github.com/jimmy058910/jmo-security-repo/issues?q=is%3Aissue)
4. **Open a new Issue** with:
   - `jmo --version` output
   - Your OS and Python version
   - The full command that failed
   - Full output with `--human-logs`
5. **For security issues**, use [GitHub Security Advisories](https://github.com/jimmy058910/jmo-security-repo/security/advisories/new) instead.

---

**Last Updated:** April 2026 | **JMo Security v1.0.1**
