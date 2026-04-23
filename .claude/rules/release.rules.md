---
title: Release & CI/CD Pipeline Rules
paths:
  - .github/workflows/**/*.yml
  - scripts/dev/update_versions.py
  - Makefile
  - pyproject.toml
references:
  - docs/RELEASE.md (detailed release guide)
  - docs/VERSION_MANAGEMENT.md (tool version sync)
  - docker.rules.md (container variants)
---

# Release & CI/CD Pipeline Rules

**What this covers:** GitHub Actions workflows, release process, Docker multi-arch builds, version management, and release troubleshooting.

## GitHub Actions Example

```yaml
- run: jmo scan --repo . --results-dir results-baseline
- run: jmo scan --repo . --results-dir results-current
- run: jmo diff results-baseline/ results-current/ --format md > diff.md
```

## GitHub Actions Workflows (4-Workflow Structure)

Consolidated from 8 workflows:

| Workflow | File | Trigger | Purpose |
|----------|------|---------|---------|
| **CI** | `ci.yml` | PR / push to main | Lint, unit tests, adapter tests, coverage |
| **Scheduled** | `scheduled.yml` | Cron / manual | Nightly e2e, tool-update checks, security scans |
| **Release** | `release.yml` | Tag push (`v*`) | Build images, publish to registries, GitHub release |
| **Maintenance** | `maintenance.yml` | Manual / cron | Dependency updates, Docker image pruning |

**Scheduled job pattern:** All `scheduled.yml` jobs that run pytest MUST include `pip install -r requirements-dev.txt` and `cache-dependency-path: requirements-dev.txt`. Reference pattern: the `e2e-tool-integration` job. Omitting dev deps causes `--json-report` to fail silently.

## Release Process

**CRITICAL:** All tools MUST be updated before release (CI enforces this).

1. **Automated (recommended):** GitHub Actions → Release workflow (tag push triggers `release.yml`).
2. **Manual:** Update tools → bump version → tag → push.
3. **Hotfix to main:** Must go through a PR (GitHub rulesets enforce `quick-checks`). Cannot push directly.

**Version management commands:**

```bash
python3 scripts/dev/update_versions.py --check-latest  # Check updates
python3 scripts/dev/update_versions.py --sync          # Sync Dockerfiles
```

**NEVER manually edit tool versions in Dockerfiles.** See [docs/VERSION_MANAGEMENT.md](../../docs/VERSION_MANAGEMENT.md).

See [docs/RELEASE.md](../../docs/RELEASE.md) for the detailed release guide.

## Release Workflow Architecture (v1.0.0+)

The release pipeline has 3 phases triggered by a `v*` tag push:

```text
Pre-Release Validation → PyPI Publish → Docker Build (8 parallel: 4 variants × 2 arches)
                                      → Homebrew (existence check, skip if not in homebrew-core)
                                      → WinGet (existence check via GitHub API, skip if not in winget-pkgs)
                                      → Badge Verify
                         Docker Build → Docker Merge (4 parallel: create multi-arch manifests)
                         Docker Merge → Docker Scan + Benchmarks + Docker Hub README
```

### Multi-Arch Docker Builds (CRITICAL Details)

**Native runners (no QEMU):**

- `docker-build-amd64`: `runs-on: ubuntu-latest` (native x86_64).
- `docker-build-arm64`: `runs-on: ubuntu-24.04-arm` (native ARM).
- `docker-merge`: downloads both digests, creates GHCR manifest via `imagetools create`, replicates to Docker Hub/ECR via `crane copy`.

**GHCR is the primary registry.** `imagetools create` targets GHCR only (cross-registry blob copy doesn't work). Docker Hub and ECR are replicated via `crane copy --platform all` with `continue-on-error: true`.

## Release Troubleshooting

| Issue | Solution |
|-------|----------|
| Tag push fails | Main has rulesets — must PR through CI, then tag |
| Docker build cache stale | `gh cache delete --all --repo owner/repo` then re-tag |
| scancode fails on arm64 | Expected — `extractcode-7z` has no arm64 wheel. Conditional install via `TARGETARCH` check |
| Homebrew/WinGet fail on first release | Both have existence checks that skip gracefully. Submit initial manifests manually. |
| `verify_badges.sh` fails on new branch types | Add branch prefix to allowlist at `scripts/dev/verify_badges.sh:100` (currently: dev, feature, refactor, hotfix, dependabot) |
| `jmo validate` fails on Linux but passes locally | Platform-specific checks (e.g., `path-mixed-separators`) — guard with `sys.platform` |
| Tool version 404 in Docker build | Run `python scripts/dev/update_versions.py --validate` to check all URLs, then `--sync` |
| Scheduled e2e jobs fail with "no test results" | Likely missing `pip install -r requirements-dev.txt` — compare against `e2e-tool-integration` job pattern |
| Dependabot PR fails deps-compile freshness | No longer possible — the freshness check is scoped to `pull_request` events from non-Dependabot authors (`ci.yml:46`, `if: github.event_name == 'pull_request' && github.event.pull_request.user.login != 'dependabot[bot]'`). The same SKIP applies to `scheduled.yml` Lint's full pre-commit suite (`SKIP: bandit,yamllint,deps-compile`). Dependabot's pip resolver emits structurally different but functionally equivalent lockfiles from `uv pip compile` (different extras, marker handling); enforcing byte-for-byte match on push events was a category error that blocked main CI after every Dependabot merge. The freshness check is a PR-time validation by design — push/workflow_dispatch events don't need it. History: PR #321 added the authorship gate; PR #323 added a redundant branch-ref check that didn't fix push-to-main; final simplification replaces both with the single event-scoped predicate. The lockfile converges to uv-canonical format whenever a human next runs `make deps-compile` on a human PR — between Dependabot merges, main may briefly hold Dependabot-format which is functionally identical at `pip install -r` time. |
| Tool contract test fails after version bump | Automated version bumps can change output schemas. Run the tool against fixtures to verify, then update `result_item_keys` in `test_tool_contracts.py` |
| Windows matrix job fails with `ParserError: Missing expression after unary operator '--'` | Multi-line `run:` block uses bash `\` line continuation; PowerShell (default on `windows-latest`) rejects it at parse time. Add `shell: bash` to the step. |
| Non-root container can't write to mounted dir in CI (`PermissionError`) | GitHub runner UID (1001) ≠ container `USER jmo` UID (1000); bind mounts preserve host UID. Fix: `chmod 777` the host dir before mount, or add `--user $(id -u):$(id -g)` to `docker run`. |
| `gh pr merge` refuses with "workflow scope" error | PR modifies `.github/workflows/*.yml`; `gh` token lacks `workflow` scope. Run `gh auth refresh -h github.com -s workflow` once, then retry. |
| Workflow references a test file that doesn't exist | Path drift after a test reorg. Current security-test canonical locations: `tests/cli/test_path_sanitizers.py`, `tests/unit/test_archive_security.py`, `tests/unit/test_history_db_performance.py`. |
| `docker pull :<variant>` returns manifest unknown after release | `docker/metadata-action` `type=raw,value=<var>` inherits global `flavor: suffix=-X` and produces `X-X` instead of bare `X`. Add per-tag `suffix=` (empty) override. Same trap for bare semver (`:1.0.2`, `:1.0`, `:1`). Fixed in PR #305. |
| `:full` vs `:deep` naming mismatch | Heavyweight Docker variant was named `full` in `release.yml` but `deep` in `scheduled.yml`, `jmo build` VARIANTS, and user docs. As of v1.0.2 the canonical name is `deep` everywhere and `Dockerfile` is renamed to `Dockerfile.deep`. `:full` alias kept for one release cycle then remove. |
| `Validate <variant>` job shows "Installed tools: 0" | `tools check --json` without `--profile` emits profile-summary dicts where `installed` is an integer count; jq's `select(.installed == true)` evaluates `7 == true` as false (strictly typed). Pass `--profile ${{ matrix.profile }}` to get per-tool `{installed: bool}` shape. |
| `tools check --profile deep` crashes silently (zero stdout, exit 1) | One of the 29 PROFILE_TOOLS entries raises an uncaught exception (yara native import segfault, scancode iterdir OSError, etc.) inside `ToolManager.check_profile` before `json.dumps` runs. Fixed in PR #308 by per-tool try/except guard. Always capture stderr separately in CI: `> out.json 2>err.log` so silent crashes are diagnosable. |
| `Validate deep` counts 25 not 29 tools | `PROFILE_TOOLS["deep"]` (29) includes 4 entries in `MANUAL_INSTALL_TOOLS` (`tool_registry.py:160`): `akto`, `afl++`, `mobsf`, `falco` — these are intentionally NOT in the Docker image. `expected_tools` in `scheduled.yml` matrix should be `len(PROFILE_TOOLS) - 4` for `deep`. |
| Pre-existing shell-injection findings in `release.yml` | Steps using `${{ inputs.X }}` or `${{ steps.X.outputs.Y }}` directly inside `run:` bash blocks are flagged by semgrep `yaml.github-actions.security.run-shell-injection` (CWE-78, HIGH). Fix: move to `env:` block, reference as `"$ENVVAR"`. Fixed across three sites in PR #303. |
| Manual backfill of missing GHCR tags (e.g. after a release workflow bug) | Use `docker buildx imagetools create --tag <new> <existing>` — creates a tag alias pointing at the existing multi-arch manifest list. No rebuild, no blob upload. Requires `write:packages` scope; `gh auth refresh -s write:packages -h github.com` if your gh token lacks it, then `gh auth token \| docker login ghcr.io -u <user> --password-stdin`. |
| Nightly Extended Tests `test_docker_variant_tools` times out despite `subprocess.run(timeout=600)` | pytest-timeout kills the test at the 120s default from `pyproject.toml` long before any `subprocess.run(timeout=...)` fires. Traceback signature: thread stack dumps + `+++ Timeout +++` banner, NO `TimeoutExpired` exception frame. Fix: override the pytest-level timeout with `@pytest.mark.timeout(1200)` on the test (or its class); keep `subprocess.run(timeout=1150)` slightly lower so `TimeoutExpired` fires cleanly before pytest-timeout does. PR #320 (180s) and PR #327 (600s) were no-ops because they raised the wrong ceiling. |
| actionlint/shellcheck SC2170 on `-lt ${{ matrix.X }}` in scheduled.yml persists despite PR #300's unquoting | actionlint substitutes `${{ }}` with an opaque placeholder BEFORE invoking shellcheck, so shellcheck sees `-lt <placeholder>` and emits SC2170 regardless of whether the expression is quoted. Fix: route matrix values through `env:` block (`EXPECTED_TOOLS: ${{ matrix.expected_tools }}`) and use `-lt "$EXPECTED_TOOLS"` — shellcheck can trace `$var` statically and SC2170 docs explicitly approve `$var` form. Bonus: aligns with CWE-78 shell-injection hardening pattern. |
| Pre-existing actionlint findings accumulate unseen on PRs, only surface in scheduled full-lint | `reviewdog/action-actionlint` in ci.yml:29 defaults to `filter_mode: added` — only reports findings on lines changed in the PR diff. Pre-existing info/error findings in workflow files that the PR didn't touch are silently skipped. The scheduled.yml "Lint (full pre-commit suite)" job runs `pre-commit run actionlint` against all files, so it catches the accumulated backlog — meaning once this job fails, you have to fix the *entire* backlog, not just newly-introduced findings. Mitigation option: `filter_mode: nofilter` on the reviewdog action (keeps `fail_level: error` so info findings are annotations not failures, but error-level findings fail CI even on unchanged lines). |
| Scheduled Lint yamllint fails on `./~/.cache/pre-commit/repo*/...` paths | A step-level `env:` block contains `PRE_COMMIT_HOME: ~/.cache/pre-commit`. GitHub Actions' `env:` does NOT shell-expand `~`, so pre-commit receives the literal string and creates a directory at `$PWD/~/.cache/pre-commit/`. A subsequent `yamllint -c .yamllint.yaml .` then descends into it and fails on third-party hook test fixtures. This also silently breaks the `actions/cache` step (its Node action DOES expand `~` to `/home/runner/.cache/pre-commit`, so the paths never match — cache has been useless). Fix: remove the `PRE_COMMIT_HOME` env line entirely; pre-commit's default (`$HOME/.cache/pre-commit` on Linux) matches the cache action's expanded path. |
| Nightly `test_docker_variant_scan` crashes with `PermissionError: [Errno 13] Permission denied: 'jmo.yml'` inside container | Python 3.12 changed `pathlib.Path.exists()` to propagate `PermissionError` (and other `OSError` subclasses besides `FileNotFoundError` / `NotADirectoryError`). Previously exists() silently returned False on any OSError; now it raises. `scripts/core/config.py:220` probes `jmo.yml` on every `jmo scan` — when the cwd's parent mount lacks search permission for the container user (UID 1000 jmo vs GitHub runner UID 1001 bind mount), the stat call raises. Two-part fix: (a) harden `config.py` with `try/except OSError` around `p.exists()` for real users; (b) `os.chmod(tmp_path, 0o777)` in tests that bind-mount pytest `tmp_path` (mirrors `scheduled.yml:1083` pattern). Mark test chmod with `# nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions` — 0o777 is intentional and tmp_path is run-scoped. |
| Nightly `test_docker_variant_tools[deep]` fails with rc=1 despite correct JSON output | `tools check --profile deep --json` (`scripts/cli/tool_commands.py:170-171`) returns 1 when any tool reports `installed: false`. The `deep` profile includes 4 tools in `MANUAL_INSTALL_TOOLS` (akto, afl++, mobsf, falco) that are intentionally NOT baked into the Docker image — so rc=1 is the correct behavior for a correctly-built deep container. Tests that hard-fail on `rc != 0` are wrong for this variant. Fix: remove the rc fast-fail; rely on the JSON count assertion (`installed >= expected_tools`), which already accounts for the 4 missing manual-install tools. Only hard-fail if JSON parsing fails (catastrophic). Balanced/slim/fast profiles have no manual-install tools so they return rc=0 as before — this is why only `deep` was affected. |
| `dependency-check` reports `installed: false` in `:deep`/`:balanced` images | `tool_registry.py:116` maps `dependency-check` → binary `dependency-check.sh` (the upstream canonical name from the zip distribution). Dockerfiles symlink only the bare `dependency-check` name at `/usr/local/bin/dependency-check`. When `tool_manager._find_binary("dependency-check.sh")` falls through to `find_tool()` (after the ~/.jmo/bin special-case branch misses), PATH search for literal `dependency-check.sh` doesn't match the bare symlink. Fix: add a second symlink `ln -s /opt/dependency-check-cli/bin/dependency-check.sh /usr/local/bin/dependency-check.sh` in both `Dockerfile.deep` and `Dockerfile.balanced`. Only takes effect after next Docker rebuild (release tag push). ZAP has the same pattern (`zap.sh` in registry, `zap` symlink) but is handled by a tool_manager special-case branch at `tool_manager.py:1116` — dependency-check needed similar treatment but never got it. |
| Docker image fixes (code in `scripts/`) don't propagate to nightly tests until next release | GHCR images `ghcr.io/jimmy058910/jmo-security:<variant>` are rebuilt ONLY on release tag push (`release.yml` triggers on `v*` tags). The scheduled nightly test pulls these pre-built images and runs `docker run <image> tools ...` — code changes merged to main via the CI workflow don't reach the container until the next release. Workaround: trigger manual rebuild via `release.yml` workflow_dispatch or tag a minor release. This means any `scripts/cli/` or `scripts/core/` fix for a Dockerfile-hosted bug requires waiting for or triggering a release to validate end-to-end. Test-level fixes (in `tests/e2e/`) ARE effective immediately because pytest runs on the host, not inside the container. |

## Re-Tag Cycle (When Release Workflow Fails)

```bash
git tag -d v1.0.0 && git push origin :refs/tags/v1.0.0  # Delete tag
# ... merge hotfix PR to main ...
git checkout main && git pull origin main                 # Sync main
git tag -a v1.0.0 -m "..." && git push origin v1.0.0     # Re-tag + push
git checkout dev && git merge origin/main && git push origin dev  # Sync dev
```
