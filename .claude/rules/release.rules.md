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
| Dependabot PR fails deps-compile freshness | No longer possible — the check is gated on Dependabot authorship at `ci.yml:46`. Two-condition guard: skip if `pull_request.user.login == 'dependabot[bot]'` OR `github.ref` starts with `refs/heads/dependabot/`. Both needed because `ci.yml` triggers on both `push` and `pull_request`, and `pull_request` context is empty on push events (so the Dependabot force-push after a rebase still triggers a push-event run that needs branch-ref-based gating). Dependabot's pip resolver emits structurally different but functionally equivalent lockfiles from `uv pip compile` (different extras, marker handling); enforcing byte-for-byte match was a category error. The lockfile converges back to uv-canonical format naturally the next time a human runs `make deps-compile`. Gate added in PR #321, push-event case added in PR #322. |
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

## Re-Tag Cycle (When Release Workflow Fails)

```bash
git tag -d v1.0.0 && git push origin :refs/tags/v1.0.0  # Delete tag
# ... merge hotfix PR to main ...
git checkout main && git pull origin main                 # Sync main
git tag -a v1.0.0 -m "..." && git push origin v1.0.0     # Re-tag + push
git checkout dev && git merge origin/main && git push origin dev  # Sync dev
```
