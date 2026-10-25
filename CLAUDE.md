# CLAUDE.md

Guidance for Claude Code when working with the JMo Security Audit Tool Suite repository.

> **Path-scoped rules** live in [`.claude/rules/`](.claude/rules/). They load
> automatically when Claude touches files matching their `paths:` frontmatter —
> this is measured, not aspirational. Keep `paths:` narrow: a rule scoped to
> `scripts/**/*.py` loads on every source file in the product.

## Project Overview

JMo Security is a terminal-first security audit toolkit orchestrating 15 scanners with unified CLI, normalized outputs, and HTML dashboard.

**Version:** v1.1.1 (latest released — see CHANGELOG.md for full history)
**Philosophy:** Two-phase architecture: scan (invoke tools) → report (normalize, dedupe, output)

## Mandatory Guardrails

1. **One formatter:** `ruff format` (Black left with #1179). The `ruff` lint hook runs before `ruff-format` in `.pre-commit-config.yaml`; never add a second formatter
2. **Test Coverage:** CI's only enforced floor is **85%** (`coverage-aggregate`'s "Verify coverage threshold" step, on the marker-filtered suite — excludes slow/docker/requires_tools/smoke). Nothing sets `--cov-fail-under` — not `make test`, not `pyproject.toml`, so there is still no *local* gate. Cite the step, never a line number: it has moved three times (#756). Measure current coverage rather than quoting a figure from this file
3. **Conventional Commits:** `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `perf:`, `ci:`. **No AI-attribution markers of any kind, in commit messages or PR bodies** — not `Co-Authored-By: Claude`, not `Generated with Claude Code`, and **not a `Claude-Session:` link**. Decided 2026-09-11, and it applies to every repo in the workspace, not only this public one. **This has to be stated here, in the repo's own `CLAUDE.md`, or it does not hold**: Claude Code's harness injects an instruction to append the trailer **every single session** and defers only to a `CLAUDE.md`, so the workspace-level ban in `C:\Projects\CLAUDE.md` sat one directory above this repo and lost silently — **0 trailers in the ~250 commits before 2026-09-02, near-universal after**, with that prohibition unchanged the whole time. A rule that competes with something re-injected on every turn has to live where the harness reads it
4. **Git Configuration:** Refines the Bash-tool default ("NEVER update the git config"). **Never** modify identity (`user.*`), signing (`commit.gpgsign`, `gpg.*`), commit templates (`commit.template`), or merge/rebase behavior (`pull.rebase`, `merge.*`, `rebase.*`) without explicit user authorization. **Permitted to unblock standard tooling**: routine repo-local unsets that restore values already equal to their default (e.g. `git config --unset core.hooksPath` when it points to `.git/hooks`, which lets `pre-commit install --install-hooks` proceed). When in doubt, ask first.

Subprocess safety (never `shell=True`), path-traversal validation, and cross-platform
test requirements are enforced in [python-safety.rules.md](.claude/rules/python-safety.rules.md)
and [testing.cross-platform.rules.md](.claude/rules/testing.cross-platform.rules.md),
which load when you touch the relevant files.

### Before Every Commit

```bash
make fmt && make lint && make test
```

### Merge Authorization: an Evidence Gate, not a Second Approval

In an **attended session** (the user is present and has said to ship it), merge is
gated on evidence rather than a second approval. Before merging you must:

1. **Name** the specific verification that could catch *this* change's failure
   mode **and that CI cannot provide**.
2. **Run it**, and put the **actual numbers** in the PR description.
3. Merge only if that passes **and** CI is green.

**Stop and ask** if the gate can't run, is inconclusive, or the change grew
beyond its stated scope. For many PRs (a dependency bump) the honest answer is
"CI is sufficient" — say so and merge.

> **Why evidence and not approval.** On PR #695, CI went green *before* the
> native-console run finished — and that run is what found 3 regressions. Merging
> on CI green would have shipped them; asking the user would have had them
> approving on the same blind signal. What protected `main` was a verification CI
> **structurally could not perform**. That is the thing worth requiring.
>
> **Unattended runs are different.** The weekly-maintenance routine's auto-merge
> tier is a separate, narrower carve-out — see the maintainer's workspace
> `ROUTINES.md` (outside this repo). Do not read this section as widening it.

**The two verifications this repo has learned it needs** (see
[testing.cross-platform.rules.md](.claude/rules/testing.cross-platform.rules.md)):

- **Diff failing-test ID *sets*, never counts.** A change can fix N tests and
  break N others, leaving every count identical. That is not hypothetical — it
  happened on #695.
- **Read the `windows-2022` shard's job log, not its check tick.** It is
  `continue-on-error: true` and reports green over exit-code-1 failures. A shifted
  **skip** count is as much a signal as a failure.

### Plans Are Hypotheses Until Measured

A plan written without running anything is a set of predictions, not a spec.
The #694 encoding plan had **8 measured-false claims**, including a reproduction
that could never fail (it exited at argparse before reaching the bug) and a
scoping premise — "153 `PLW1514` sites = the read-side failure class" — that
turned out nearly disjoint from the actual failures (fixing all 153 fixed **0**).

So: **spend the first hour measuring, then plan.** When executing someone else's
plan, verify its central claims before building on them, and when one is wrong,
fix the plan rather than working around it.

### Where Deferred Work Goes

There is no fourth option — a private notes file was tried and removed, because
nothing ever closed it:

| Kind of thing | Goes to | Why there |
|---|---|---|
| Anything with a plausible fix | **GitHub issue** (`technical-debt` / `enhancement`) + `# TODO(issue-#):` at the site | It can be closed, assigned, and searched. A file can only be edited. |
| Behaviour a *user* can hit and we intend to keep | [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md) | Ships in the repo, so users find it without reading the tracker. |
| A trap that only bites *developers* | the matching [`.claude/rules/*.md`](.claude/rules/) | Loads automatically when Claude touches those paths. |

> A private `known-issues` log under `.claude/` was the previous answer, and it is
> **gone**. It was gitignored — so this instruction pointed contributors at a file
> they could not see — and by the end it was 95 lines carrying a stale "Last
> Updated", a RESOLVED entry, and an obsolete one for a tool deleted six months
> earlier. A log with no close mechanism only accumulates.

### Artifact Guardrails (CI blocks these)

- No `venv/`, `__pycache__/`, `build/`, `dist/` in git
- No files >10MB (`check-added-large-files` hook)
- No secrets (detect-private-key pre-commit hook + TruffleHog CI scan)

### Plan Mode Format

When creating plans (via `/plan` or plan mode): be extremely concise, present a single recommended approach, include exact file paths (e.g. `scripts/core/adapters/foo.py:45`), and end with unresolved questions if any ambiguity remains.

## Quick Reference

### Development Setup

```bash
uv sync --group dev                    # Install dev deps + project (editable) from uv.lock
make pre-commit-install                # Setup pre-commit hooks
jmo tools install                      # Install security tools
make test-fast                         # Fast parallel tests (recommended for dev)
```

> `make test` runs sequentially with coverage. Use `make test-fast` for 3-5x faster parallel execution during development (requires `pytest-xdist`, included in dev deps).

### Essential Commands

`jmo` subcommands and flags: [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md). Make targets: `make help` (the test targets are explained in [TEST.md](TEST.md)).

One command neither lists: run `python scripts/dev/test_wizard_tools.py` before `jmo wizard`. It tests wizard tool detection non-interactively — isolated venvs, version detection, and the Java dependency.

### Version Management (CRITICAL)

```bash
python3 scripts/dev/update_versions.py --check-latest  # Check updates
python3 scripts/dev/update_versions.py --sync          # Sync Dockerfiles
```

**NEVER manually edit tool versions in Dockerfiles!** See [docs/VERSION_MANAGEMENT.md](docs/VERSION_MANAGEMENT.md)

## AI Tooling Ecosystem

JMo Security ships 12 skills, 7 agents, and an MCP server for AI-assisted development.
Claude Code lists the available skills and agents automatically, so they are not
enumerated here. Full index: [.claude/skills/INDEX.md](.claude/skills/INDEX.md) ·
personas: [.claude/PERSONA_GUIDELINES.md](.claude/PERSONA_GUIDELINES.md) ·
MCP entry points and their measured state: [.claude/rules/mcp.rules.md](.claude/rules/mcp.rules.md).

### What ships, and what does not

`.claude/` is scoped to **contributors**. Skills that generate an adapter, fabricate tests, debug CI, or map compliance frameworks are tracked. Maintainer workflows — issue and PR triage, dependency sweeps, merges, releases, marketing — are deliberately not published: they need `gh` write access or push rights to `main`, so they would be unusable to a contributor anyway. They stay on the maintainer's machine, in place under `.claude/skills/` and untracked.

The split is mechanical rather than remembered. `.gitignore` carries an explicit per-skill allowlist under `.claude/`, and `scripts/dev/check_doc_links.py` fails CI and pre-commit if any tracked file links to a path a clone does not receive. **Anything this file names must be tracked** — an instruction pointing at an untracked path is a dead end for every contributor who follows it.

### Optional: local knowledge graph (not shipped)

Maintainer-local and **absent from a clone**. Recorded here because a session that
has it should use it.

[Graphify](https://github.com/Graphify-Labs/graphify) (`uv` tool `graphifyy`;
`graphify --version` names the installed release) indexes the repo into
`graphify-out/` — deterministic AST parsing, no LLM, no API cost. The git hooks from
`graphify hook install` (`post-commit`, `post-checkout`, `post-merge`,
`post-rewrite`) rebuild it incrementally.

| Task | Command |
|---|---|
| Refresh after many commits | `graphify update .` |
| Ask a structural question | `graphify query "what connects X to Y?"` |
| Explain one symbol | `graphify explain "store_scan"` |
| Path between two symbols | `graphify path "A" "B"` |
| Check the git hooks | `graphify hook status` |
| Upgrade (machine-global; affects every repo) | `uv tool upgrade graphifyy && graphify install --platform claude` |

The MCP server is registered in the repo's **`.mcp.json`**, which is gitignored
because a copy of the tracked `.mcp.json.example` carries a `${GH_TOKEN}` entry;
`~/.claude.json` has no servers for this project. It is deliberately absent from
the example, since the graph is maintainer-local. So a grep of the *tracked* tree
finds nothing, and `cat .mcp.json` on the maintainer's machine finds it. Confirm
with `/mcp`. (This paragraph said the reverse until 2026-09-02.)

**Freshness is `built_at_commit` inside `graph.json`, not the file mtime** —
clustering rewrites `graph.json` without re-extracting, so mtime reads fresher than
the content is. A hook that fires during a rebase or squash simulation can stamp the
graph with a commit that is not an ancestor of `HEAD`; check with
`git merge-base --is-ancestor <built_at_commit> HEAD` before trusting it.

**Hooks fail silently.** Git skips a hook that has lost its executable bit, and
copying the repo between machines can strip it; `graphify hook install` keeps the
mode of a hook it updates, so check `ls -l .git/hooks/post-commit` and `chmod +x`
it. Re-run `graphify install --platform claude` after **every** upgrade, or the
installed skill keeps its old `.graphify_version` stamp while the binary moves on.
On Windows under Git Bash the hook can also fail to find a Python with graphify;
the fix there is a gitignored `graphify-out/.graphify_python` holding the absolute
interpreter path.

## Architecture Overview

The phase walkthrough and the key-files map are in [CONTRIBUTING.md](CONTRIBUTING.md#architecture-and-key-files). The rule that applies everywhere: compliance enrichment happens once, centrally, in `normalize_and_report.py` — **adapters return raw findings and never enrich**.

## Path-Scoped Rules

These load automatically when Claude touches matching files. **Their `paths:`
frontmatter is load-bearing** — widening it taxes every turn that touches those
files, so scope a rule to the code it actually governs.

| Rule File | Applies To | Key Topics |
|-----------|-----------|-----------|
| [adapters.rules.md](.claude/rules/adapters.rules.md) | `scripts/core/adapters/`, `tests/adapters/` | New tool adapters, naming conventions, compliance enrichment |
| [reporters.rules.md](.claude/rules/reporters.rules.md) | `scripts/core/reporters/`, `tests/reporters/` | Output reporters, CommonFinding normalization |
| [python-safety.rules.md](.claude/rules/python-safety.rules.md) | All Python code | Subprocess security (CWE-78), secrets, logging |
| [mcp.rules.md](.claude/rules/mcp.rules.md) | `scripts/jmo_mcp/` | MCP entry points and their measured state |
| [windows-encoding.rules.md](.claude/rules/windows-encoding.rules.md) | CLI, reporters, dev scripts, `tests/` | Console codecs, the `PYTHONUTF8` blind spot, newline translation |
| [testing.rules.md](.claude/rules/testing.rules.md) | `tests/**/*.py`, `Makefile` | Test organization, pytest patterns, mocking, coverage |
| [testing.cross-platform.rules.md](.claude/rules/testing.cross-platform.rules.md) | `tests/`, `ci.yml` | Windows hangs, platform skips, Docker UID, marker filters |
| [release.rules.md](.claude/rules/release.rules.md) | `.github/workflows/`, `update_versions.py` | CI/CD pipelines, version management, release troubleshooting |
| [docker.rules.md](.claude/rules/docker.rules.md) | `Dockerfile*`, container code | Volumes, multi-arch, registries, arm64 limitations |

## Configuration

| File | Purpose |
|------|---------|
| `pyproject.toml` | Single declaration of all deps — runtime, extras, and `[dependency-groups] dev` (PEP 735) |
| `uv.lock` | The only lockfile. Universal, tracked, generated (NEVER hand-edit; use `make deps-lock`) |
| `versions.yaml` | Tool versions (NEVER edit manually; use `update_versions.py`) |

### jmo.yml Key Settings

The shipped `jmo.yml` and [docs/USER_GUIDE.md](docs/USER_GUIDE.md) are the key reference.

> There is **no `email` and no `schedule` key**, and no SMTP anywhere in the
> product — email goes through the Resend HTTP API
> (`scripts/core/email_service.py`) and schedules live in `~/.jmo/schedules.json`,
> managed by `jmo schedule`. Both keys were documented here in error and the "SMTP"
> wording had already propagated into a session handoff as a real hazard to plan
> around.

## Troubleshooting (Quick Lookup)

| Issue | Solution |
|-------|----------|
| Tests failing | `make test` (already carries `--maxfail=1` via `TEST_FLAGS`). No local coverage gate exists — CI's floor is 85%, in `coverage-aggregate`'s "Verify coverage threshold" step (#756) |
| Tool not found, or tool startup crash | `jmo tools check`, then `jmo tools install`; for a crash, `jmo tools clean --force && jmo tools install <tool>` |
| Pre-commit fails | `make fmt`, `make lint` |
| `No module named pytest` when the venv demonstrably has it | You are on a different interpreter. On Windows the venv is `.venv/Scripts/python.exe`, never `.venv/bin/python`, and `chmod +x` is a no-op there — so `[ -x .venv/bin/python ]` is false *whatever* exists, and PATH `python3` wins. Use `.venv/Scripts/python.exe -m pytest` or `uv run pytest` (resolves the project venv everywhere — note it syncs against `uv.lock` first). `Makefile:6` probes both layouts as of #722 |
| `uv.lock needs to be updated, but --check was provided` | Deps changed in `pyproject.toml` without relocking. `make deps-lock && git add uv.lock`. Local `uv sync` refreshes a stale lock silently; CI and pre-commit hard-fail — that asymmetry is deliberate |
| SQLite locked | `jmo history optimize` (runs VACUUM + ANALYZE; there is no `vacuum` subcommand) |
| Docker persistence | Mount `.jmo/` volume |
| Daily nightly fails, and the visible failure count is exactly 5 | `--maxfail=5` truncation. Fix the visible 5, re-dispatch with `gh workflow run scheduled.yml --ref main -f task=nightly`, repeat. See [testing.rules.md](.claude/rules/testing.rules.md) "Bug Archeology" |
| Code on main works but Docker images don't | Container code is whatever shipped in the last release tag. `scripts/cli/` and `scripts/core/` fixes don't propagate until the next `v*` tag triggers `release.yml` and rebuilds GHCR images. `tests/` fixes ARE effective immediately — pytest runs on the host |
| `PermissionError: [Errno 13]` from `Path.exists()` inside a container | Python 3.12 propagates it instead of returning False. UID mismatch on a bind mount (host 1001 vs container `USER jmo` 1000). In a test: `os.chmod(tmp_path, 0o777)` before `docker run`. In code: wrap in `try/except OSError`. See [testing.cross-platform.rules.md](.claude/rules/testing.cross-platform.rules.md) |
| `expected_tools` count off by one after a `TOOL_MATRIX` change | Don't edit a number: `tests/e2e/test_docker_workflows.py` and `.github/workflows/scheduled.yml`'s `validate-image` job both derive `expected_tools` from `len(TOOL_MATRIX)`. A mismatch means the image and the matrix disagree, so add or remove the tool in `Dockerfile` (versions via `update_versions.py`) |
| Docker build fails with `tar: not in gzip format` / `gzip: stdin: not in gzip format` | A binary download returned an HTML error page or partial body — `curl -sSL` exits 0 on HTTP errors. Every download in `Dockerfile` MUST use `curl -fsSL --retry 3 --retry-delay 5 --retry-all-errors --connect-timeout 30 --max-time 600`, plus a `gzip -t`/`xz -t`/`unzip -t` integrity check before extraction. See [docker.rules.md](.claude/rules/docker.rules.md) |
| `UnicodeEncodeError` / `UnicodeDecodeError` locally on Windows but CI is green | CI sets `PYTHONUTF8: "1"` (`ci.yml:299,318,343`), forcing UTF-8 for `open()`, `read_text()` **and** stdio — an environment no real user has. Reproduce with `PYTHONUTF8` unset. See [windows-encoding.rules.md](.claude/rules/windows-encoding.rules.md) |
| `ruff --select PLW1514` says "All checks passed" on a file that demonstrably fails to decode | It flags `p.read_text()` only when it can prove the receiver is a `Path`; it cannot type `(tmp_path / "x").read_text()` — the dominant pytest idiom. 153 flagged vs 1198 real sites. Treat the lint count as a **lower bound**, never the sole guard |
| A commit shows thousands of changed lines for a small edit | `Path.write_text()` on Windows translates `\n` → `\r\n` (`newline=None` → `os.linesep`), converting a whole LF file. Use `write_bytes()`. A file the Write tool or a script *creates* is LF, so a renamed or recreated CRLF file flips too. `scripts/dev/check_eol_flips.py` catches both (the `eol-flips` pre-commit hook and CI job; by hand, `--base origin/dev`); it diffs the whole tree because a per-file `-- "$f"` check cannot pair a rename. `grep -c $'\r'` is NOT reliable under MSYS |
| CI failures generally | Check matrix tests, coverage, pre-commit. Release-specific: [release.rules.md](.claude/rules/release.rules.md) (~25 entries). Contributor-facing: [CONTRIBUTING.md#ci-troubleshooting](CONTRIBUTING.md#ci-troubleshooting) |

## Documentation References

**Core:** [README.md](README.md) | [QUICKSTART.md](QUICKSTART.md) | [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) | [CONTRIBUTING.md](CONTRIBUTING.md) | [TEST.md](TEST.md)

**Features:** [docs/TOOLS.md](docs/TOOLS.md) | [docs/VERSION_MANAGEMENT.md](docs/VERSION_MANAGEMENT.md) | [docs/DOCKER_README.md](docs/DOCKER_README.md) | [docs/RESULTS_GUIDE.md](docs/RESULTS_GUIDE.md)

**Operations:** [docs/RELEASE.md](docs/RELEASE.md) | [docs/SCHEDULE_GUIDE.md](docs/SCHEDULE_GUIDE.md) | [docs/POLICY_AS_CODE.md](docs/POLICY_AS_CODE.md) | [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md)

**Internal (Dev-Only):** `dev-only/` — plans, archive, and internal documentation (not published)

## Notes

- Agent threads reset cwd between bash calls — use absolute paths
- Avoid emojis unless explicitly requested
- Only create documentation with long-term value; use `.claude/` for temporary work
- **Scope Discipline:** When given a bounded task ("root directory files only", "just these 13 bugs"), stay strictly within it — do not expand to adjacent directories, related systems, or broader reorganizations unless explicitly asked
