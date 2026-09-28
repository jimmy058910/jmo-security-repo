# Phase 4 — New tools in, dependency flags right: task plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** zizmor, osv-scanner and the JMo-native pack become descriptor rows that run
through `jmo scan`; trivy reads dev dependencies offline; checkov hands GitHub Actions
to zizmor; a repository with no lockfile says so (**G8**); two dependency scanners that
report one vulnerability report it once; and the eight rostered issues close, which
are #1221, #1243, #1310, #1311, #1313, #1328, #1331 and #1335.

**Architecture:** the three new tools are rows in `scripts/core/tool_descriptors.py`,
each fed by the walk that hadolint and shellcheck already use (`file_patterns` →
`collect_files` → `ctx.files`, and `skipped:<no_files_reason>` when the walk finds
nothing). That one mechanism gives osv-scanner its `-L` list and G8, gives zizmor
JMo's exclusion list (it has no exclude flag), and keeps both tools' paths
repository-relative. The native pack is JMo's own runner (as `yara_runner` is), not a
rule file handed to a third-party engine. Dependency findings get an identity of their
own, because location-based clustering can never pair them (measured below).

**Tech Stack:** Python 3.12, pytest (+xdist), SQLite, zizmor 1.30.1, osv-scanner 2.6.0
(new pin; the Phase 1 golden is 2.5.1), trivy 0.74.0, checkov 3.3.16, GitHub Actions,
Docker (WSL only on this machine).

**Spec:** [2026-09-12-v2.0.0-program-design.md](../specs/2026-09-12-v2.0.0-program-design.md)
§3, §4.3 (G8), §6 row 4; program plan
[2026-09-12-v2.0.0-program.md](2026-09-12-v2.0.0-program.md) § Phase 4; the model is
[the Phase 3 task plan](2026-09-24-phase-3-descriptor-table.md).

## Global Constraints

Copied from the program plan and the Phase 3 task plan; every task includes these.

- **Backward compatibility is NOT a constraint.** No users. Fingerprints of trivy
  misconfigurations and of dependency findings change once, deliberately.
- **One formatter:** `ruff format`. `make` is not on PATH: run `pre-commit run --all-files`.
- **No `shell=True`.** Every `subprocess.run` passes `timeout=`.
- **Conventional commits, no AI-attribution markers of any kind** (no `Co-Authored-By`,
  no "Generated with", no `Claude-Session:`), in commits and PR bodies.
- **Commit and merge only when Jimmy says.** Never to `dev`; PR into it, squash.
  `Closes #N` goes in the COMMIT; a PR body into `dev` is inert.
- **The `dev` → `main` sync is a fast-forward push, never a PR** (`release.rules.md`).
- **Gates are numbers through `jmo scan` / `jmo report`, never a bare binary.** Every
  spawned `jmo scan` / `jmo ci` gets `--history-db <tmp>` and `--results-dir <tmp>`.
- **Line endings over the whole diff:** `python scripts/dev/check_eol_flips.py --base
  origin/dev` after `git add`. Scripts write with `write_bytes`.
- **Suite from Git Bash, `PYTHONUTF8` unset, foreground, three parts under 10 min**
  (`tests/cli` | `tests/unit tests/core tests/adapters` | the rest):
  `JMO_THREADS=2 .venv/Scripts/python.exe -m pytest <part> -n 8 -q -rfEs -m "not smoke and not requires_tools and not docker"`.
  Windows-skipped files under WSL (carried: 2 environment failures).
- **Baselines.** Local 9171 / 99 / 0 at `dda79bde`. `windows-2022` at `292d3cff`:
  9155 / 92 / 195. macOS (push only) 9224 / 49 / 169. **Diff failing-test ID sets,
  never counts. Read the `windows-2022` and `docker-smoke` logs, never their ticks.**
- **Mutation-test every guard** from a byte backup; re-anchor after `ruff --fix`.
- **Never edit tool versions in `Dockerfile` by hand**: `versions.yaml`, then
  `python3 scripts/dev/update_versions.py --sync`.
- **Nothing about a private repository goes into this public repository** beyond
  timings and counts. bracketforge, BetHedgeSlider and jmoadaptivegolf are measured on
  `git archive` exports in a scratch directory, never in place.
- **Backslash edits via Edit/Write, never a heredoc** (measured again 2026-09-27: a
  quoted-delimiter heredoc turned `\\` into `\`). A markdown line starting `#NNNN` is a
  heading (MD018).
- Do not touch `.jmo/history.db` or its snapshots, `dev-only/`, stray merged branches,
  or the bot PRs.

## Measured before this plan was written (2026-09-27)

A throwaway worktree at `292d3cff` carried spike rows for zizmor and osv-scanner and a
`--scanners` override for trivy, so every number below came through a real `jmo scan`
(`--history-db`, `--results-dir` in tmp). The spike is not the implementation; it is
deleted with the scratchpad. Binaries: zizmor 1.30.1 and osv-scanner 2.5.1 from the
evidence archive; osv-scanner 2.6.0 downloaded, sha256 equal to the release's
`SHA256SUMS`.

### zizmor

| Claim | Measured |
|---|---|
| The program's "217 offline" | True **only at `3098c766`**, the golden's commit: a `git archive` of it through `jmo scan` gives **217 raw = the golden, 216 post-dedup** (one pair is a real duplicate: `github-env` at `.github/actions/setup-python-jmo/action.yml:37:7`, reported twice). **HEAD `292d3cff`: 214 raw, 213 post-dedup.** A gate of "217 on this repository" fails on today's tree |
| `--offline` vs `--no-online-audits` | Both 217. `--offline` forbids every network operation; `--no-online-audits` only drops online audits. zizmor reads `GH_TOKEN`/`GITHUB_TOKEN` from the environment, so the stronger switch is the one that holds when a token is set |
| Exit codes | 10-14 on findings by default; `--no-exit-codes` makes a clean run and a run with findings both rc 0, so any nonzero is a real failure |
| Directory input (`zizmor .`) | Repository-relative URIs, as the golden. But it **collects vendored trees**: a fixture with a planted `node_modules/evil/.github/workflows/ci.yml` and `vendor/act/action.yml` gave 10 findings, 7 of them in those two trees; with a `.git` and a `.gitignore` naming `node_modules/`, 5 (vendor still read). zizmor has no exclude flag |
| Walk-fed, absolute paths | **Absolute URIs** (a finding's id would depend on where the checkout lives: the defect PR C fixed for gitleaks), and 211 at `3098c766`: the 6 `dependabot-cooldown` findings in `.github/dependabot.yml` are lost, since the walk's patterns did not name it |
| **Walk-fed, repository-relative, run from the root, `dependabot.yml` in the patterns** | **217 at `3098c766` (URIs identical to the golden's), 214 at HEAD, 3 on the vendored fixture (only the repository's own workflow).** This is the row |
| Release assets | Five archives named by target triple (`x86_64-unknown-linux-gnu.tar.gz`, `aarch64-…`, `x86_64-pc-windows-msvc.zip`, two darwin); **no checksum file**; no Windows arm64 |

### osv-scanner

| Claim | Measured |
|---|---|
| A directory on Windows | 2.5.1 and 2.6.0, relative, `./`, and absolute forms alike: "Starting filesystem walk for root: C:\\", **1 dir visited, 0 Extract calls, rc 128, "No package sources found"**. Not a drive walk, as the coverage review read it: a silent nothing. JMo must pass `-L` per lockfile |
| `-L` on NodeGoat | online **304** on both versions (the golden's 303 was 2026-09-12); offline **304**. Through `jmo scan`: **304 raw, 292 post-dedup**. The golden's 303 results are all present; the one new is `CVE-2026-77301` (adm-zip@0.4.4). Phase 1 recorded 291 post-dedup: the same 12 byte-identical duplicates, plus that one |
| Offline database | Per ecosystem, fetched lazily by `--download-offline-databases`: npm **206 MB**, PyPI 33, Go 11, Packagist 10, Maven 9, RubyGems 4, crates.io 3, NuGet 2; about 280 MB for the ten. **The download flag fetches mid-scan** (measured: Go and PyPI arrived during a scan, 207 → 252 MB). A missing database under `--offline-vulnerabilities`: **rc 127**, "no offline version of the OSV database is available", 0 results (loud, so the row is `failed`, not a silent clean) |
| One unsupported input | `go.sum` in the `-L` list: **rc 127 and no output at all**; the other lockfiles' findings are lost with it (reproduced on 2.6.0). A prose file named `requirements-notes.txt` is tolerated (rc 1, the rest kept) |
| SARIF shape | Rule ids are CVE ids; `rules[].deprecatedIds` holds the aliases (CVE and GHSA); `properties.security-severity` holds the CVSS score. **No structured package or version**: only the message template, `Package 'minimatch@3.1.2' is vulnerable to 'CVE-…' (also known as 'GHSA-…').` URIs are absolute `file:///` (Phase 1 already decodes them) |
| Release assets | Raw binaries `osv-scanner_{linux,darwin,windows}_{amd64,arm64}[.exe]` and `osv-scanner_SHA256SUMS`; latest **2.6.0** (2026-09-14) |

### trivy, and dependency identity

| Claim | Measured |
|---|---|
| Where the flags live | The descriptor, `_trivy("fs", "--scanners", "vuln,secret,misconfig")`; the program plan's `jmo.yml:45-46` is stale |
| jmoadaptivegolf as shipped | **0**: the coverage review's "golf 0" reproduced (dev dependencies are skipped by default) |
| With `--scanners vuln,misconfig,license --include-dev-deps --offline-scan` | raw **47 vulnerabilities + 408 license entries**; the report keeps **38**. The 47 are 38 distinct (package, id): **the same CVE in two installed versions of a package shares one id**, because trivy's message is the advisory title |
| osv-scanner on the same export | **47 raw, 47 post-dedup** (its message names the version). The same 38 (package, id) as trivy: no id is unique to either tool |
| Both together | **85 post-dedup, 0 clusters.** `dedup_enhanced.py:396-397` returns location similarity 0.0 when either finding has no line, and a dependency finding never has one, so two dependency scanners reach at most 0.25 + 0.25 = 0.50 against the 0.65 threshold. **No two dependency scanners have ever clustered** (trivy and grype included) |
| juice-shop at `1618a611` | commits no lockfile (`.npmrc`: `package-lock=false`). The spike's osv-scanner row reads **`skipped:no lockfile`** (G8). trivy's row reads `ran`: its 89 are all misconfigurations, 0 vulnerabilities; per-tool accounting cannot say that trivy's vulnerability pass read nothing |
| trivy misconfigurations lose their lines | juice-shop: 89 raw are **87 distinct (target, ID, lines)**, and the report keeps **47 = the distinct (target, ID)**. `trivy_adapter.py:140` reads a top-level `StartLine`; 0.74.0 puts it in `CauseMetadata.StartLine`, so every misconfiguration is line 0 and same-rule findings in one file share an id. **40 real findings dropped on one repository.** Not in #1221's body, and no issue has it |

### The native pack

| Claim | Measured |
|---|---|
| The review's fixture | `fixture-vibe/` was never archived (Phase 0 missed it) and its files are **gone** from the 2026-09-12 scratchpad (directories dated 2026-09-18, empty). "5 of 5" was five findings of three rules on a three-file fixture, not five checks |
| The fifth check | The spec's Firebase rule (`allow read, write: if true`) was **never prototyped** |
| Rebuilt fixture (scratch): RLS in three states, a public-prefix secret in `.env.example` and in source, `service_role` in client code and in an API route, `dangerouslyAllowBrowser`, open and closed Firebase rules | 8 expected findings |
| The three archived rules through `jmo scan` (`per_tool.semgrep.configs`) | **5 = 4 expected + 1 false positive**: `pattern-regex: 'service_role'` matched a comment. No Firebase rule, so the open `firestore.rules` is missed. `rls_check.py`: 3 of 3 states right |
| The three real apps (`git archive` of HEAD) | bracketforge `d616391`, BetHedgeSlider `e30ef6d`, jmoadaptivegolf `95753ba`: **0, 0, 0 findings, 0 errors**, 805 + 294 + 71 files. None has `supabase/migrations` or a `*.rules` file, so the RLS and Firebase checks **have no real-app negative control** |
| Planted `NEXT_PUBLIC_STRIPE_SECRET_KEY=placeholder` in bracketforge's `.env.example` (scratch copy) | **caught, 1 finding** (line 148) |
| An engine-free Python runner of all five checks | **8 of 8** on the fixture (comments stripped, so no false positive; Firebase included); the planted key 1; the other two apps 0; 0.2–4 s. The engine choice is open (Decisions) |

### Short output flags (#1335) and trivy's JSON (#1221)

Each spelling was run against a small fixture and judged by what the tool wrote, then
through `tool_flags(...)` and, for the worst, through `jmo scan`.

| Claim | Measured |
|---|---|
| Through `jmo scan` | Five configured flags took one fixture's findings from **57 to 0 with rc 0**: four attached or clustered (`trivy -ftable`, `grype -otable`, `hadolint -ftty`, `gitleaks -vfjson`) and one repeated (`--no-verification`, which JMo already passes trufflehog). The trivy, grype and gitleaks rows still read **`ran`** |
| #1325's attached-value rule | checks `token[:2]`, so a **cluster** of short flags passes: `-qftable`, `-vftable`, `-qotable`, `-socli`, `-Vftty`, and gitleaks' own `-vfjson`, `-vr<path>`, `-vc<file>` all parse and none is refused. The issue's proposed per-tool sets still miss all 17 cluster cases (simulated); **a walk over each tool's no-value short flags catches all 17** and kept every real flag tried |
| A report written into the scanned tree | `gitleaks … -vrREPORT.sarif` wrote the **unredacted** secret report into the repository, since gitleaks runs with `cwd` = the repository |
| grype and syft `-o` | appends an output rather than replacing it, so even `-ojson` breaks them; their `--file` is not reserved and leaves stdout empty |
| Long spellings not refused today | nuclei `-jsonl=false`, `-output x`; gosec `-fmt=text`, `--fmt text`, `-out=x`; osv-scanner `-format table`, `--output-file x`; semgrep `--text`; yara_runner `--o`/`--ou`/`--outp` (argparse abbreviations: `allow_abbrev=False`) |
| The shared set refuses real flags | grype `-f` (`--fail-on`), semgrep `-f` (`--config`), checkov `-f` (`--file`), shellcheck `-o all` (`--enable`: 9 findings became 6 when refused), zizmor `-o` (`--offline`) |
| Parser families | Go's stdlib `flag`, urfave/cli and clap reject an attached value loudly; nuclei, gosec and osv-scanner must NOT get the attached-value rule, which would refuse nuclei's `-omit-raw`, `-or`, `-ot`, `-je` |
| #1221 at trivy 0.74.0 | All 34 misconfigurations on the fixture carry `ID` (`DS-0001`, `KSV-0001`, `AWS-0086`); none has `AVDID` or `RuleID`. The adapter makes `Title` the ruleId for all 34, **and for secrets too** (`github-pat` becomes "GitHub Personal Access Token") |
| Two more trivy adapter defects | `startLine` 0 on all 34 (`CauseMetadata.StartLine`, as juice-shop showed); **`tool.version` `unknown`**, since 0.74.0 writes it at `Trivy.Version` (#1333's class, for another tool) |
| Licenses | A separate `Results[]` entry with `Class: "license"` and a `Licenses` array; **the adapter ignores it, so the license scanner adds 0 findings** |
| `--include-dev-deps` | a node fixture 10 → 12; NodeGoat 87 → 313 |
| A trivy golden | none has ever existed (only trivy-rbac's, deleted with it) |

### checkov's exclusions (#1313) and its narrowing

checkov 3.3.16 from JMo's venv (`checkov.cmd`), through unmodified `jmo scan`, through
JMo's own `ToolRunner` with chosen `--skip-path` values, and on Linux in
`jmo-security-dev:v2`.

| Claim | Measured |
|---|---|
| "This host's checkov is broken" | **False.** It runs through `jmo scan` (row `ran`). The `No module named 'checkov'` came from launching `checkov.cmd` bare, which runs the first `python.exe` on `PATH`; JMo puts the venv's `Scripts` first (`tool_runner.py:467-493`). The semgrep launcher artifact again |
| How checkov applies `--skip-path` | `re.search` against the **absolute** path, with a literal-substring fallback, escaping only values that start with a dot (`base_runner.py:241-248`) |
| The substring defect | real: `vendor` drops `vendor-accounts.tf`, `venv` drops `envs/devenv/main.tf`, `results` drops `modules/results-bucket/main.tf`, and **`.git` drops every `.github/workflows` finding**. The row reads `ran` |
| The root-prefix defect | real, Windows and Linux: a repository under `vendor/`, under `vendor-portal/`, or under `results/` with its results inside it, scans **nothing**: `resource_count: 0`, exit 0, row `ran` |
| #1313's proposed `(^\|[\\/])NAME([\\/]\|$)` | **crashes checkov.** On Windows, cmd.exe re-parses the `\|` and `^` of a `.cmd` tool's arguments (Python's `list2cmdline` quotes only arguments with spaces): rc 255 in 0.15 s. On every platform an unguarded `re.compile` (`module_finder.py:63`) raises: rc 2, no output |
| **`[\\/]NAME$`, the name escaped** | works on 8 roots, through cmd.exe, through a real `jmo scan` with only the rendering patched, and on Linux. checkov tests `<walked dir>\<entry>` as it walks, so an end-anchored pattern can only match the entry itself, never a folder of the scan root |
| Actions under checkov | **never read under JMo**, because `.git` also skipped `.github`. On bracketforge checkov runs 293 s, triggered only by 5 workflows, and finds nothing |
| `--framework terraform cloudformation helm` | space-, comma- and repeat-separated all work. bracketforge **8.7 s instead of 246.8 s**; the `secrets` framework alone took 195.8 s |
| `helm` | **dead in both environments**: no helm binary on the host or in the image, and checkov disables the framework without a word. `.tf.json` is read only by `terraform_json`, which the narrowed list drops while the trigger still fires on it. trivy reads charts, Kubernetes, Dockerfiles and `.tf.json` |

### zap and nuclei with an OpenAPI definition (#1331)

A standard-library fixture on 127.0.0.1 (`GET /api/items?q&limit`, `GET
/api/items/{id}`, `POST /api/login`, `GET /api/admin/users`, no links from `/`) that
logs every request, and can act as the tools' upstream proxy so that a request to any
other host is logged and answered 502 without resolving. Its spec names
`servers: [http://prod.invalid/]`. ZAP 2.17.0 (add-ons openapi 48.0.0, automation
0.58.0, reports 0.43.0) on **Java 21.0.12**; nuclei 3.11.0.

| Claim | Measured |
|---|---|
| Today's command (`-quickurl <url> -quickout`) | reaches **0 of 4** spec operations: rc 0, 33.7 s, 94 requests, 4 alerts |
| `-openapifile` + `-openapitargeturl` + `-quickurl http://h/` | imports first but attacks nothing it imported: 1 request per operation, 0 payloads |
| The same with `-quickurl http://h` (no trailing slash), and with `-openapiurl` | attacks them: ~1,145 requests, 296 payloads on `items`, 301 on `login`; the `{id}` path parameter gets 0 |
| **A trailing slash breaks today's `--url` scan too** | on a spiderable fixture, `http://h/` missed a reflected XSS (1 request, 0 payloads, 0 High); `http://h` found it (227 requests, 149 payloads, 1 High). No issue has it |
| An automation plan (`-cmd -autorun plan.yaml`: context, `openapi` job with `targetUrl`, `passiveScan-wait`, `activeScan`, `report` as `traditional-json`) | rc 0, 45.0 s, 1,469 requests, payloads on 3 of 4 operations **including `{id}`** (150); JMo's adapter parses the report (7 findings). A failed import: rc 1 and no report (the `-cmd -openapi*` form says rc 0) |
| **No explicit target** | a plan whose context named only 127.0.0.1 sent **1,276 requests (753 payloads) to the spec's `prod.invalid`**; the `-cmd` imports sent 4 and 8. zap.log names no reachable host at all |
| `targetUrl` and the spec's path | `http://h` keeps the spec's `/v1`, `http://h/` drops it, `http://h/v2` replaces it |
| `-silent` | removes zap's own calls home (6–13 connections to `*.zaproxy.org` per run); 1,471 vs 1,469 requests, the same 7 findings |
| nuclei | reads a spec with `-im openapi -l <spec> -sfv` (257 requests, 3 of 4 operations fuzzed) but **cannot override the target**: `-u` is taken as a second spec (FTL, rc 1), and the spec as given sent 278 requests (212 payloads) to `prod.invalid`. Without `-sfv` it exits 1 and writes `required_openapi_params.yaml` into its working directory. JMo's current nuclei command hit the 300 s cap on this fixture (rc 124) |
| **Every zap finding is MEDIUM** | `zap_adapter.py:93` reads `alert.get("risk") or "Medium"`; ZAP 2.17 writes `riskcode`/`riskdesc`, never `risk`. A High XSS came out `MEDIUM ZAP-79`, so `--fail-on HIGH` does not stop on it; the tests feed an invented `risk` key. No issue has it |

### gosec and Go (#1310)

Fixtures: a no-dependency module with G404 and G104 bait; a module requiring
`github.com/google/uuid`, with `go.sum`; the same vendored; one whose `go.mod` asks for a
newer Go than is installed.

| Claim | Measured |
|---|---|
| Without Go | gosec exits **1** (the issue said 1, the coverage review 0: settled; it exits 0 only with `-quiet` or `-no-fail`). The row is `failed:examined 0 files`; `Golang errors`: `go command required, not found` |
| With go1.27.1 on `PATH` | `Stats.files` 1, G404 and G104 found, natively (gosec 2.28.0) and in the image (2.29.0); 4.0–4.6 s with a cold build cache, 0.13–0.42 s warm |
| Toolchain size | Windows zip 78.9 MB → 246.9 MB, 15,639 files. Linux tarball 70.6 MB → 243.9 MB; trimmed to 189.6 MB, gosec still works. As an image layer about **71.6 MB compressed, 57.8 MB trimmed**, against today's image of 1,280 MB compressed / 2,438 MB unpacked. apt's `golang-go`: +228 MB for **go1.22.2**, which cannot load a `go.mod` asking for 1.23 or later without downloading a toolchain |
| **Network during a scan** | **Yes, by default**: the module cache grew 0 → 110 KB (uuid) mid-scan, and `GOTOOLCHAIN=auto` (the default in both builds) started `go: downloading go1.28.0` |
| `GOPROXY=off`, empty cache | gosec **degrades silently**: `files` 1, G404 still found, `could not import github.com/google/uuid`, and the row reads **`ran`** with no warning. A populated module cache or a vendored tree loads cleanly offline; `GOTOOLCHAIN=local` with a too-new `go.mod` is `failed:examined 0 files` |
| `jmo tools check` | `execution_commands=("gosec", "go")` gives `NOT READY -> Missing: go`, exit 1 (simulated); the wizard then fails `Unknown dependency: go` unless `install_config` gains a `go` entry |
| Found on the way | `gosec_adapter.py:179` reads the version from `Golang errors`, so every gosec finding reports `tool.version` `unknown`. The WSL image `jmo-security-dev:v2` predates Phase 3 |

### Issues and CI

| Claim | Measured |
|---|---|
| #1243 | `diff_engine.py:698` still reads `cvss.baseScore`. osv-scanner findings now carry `cvss.score` (47 of 47 on golf, through the SARIF importer); **trivy findings carry no `cvss` at all**, though trivy's raw output has `CVSS` |
| #1311 | `gitlab_scanner.py:352`, `scan_image(  # type: ignore[call-arg]` with `tool_exists_func`, unchanged. Only GitLab targets discover images; a `--repo` scan never has |
| #1328 | trufflehog + gitleaks on juice-shop: **76 post-dedup, 1 cluster**. Five places where both tools report one line stay apart: `PrivateKey`/`private-key` ×2, `JWT`/`jwt` ×2, `JWT`/`jwt`/`generic-api-key` ×1. `rule_equivalence.py` lists `aws-access-token` and `github-pat`, which are **gitleaks** rule ids, under the tool name `trufflehog`, so they can never match |
| CI's "Tool Smoke Tests (Juice-Shop Fixture)" | **22 skipped, 0 passed** in the dispatched nightly at `292d3cff`: `tests/integration/juice_shop_fixture/` is **gitignored** (`.gitignore:245`, since `70900945`, 2026-02-01), so no checkout has it and every test skips. It exists on this machine only, as juice-shop 16.0.0. No issue has it |
| juice-shop's freshness | The archived `1618a611` **is** juice-shop's `master` today, release v20.2.0 (2026-08-10); `develop` is 235 commits ahead, unreleased. The e2e tests clone the default branch unpinned |
| Why the smoke fixture is ignored | `70900945`'s message: "excluded due to intentional test secrets triggering GitHub push protection" (2 of its 15 files hold a PEM block). The CI job that needs it was never changed |
| Where a dependency identity can live | CommonFinding has no package field; `secretContext` (Phase 3) is the precedent for a typed sub-object. `fingerprint()` (`common_finding.py:202`) already appends optional components (`\|column`, `\|@commit`) that leave every other id unchanged |

## Program-plan corrections (land in PR A)

The program plan's Phase 4 gates were written before any of this ran. Each correction
below replaces a number that would fail, or pass for the wrong reason:

| Gate as written | Corrected |
|---|---|
| "zizmor on this repository = 217" | zizmor through `jmo scan` on a `git archive` of `3098c766` (the golden's commit) = **217 raw, 216 post-dedup, ids equal to the golden's**; on HEAD, the number measured at the PR, recorded |
| "osv-scanner = the Phase 1 golden count" | through `jmo scan` on NodeGoat `c5cb68a7`: every one of the golden's 303 results present, and post-dedup = **291 + the advisories published since 2026-09-12** (292 on 2026-09-27, the one named). An online count only grows; the offline database is dated |
| "native pack 5/5 on the fixture" | the rebuilt, tracked fixture: **8 of 8**, one per check and state, with a named negative for each (an API route, a closed rule file, a comment) |
| "jmoadaptivegolf = 38 … dedup → 38" | **47** (package, version, id; decision 4), **from trivy, from osv-scanner, and from both together**; today both together are 85 |
| "trivy `vuln,secret,misconfig` (`jmo.yml:45-46`)" | the flags live in the descriptor |

## Decided from measurement (veto any in review)

- **zizmor is walk-fed with repository-relative paths**, run from the repository root:
  `zizmor --format sarif --offline --no-exit-codes <rel paths>`. Patterns:
  `.github/workflows/*.yml`, `.github/workflows/*.yaml`, `**/action.yml`,
  `**/action.yaml`, `.github/dependabot.yml`, `.github/dependabot.yaml`. No match is
  `skipped:no GitHub Actions workflows`. `--offline`, not `--no-online-audits`: a
  token in the environment must not turn a scan into network calls.
- **osv-scanner is walk-fed** with exactly the names 2.6.0 accepts through `-L`
  (measured one by one, 2026-09-27): `package-lock.json`, `npm-shrinkwrap.json`,
  `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `requirements*.txt`, `poetry.lock`,
  `Pipfile.lock`, `pdm.lock`, `uv.lock`, `pylock.toml`, `go.mod`, `Cargo.lock`,
  `composer.lock`, `Gemfile.lock`, `gradle.lockfile`, `pom.xml`, `packages.lock.json`,
  `packages.config`, `pubspec.lock`, `mix.lock`, `renv.lock`, `conan.lock`. Rejected
  (each aborts the whole run, rc 127, no output): `go.sum`, `requirements.in`,
  `package.json`, `Pipfile`, `pyproject.toml`, `verification-metadata.xml`,
  `deps.json`. No match is `skipped:no lockfile` (G8).
- **One osv-scanner invocation for every lockfile; on rc 127 with an extraction error,
  one invocation per lockfile.** A single truncated `package-lock.json` in a
  subdirectory cost all 304 of NodeGoat's results (rc 127, no output), and a
  per-lockfile run costs the database load each time (npm ~11 s even for a one-package
  lockfile, PyPI ~3 s). The row is `failed`, and its detail names each lockfile that
  failed; the others' findings are kept.
- **Scans never download.** `--offline-vulnerabilities` without
  `--download-offline-databases`, and `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` pointed at
  JMo's own cache. A lockfile whose ecosystem has no database is
  `failed:offline database missing`, naming `jmo tools update`, decided before the
  run (osv-scanner's own rc 127 would read `unaccepted exit code`).
- **trivy's repository scan turns its secret pass off; its image scan keeps it.**
  gitleaks and trufflehog read a repository; nothing else reads an image's layers for
  secrets.
- **trivy gains `--offline-scan`**: the coverage review measured a Maven lookup failing
  twice with 429 and producing no output; the vulnerability database is already local.

## PR sequence

Each PR into `dev`, green before the next is cut from it. The tool count moves in Z,
O and N, and `tests/unit/test_tool_catalogue_count_claims.py` makes each of those
touch the ~25 documents that state it.

| PR | Carries | Closes |
|---|---|---|
| **A** | this plan; the program-plan corrections; Phase 3 marked landed; the new issues filed and rostered; report-side fixes that touch no scan-engine code: trivy's rule id and lines, CVSS for the diff tier, gitleaks' rule equivalences | #1221 #1243 #1328 |
| **Z** | zizmor's row, installer, image; checkov hands Actions over (trigger and `--framework`); checkov's exclusions | #1313 |
| **O** | osv-scanner's row, installer, image and offline database; trivy's dependency flags; one identity per dependency finding, so two scanners' reports of one vulnerability cluster | #1346 |
| **N** | the `jmo-native` row, its runner and its tracked fixture | — |
| **G** | gosec removed (#1310); GitLab targets scan the images they reference (#1311); every tool's short output flags, new rows included | #1310 #1311 #1335 |
| **API** | zap's OpenAPI import: a new invocation with its own target rules, on its own PR as PR T was | #1331 #1347 #1348 |

A precedes Z because the corrections change Z's gate. Z precedes O only for review
size; O and N are independent. G follows N because #1335 covers the new rows' flags.

---

## Task A1: Plan text (PR A)

**Files:** `docs/superpowers/plans/2026-09-12-v2.0.0-program.md` (§ Phase 4, the
summary table), this file.

- [x] Phase 3's summary row: `on dev as 3d1a4bf8 025edd01 b451dc31 66b3ab49 2fc7fc30
  dda79bde + a2d4010a; on main at 292d3cff`; the Phase 3 task plan's Acceptance gains
  its measured table (the 13-row clause re-run at `292d3cff`).
- [x] § Phase 4 "Acceptance": the corrected gates above. "Measure first": done, this file.
  Remove the `jmo.yml:45-46` citation. Record decisions 1-7 in its "Why here".
- [x] § Phase 5 "Measure first" gains the two measured traps (Defender quarantines two
  opengrep-rules test files; `generic/secrets` trips secret scanning). § Phase 6 gains
  the answer-key targets (decision 9).
- [x] Search again, then file six issues **immediately before pushing** (decision 8),
  each body carrying its measurement from this plan, and roster them: dependency
  scanners never cluster (`phase:4`); zap severity always MEDIUM (`phase:4`); a trailing
  slash stops zap's spider (`phase:4`); the vacuous juice-shop smoke job (`phase:6`);
  the schema missing from the wheel and image (`phase:8`); nuclei's spec import (after
  the tag). Rosters move Phase 4 8 → 11, Phase 6 3 → 4, Phase 8 9 → 10, after the tag
  26 → 27, `before tag` 95 → 100. Amend #1221's body with the lines and the version.
  Filing reddens every open PR's `phase-audit` until this merges.
- [x] `phase_audit.py derive` exit 0; `verify` unclaimed 0; `test_real_plan_parses` green.

## Task A2: trivy's rule id and lines (#1221, and the line defect)

**Files:** `scripts/core/adapters/trivy_adapter.py:120-170`,
`tests/adapters/test_trivy_adapter.py`, a new fixture
`tests/fixtures/samples/trivy/misconfig-0.74.json` (trivy's own output on three
files, recorded with its command).

- [ ] Red first, from the recorded 0.74.0 output: a misconfiguration's `ruleId` is its
  `ID` (`DS-0001`, `KSV-0109`, `AVD-AWS-…` as trivy prints them), its `title` is
  `Title`, and its `startLine`/`endLine` are `CauseMetadata.StartLine`/`EndLine`. Today:
  the title, and 0.
- [ ] The chain becomes `VulnerabilityID → ID → RuleID → Title → tag`, for secrets too
  (`github-pat`, not its title); `title=` keeps `Title`; the line reads `CauseMetadata`
  first, then the top-level key; `tool.version` reads `Trivy.Version` (0.74.0), today
  `unknown` on every trivy finding. Red first for each.
- [ ] Gate through `jmo scan --tools trivy` on juice-shop `1618a611`: post-dedup trivy
  findings = the distinct (target, ID, lines) of the raw output (**87** measured, from
  47), and no two findings share an id.
- [ ] Mutations: drop `ID` from the chain; read the top-level line only; each caught.

## Task A3: the diff's CVSS tier (#1243)

**Files:** `scripts/core/diff_engine.py:698`, `scripts/core/adapters/trivy_adapter.py`
(vulnerabilities), `tests/unit/test_diff_engine*.py`.

- [ ] Red first: a finding with `cvss: {"score": 9.8}` scores 98, one with 9.0 scores
  90, and one with no `cvss` takes the severity fallback. Today both take 90.
- [ ] Read `score` (the schema's required key, and what `history_db.py` and the SARIF
  importer use).
- [ ] trivy's vulnerabilities write `cvss.score` from their `CVSS` block (NVD's V3
  score first, then the vendor's). Measured: 0 of 38 trivy findings on golf carry
  `cvss` today, against 47 of 47 osv-scanner findings.
- [ ] Mutation: restore `baseScore`; the 98 case fails.

## Task A4: rule equivalences for gitleaks (#1328)

**Files:** `scripts/core/rule_equivalence.py:163-176`, `tests/unit/test_rule_equivalence*.py`.

- [ ] Red first, through `jmo report` on the trufflehog and gitleaks outputs of
  juice-shop `1618a611`: today 76 post-dedup, 1 cluster, and five same-line pairs
  apart (`PrivateKey`/`private-key` ×2, `JWT`/`jwt` ×2, `JWT`/`jwt`/`generic-api-key`).
- [ ] Add gitleaks' ids to the secret classes under the tool name `gitleaks`, a
  `secret-jwt` class, and move `aws-access-token` and `github-pat` (gitleaks ids,
  listed under `trufflehog`) to `gitleaks`. Ids come from gitleaks 8.30.1's default
  config, not from memory.
- [ ] Gate: juice-shop's five pairs cluster (76 → 71, or the measured number with the
  pair list); and a negative, **two different keys on one line stay two** (columns 82
  and 116, #1242's shape), through `jmo report`.
- [ ] Mutation: remove the `private-key` mapping; the two `PrivateKey` pairs split again.

## Task A5: gates, then PR A

- [ ] Touched test files, then the bounded suite (three parts); diff failing IDs
  against `dda79bde`'s empty set. `pre-commit run --all-files`; `check_eol_flips.py`.
- [ ] PR body: the numbers; one `Closes #N` per commit at squash time.

---

## Task Z1: zizmor's row

**Files:** `scripts/core/tool_descriptors.py` (a `_zizmor_repo` builder and a row),
`scripts/core/scan_timings.py` (`Reason.NO_WORKFLOWS` in `SKIP_REASONS`),
`versions.yaml`, `scripts/core/install_config.py`, `Dockerfile` (via
`update_versions.py --sync`), `tests/unit/test_tool_descriptors.py`,
`tests/integration/test_tool_contracts.py`, the documents the count test names.

**Interfaces:**
- Produces: `DESCRIPTORS["zizmor"]`; `Reason.NO_WORKFLOWS = "no GitHub Actions workflows"`.
  `TOOL_MATRIX` gains `zizmor` (13 → 14).

- [ ] Red first: `jmo scan --tools zizmor` exits 2 today ("unknown tool"); a workflow-less
  repository must read `skipped:no GitHub Actions workflows`; a vendored
  `node_modules/x/action.yml` must not be read.
- [ ] The builder, as the spike measured it:

```python
def _zizmor_repo(ctx: ScanContext) -> list[Invocation]:
    # Walk-fed and repository-relative, run from the root: zizmor has no
    # exclude flag and reads vendored workflows (a planted node_modules
    # workflow was audited, measured 1.30.1), and an absolute input puts an
    # absolute URI, so a checkout-dependent id, in every finding.
    root = Path(scan_root(ctx.target)).resolve()
    inputs = [Path(f).resolve().relative_to(root).as_posix() for f in ctx.files]
    return [
        Invocation(
            command=(
                ctx.binary, "--format", "sarif",
                # --offline, not --no-online-audits: zizmor reads GH_TOKEN,
                # and a scan makes no network call.
                "--offline", "--no-exit-codes",
                *ctx.flags, *inputs,
            ),
            output_file=ctx.output,
            capture_stdout=True,
            ok_return_codes=(0,),
            cwd=root,
        )
    ]
```

- [ ] The row: `exclusion_style=ExclusionStyle.WALK`, the six patterns above,
  `no_files_reason=Reason.NO_WORKFLOWS`, `version_probe` `zizmor\s+v?(\d+\.\d+\.\d+)`,
  `stub={"version": "2.1.0", "runs": []}`.
- [ ] Install: `versions.yaml` `zizmor` 1.30.1, `release_pattern`
  `zizmor-{arch_aarch}-unknown-linux-gnu.tar.gz`; Windows `x86_64-pc-windows-msvc.zip`,
  no Windows arm64 (say so in `jmo tools check`'s hint). zizmor publishes no checksum
  file.
- [ ] Gates through `jmo scan --tools zizmor`: a `git archive` of `3098c766` gives **217
  raw, 216 post-dedup, and ids equal to the golden's expected findings**; HEAD's number
  recorded; the vendored fixture gives the repository's own workflow only; a
  workflow-less fixture reads `skipped:no GitHub Actions workflows`.

## Task Z2: checkov hands GitHub Actions to zizmor

**Files:** `scripts/core/tool_descriptors.py` (`_iac_trigger`, `_checkov`),
`scripts/core/scan_timings.py` (`Reason.NO_IAC`'s text), tests beside each.

- [ ] Red first: a repository whose only content is `.github/workflows/ci.yml` reads
  checkov `ran` today; it must read `skipped:no IaC files`, with zizmor `ran`.
- [ ] `_iac_trigger` stops counting `.github/workflows`; `Reason.NO_IAC` says
  "no IaC files"; checkov gets `--framework terraform terraform_json cloudformation`.
  **Not helm**: no helm binary exists on the host or in the image, and checkov
  disables the framework silently (measured); trivy reads charts. `terraform_json`
  because the trigger fires on `.tf.json`, which only that framework reads.
- [ ] Gate: bracketforge's export through `jmo scan --tools checkov zizmor`: checkov
  `skipped:no IaC files` (it spent 293 s there for nothing), zizmor `ran`.

## Task Z3: checkov's exclusions (#1313)

**Files:** `scripts/cli/scan_utils.py` (`tool_exclusion_flags`, the `REGEX` style),
`scripts/core/tool_descriptors.py` (`ExclusionStyle.REGEX`'s comment), tests beside each.

- [ ] Red first, through `jmo scan` on a fixture holding `main.tf`, `vendor-accounts.tf`,
  `envs/devenv/main.tf` and `modules/results-bucket/main.tf`, one known finding each:
  today three are dropped and the row reads `ran`. The same fixture copied under
  `<tmp>/vendor/app` and `<tmp>/vendor-portal/app`: today `resource_count` 0.
- [ ] Render each name as `[\\/]NAME$` with the name `re.escape`d. **Never `|` or `^`**:
  on Windows `checkov.cmd`'s arguments are re-parsed by cmd.exe (rc 255 measured), and
  checkov's `module_finder` compiles the value unguarded (rc 2, no output).
- [ ] Gate: all four findings kept at both roots, a real `vendor/x.tf` and a
  `node_modules/` tree still skipped, on Windows and in the image.
- [ ] Mutations: the bare name, a missing `$`, a missing escape; each caught.

---

## Task G1: gosec leaves the matrix (#1310)

**Files:** `scripts/core/tool_descriptors.py` (the row, `_gosec_repo`, `_go_trigger`,
`_is_go`, `_gosec_scanned`; `REMOVED_TOOLS` gains `gosec`),
`scripts/core/scan_timings.py` (`Reason.NO_GO_SOURCES` goes),
`scripts/core/adapters/gosec_adapter.py` (deleted), `versions.yaml`,
`scripts/core/install_config.py`, `Dockerfile` (via `update_versions.py --sync`), and
every other reference: 26 Python files and 28 documents name gosec today
(`grep -rln gosec`); list them in the PR, as Phase 2 did.

- [ ] Red first: `jmo scan --tools gosec` must exit 2 with "removed in v2.0.0", as the
  Phase 2 names do (`parse_tool_names`); today it runs and reads
  `failed:examined 0 files`.
- [ ] The count moves 16 → 15 (after N), and `test_tool_catalogue_count_claims.py`'s
  documents follow. No gosec version-checker issue is open (checked 2026-09-27), so
  nothing is un-exempted.
- [ ] #1286's body (Phase 8) loses gosec from its list; a comment says why.
- [ ] Gate: a Go repository through `jmo scan` has no gosec row and no "not installed"
  warning; `jmo tools check` lists 15; the image builds without gosec (docker-smoke's
  LOG, which is path-filtered: confirm it ran).

## Task G2: GitLab targets scan the images they reference (#1311)

**Files:** `scripts/cli/scan_jobs/gitlab_scanner.py:334-369`,
`scripts/cli/scan_jobs/image_scanner.py` (`scan_image`, unchanged signature),
`scripts/cli/scan_orchestrator.py` (the session's targets), `docs/TOOLS.md`'s GitLab
row, tests beside each.

**Interfaces:**
- Consumes: `scan_image(image, results_dir, tools, timeout, retries, per_tool_config,
  allow_missing_tools, find_tool_func=None, write_stub_func=None, result_name=None)
  -> tuple[str, TargetRows]` (`image_scanner.py:20-31`).

- [ ] Measure first: a public gitlab.com repository whose Dockerfile names a small
  image (`alpine:3.19` or similar), cloned through `jmo scan --gitlab-repo` (no token:
  #1319 made `--gitlab-url` default to gitlab.com). Record discovery's output and
  today's ERROR (`TypeError: … tool_exists_func`).
- [ ] Red first through `jmo scan --gitlab-repo <that repository> --tools trivy syft`:
  today no `individual-images/` folder, no image rows, one ERROR per image.
- [ ] Each discovered image is scanned as an image target: `scan_image` with
  `find_tool_func` (the argument it has), `results_dir` = the scan's
  `individual-images/`, `result_name` unique in the scan (#1312's rule), and its rows
  returned with `target_type` `image` beside the repository's. The
  `# type: ignore[call-arg]` and the `TODO(issue-#1311)` go.
- [ ] A reference JMo cannot pull (a private registry, a build-arg `FROM $BASE`) is a
  `failed` image row naming the reference, never a scan-wide error. An `ARG`-templated
  `FROM` is skipped by discovery, with an INFO line.
- [ ] Gate: that repository through `jmo scan --gitlab-repo`: one image target with trivy
  and syft rows, its findings in the report under the image's name; the reconciler
  passes; the clone's temporary directory holds nothing the report needs.

## Task G3: every tool's own flag grammar (#1335)

**Files:** `scripts/cli/scan_utils.py` (`RESERVED_OUTPUT_FLAGS`, `tool_flags`),
`scripts/core/tool_descriptors.py` (each row's `reserved_flags` and a new
`short_flags` / parser family), `scripts/core/yara_runner.py` and the native runner
(`allow_abbrev=False`), tests beside each.

- [ ] Red first, through `jmo scan` on the flags fixture: `trivy -ftable`, `grype
  -otable`, `hadolint -ftty`, `gitleaks -vfjson` today take 57 findings to 0 with the
  rows `ran`; `gitleaks -vrREPORT.sarif` writes the unredacted report into the scanned
  tree.
- [ ] The shared set goes: it refuses real flags (grype `-f`, semgrep `-f`, checkov
  `-f`, shellcheck `-o`, zizmor `-o`). Each row declares its own output flags, long
  and short, with every spelling measured (`=` forms, nuclei `-jsonl=false`, gosec
  `--fmt`, osv-scanner `-format`, semgrep `--text`).
- [ ] Parsers that cluster short flags (pflag, kingpin, getopt, optparse-applicative,
  argparse) get a cluster walk over the row's no-value short flags, so `-qftable` is
  refused and every real flag measured still passes. Go's stdlib `flag`, urfave/cli and
  clap reject attached values themselves; nuclei, gosec and osv-scanner must not get
  the rule (it would refuse nuclei's `-omit-raw`, `-or`, `-ot`, `-je`).
- [ ] grype and syft: `-o`/`--output` and `--file` reserved (their `-o` appends).
- [ ] Gate: the 17 cluster cases refused, the measured real flags kept, and the fixture
  back to 57 through `jmo scan` with each bad spelling configured (refused by name).

---

## Task API1: zap imports an OpenAPI definition (#1331)

**Files:** `scripts/core/tool_descriptors.py` (`_zap_url`, a plan builder),
`scripts/cli/scan_orchestrator.py` (`--api-spec` discovery), `scripts/core/adapters/zap_adapter.py`,
the wizard's API mode, tests beside each.

- [ ] Red first, against the measurement fixture (a local API whose spec names
  `servers: [http://prod.invalid/]`, behind a logging proxy): today 0 of 4 operations
  requested.
- [ ] `--api-spec FILE|URL` requires `--url TARGET` (exit 2 naming both otherwise):
  without an explicit target zap sent 1,276 requests to the spec's own server.
- [ ] JMo writes an automation plan into the output directory (context = the target;
  an `openapi` job with `apiFile`/`apiUrl` and `targetUrl`; `passiveScan-wait`;
  `activeScan` with a `maxDuration` from the tool's timeout; a `traditional-json`
  report) and runs `zap -cmd -silent -autorun <plan>`. rc 1 is a failure for this
  invocation (a failed import writes no report).
- [ ] `targetUrl` keeps the user's path as typed (`http://h` keeps the spec's base
  path, `http://h/` drops it: measured), and the PR records which one JMo sends.
- [ ] Gate: 3 of 4 operations attacked including `{id}`, 0 requests to `prod.invalid`,
  the adapter's findings equal to the report's alerts.

## Task API2: zap's URL scans, as found in API1's measurement

- [ ] `-silent` on every zap run (6–13 calls to `*.zaproxy.org` per run without it).
- [ ] The trailing slash, as decided (see "New defects"): measured, `-quickurl
  http://h/` missed an XSS that `http://h` found. Red first on the spiderable fixture.
- [ ] Severity, as decided: `zap_adapter.py:93` reads `riskcode`/`riskdesc`. Red first:
  the fixture's High XSS reads `MEDIUM` today.
- [ ] nuclei stays a plain `-u` scan (decision 7); its spec import is the after-the-tag
  issue filed with PR A.

---

## Decisions taken 2026-09-27 (Jimmy)

| # | Question | Decision |
|---|---|---|
| 1 | gosec (#1310): fix or remove | **Remove.** It has examined 0 files on every run, so no user has ever had a finding from it; semgrep covers Go until Phase 5, then the bundle's 71 `go` security rules. Fixing meant ~58–72 MB of Go in the image, `go` natively, and module and toolchain downloads mid-scan by default |
| 2 | GitLab image discovery (#1311): fix or remove | **Fix, GitLab only** (recommended was remove). Each discovered image is scanned as an image target with its own rows; this pulls images from registries mid-scan, and only GitLab targets discover images (`--repo` never has) |
| 3 | The native pack's engine | **A Python runner**, `jmo-native`, as `yara_runner` is: 8 of 8 on the fixture with no false positive, all five checks, no engine dependency |
| 4 | A dependency finding's identity | **(package, version, id)**: golf = **47** from trivy, from osv-scanner, and together, each finding detected by both. A vulnerable installed version is its own finding; the spec's 38 was the review's (package, id) key |
| 5 | trivy's license scanner | **Dropped**: the adapter ignores license results (408 raw entries and 0 findings on golf). trivy's repository scan is `--scanners vuln,misconfig`, a deviation from the spec's §3 recorded here |
| 6 | osv-scanner's offline database | **All ten ecosystems (~280 MB)**, fetched by `jmo tools update` and when osv-scanner is installed; **the image does not carry it** and fetches on first use. Consequence, carried to the Docker docs: a container without a persistent `~/.jmo` volume has no database, so its osv-scanner row reads `failed:offline database missing` until `jmo tools update` runs in it |
| 7 | #1331's scope | **zap only**, through an automation plan. nuclei stays a plain `-u` scan; its spec import is filed after the tag |
| 8 | The new defects | **Filed as proposed** (the table below), immediately before PR A is pushed |
| 9 | The answer-key targets ("Ground truth", below) | **All in Phase 6**, with its golden-fixture work; Phase 4 keeps its measured gates. PR A roster-notes them in the program plan's Phase 6 |
| 10 | The schema-packaging defect | **Filed, Phase 8** (distribution) |

## New defects found by the measurement (searched; filed 2026-09-28)

| Defect | Routing (decided) |
|---|---|
| trivy misconfigurations lose their lines (40 of 87 on juice-shop), and trivy findings report `tool.version` `unknown` | into #1221's body (same file, same fixture, PR A) |
| No two dependency scanners can ever cluster (golf: 85 post-dedup, 0 clusters, 38 shared CVEs) | #1346, Phase 4, PR O |
| CI's "Tool Smoke Tests (Juice-Shop Fixture)" has passed on 22 skips since 2026-02-01: its fixture is gitignored for push protection | #1349, Phase 6 (golden fixtures and silent adapter failure are that phase's); its keys generated at test time as G1's are |
| Every zap finding is MEDIUM (`zap_adapter.py:93`), so `--fail-on HIGH` misses a High XSS | #1347, Phase 4, PR API |
| A trailing slash on `--url` stops zap's spider (an XSS missed) | #1348, Phase 4, PR API |
| nuclei cannot import a spec without attacking its `servers` | #1351, after the tag (decision 7) |
| **Neither the wheel nor the image ships the findings schema**: the wheel built from `292d3cff` has 188 entries and no `common_finding.v1.json` (`package-data` names only the dashboard), and `.dockerignore:45` drops `docs/`. `schema_validator.py:34` looks for `docs/schemas/` beside the package, so every installed JMo logs "Schema validation skipped" and validates nothing (seen in the docker-task run at `292d3cff`) | #1350, Phase 8 (decision 10) |
| gosec findings report `tool.version` `unknown` | moot: gosec is removed |
| A `.cmd` tool's arguments are re-parsed by cmd.exe on Windows (`\|`, `^`, `&`) | into #1313 for checkov's rendering; `.claude/rules/windows-encoding.rules.md` for the class |

Removing gosec also narrows #1286 (Phase 8: the packaging scripts never covered
shellcheck, gosec, grype, yara or opa): its gosec part closes with the tool, and #1286's
body says so in PR G.

## Review Focus

The five inputs no task's tests above exercise yet, most likely first:

1. **A monorepo with many lockfiles, one malformed** (a stale `package-lock.json` in an
   example directory): osv-scanner must keep the rest and name the bad one. Pinned by
   O1's truncated-lockfile gate.
2. **A repository cloned without `node_modules` but with an in-tree `results/`** from an
   earlier scan: zizmor and osv-scanner are walk-fed, so the walk's results-tree
   exclusion must hold for them as it does for hadolint. Add a case to Z1 and O1.
3. **A `--url` with a path and a trailing slash** (`http://h/app/`): API2 measures the
   root form only. Add the path form to API2's red test before choosing a rule.
4. **An ecosystem whose offline database is missing** mid-scan (a new language added
   since the last `jmo tools update`): O1's pre-run check. Add a Go lockfile with no Go
   database to O1's gate.
5. **A user's `per_tool.<tool>.flags` containing a cmd.exe metacharacter** for a `.cmd`
   tool (checkov, on Windows): G3 must refuse or quote it, since checkov's `.cmd`
   launcher re-parses its arguments. Add a checkov `--skip-check 'A|B'` case to G3.

## Acceptance (Phase 4)

Through `jmo scan`, every spawned run with `--history-db` and `--results-dir` in tmp:
zizmor on a `git archive` of `3098c766` = 217 raw, 216 post-dedup, the golden's ids;
osv-scanner on NodeGoat `c5cb68a7` ⊇ the golden's 303, post-dedup 291 + the named
newer advisories; the native pack 8 of 8 on its fixture, 0 on three real apps, the
planted `NEXT_PUBLIC_STRIPE_SECRET_KEY` caught; jmoadaptivegolf = 47 from trivy, from
osv-scanner, and from both together, each detected by both; juice-shop's osv-scanner
row `skipped:no lockfile`; checkov `skipped:no IaC files` on a workflow-only repository
and all four #1313 findings kept at both roots; the flags fixture refuses every
measured bad spelling and keeps 57; `jmo scan --tools gosec` exits 2, "removed in
v2.0.0"; a GitLab repository that names an image reports that image's rows; zap
attacks a spec's operations at the explicit `--url` and sends nothing to its
`servers`. `TOOL_MATRIX` = 15. Suite green; `windows-2022` no new failures against
9155 / 92 / 195.

## Ground truth: targets that ship an answer key (researched 2026-09-27)

Jimmy asked whether a target with known, expected vulnerabilities could check that the
tools work as intended. The reference targets today (juice-shop, NodeGoat, the goats)
are deliberately vulnerable but ship no list of what a scanner should find, so a count
can only go up or down, never be graded. Two kinds of answer key exist, and JMo needs
both: **independent keys** grade a scanner's quality; **a scanner's own regression
corpus**, at the tag `versions.yaml` pins, grades whether JMo invokes and parses it
correctly, exactly.

| Class | Answer key (license) | What it holds | Fits |
|---|---|---|---|
| GitHub Actions | zizmor's `crates/zizmor/tests/integration` at v1.30.1 (MIT) | 267 test functions over 245 inputs: 383 findings (378 with file:line:col) in insta snapshots, 49 "no findings" true negatives; two audits need a token | **PR Z**: JMo's zizmor on each input, the (audit, line, col) set equal to the snapshot |
| Dependencies | osv-scanner's own fixtures (Apache-2.0) | a frozen offline database of 28 advisories, `locks-*` inputs, 26 output snapshots | **PR O**: the wiring oracle |
| Dependencies, quality | none published; build one from `QuackatronHQ/sca-kitchen-sink` (MIT: npm, pnpm, yarn 4, bun, poetry, uv, requirements, composer, Gemfile, Cargo, gradle, NuGet lockfiles) against a **frozen** OSV snapshot | the expected set is every (ecosystem, package, version) the snapshot matches | Phase 6. A frozen snapshot also cures "an online count only grows" |
| Native pack | `humora2504/vibeproof` `test/fixtures` (MIT, created 2026-09-17, one maintainer; a competing Supabase/Next.js scanner, so these are its own test data, not an independent benchmark) | the `EXPECTED` list in `test/run.js`: 12 expected rule ids, exactly 2 "RLS not enabled", a protected table not reported, a clean fixture with 0. Covers a service_role key under `NEXT_PUBLIC_`, an admin client in browser code, RLS off, a `using (true)` policy, anon grants, a public storage bucket, open Firestore rules | **PR N**: map its ids to JMo's; per-class recall and 0 on the clean fixture. It covers three checks **JMo's pack lacks** (`using (true)`, anon grants, public buckets) and lacks `dangerouslyAllowBrowser`, `VITE_`, storage rules. trufflehog finds 3 Postgres URIs in it: fetch at a pinned commit, do not vendor |
| SAST | `TheAuditorTool/BenchProctor` (Apache-2.0) | `expectedresults-2026.07.22.csv` + a SARIF scorer; TS 12,400, JS, Go, bash cases, each exactly half vulnerable and half safe look-alikes; labels generated and not auditable | Phase 5, with OWASP BenchmarkPython/Java (GPL, fetch only) to calibrate it |
| SAST, in an existing target | juice-shop's own `// vuln-code-snippet vuln-line` markers (MIT) | 38 lines in 16 files, 35 of 116 challenges, at `1618a611` | Phase 5; turns `tests/integration/baselines/juice-shop.baseline.json` (juice-shop 16.0.0, min-count per CWE, still naming njsscan) into a file+line key |
| IaC, Dockerfile | Checkmarx KICS `assets/queries` (Apache-2.0) | per rule, `positive_expected_result.json` (line, file) and negative samples: Terraform 2,507, CloudFormation 1,887, Kubernetes 430, Dockerfile 242 | Phase 6; the cost is mapping KICS rules to checkov, trivy and hadolint ids |
| Secrets | `Samsung/CredData` (Apache-2.0 tooling; data under each source's license) | 67,564 labelled lines, 15,714 true, with a `--scanner gitleaks\|trufflehog` harness; its download needs Linux | Phase 6, under WSL; report precision and per-category recall, never accuracy |
| Shell, YARA | none clears the bar | — | a JMo-written canary rule and file generated in `tmp_path` for YARA; never EICAR |

**Traps the research measured, for the phases that fetch these:**

- **Defender deletes rule-test files.** A plain clone of opengrep-rules at `f1d2b56`, the
  Phase 5 bundle's source, lost `no-scriptlets.jsp` (Backdoor:Java/WebShell.GP!MSR) and
  `python-reverse-shell.py` (Backdoor:Python/Reverseshell!AMTB) within ~25 s. Phase 5's
  "Measure first" gains this (PR A adds the line to the program plan).
- **Rule and secret corpora trip JMo's own secret scanning**: trufflehog finds 115
  secrets in opengrep-rules' `generic/secrets`, 694 in titus's rules, 19 in KICS's.
  Fetch into a gitignored directory at test time at a pinned commit; vendoring them
  would trip TruffleHog CI and likely push protection (Phase 5's bundle too).
- **Windows path length.** zizmor's and ossf-cve-benchmark's checkouts fail under a
  110-character base; use `git clone -c core.longpaths=true` (the per-process `git -c`
  form leaves 37 files reading modified on every later `git status`).
- **Licenses.** Vendorable with attribution: BenchProctor, KICS, zizmor, trivy-checks,
  checkov, vibeproof, sca-kitchen-sink, juice-shop. Fetch at a pinned commit, never
  vendor: GPL (OWASP Benchmark, hadolint, shellcheck), AGPL (WrongSecrets), LGPL +
  Commons Clause (opengrep-rules), CredData's data, anything unlicensed.

The "Fits" column above is where each key would plug in; decision 9 puts all of them in
Phase 6, and PR A records that in the program plan's Phase 6 section (its golden set
gains the scored keys) and adds the two Phase 5 traps to Phase 5's "Measure first".

## Unresolved

None at the time of writing: decisions 1-10 are Jimmy's, 2026-09-27.

---

## Task O1: osv-scanner's row

**Files:** `scripts/core/tool_descriptors.py`, `scripts/core/scan_timings.py`
(`Reason.NO_LOCKFILE`, `Reason.NO_OFFLINE_DB`), `scripts/cli/scan_jobs/tool_loop.py`
(the per-lockfile fallback; an invocation's environment), `versions.yaml`,
`install_config.py`, `Dockerfile`, tests beside each.

**Interfaces:**
- Produces: `DESCRIPTORS["osv-scanner"]`; `Invocation.env: Mapping[str, str] | None`;
  `Reason.NO_LOCKFILE = "no lockfile"` (skip), `Reason.NO_OFFLINE_DB = "offline
  database missing"` (fail). `TOOL_MATRIX` 14 → 15.

- [ ] Red first, through `jmo scan`: juice-shop `1618a611` reads
  `skipped:no lockfile`; NodeGoat's golden set is present; a repository with a
  truncated `package-lock.json` beside a valid one keeps the valid one's findings and
  reads `failed`, naming the truncated file.
- [ ] Command: `osv-scanner scan source --format sarif --output-file <out>
  --offline-vulnerabilities -L <lockfile>...`, `ok_return_codes=(0, 1)` (1 = findings),
  environment `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=<JMo's cache>`.
- [ ] Before the run: each lockfile's ecosystem has a database in the cache, or the row
  is `failed:offline database missing` and names `jmo tools update`.
- [ ] Gates: NodeGoat `c5cb68a7`, every golden result present, post-dedup = 291 + the
  advisories since 2026-09-12 (named in the PR); juice-shop `skipped:no lockfile`;
  the truncated-lockfile fixture keeps 304 and names its failure.

## Task O2: the offline database

**Files:** `scripts/cli/tool_commands.py` (`cmd_tools_update`, `cmd_tools_install`),
a new `scripts/core/osv_database.py`, `Dockerfile`, tests beside each.

- [ ] `jmo tools update` (and installing osv-scanner) fetches
  `https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip` into
  `~/.jmo/osv-db/osv-scalibr/<ecosystem>/all.zip`, the layout osv-scanner reads
  (measured: `osv-scalibr/npm/all.zip`), for all ten ecosystems (decision 6: npm,
  PyPI, Go, Maven, crates.io, RubyGems, Packagist, NuGet, Pub, Hex); `curl -f`
  semantics (an HTTP error is a failure, never a saved HTML page); each zip is
  replaced only after its download completes and unzips (`zipfile.testzip`).
- [ ] The image carries no database (decision 6). `docs/DOCKER_README.md` says a
  container needs `jmo tools update` once, on a persistent `~/.jmo` volume, or its
  osv-scanner row reads `failed:offline database missing`; the Docker e2e case asserts
  exactly that row on a fresh container, so the behaviour is pinned, not assumed.
- [ ] Gate: with the cache populated and no network (a firewall rule or an unroutable
  proxy), `jmo scan` on golf gives the same 47.

## Task O3: trivy's dependency flags

**Files:** `scripts/core/tool_descriptors.py` (`trivy`'s `repo` and `image` builders),
tests beside it.

- [ ] Red first: golf reads 0 through `jmo scan --tools trivy` today.
- [ ] `repo`: `--scanners vuln,misconfig` (no `license`: decision 5), `--include-dev-deps`,
  `--offline-scan`. `image`: `--scanners vuln,secret,misconfig`, unchanged.
- [ ] Gate: golf's trivy findings equal osv-scanner's (package, version, id) set: 47.
- [ ] Gate: a repository scan reports 0 trivy secret findings (its secret pass is off),
  so a trivy secret reaches a repo report only through an image scan.

## Task O4: one identity per dependency finding

**Files:** `docs/schemas/common_finding.v1.json` (a `dependency` object: `name`,
`version`, `ecosystem`, `aliases`), `scripts/core/common_finding.py`
(`fingerprint(..., package=...)`, appended like `commit`),
`scripts/core/adapters/{trivy,osv_scanner,grype}_adapter.py`,
`scripts/core/dedup_enhanced.py` (dependency findings match on identity, not on
lines), tests beside each.

- [ ] Red first, through `jmo report` on golf's two outputs: 85 post-dedup and 0
  clusters today, all 38 CVE ids in both tools.
- [ ] osv-scanner's binding reads `name@version` from its message template and the
  aliases from `rules[].deprecatedIds` (SARIF carries nothing structured, measured);
  trivy's reads `PkgName`, `InstalledVersion` and `VulnerabilityID`; grype's its match.
- [ ] Two dependency findings are the same finding when their lockfile, name and version
  match and their id sets (id plus aliases) intersect. That bypasses location
  similarity, which is 0 for every dependency finding.
- [ ] Gate: golf through `jmo scan --tools trivy osv-scanner` = **47** (decision 4), each
  finding detected by both tools; trivy alone 47 (was 38: two installed versions no
  longer share an id); NodeGoat's osv-scanner number unchanged.

---

## Task N1: the `jmo-native` row

**Files:** create `scripts/core/native_checks.py` (the runner) and
`scripts/core/adapters/jmo_native_adapter.py` (a SARIF binding); create
`tests/fixtures/samples/native/` (the rebuilt fixture, tracked); modify
`scripts/core/tool_descriptors.py`; tests beside each.

**Interfaces:**
- Produces: `python -m scripts.core.native_checks --target DIR --output FILE
  [--exclude-dir NAME]...`, writing SARIF 2.1.0; rule ids
  `jmo.nextjs.public-env-holds-server-secret`, `jmo.supabase.service-role-key-in-client-code`,
  `jmo.ai.llm-api-key-in-browser-code`, `jmo.supabase.table-without-rls`,
  `jmo.supabase.rls-without-policy`, `jmo.firebase.rules-open`. `TOOL_MATRIX` 15 → 16.

- [ ] The fixture, tracked, with placeholder values only (no key-shaped string, so
  neither Defender, `detect-private-key` nor push protection acts on it): a migration
  with RLS in three states, `.env.example`, a client module and an API route both naming
  the service_role key, a browser LLM client, open `firestore.rules`, closed
  `storage.rules`, and a comment naming `service_role`. Expected: 8, listed in a
  `README.md` beside it.
- [ ] Red first through `jmo scan --tools jmo-native`: exit 2 today.
- [ ] The runner, from the spike (`p4-native.py`): comments stripped before the source
  rules; the client/server split by path (`app/ src/ components/ pages/ lib/` minus
  `.server.`, `/api/`, `/server/`, `/actions/`, `supabase/functions/`); `.env*` lines
  that start with `#` skipped.
- [ ] Gates: the fixture **8 of 8** and no finding on the four negatives; `git archive`
  exports of bracketforge, BetHedgeSlider and jmoadaptivegolf **0 each** (counts
  only); the planted `NEXT_PUBLIC_STRIPE_SECRET_KEY` caught; the row under 5 s on each.
