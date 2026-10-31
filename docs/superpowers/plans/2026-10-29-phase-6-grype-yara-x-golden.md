# Phase 6 — grype's verdict, yara-x, golden for every adapter: task plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** grype leaves the matrix on a re-measured verdict; yara-x with Neo23x0's
signature-base replaces yara-python and the ReversingLabs rules, and is the one tool that
reads vendored dependency trees; every adapter in the final matrix (14) has a non-empty
golden fixture captured through `jmo scan`, guarded so that a missing or empty one fails;
and the 27 open Phase 6 issues close: the 22 whose premises were re-measured on
2026-10-29, #1502, which that measurement filed, #1506, filed from Phase 5's PR B,
two filed from PR A on 2026-10-30: the e2e helper's #1517, from its measurement, and
the raised scanner's stale timings, #1518, from building Task A2; and the GitLab URL
token leak, #1522, found by PR T's review and fixed by PR A's Task A2d.

**Architecture:** eight PRs in two groups. Four touch no file that Phase 5's Tasks B1–B8
list (A, D, T, N). Four do (G, Y, E, F). **No Phase 6 implementation PR opened before Phase 5's
PR B merged** (Jimmy, 2026-10-29); it merged as `8ac90d8c` on 2026-10-30, so every PR now
starts from `dev`. F is last: it captures the final matrix's fixtures, after G removes grype
and Y brings yara-x.

**Tech Stack:** Python 3.12, pytest (+xdist), yara-x (the PyPI wheel, a runtime dependency:
J2), Neo23x0/signature-base at a pinned commit (DRL 1.1), osv-scanner 2.7.0,
trivy 0.74.0, grype 0.118.0 (leaving), GitHub Actions, Docker.

**Spec:** [2026-09-12-v2.0.0-program-design.md](../specs/2026-09-12-v2.0.0-program-design.md)
§3, §4.2 R1, §6, §11, §12; program plan
[2026-09-12-v2.0.0-program.md](2026-09-12-v2.0.0-program.md) § Phase 6; the Ground truth
section and decision 9 of [the Phase 4 task plan](2026-09-27-phase-4-new-tools.md); the
model is the Phase 5 task plan, `2026-10-23-phase-5-rule-bundle.md`.

## Global Constraints

- **Phase 5's PR B has merged** (`8ac90d8c`, 2026-10-30). Tasks marked **P5** touch a file
  that Phase 5's Tasks B1–B8 list (`2026-10-23-phase-5-rule-bundle.md` is the authority),
  among them `tool_descriptors.py`, `install_config.py`, `tool_installer.py`,
  `versions.yaml`, `Dockerfile`, `ci.yml`, `scheduled.yml`, `common_finding.py`,
  `compliance_mapper.py`, `compliance_frameworks.py`, `rule_equivalence.py`,
  `scan_validator.py`, `basic_reporter.py`, `tool_manager.py`, `tool_utils.py`,
  `scan_timings.py`, `generate_golden.py`, `jmo.yml`, `tests/conftest.py`,
  `test_adapter_golden.py`, `test_docker_workflows.py`, `test_tool_smoke.py`, the packaging
  files, `.gitignore`, `UPGRADE.md`, `CHANGELOG.md` and `docs/TOOLS.md`. Every line number this plan cites
  is at `c05aef28`; in a P5 file, re-read it on `dev` before editing.
- **Backward compatibility is NOT a constraint.** No users. The tool name is hashed into
  every finding id (`fingerprint()`, `scripts/core/common_finding.py:276`), so renaming
  `yara` to `yara-x` changes every yara finding id once, deliberately; `UPGRADE.md` says so.
- **One formatter:** `ruff format`. `make fmt && make lint` (or `pre-commit run --all-files`).
- **No `shell=True`.** Every `subprocess.run` passes `timeout=`.
- **Conventional commits, no AI-attribution markers of any kind** (no `Co-Authored-By`,
  no "Generated with", no `Claude-Session:`), in commits and PR bodies.
- **Commit and merge only when Jimmy says.** PR into `dev`, squash; subject
  `feat!: v2.0.0 Phase 6 PR <X>, …` as Phase 4's and 5's were. `Closes #N` goes in the
  COMMIT body; a PR body into `dev` is inert. The `dev` → `main` sync is a fast-forward push.
- **Work in a worktree** under `~/.cache/jmo-wt/`. Scratch and `pytest --basetemp` (a CLI
  flag, never `PYTEST_ADDOPTS`) go under `~/.cache/`: `/tmp` is tmpfs.
- **A `jmo scan` rewrites the real `~/.jmo/config.yml`** (`_show_kofi_reminder`,
  `scripts/cli/jmo.py:2505`, has no non-interactive skip: #1506, fixed by Task A6), and
  `_guard_real_jmo_config` (`tests/conftest.py:489` on `dev`) fails whichever test is open when it changes. While any other
  session may run the suite, scan with `HOME=<scratch home>` whose `.jmo/bin`, `.jmo/tools`
  and `.jmo/yara-rules` are symlinks to the real ones, and prove it first with
  `jmo tools check` under that HOME. Every spawned `jmo scan` gets `--history-db <tmp>` and
  `--results-dir <tmp>`.
- **Gates are numbers through `jmo scan` / `jmo report`, never a bare binary**, except where
  a task measures the binary itself.
- **Suite:** `.venv/bin/python -m pytest <part> -n 4 -q -rfEs --basetemp ~/.cache/pytest-p6 -m "not smoke and not requires_tools and not docker"`.
  **Diff failing-test ID sets, never counts.** Read the `windows-2022`, `windows-opengrep` and
  `docker-smoke` job logs, never their ticks. Windows is CI plus a script Jimmy runs on
  `.198` (the laptop, `.218`, is retired).
- **Mutation-test every guard** from a byte backup; restore byte for byte.
- **Never edit tool versions in `Dockerfile` by hand**: `versions.yaml`, then
  `python3 scripts/dev/update_versions.py --sync`.
- **No private repository's name or content** beyond counts and timings, in anything
  tracked; measure them on `git archive` exports. This plan calls them **app A** (Next.js,
  pnpm lockfile) and **app B** (React SPA, npm lockfile).
- **No juice-shop file is ever committed**, and **no malware sample anywhere**: the yara
  fixture is a JMo canary string, never EICAR (Defender deletes signature-bearing files,
  measured 2026-08-02; the Phase 4 Ground truth row for YARA says the same).
- **Answer keys are fetched, never vendored**, by pinned commit or release and sha256, into
  `~/.cache/jmo-answer-keys/<key>/<pin>/`, outside the repository (overridable by
  `JMO_ANSWER_KEYS_DIR`; CI caches it): nothing to gitignore, nothing to commit by accident,
  and `.gitignore` stays untouched, since Phase 5's PR B edits it. A test whose key is absent
  skips naming the fetch command; the nightly fetches first.
- **Line endings:** `python scripts/dev/check_eol_flips.py --base origin/dev` after
  `git add`. Generated files are written with `write_bytes`, LF.
- **File no issue without Jimmy's word:** an unrostered issue reddens `phase_audit` on every
  open PR. The defects this measurement found are listed, unfiled, at the end.

## Measured before this plan was written (2026-10-29, Debian `.199`)

Evidence and scripts are in `~/.cache/jmo-p6/` (not backed up); every number this plan
argues from is copied here. Base `origin/dev` = `origin/main` = `c05aef28`. All scans ran
under an isolated HOME with its own OSV offline database (fetched 10:45 EDT by
`osv_database.fetch_all`, 290 MB, 11 ecosystems); grype's and trivy's databases were
fetched fresh by the first scan. Versions are the `versions.yaml` pins: grype 0.118.0,
trivy 0.74.0, osv-scanner 2.7.0 (downloaded and checked against the release's
`osv-scanner_SHA256SUMS`, since `~/.jmo/bin` held 2.6.0).

### grype against osv-scanner and trivy (R1, re-measured)

**Targets.** B's nine, at B's commits: juice-shop `1618a611`, NodeGoat `c5cb68a7`, pygoat
`19d17cc8`, terragoat `729f8da6`, cfngoat `0c09b69c`, kubernetes-goat `723a0db4`,
github-actions-goat `4da23c86` (file counts equal B's inventory: 1300, 111, 276, 72, 7,
379, 89), plus `git archive` exports of app A and app B at their `HEAD`. B scanned the
apps' working trees; these are clean exports with no installed `node_modules`, which is
what a clone gives.

**Method.** `jmo scan --tools trivy osv-scanner grype --threads 1`, then each tool's
`individual-repos/<t>/<tool>.json` read through JMo's own adapters (never `findings.json`:
the clusterer would hide exactly the uniqueness being measured), union-find over every id
and alias any tool reported (B's `analyze.py` method), keyed by B's `(package, canonical
id)` and by Phase 4 decision 4's `(package, version, canonical id)`.

| Target | adapter findings grype / osv / trivy | grype-unique (pkg, id) | (pkg, ver, id) | (pkg, ver, id), grype's Maven names from its purl | B's (pkg, id), 2026-09-11 |
|---|---|---|---|---|---|
| NodeGoat | 105 / 204 / 329 | 0 | 0 | 0 | 0 |
| pygoat | 219 / 402 / 219 | 0 | 0 | 0 | 0 |
| terragoat | 507 / 781 / 616 | 36 | 41 | **0** | 29 |
| kubernetes-goat | 162 / 171 / 160 | 0 | 1 | 1 | 3 |
| github-actions-goat | 71 / 0 / 0 | 7 | 14 | 14 | 7 |
| juice-shop | 0 / 0 / 0 (osv `skipped: no lockfile`) | 0 | 0 | 0 | 0 |
| cfngoat | 0 / 0 / 0 (osv `skipped: no lockfile`) | 0 | 0 | 0 | 0 |
| **app A** | 25 / 25 / 24 | **0** | **0** | 0 | 0 |
| **app B** | 1 / 61 / 60 | **0** | **0** | 0 | 0 |

- **grype-unique on both real applications is 0** under both keys. By the program's
  acceptance rule, grype is dropped.
- **terragoat's whole margin is a naming artifact (#1372's first edge, measured).** All 41
  are Maven packages from two `pom.xml` files. grype names a Maven package by its artifactId
  (`log4j-core`); trivy and osv-scanner name it `groupId:artifactId`
  (`org.apache.logging.log4j:log4j-core`). All 35 of trivy's Maven advisory ids are in
  grype's id-and-alias set. With grype's names taken from its purl, terragoat's grype-unique
  is 0: trivy and osv-scanner report every one, Log4Shell included. B's archived reports
  give B's 29 exactly with raw names and **1** (`junit:junit`) with purl names, so 28 of
  the spec's 29 were the same artifact.
- **The one real residual is known-vulnerable GitHub Actions.** On github-actions-goat
  grype's GitHub Actions cataloger reports `tj-actions/changed-files` v35/v40 and
  `step-security/harden-runner`: 71 findings in 14 workflow files, 7 distinct (package,
  advisory) pairs and 14 distinct (package, version, advisory) triples.
  osv-scanner 2.7.0's source scan finds no package source in workflow files ("No package
  sources found", 0 extract calls). zizmor `--offline` flags the same three
  `tj-actions/changed-files` uses as `unpinned-uses` only (it reports 72 `unpinned-uses`, 25
  `artipacked`, 22 `excessive-permissions`, 3 `template-injection`, 2 `dangerous-triggers`);
  its known-vulnerable-actions audit is online-only. OSV publishes
  `GitHub Actions/all.zip` (99,127 bytes, 56 advisories, all four tj-actions/changed-files
  GHSAs in it), so an offline check is possible without grype.
- kubernetes-goat's one (pkg, ver, id) residual is `github.com/valyala/fasthttp` v1.51.0,
  `GO-2026-4950`, severity INFO.
- **grype sees 1 of app B's 61:** it does not read npm dev dependencies, as trivy without
  `--include-dev-deps` did not.
- **osv-scanner 2.7.0 read NodeGoat's lockfile "partly audited"**: 270 npm packages have no
  `resolved` URL (#1472's class, the row's detail says so); trivy reports them (trivy-unique
  106 at (pkg, ver, id)), so the dependency set without grype still covers NodeGoat.
- **grype's cost:** its database is **3.2 GB** on disk (trivy's 1.6 GB); the first scan
  spent 103 s hydrating it, later scans 2–4 s.

### yara-x and its rules

**The engine.** yara-x **v1.22.1** (2026-10-26; the spec says 1.20, released 2026-08-24).
The `yr` CLI ships for Linux x86_64 and aarch64 (glibc), macOS x86_64 and arm64, and Windows
x86_64; no checksum file is published (Linux tarball sha256 `c0ff80408d57…eecf`, binary
32 MB). PyPI `yara-x` 1.22.1 ships abi3 wheels for the same platforms (manylinux_2_28,
macOS 14, win_amd64; none for musl or Windows ARM64). `yr scan` takes `--scan-list` (a
file of paths, so JMo's own walk decides what is scanned), `--ignore-invalid-rules`,
`-o ndjson` (with `-m -e -g` it carries each rule's metadata, namespace and tags),
`-d VAR=VALUE`, `-z`, `-a`, `-p`; it has no exclude flag and recurses only with `-r`.

**The rules.** signature-base `master` `36ab7042` (2026-10-29): `yara/` holds 752 files
(748 `.yar`, 4 `.yara`), about 5,957 rules, **6.8 MB**; the tarball is 1.9 MB. Its LICENSE
is the Detection Rule License 1.1 (GitHub's API says `NOASSERTION` because it does not
recognise DRL). DRL is permissive with two attribution duties: whoever shares the rules
keeps each rule's author, URI and license; and **"messages based on matches with the Rules
must retain … the author(s)"**, so every finding JMo reports from a rule must carry its
`author`. Not every rule is DRL: the rules' own `license` metadata lines read DRL 1.1 2,883
times, CC BY-NC 4.0 13, UK Open Government Licence v3 8, Volexity's license 6, SigmaHQ's
DRL 6, BSD-2-Clause 6, CC BY 4.0 4, CAPEv2's license 3. The rules use LOKI/THOR external
variables: `filename` (729 references), `filepath` (66), `filetype` (15), `extension` (14),
`owner` (1); modules `pe` (136 files), `math` (5), `hash` (1). Three files are npm
supply-chain rules (`mal_npm_supply_chain_{sep25,nov25,mar26}.yar`, among them
`SUSP_JS_NPM_Sha1_Hulud_Nov25`).

The shipped bundle today is ReversingLabs `e0a0be54` (`install_config.py:96`, still
upstream HEAD): 310 files, about 1,240 rules, PE/ELF malware categories.
`install_config.py:75-95` chose it over signature-base for two reasons, both measured false:
"42 MB" is GitHub's size of the repository *with its history* (`size` 43,050 KB), and
NOASSERTION is GitHub not recognising DRL; nothing is vendored either way.

**Compile under yara-x 1.22.1:** ReversingLabs 310 of 310 files, 0 errors (932
`deprecated_field` warnings). signature-base with no externals declared: 595 errors (594
`E009 unknown identifier`); with the five declared: **752 of 752, 0 errors**.

**False positives** (yara-x Python bindings with per-file `filename`/`filepath`/`extension`
as LOKI sets them; 50 MB file cap; `.git` pruned):

| Target | files | signature-base | ReversingLabs |
|---|---|---|---|
| app B with `node_modules` (`npm ci --ignore-scripts`) | 24,942 | **0** (29.6 s, 1 thread, 223 MB peak) | 0 |
| app A, app B (source) | 1,252 / 618 | 0 / 0 | 0 / 0 |
| juice-shop | 1,300 | 2: `EXPL_SUSP_JS_POC_Dec25` `test/cypress/e2e/profile.spec.ts`, `VULN_KeePass_DB_Brute_Forcible` `ftp/incident-support.kdbx` (a challenge file) | 0 |
| pygoat, kubernetes-goat, NodeGoat, github-actions-goat | 276 / 377 / 96 / 89 | 0 | 0 |
| this repository at `c05aef28` | 943 | 2: `WEBSHELL_PHP_Generic_Eval` in `tests/unit/test_yara_runner.py` and `tests/adapters/test_yara_adapter.py` | 0 |

The `yr` CLI with the five externals set to a constant (`-d filename="x"` …), `-p 4`,
`--scan-list` of the same 24,942 files: **0 matches, 5.1 s**; with the canary rule and its
two files added, exactly the two canary matches. The same CLI over this repository's Linux
`.venv` (5,870 files, 184 MB, compiled extension modules; the interpreter is a symlink and
not read): **0 matches, 3.6 s**. A Windows `.venv`, which holds a real `python.exe` (grype's
104 hits on 2026-09-11 were that interpreter), was not measured. Compile time 3.6–9.7 s for
both bundles.
ReversingLabs matched nothing on any of the nine targets or the vendored tree.

**Today's runner** (`scripts/core/yara_runner.py`, yara-python 4.5.4): a canary rule, and
the canary string in `src/planted.js` and `node_modules/left-pad/index.js` → "scanned 1 of 1
file(s)", 1 match. `SKIP_DIRS = VENDORED_DIRS` prunes `node_modules`, so **the program's
acceptance ("a fixture under `node_modules` is reported") cannot pass against it**, and
spec §3's trigger for yara-x ("vendored dependency trees") contradicts it. A single rule
file as `--rules` → `ValueError: PosixPath('.') has an empty name`, rc 2 (#1413, on Linux).
The image installs yara twice: apt's `yara` CLI (`Dockerfile:170`, verified at `:286`) and
`yara-python==4.5.4` (`:213`); no rule bundle is fetched.

### Golden coverage

| Final-matrix tool | Golden fixture today | Capture source for Phase 6 |
|---|---|---|
| gitleaks | v8.30.1, 69 | kept |
| osv-scanner | v2.5.1, 303 (pinned 2.7.0) | kept |
| zizmor | v1.30.1, 217 (pinned 1.31.1) | kept |
| opengrep | v1.32.0, 10 (Phase 5's PR B; semgrep's empty v1.146.0 fixture went with it) | kept |
| trivy | — | re-home `tests/fixtures/samples/trivy/{vuln,misconfig}-0.74.json` (3 and 47 findings) |
| zap | — | re-home `tests/fixtures/samples/zap/report-2.17.0-xss.json` (10: High, Medium, Low; target `fixture_server.py`) |
| trufflehog, checkov, hadolint, shellcheck, syft, jmo-native | — | `tests/fixtures/samples/` through `jmo scan` |
| yara-x | — | the canary rule and file, generated |
| nuclei | — | `fixture_server.py` with a JMo-written template (nuclei fetches its templates unpinned at run time) |

`scripts/dev/generate_golden.py:88-154` (on `dev`) hand-writes commands for five tools (trivy,
hadolint, checkov, trufflehog, shellcheck; semgrep's left with Phase 5's PR B) rather than
taking them from the descriptors, the
drift #1349's comment names. Golden metadata since Phase 0 records tool, version, binary
sha256, download URL, target and command (`tests/fixtures/golden/gitleaks/v8.30.1/metadata.json`).

### Answer keys (decision 9), measured 2026-10-29

| Key | Pin | Measured | Phase 6? (J7) |
|---|---|---|---|
| juice-shop's `// vuln-code-snippet vuln-line` markers (MIT) | `1618a611` (T2's pin) | **40** marked lines in 17 files: 10 TypeScript, 3 Solidity, 2 Terraform, 2 YAML (Phase 4's research said 38 in 16). B's archived registry-rule runs hit **5 of 40** (semgrep 137 results, opengrep 129) | yes, T3 |
| QuackatronHQ/sca-kitchen-sink (MIT) | `eeddfe4d92fddb749915a98a7b02956eae33af22` (2025-06-19) | 15 lockfiles in 14 formats, every one in `LOCKFILE_ECOSYSTEMS`. Through `jmo scan --tools osv-scanner trivy`, adapter findings per lockfile (osv / trivy): `packages.lock.json` 4/4, `packages.config` 2/2, `go.mod` 108/66, `gradle.lockfile` 108/108, `pom.xml` 94/94, `bun.lock` 44/44, `package-lock.json` 44/44, `pnpm-lock.yaml` 44/44, `yarn.lock` (yarn 4) 44/44, `composer.lock` 29/28, `poetry.lock` 89/44, `requirements.txt` 168/98, `uv.lock` 89/44, `Gemfile.lock` 58/58, `Cargo.lock` 8/4. No format is silent today. trivy also reads `csharp/API.deps.json` (7), which JMo does not hand osv-scanner | yes, T4: a per-format wiring oracle, not a quality score (a "real" frozen snapshot needs a matcher, and osv-scanner would be grading itself) |
| TheAuditorTool/BenchProctor (Apache-2.0) | release 2026.07.22 (releases halted, so the pin cannot move); repository `ad70ff85` | quicktest bundles: TypeScript 6,571,432 bytes, sha256 `80f417b0d7aa…59c4`; JavaScript 5,726,494 bytes, `ce18f02c168f…3a3e`; a standard-library `score_sarif.py` and `expectedresults-2026.07.22.csv` per framework; the scorer reads CWE from `ruleId`, `properties`/`tags` or `taxa`. Not run: it grades Phase 5's bundle | yes, F7, after PR B |
| Checkmarx/kics `assets/queries` (Apache-2.0) | v2.2.0 `453066aa9c66014ad7aee7dd0149ba1944c78050` | Dockerfile: 48 queries, 131 positive and 154 negative samples, **242** expected (file, line). hadolint 2.15.1 and trivy 0.74.0 (bare binaries) put some finding on 176 and 112 of those lines, **181 (74%)** either. "Some finding on the line" is not "the same check", so this is a floor, not recall. Negatives are unusable without an id mapping: 250 of 308 (tool, negative sample) pairs report something, because a negative for one query still breaks others. Kubernetes: 142 queries (same `positive*.yaml` + `positive_expected_result.json` layout), not run | yes, E6: Dockerfile and Kubernetes; Terraform (340 AWS queries alone) and CloudFormation (262) after the tag |
| Samsung/CredData | — | now 73,842 labelled lines, 4,583 true, from 19.5 M lines in 297 repositories (Phase 4 recorded 67,564 / 15,714: the labels were revised); `download_data.py` clones all 297 | **no: after the tag** (J7) |

### Issue premises (22 open; #1426 and #1472 closed 2026-10-24)

Re-measured on `c05aef28`, every `jmo scan` under an isolated HOME. Scripts and per-issue
reports are in `~/.cache/jmo-p6/premise/`.

| Issue | Verdict | Evidence |
|---|---|---|
| #1405 | confirmed | `validate_container_image` False for `registry.example.com:5000/team/app:1.2`, `localhost:5000/app`, and a digest after a port; True for `nginx:1.27`, `ghcr.io/org/app:1.0` |
| #1415 | confirmed | `ONBUILD RUN <<EOF` body → `['os', 'python:3.12']`; plain `RUN <<EOF` skipped correctly |
| #1416 | confirmed | `RUN echo "usage: cat <<EOF here"` and `'a <<EOF b'` swallow the later `FROM`; nothing logged |
| #1410 | confirmed | every "missed" spelling still missed; the Kubernetes row is a parser feature (`apiVersion` + `kind`, pod templates), not a spelling |
| #1365 | confirmed | assertion reads as quoted; the strict `test_docker_image_tools` exists; `KNOWN_NOT_READY` = {yara} |
| #1349 | confirmed, numbers moved | `.gitignore:235` (was :245); nightly 40839417042 at `c05aef28`, job 123331898469: **24 skipped, 0 passed, `success`**; `nightly-notify-failure` fires only on failure; every tool's command in `test_tool_smoke.py` is hand-written (trivy's still `vuln,secret,misconfig`); `tests/integration/conftest.py:22,48` holds a second dead fixture path |
| #1353 | **partly false** | the baseline half holds (`clone_target`, `test_baseline_validation.py:57-77`: unpinned, no `timeout=`; baseline is juice-shop 16.0.0 and names `njsscan`). The e2e half is false: `test_scan_workflows.py`'s U1, U5, M1, W1 pass a URL to `jmo ci --repo`, which takes a path, so they scan **nothing** (rc 1, "Every target was rejected"), and pass (`assert rc in (0, 1)`, an existence-only validator, `continue-on-error: true` at `scheduled.yml:884,1006`). Upstream moved: `master` `717f5efa`, release v20.3.0 `f189f521`; `1618a611` is one commit after the v20.2.0 tag, so pin the sha, not the tag |
| #1173 | partly fixed | `test_scan_pipeline.py` fixed by `dda79bde`; `test_baseline_validation.py:116` still reads `results_dir / "findings.json"`, ignores `run_scan`'s rc (:272) and skips unconditionally (:289-293); **no CI job selects the test** |
| #1408 | confirmed | `syft_adapter.py:173` ids carry no image; two syft documents differing only in `source.name` give identical ids; collisions need the same name, version and in-image path (images sharing a distro) |
| #1282 | confirmed (statically) | `Dockerfile:170` apt `yara`, `:213` `yara-python==4.5.4`, no rules step; `KNOWN_NOT_READY = {"yara"}` (`test_docker_workflows.py:54-60`). The live image was not run: this user cannot reach the Docker socket. The pin is `install_config.YARA_RULES_BUNDLE`, not `YARA_RULES` |
| #1413 | confirmed (Linux) | `--rules <one .yar>` → `ValueError … PosixPath('.')`, rc 2 |
| #1372 | first edge **measured**, second unmeasured | the Maven-name edge is terragoat's entire margin (above); the grouped-rule edge was never exercised and closes with grype |
| #1309 | confirmed, both halves | two repositories each with an identical `deploy.sh` (4 shellcheck findings each) → **4** findings, `target_count` 2, every survivor `path: deploy.sh` with no repository (the first repository's copy survived 6 of 6 reports). Two repositories each with a root lockfile (lodash 4.17.15), `--tools trivy osv-scanner` → **7** findings, the same as one repository alone; 14 expected |
| #1371 | confirmed, sharper | a stale `trivy.json` (4 findings) in a reused results directory, then `--tools shellcheck` → `findings.json` 10 (shellcheck 6, trivy 4), `meta.tools` `['shellcheck']`, and **the history database stores all 10**. A stale `osv-scanner.json` under a row `failed:offline database missing` → 291 old findings reported; under a row that exited 127 before writing → 291. A requested tool that skips is clean (it writes a stub). Inferred, not run: `ToolRunner`'s `_wrote_nothing` (`tool_runner.py:349-352`) is `not output_file.exists()`, so a stale file also passes that check |
| #1432 | confirmed; the body's fix is wrong twice | bad `osv-scanner.toml`: rc 130, row `failed`, `kept_findings` null, "No tool ran … not stored in history", and `findings.json` holds **6** findings (4 on 2.6.0). Correction 1: `collect_tool_diagnostics` reads each output's error channel, not a row's state; state is in `scan-timings.json`, which the report reads only for `root` (`normalize_and_report.py:188`). Correction 2: #1369 deliberately keeps a failed row's working runs (`ToolRun.kept_findings`, `scan_timings.py:140-150`), so "skip every failed row" would drop them. The rule is per row: `kept_findings` null → not a finding of this scan |
| #1370 | confirmed, both halves | trivy tags are `vulnerability`, `secret`, `misconfig` (`trivy_adapter.py:261-265, 338`); `get_tool_category` (`compliance_mapper.py:893-933`) checks the tag `secrets` (`:906`) and maps `tool in ["trivy","syft"]` to `sca` (`:914`) before any content test. A real misconfiguration (DS-0002) gets `sca`: CIS 7.1-7.4, 16.11, NIST GV.SC-3, PCI 6.3.3 / 11.3.1, MITRE T1195. Six keys carry two wordings (`:556/:636`, `:650/:709`, `:655/:714`, `:662/:735`, `:781/:871`, `:797/:880`). Also: **shellcheck and zizmor findings get no category at all** (`None`) |
| #1354 | partly | the four pairs are absent, and trivy 0.74.0 does emit `DS-0013` (`rule_equivalence.py:57`'s comment says it does not). Added in-process: **only `DS-0013`/`DL3003` merges** (43 → 42). No Kubernetes pair merges, **including the six already in the table** (`KSV-0017/CKV_K8S_16`, `KSV-0011/_11`, `KSV-0016/_12`, `KSV-0018/_13`, `KSV-0012/_23`, `KSV-0001/_20`): the checkov adapter keeps only the first element of `file_line_range` (`checkov_adapter.py:192-198, 228`), so checkov's finding is line 1 with no end, trivy's 7-10, and location similarity is 0; with the end supplied (Jaccard 0.4) still no merge |
| #1380 | confirmed, 9 of 9 | every row reproduces with a planted input and a correct control; `native_checks.py` unchanged since `5847d94b`. Row 5 (`CLIENT_DIRS`, `:126`) sits beside `TODO(issue-#1381)`, the after-the-tag monorepo issue |
| #1007 | partly; the live defect confirmed with corrected counts | the osv-scanner golden through `jmo report` with its Windows scan root: `findings.sarif` **1,896** (958 in `results[].properties.remediation`, 938 in the rules' `help` text and markdown from `sarif_common.py:320`), `findings.json` / `.yaml` / `dashboard.html` 1,249 each (958 `remediation` + 291 `raw` URIs), CSV and the Markdown reports 0. A real Linux scan (osv-scanner 2.7.0, 6 findings): SARIF 36, JSON 18. Across eight tools on the samples only `raw` carries the root (checkov 75, hadolint 10, shellcheck 17). A clustered finding nests its duplicates' `raw` in `context.duplicates[].raw`, so a guard must walk every string |
| #1430 | confirmed | `_announce_own_config` (`tool_loop.py:278`) only logs; the row's `detail` stays null; nothing in the results directory or `findings.json` names the file, and the history table `scan_tool_runs` has no `detail` column. A repository whose `osv-scanner.toml` ignores one advisory and one package: 0 findings against 6, and one console line |
| #1431 | confirmed statically | `_zap_context` (`tool_descriptors.py:1467-1515`) scopes to the typed origin and path; nothing handles a redirect; the "examined nothing" hook (`scanned_count`, `:494`) exists only for semgrep. Not run |
| #1097 | partly | 15 adapters, 15 matrix tools, 10 `ADAPTER_REGISTRY` entries (`test_adapter_golden.py:45-91`; syft, jmo-native, yara, zap, nuclei have none), 4 fixture directories. The six registered tools with no directory do not skip: they generate **no test**; 15 collected, 15 passed. Neither guard exists (`:382-391` checks directory → registry only; `0 == 0` passes semgrep's empty fixture). The directory is `osv_scanner`, the matrix name `osv-scanner`. Installed here behind the pin: checkov 3.3.29 (3.3.30), syft 1.51.1 (1.55.0), trufflehog 3.97.1 (3.99.7) |

## Program-plan and spec corrections (land in PR A, Task A1)

- Spec §3, grype row, and §4.2 R1: "unique only on terragoat 29 / kubernetes-goat 3 /
  GitHub-Actions-Goat 7" and "39 findings" → re-measured 2026-10-29: terragoat 0 once Maven
  names agree (28 of B's 29 were the naming artifact), kubernetes-goat 0 at (pkg, id) and 1
  INFO at (pkg, ver, id), github-actions-goat 7 at (pkg, id) and 14 at (pkg, ver, id)
  (known-vulnerable Actions, the residual), 0 on both real apps. R1's residual is the GitHub
  Actions class.
- Spec §3, grype row ("drop **after** osv-scanner lands") and the v2 matrix's `--with` row
  ("kube-linter, grype (if P6 keeps it)") → grype dropped outright, Jimmy 2026-10-29 (J1);
  `--with` is kube-linter alone. Program plan § Phase 6 acceptance: the "else kept as
  `--with grype`" branch goes.
- Spec §3, yara row: "yara-x 1.20" → the pin is set by Task Y2 (1.22.1 on 2026-10-29), as
  a PyPI runtime dependency of jmo-security (J2); "signature-base (DRL 1.1)" stands, with its
  non-DRL rules filtered (D6, J3).
- Spec §3, the matrix table's "yara-x (vendored dependency trees)": made true by D4.
- Program plan § Phase 6: "yara-python (whose pinned version never existed)" is stale:
  4.5.4 is pinned, installs and reads OK. "coverage has been 0/12" → 4 of 15 non-empty
  (gitleaks, opengrep, osv-scanner, zizmor) since Phase 5's PR B, which removed semgrep's
  empty fixture. "an EICAR-style fixture" → a JMo canary rule and file. The
  #1472 paragraph's work landed in `aed1bab2`; #1426 closed, measured false (`64bbd770`
  audit). The roster line stays as it is (`derive` hashes it; Phase 4's keeps its closed
  issues too); the prose says 22 were open on 2026-10-29.
- Program plan § Phase 6, the answer keys (decision 9 put all of them here): Phase 6
  carries vibeproof, zizmor's and osv-scanner's own fixtures, juice-shop's markers,
  sca-kitchen-sink, BenchProctor TypeScript and JavaScript, and KICS Dockerfile and
  Kubernetes; CredData and KICS Terraform and CloudFormation go after the tag (J7). The
  Phase 4 plan's Ground truth table puts SAST and the juice-shop markers in Phase 5, whose
  plan carries neither: this section supersedes that column.
- Program plan § After the tag: its count already reads 34 (Phase 5's PR B updated it).
  Phase 9's acceptance ("no document states a tool count other than 14") **stays 14**:
  grype is dropped (J1), so the final matrix is 15 − 1.
- Cite commits by sha in prose; a `#NNNN` the plan does not roster reddens `phase_audit`.

## Decided from measurement (veto any in review)

1. **grype leaves the matrix** (the acceptance rule: 0 grype-unique on both real apps,
   under both keys). It also costs a 3.2 GB database and a 103 s first scan, and reads 1 of
   app B's 61 dependency findings. No `--with grype` either (J1).
2. **#1372 closes with grype.** Its first edge is measured (the Maven names); nothing
   else clusters a Maven name across tools today, since trivy and osv-scanner already agree.
3. **signature-base replaces ReversingLabs.** ReversingLabs matched nothing on nine targets
   and a 24,942-file vendored tree; its categories are PE/ELF malware. signature-base is
   pinned by commit, its five LOKI externals are declared, and every rule compiles.
4. **yara-x is the one tool that reads vendored trees** (`node_modules`, `vendor`, `.venv`,
   `venv`; `.git` stays out). That is spec §3's trigger and the only place signature-base's
   npm supply-chain rules can match. Measured: one `node_modules` (24,942 files, 0 false
   positives, 5.1 s at `yr -p 4`, 29.6 s on the bindings' one thread) and one Linux `.venv`
   (5,870 files, 0, 3.6 s). Not measured: `vendor/` trees and a Windows `.venv`; Y6 measures
   the latter on `.198`, and a false positive there takes `.venv`/`venv` back out of
   yara-x's walk (decided in that PR, numbers in its body).
5. **DRL's output clause is a requirement, not an option:** every yara-x finding carries
   its rule's `author` (and `reference` when present) in `context` and in the message the
   reporters show.
6. **Only DRL-licensed rules ship.** A rule whose `license` metadata names another license
   (CC BY-NC 4.0 13, OGL 8, Volexity 6, BSD-2 6, CC BY 4.0 4, CAPEv2 3 metadata lines) is
   dropped at fetch time, and the manifest records each one dropped and why (J3).
7. **The fixture is a canary**: a JMo-written rule and a file holding its string,
   generated in `tmp_path`, under `node_modules/`. Never EICAR, never a real sample.
8. **The row is renamed `yara-x`**; `yara` joins `REMOVED_TOOLS` with a warning naming
   `per_tool.yara-x`, as Phase 5 did for semgrep. Every yara finding id changes once.
9. **Golden fixtures are captured through `jmo scan`** on `tests/fixtures/samples/` (or a
   pinned target), so the command is the descriptor's, not a hand-written copy; metadata in
   Phase 0's shape (tool, version, binary sha256, download URL, target, command,
   finding_count). A fixture's version need not equal the current pin: the weekly bump would
   redden it every Sunday; a bump that changes the output format re-captures.
10. **"Golden = 14/14" is `TOOL_MATRIX` after this phase**: 15 on `dev` since PR B put
    opengrep in semgrep's place, 14 once grype leaves. The guard walks `TOOL_MATRIX`, so `--with` tools
    (kube-linter) need no fixture until they join the matrix.
11. **trufflehog's golden gets the `detect-private-key` exclusion** that
    `.pre-commit-config.yaml:28-36` gives gitleaks'.

## PR sequence

| PR | Tasks | P5 file? | Closes |
|---|---|---|---|
| A — plan text; the report holds only what this scan produced, and the scan writes nothing it does not need | A1–A8 | no (A3 becomes P5 if it must edit `basic_reporter.py`; A7 edits `tests/conftest.py`, a P5 file: re-read it on `dev`) | #1007 #1309 #1371 #1408 #1432 #1506 #1517 #1518 #1522 |
| D — image discovery and validation | D1–D4 | no | #1405 #1415 #1416 |
| T — tests that cannot fail; juice-shop's markers and the lockfile oracle | T1–T6 | no (CI wiring moves to F4) | #1173 #1353 |
| N — the native pack's precision and answer key | N1–N3 | no | #1380 |
| G — grype leaves | G1–G3 | **P5** | #1372 and grype's version-checker issue |
| Y — yara-x and signature-base | Y1–Y6 | **P5** | #1282 #1413 |
| E — rows and tables keyed by tool; KICS's line floor | E1–E7 | **P5** | #1354 #1370 #1410 #1430 #1431 |
| F — golden for every adapter; BenchProctor | F1–F8 | **P5** | #1097 #1349 #1365 #1502 |

A, D, T and N touch no file PR B's task list names (A6's `jmo.py` took 12 incidental lines
from PR B; its cited lines are re-read on `dev`) and can be built in parallel worktrees. A precedes G (both
edit `dedup_enhanced.py`) and F (A6 removes the cause of the errors F4's gate will count). G
and Y precede F. E is independent of G and Y.

## Review Focus

1. A scan into a results directory reused from an earlier scan reports nothing the new
   scan did not produce, including a tool the new scan did not request (A2) and a target
   whose scanner raised before its tools ran (A2b).
2. Two repositories in one scan each holding the same vulnerable lockfile report one
   finding per repository, each naming its repository (A3).
3. A yara-x scan of a repository with a `node_modules` reports the canary there and still
   honours `.git` and JMo's results directory (Y3, Y5).
4. A rule whose `license` metadata is not DRL never reaches the compiled set, and the
   manifest says so (Y1).
5. Removing any one golden fixture, or emptying it, fails the meta-guard (F3).

---

## Task A1: Plan text and corrections

**Files:**
- Modify: `docs/superpowers/plans/2026-09-12-v2.0.0-program.md` (§ Phase 6)
- Modify: `docs/superpowers/specs/2026-09-12-v2.0.0-program-design.md` (§3 grype and yara rows, §4.2 R1, §6 row 6, §12)
- Create: this file, as committed

- [ ] **Step 1:** Apply the corrections section above, one edit per bullet.
- [ ] **Step 2:** `python3 scripts/dev/phase_audit.py derive | tail -2` → "all four
  plan checksums agree"; `verify` → `unclaimed: 0`.
- [ ] **Step 3:** Commit `docs: Phase 6 task plan, and what its measurement corrected`.

## Task A2: The report reads only what this scan's rows produced (#1371, #1432)

**Files:** `scripts/core/normalize_and_report.py:450` (`_target_dirs`), `:467-528`
(`gather_results`, its glob at `:515`), `:317-339` (`collect_tool_diagnostics`, which must
filter identically), `scripts/cli/scan_jobs/tool_loop.py` (before each planned tool runs),
tests in `tests/unit/test_normalize_and_report.py` and `tests/cli/`. Read rows with the
existing `ScanTimings.from_dict` (`scan_timings.py:196`); editing `scan_timings.py` would
make this task P5.

- [ ] **Step 1: Failing tests**, each through `jmo scan` then `jmo report`:
  - `test_a_tool_this_scan_did_not_request_is_not_reported`: a stale `trivy.json` (4
    findings), `--tools shellcheck` → `findings.json` and the history row hold shellcheck's
    findings only.
  - `test_a_failed_row_with_no_kept_findings_is_not_reported`: #1432's bad
    `osv-scanner.toml` → 0 osv-scanner findings, and the report's diagnostics name the row.
  - `test_a_failed_row_keeps_what_its_working_runs_found`: #1369's case (one unreadable
    lockfile beside a readable one) → the readable one's findings, as today.
  - `test_a_stale_output_does_not_pass_as_written`: a tool that exits 0 and writes nothing
    over a stale file is `failed:wrote no output` (the inferred `_wrote_nothing` hole).
  - `test_a_results_dir_without_timings_reads_everything`: a directory `jmo scan` did not
    write still reports every `<tool>.json` (`jmo report` on outside output).
- [ ] **Step 2:** Implement: the scan deletes each planned tool's `<tool>*.json` before its
  first invocation; the report reads `scan-timings.json` per target and skips a tool's output
  when the tool is not listed, or its row is not `ran` and `kept_findings` is null.
- [ ] **Step 3:** Commit `fix: a report holds only what this scan's tools produced`, body
  `Closes #1371` and `Closes #1432`.

## Task A2b: A target whose scanner raised reports nothing old (#1518)

**Files:** `scripts/cli/scan_orchestrator.py:1246-1420` (the futures list, `("repo",
result_name, future)` and its siblings, and the except block at `:1405`), `tests/cli/`
(beside A2's reused-directory tests). `scan_timings.py` stays unedited (P5): call the
existing `write_scan_timings` (`:258`) as `gitlab_scanner._abandon` (`:239-268`) does.

Measured from the code at `2dbb89c0` + A2: the except block knows `target_type` and the
recorded `target_id`, not the target's output folder. For a repository the two agree
(`result_name`); for an image the id is the reference and the folder is `image_folders`'
sanitised name, and for IaC the id is `iac_target_name` and the folder is `iac_folders`'.
Clearing the old `scan-timings.json` alone would make the leak worse: A2's rule reads every
output in a directory that has no timings file.

- [ ] **Step 1: Failing tests**, through `jmo report` on a results directory shaped as
  `jmo scan` writes it (A2's ruling): a repository target and an image target, each holding
  an earlier scan's `scan-timings.json` (one tool `ran`) and that tool's output; the
  target's scanner patched to raise before `run_tools`; then `findings.json` holds none of
  the earlier findings, and the target's `scan-timings.json` rows read `failed` with the
  scanner-error reason. A resumed target (`_is_completed`) keeps its earlier timings and
  outputs untouched.
- [ ] **Step 2:** Carry each job's output folder with its future, and in the except block
  write the `failed_rows` it already builds to that folder's `scan-timings.json`, with the
  failed outcome and the error, creating the folder as `_abandon` does. A write failure
  logs and never replaces the target's failure.
- [ ] **Step 3:** Commit `fix: a target whose scanner raised reports none of an earlier
  scan's findings`, body `Closes #1518`.

## Task A2c: A GitLab repository keeps its rows when its image step fails (folded in, no issue)

Found by A2b's review (2026-10-30); folded into PR A on Jimmy's word rather than filed.

**Files:** `scripts/cli/scan_jobs/gitlab_scanner.py` (`scan_gitlab_repo`: `scan_repository`
then `_scan_named_images` inside one `try`, whose generic `except` calls
`_record_abandoned_target`), its tests.

The generic `except` replaces the repository's own `ran` rows and outputs with
`failed:target not scanned` when anything after `scan_repository` raises, so the report
withholds the repository's real findings; `_record_abandoned_target`'s docstring says a
failure after the repository's scan never comes there.

- [ ] **Step 1: Measure first:** what can raise out of `_scan_named_images` (it catches
  per image at `:549` and `:564`) and reach that `except`; if nothing can, record it and
  pin the docstring's promise with a test instead of changing code.
- [ ] **Step 2: Failing test:** a GitLab target whose repository scan writes `ran` rows and
  output, then an image step that raises → the report holds the repository's findings
  and its rows read `ran`; the image failure is logged and recorded.
- [ ] **Step 3:** Commit `fix: a GitLab repository keeps its findings when its image step fails`.

## Task A2d: A GitLab URL without a scheme clones from that host, never gitlab.com (#1522)

Found by PR T's review of its Task T5b (2026-10-30); a security defect, folded into PR A on
Jimmy's word, then filed as #1522 and rostered in Phase 6 (roster PR, 2026-10-30).

**Files:** `scripts/cli/scan_jobs/gitlab_scanner.py` (`scan_gitlab_repo`, the clone URL),
its tests; `scan_orchestrator.py` (the `or "https://gitlab.com"` default) read, not changed
unless the measurement needs it.

`scan_gitlab_repo` replaces any `--gitlab-url` that does not start with `http` with
`https://gitlab.com`, so `--gitlab-url gitlab.example.com` clones from gitlab.com; on a
private or missing path gitlab.com answers 401, and git's credential helper sends the
self-hosted instance's token to gitlab.com.

- [ ] **Step 1: Failing tests** (the clone argument read from a patched `subprocess.run`, no
  network): `gitlab.example.com` and `gitlab.example.com/` → `https://gitlab.example.com/<path>.git`;
  `https://` and `http://` URLs unchanged; an empty URL → the gitlab.com default; any other
  scheme (`ssh://`, `git@host:`, `ftp://`) → the target abandoned with a reason naming the
  URL's scheme, no clone, and the token never handed to git.
- [ ] **Step 2:** Implement in `scan_gitlab_repo`; no path from the user's URL leads to
  another host.
- [ ] **Step 3:** Commit `fix: a GitLab URL without a scheme clones from that host, never gitlab.com`.

## Task A2e: Schedules and generated workflows keep a self-hosted GitLab URL (folded in, no issue)

Found by A2d's review (2026-10-30); same class as A2d, folded into PR A on Jimmy's word.

**Files:** `scripts/core/schedule_manager.py` (the GitLab target), `scripts/cli/schedule_commands.py`
and `scripts/cli/jmo.py` (`jmo schedule create`'s flags), `scripts/core/cron_installer.py`,
`scripts/core/workflow_generators/github_actions.py` and `gitlab_ci.py`,
`scripts/cli/wizard_generators.py`, their tests.

A schedule stores a GitLab target as a repository or group with no URL, and the cron line, the
GitHub Actions workflow and the wizard's generated workflow emit `--gitlab-repo` or
`--gitlab-group` and the token without `--gitlab-url`, so a self-hosted schedule clones
gitlab.com with the self-hosted token.

- [ ] **Step 1: Measure first:** every place a GitLab target becomes a stored spec or a command,
  and which drop the URL.
- [ ] **Step 2: Failing tests** per generator: a self-hosted URL in, `--gitlab-url` with that URL
  out; no URL, no flag; a URL A2d would refuse is refused when the schedule is created.
- [ ] **Step 3:** The spec gains the URL; every generator emits it; validation reuses A2d's.
- [ ] **Step 4:** Commit `fix: schedules and generated workflows keep a self-hosted GitLab URL`.

## Task A3: Every finding names its target (#1309)

**Files:** `scripts/core/normalize_and_report.py:221-310` (`_normalize_paths_and_ids`), `:59`
(dedup), `scripts/core/adapters/common.py:325` (`normalize_finding_path`) and `fingerprint`,
`scripts/core/dedup_enhanced.py:136` (`dependency_key`; PR G edits this file later), the
reporters that print a location (SARIF, CSV, HTML), `docs/schemas/` if a field is added. If
`scripts/core/reporters/basic_reporter.py` must change, this task is P5.

- [ ] **Step 1: Failing tests:** `--repos-dir` over two repositories with an identical
  `deploy.sh` → 8 findings, each naming its repository; two repositories each with a root
  `package-lock.json` holding lodash 4.17.15, `--tools trivy osv-scanner` → clusters per
  repository, never across them (as measured: 26 adapter outputs, 26 after fingerprint
  dedup, 14 after cross-tool clustering, which is 7 per repository, and origin/dev gives 7
  for one repository); a single-repository scan's ids and paths are unchanged in shape apart
  from the new target key.
- [ ] **Step 2:** Implement: the target joins the fingerprint's inputs, the dedup key and
  `dependency_key`; the target is carried on the finding (`location` or a top-level field)
  and printed by the location columns. Every stored id changes once; `UPGRADE.md` says so.
- [ ] **Step 3:** Commit `fix!: a finding in two repositories of one scan is two findings`,
  body `Closes #1309`.

## Task A4: No scan root in a field JMo writes (#1007)

**Files:** `scripts/core/normalize_and_report.py:221` (path normalisation reaches
`remediation`), `scripts/core/adapters/sarif_common.py:320` (rule `help` → `remediation`),
`scripts/core/reporters/sarif_reporter.py:154-166` (`properties.remediation`, rules' help),
`scripts/core/reporters/html_reporter.py` (the dashboard redacts the scan root in `raw`, J5),
`tests/unit/test_no_scan_root_in_artifacts.py` (new)

- [ ] **Step 1: Failing guard** `test_no_scan_root_in_any_shipped_artifact`: the osv-scanner
  golden through `gather_results` and every reporter with a scan root set; walk **every
  string** of every artifact (so `context.duplicates[].raw` is reached) and assert the root
  occurs 0 times, except inside `raw` in `findings.json` and `findings.yaml`, which stay
  verbatim (J5). The guard names that one exemption; it does not enumerate the fields it
  checks. `dashboard.html` gets no exemption. Measured today: SARIF 1,896, JSON 1,249,
  dashboard 1,249.
- [ ] **Step 2:** Implement: rewrite the scan root to the relative path in every string
  field JMo writes (`remediation`, `message`, rule `help`), at the one place paths are
  already normalised; the dashboard reporter redacts the root inside `raw` when it embeds it.
- [ ] **Step 3:** Mutation-test the guard (remove the rewrite, then the dashboard redaction,
  each from a byte backup → red).
- [ ] **Step 4:** `docs/KNOWN_LIMITATIONS.md`: the #1007 entry (`:604-608`, "dashboard.html
  embeds the scanning user's home directory") becomes "`raw` in `findings.json` and
  `findings.yaml` is each tool's verbatim output and can hold the scanning machine's paths;
  the dashboard redacts them", and the section heading `:571` "Defects shipping in v1.1.0" is
  corrected (10-29 handoff).
- [ ] **Step 5:** Commit `fix: no field JMo writes carries the scanning machine's path`,
  body `Closes #1007`.

## Task A5: syft's image packages name their image (#1408)

**Files:** `scripts/core/adapters/syft_adapter.py:160-173`, `scripts/core/normalize_and_report.py:792-822` (`_build_syft_indexes`), `tests/adapters/test_syft_adapter.py`

- [ ] **Step 1: Failing test** `test_two_images_holding_one_package_are_two_findings`: two
  syft documents identical but for `source.name` (`nginx:1.27`, `alpine:3.19`) → two ids;
  the same package in one image read twice → one id. And `_build_syft_indexes` keyed by
  (image, path, name): trivy's finding in image X never takes image Y's SBOM entry.
- [ ] **Step 2:** For image targets carry `source.name` + `source.version` into the
  fingerprint's path slot (`<image>!<path>`) and into the index key. Repository targets
  are unchanged (assert one repository id is byte-identical before and after).
- [ ] **Step 3:** Commit `fix: an image's SBOM packages name the image they came from`, body `Closes #1408`.

## Task A6: A non-interactive scan leaves `~/.jmo/config.yml` alone (#1506)

**Files:** `scripts/cli/jmo.py:2505` (`_show_kofi_reminder`), `:3492` (its one call, in
`cmd_scan`), tests in `tests/cli/`; `tests/conftest.py:489` (`_guard_real_jmo_config`) is
read, not changed.

Placed in PR A, not beside F4's gate fix, so the cause of the e2e errors leaves `dev` before
any gate counts them, and every later PR's `jmo scan` gates stop writing the real config.

- [ ] **Step 1: Measure first:** which entry points reach the call (`jmo scan`, `jmo ci`,
  `--yes`, a piped stdout, `CI` set), and what each writes; the issue's fix direction is
  unmeasured.
- [ ] **Step 2: Failing tests** under a `tmp_path` HOME holding a `~/.jmo/config.yml`:
  a scan with stdout not a TTY, and one with `CI` set, leave the file byte-identical and
  print no reminder; an interactive scan (patched `isatty`) still counts, as today.
- [ ] **Step 3:** Implement: `_show_kofi_reminder` returns before it reads or writes the
  config when the scan is not interactive, by Step 1's definition.
- [ ] **Step 4:** Commit `fix: a non-interactive scan leaves ~/.jmo/config.yml alone`, body
  `Closes #1506`.

## Task A5b: Two versions of one package take their own SBOM entry (folded in, no issue)

Found by A5's review (2026-10-30); folded into PR A on Jimmy's word rather than filed.

**Files:** `scripts/core/normalize_and_report.py` (`_find_sbom_match`, the function A5
changed), its tests beside A5's.

- [ ] **Step 1: Failing test:** one target whose SBOM lists one package at two versions
  (two paths); a trivy finding naming that package and one of the versions, at a path
  syft does not list (the by-name fallback) → `context.sbom` carries that version, for
  each version in turn.
- [ ] **Step 2:** Among by-name candidates, prefer the one whose version equals trivy's
  `InstalledVersion`; without a version match, behave as today.
- [ ] **Step 3:** Commit `fix: SBOM enrichment takes the package version trivy names`.

## Task A6b: Every prompt guard survives a closed stdin (folded in, no issue)

Found by A6's review (2026-10-30); folded into PR A on Jimmy's word rather than filed.

**Files:** `scripts/cli/jmo.py`: the four guards A6 did not touch (the missing-tools
prompt, `_collect_email_opt_in`, the resume prompt, the MCP install prompt), each calling a
bare `sys.stdin.isatty()`; A6's `_stream_is_tty`.

- [ ] **Step 1: Measure first:** run each guard's path with stdin closed (`<&-`, or
  `sys.stdin = None` in-process): which raise, and what the user sees.
- [ ] **Step 2: Failing tests** for each guard that raises; then implement with
  `_stream_is_tty`, the closed stream read as not interactive.
- [ ] **Step 3:** Commit `fix: a closed stdin reads as non-interactive at every prompt`.

## Task A7: The e2e helper's HOME hides the scanners and moves their caches (#1517)

**Files:** `tests/conftest.py:106` (`jmo_runner`), `tests/e2e/test_linux_specific.py` (its
five scan tests), and every other test file that scans through `jmo_runner` (Step 1 lists
them).

Placed right after A6: the fake HOME exists to keep the Ko-fi write (#1506) off the real
config, and A6 removes that write for a non-interactive scan (`jmo_runner` captures output,
so it is not a TTY). The override may then go entirely.

- [ ] **Step 1: Measure first**, with A6 in: what a `jmo scan` run through `jmo_runner`
  still writes under `~/.jmo` (history is cwd-relative, and `jmo_runner` keeps
  `cwd=tmp_path`); which test files scan through `jmo_runner`, and which of their scans run
  a scanner on `.199` and in `ci.yml`'s shards.
- [ ] **Step 2: Failing tests:** `jmo_runner` itself: a scan leaves the real
  `~/.jmo/config.yml` untouched (A6's guarantee, checked by `_guard_real_jmo_config`) and
  hands the subprocess no fresh per-test scanner cache; each scan test that means to scan
  asserts at least one scanner row `ran`, or becomes a CLI-plumbing test whose `--tools`
  names a tool it can run.
- [ ] **Step 3:** Implement Step 1's answer: drop the HOME override if A6 leaves nothing
  else under `~/.jmo`; otherwise keep it and point the scanners at one session-scoped cache
  (`XDG_CACHE_HOME`, or `TRIVY_CACHE_DIR` and `GRYPE_DB_CACHE_DIR`).
- [ ] **Step 4:** Repeat the 2026-10-30 measurement: `test_linux_specific.py` with
  `~/.jmo/bin` on PATH and one unique `--basetemp` under `~/.cache` (deleted after reading)
  → record the size and time (24 GB and 6 min 57 s before; 5.0 MB and 11 s without the
  scanners on PATH).
- [ ] **Step 5:** Commit `test: e2e scans find the installed scanners and share one cache`,
  body `Closes #1517`.

## Task A8: Gates, then PR A

- [ ] **Step 1:** Suite in three parts; diff failing ID sets against `origin/dev`'s.
- [ ] **Step 2: Through `jmo scan`** (isolated HOME): the two-repository fixture of A3;
  a reused results directory (A2); the osv-scanner golden fed through `gather_results` and
  every reporter, with the scan root counted in each artifact (A4); a scan piped to a file
  with the config's sha256 taken before and after (A6); A7's Step 4 numbers.
- [ ] **Step 3:** Push, open PR A; the body carries those numbers and the Windows run's
  ID-set diff.

## Task D1: A registry with a port is a registry (#1405)

**Files:** `scripts/core/validation.py:529-599` (`validate_container_image`),
`scripts/cli/scan_jobs/gitlab_scanner.py` (`_REFERENCE`, which already accepts every form
below; `_abandon` at `:507` loses its live trigger), `tests/cli/test_scan_target_names.py:779, 1079`
(both use a port as their "refused" example), `docs/TOOLS.md:128`

- [ ] **Step 1: Failing test** parametrized over the references measured: `nginx:1.27`,
  `ghcr.io/org/app:1.0`, `registry.example.com:5000/team/app:1.2`, `localhost:5000/app`,
  `host:5000/app@sha256:<64 hex>`, and a single-character path component (`ghcr.io/o/a:1`,
  refused today) → all True; an upper-case repository path (`registry.example.com/App:1`,
  accepted today) and three more that must be False (a shell metacharacter, an empty name, a
  `..` component). Give the two `test_scan_target_names.py` tests a refused reference that is
  still invalid, and keep `_abandon` reachable from a test.
- [ ] **Step 2:** One grammar: `validate_container_image` and `_REFERENCE` share the Docker
  reference rule (a first component holding `.` or `:`, or exactly `localhost`, is a registry;
  its `:port` is digits; repository components are lower case).
- [ ] **Step 3:** Commit `fix: an image on a registry with a port is a valid target`, body `Closes #1405`.

## Task D2: Heredocs: ONBUILD, and a marker inside quotes (#1415, #1416)

**Files:** `scripts/cli/scan_jobs/gitlab_scanner.py:76-79` (`_HEREDOC`, `_HEREDOC_INSTRUCTIONS`), `:313` (`_discover_container_images`), `tests/unit/test_gitlab_image_discovery.py` (or the existing discovery test file)

- [ ] **Step 1: Failing tests**: #1415's Dockerfile → `{'python:3.12'}` and no `os`; each
  row of #1416's table between `FROM alpine:3.19` and `FROM nginx:1.27` → both images; an
  unterminated heredoc at end of file logs one WARNING naming the file and marker.
- [ ] **Step 2:** `ONBUILD`: test the second word against `_HEREDOC_INSTRUCTIONS`. Quotes:
  blank `'…'` and `"…"` spans before matching `_HEREDOC`. End of file with a body open:
  warn.
- [ ] **Step 3:** Commit `fix: image discovery reads ONBUILD heredocs and quoted markers correctly`, body `Closes #1415` and `Closes #1416`.

## Task D3: compose.yaml and workload manifests (#1410, its compose and Kubernetes rows)

**Files:** `scripts/cli/scan_jobs/gitlab_scanner.py` (discovery), its tests

- [ ] **Step 1: Failing tests**, one per probe row: `compose.yaml` and `compose.yml`; a
  Pod's `initContainers`; a Deployment's (and StatefulSet's, DaemonSet's, Job's)
  `spec.template.spec.containers`; a CronJob's `spec.jobTemplate.spec.template`; a manifest
  named `app.yaml` (no `.k8s.`) detected by `apiVersion` + `kind`; a YAML that is not a
  manifest contributes nothing; a multi-document file.
- [ ] **Step 2:** Implement with `yaml.safe_load_all`; a document is a manifest when it
  has string `apiVersion` and `kind`.
- [ ] **Step 3:** Commit `feat: image discovery reads compose.yaml and every workload's pod template`.
  #1410 stays open: its Dockerfile-spelling row is `is_dockerfile`, a P5 file (Task E3).

## Task D4: Gates, then PR D

- [ ] Suite; ID-set diff; a GitLab-shaped fixture through `jmo scan` names every image
  of D2's and D3's fixtures. Push, open PR D.

## Task T1: The baseline test asserts (#1173)

**Files:** `tests/integration/test_baseline_validation.py:99-127` (`load_findings`), `:261-293`

- [ ] **Step 1:** `load_findings` reads `results_dir / "summaries" / "findings.json"` and
  raises when it is absent; `run_scan`'s return code is asserted (`:272`); the
  "0 findings, tools not installed" skip goes (a missing tool is `requires_tools`' job).
- [ ] **Step 2:** Run it once against the T2 pin, record what it asserts, and expect real
  failures: none of its assertions has ever executed.
- [ ] **Step 3:** Commit `test: the juice-shop baseline test reads the findings the product writes`, body `Closes #1173`.

## Task T2: One juice-shop pin, and clones that time out (#1353)

**Files:** `tests/integration/test_baseline_validation.py:57-77, 258, 260`, `tests/integration/baselines/juice-shop.baseline.json`, a shared constant (e.g. `tests/integration/targets.py`)

- [ ] **Step 1:** One constant, `JUICE_SHOP_COMMIT = "1618a611b173b4bf114028e6e02549950606e29d"`
  (the evidence commit; one commit after the v20.2.0 tag, so a sha, never `--branch`);
  `clone_target` does `git init` + `git fetch --depth 1 origin <sha>` with `timeout=`;
  WebGoat gets the same treatment.
- [ ] **Step 2:** Re-derive the baseline at the pin through `jmo scan` with the matrix on
  `dev` after Phase 5's PR B (its `tools_used` names `njsscan` and `semgrep`). Record the
  counts per tool. Y changes juice-shop's count (signature-base: 2 measured), so F4
  re-derives it once more, after G and Y.
- [ ] **Step 3:** Commit `test: the baseline test scans one pinned juice-shop commit`, body `Closes #1353`.
  The e2e half of #1353's body is false (it scans nothing); that is #1502, whose tests T5
  fixes.

## Task T3: juice-shop's own markers are the answer key (J7)

**Files:** `tests/integration/juice_shop_markers.py` (new: the parser),
`tests/integration/test_baseline_validation.py` (the marker test beside T1's),
`tests/integration/baselines/juice-shop.markers.json` (new: the recorded detection table),
`tests/unit/test_juice_shop_markers.py` (the parser's own test)

The markers are comments in juice-shop's source, read from T2's clone at the pin at test
time. Nothing from juice-shop is committed except (file, line, challenge) triples and which
tools detected them.

- [ ] **Step 1: Failing parser test** on a file written in `tmp_path` with a made-up
  challenge name: the end-of-line `// vuln-code-snippet vuln-line <challenge>` (TypeScript,
  Solidity) and `# …` (YAML, Terraform) forms → (file, line, challenge); a `start`/`end`
  snippet marker is not a vulnerable line; the parser returns no line text (a marked
  Terraform line holds juice-shop's RSA private key, and the secret hooks would block it).
- [ ] **Step 2:** Parse the pin and assert the count: 40 lines in 17 files (measured); a
  different count means the pin moved or the parser is wrong.
- [ ] **Step 3: Failing test** (`requires_tools`): a full `jmo scan` of the pinned clone,
  then for each marked line the set of tools with a finding on it. The recorded table is
  the answer key: the test fails when a line detected before is detected by nobody, and
  prints lines newly detected (record them in the PR that improves them). Record recall per
  file type. The archived registry-rule runs hit 5 of 40; the first recorded number is on
  `dev` after Phase 5's PR B, and F4 re-records it after G and Y, as it does T2's baseline.
- [ ] **Step 4:** Commit `test: juice-shop's own vulnerable-line markers grade the whole scan`.

## Task T4: every lockfile format reaches osv-scanner (J7)

**Files:** the answer-key fetch script (`scripts/dev/fetch_answer_keys.py`, created by
whichever of N2 and T4 lands first; one function per key, pinned commit, sha256 per file),
`tests/fixtures/osv-db-lockfiles/osv-scalibr/<ecosystem>/all.zip` (new frozen database,
separate from `tests/fixtures/osv-db`, whose three advisories other tests count exactly),
`tests/integration/test_lockfile_formats.py` (new, `requires_tools`)

The lockfiles are fetched from sca-kitchen-sink at `eeddfe4d92fddb749915a98a7b02956eae33af22`
into the answer-key cache, never committed: tracked vulnerable lockfiles would raise
Dependabot alerts on JMo's own repository.

- [ ] **Step 1:** For each of the 15 lockfiles pick one package at the version it pins and
  write one synthetic advisory (`JMO-TEST-2026-01NN`) affecting exactly that version, in the
  ecosystem's version scheme: npm (×4: `bun.lock`, `package-lock.json`, `pnpm-lock.yaml`,
  yarn 4 `yarn.lock`), PyPI (×3), Go, crates.io, Packagist, RubyGems, Maven (×2: `pom.xml`,
  `gradle.lockfile`), NuGet (×2: `packages.lock.json`, `packages.config`). A generator
  script writes the zips (`write_bytes`, sorted entries, fixed timestamps) so they rebuild
  byte-identically.
- [ ] **Step 2: Failing test** through `tool_loop.run_tools` as
  `test_osv_scanner_wiring.py::_real_scan` does, offline against the new database: exactly
  the 15 (lockfile, advisory) pairs, nothing else; a lockfile that yields nothing fails
  naming its format; any `partly audited` detail (#1472's class) fails too.
- [ ] **Step 3:** Mutation-test: remove one entry from `LOCKFILE_ECOSYSTEMS`
  (`scripts/core/osv_database.py:48-71`) from a byte backup → red, naming that format.
- [ ] **Step 4:** Measure whether osv-scanner 2.7.0 reads `*.deps.json` (trivy reads
  sca-kitchen-sink's `csharp/API.deps.json`, 7 findings). If it does, add the pattern to
  `LOCKFILE_ECOSYSTEMS` and a 16th pair; if not, record it in the PR.
- [ ] **Step 5:** Commit `test: every lockfile format JMo claims reaches osv-scanner, offline`.

## Task T5: The e2e URL tests scan what they name (#1502, its tests)

**Files:** `tests/e2e/test_scan_workflows.py:27, 59, 119, 138, 183, 213` (`DEFAULT_REPO`,
`_get_test_repo()`, U1, U5, M1, W1, the `rc in (0, 1)` assertion), `tests/e2e/conftest.py:80-100`
(`validate_basic_scan`), T2's shared juice-shop pin

- [ ] **Step 1: Failing test:** `validate_basic_scan` asserts `meta.target_count >= 1`
  and, for a repository target, a non-zero finding count; run U1 as it is today → it fails
  (measured: rc 1, "Every target was rejected", `target_count` 0).
- [ ] **Step 2:** `_get_test_repo()` clones `TEST_REPO` to a path at T2's pin (`git init` +
  `git fetch --depth 1`, with `timeout=`) and returns the path; a URL that does not clone
  fails the test. U1, U5, M1 and W1 then scan juice-shop.
- [ ] **Step 3:** Commit `test: the e2e repository tests scan the repository they name`. No
  closing keyword: #1502's gate half is F4's.

## Task T6: Gates, then PR T

- [ ] Suite; the baseline and marker tests run locally with real tools (`-m "requires_tools"`)
  pass or fail on assertions, never skip; T4's test passes offline (`unshare -rn`); U1 run
  locally reports juice-shop's findings. Push, open PR T. Its CI wiring lands in F4.

## Task N1: The native pack's nine precision gaps (#1380)

**Files:** `scripts/core/native_checks.py` (`:126` `CLIENT_DIRS`, `:135-140` the middleware
files, `:141` `SERVER_ONLY_IMPORT`, `:145` `RULES_FILE_NAMES`, `:160-163` `FIREBASE_OPEN`,
`:178` `DROP_TABLE_RE`, `:311-318` `_CODE_TOKENS`, `:432`, `:468`, `:508-509`),
`tests/unit/test_native_checks.py`. The row's trigger (`tool_descriptors.py:596-621`) reads
these constants, so a new rules file name widens it without editing that P5 file.

- [ ] **Step 1: Failing tests**, one per row, each beside the control the measurement used:
  `src/proxy.ts` is server code (1); `allow read;` and `allow read, write;` are open (2);
  `database.rules.json` `".read": true` / `".write": true` at any depth is open (3);
  `KEY: value` in a dotenv file is read (4); a root `package.json` with no browser framework
  (Next, Vite, CRA, Expo) makes `src/` server code, at the root only, nested apps staying
  #1381's (5); `drop table` inside a string or a dollar-quoted body does not drop RLS state
  (6); a quoted `import "server-only"` and `route.*` under a `_`-prefixed folder do not hide
  client code (7a, 7b); a rule continued on the next line is one rule (8); a `\` + CRLF
  continuation reads as LF does (9).
- [ ] **Step 2:** Implement row by row, red then green, one commit each or one per file area.
- [ ] **Step 3:** Commit body `Closes #1380` on the last.

## Task N2: The native pack's answer key (decision 9)

**Files:** `scripts/dev/fetch_answer_keys.py` (new unless T4 landed first; one function per
key, pinned commit and sha256 per file), `tests/integration/test_native_answer_key.py` (`requires_tools` not needed:
the pack is built in)

- [ ] **Step 1:** Pin `humora2504/vibeproof` (MIT, one maintainer, unchanged since
  2026-09-17) by commit; fetch `test/fixtures` at test time, never vendored (trufflehog
  finds 3 Postgres URIs in it).
- [ ] **Step 2: Failing test:** map vibeproof's 12 expected rule ids to JMo's five checks;
  assert per-class recall for the classes both cover, 0 findings on its clean fixture,
  and record the three classes JMo's pack lacks (`using (true)`, anon grants, public
  buckets) as `xfail(strict=True)` with the reason.
- [ ] **Step 3:** Commit `test: the native pack graded against vibeproof's fixtures`.

## Task N3: Gates, then PR N

- [ ] Suite; the pack still reports 0 on app A and app B (exports) and 8 of 8 on its own
  fixture. Push, open PR N.

## Task G1: grype leaves (P5)

**Files** (re-read each on `dev` after PR B): `scripts/core/tool_descriptors.py`
(`_grype_repo` `:1389`, the row `:2000-2020`, `REMOVED_TOOLS` `:2112`),
`scripts/core/adapters/grype_adapter.py` (delete), `versions.yaml:100-108, 213`,
`Dockerfile:90-97, 230, 243, 252, 289, 335`, `scripts/core/install_config.py`,
`scripts/core/dedup_enhanced.py`, `scripts/core/adapters/syft_adapter.py`,
`scripts/core/adapters/trivy_adapter.py`, `scripts/core/common_finding.py`,
`scripts/core/reporters/basic_reporter.py`, `scripts/core/validators/scan_validator.py`,
`scripts/cli/scan_utils.py`, `scripts/cli/tool_manager.py`,
`scripts/cli/wizard_flows/ui_helpers.py`, `jmo.yml`, `.github/workflows/ci.yml:1617-1638`,
`scheduled.yml`, the packaging files; 37 test files and 31 docs name grype (`git grep -il grype`).

- [ ] **Step 1: Failing test** `test_grype_is_removed`: `jmo scan --tools grype` exits 2
  with "removed in v2.0.0"; a config with `per_tool.grype` gets one warning; `TOOL_MATRIX`
  has no grype; `len(TOOL_MATRIX) == 14` where the count is asserted.
- [ ] **Step 2:** Remove; `update_versions.py --sync`; `--sync --dry-run` rc 0;
  `git grep -in grype -- scripts .github Dockerfile versions.yaml jmo.yml packaging` leaves
  only `REMOVED_TOOLS`, the warning, `version_history`, and comments naming what replaced it.
  This is Phase 6's first edit of `tool_descriptors.py`: add the missing
  `# TODO(issue-#1351)` at `_nuclei_url` (`:1666` at `c05aef28`; 10-29 handoff).
- [ ] **Step 3:** Commit `feat!: grype leaves the matrix`, body `Closes #1372` and closing
  grype's version-checker issue (#1492 on 2026-10-29: it is exempt only while
  `versions.yaml` lists grype, so the sync would redden `phase_audit` otherwise).

## Task G2: The residual is written down (P5)

**Files:** `docs/KNOWN_LIMITATIONS.md`, `UPGRADE.md`, `CHANGELOG.md`, `docs/TOOLS.md`

- [ ] **Step 1:** KNOWN_LIMITATIONS: known-vulnerable GitHub Actions (a compromised
  action's version) are not reported offline; zizmor reports the same `uses:` as
  `unpinned-uses`; pinning to a sha closes the class; the measured numbers above.
- [ ] **Step 2:** UPGRADE: grype removed; no other finding's id changes.
- [ ] **Step 3:** Commit `docs: what leaving grype costs, measured`.

## Task G3: Gates, then PR G

- [ ] Suite; through `jmo scan` on app A and app B (exports): the dependency findings
  equal this plan's (25 and 61) without grype, every one detected by osv-scanner and all
  but one per app (24 of 25, 60 of 61) by trivy too, as measured with grype present;
  `docker-smoke`'s `expected_tools` derives 14. Push, open PR G.

## Task Y1: The rules: signature-base, DRL only, five externals (P5)

**Files:** `scripts/core/install_config.py:75-109` (`YARA_RULES_BUNDLE` → signature-base;
its comment's two false reasons go), `scripts/cli/tool_installer.py:1816-1903` (the fetch),
`scripts/core/yara_rules.py` (new: filter + manifest), `tests/unit/test_yara_rules.py`

- [ ] **Step 1:** Pin signature-base by commit and tarball sha256 (verify before
  extracting; `tarfile` `data` filter). Keep `yara/` only.
- [ ] **Step 2: Failing tests** on a synthetic tree: a rule with
  `license = "https://creativecommons.org/licenses/by-nc/4.0/"` is dropped and named in the
  manifest; a DRL rule and a rule with no `license` line are kept (a file inherits the
  repository's DRL); a file whose rules are all dropped leaves no empty file behind.
- [ ] **Step 3:** Implement; then measure on the real pin and record in the PR: files and
  rules kept, rules dropped per license.
- [ ] **Step 4:** Commit `feat: signature-base's DRL rules replace the ReversingLabs bundle`.

## Task Y2: The engine (P5)

The install path is the PyPI wheel as a runtime dependency of jmo-security (J2).

**Files:** `pyproject.toml` (`yara-x==<pin>` in `dependencies`), `uv.lock` (`make
deps-lock`), `versions.yaml:142-162` (the `yara` row leaves `python_tools`),
`scripts/cli/installers/pip_installer.py`, `scripts/core/tool_utils.py`,
`Dockerfile:170, 213, 286` (apt `yara` and `yara-python` both go)

- [ ] **Step 1:** Pin the newest yara-x release at least seven days old when PR Y is cut
  (1.22.0, released 2026-10-20, qualifies now; 1.22.1 from 2026-11-02 08:53 EST). `uv` must
  be 0.13.1 before the relock.
- [ ] **Step 2: Failing test** `test_yara_x_is_importable_where_jmo_is`: the version probe
  reads `yara_x` and matches the lock.
- [ ] **Step 3:** Commit `feat!: yara-x is a dependency of JMo, not an installed tool`.

## Task Y3: The runner reads vendored trees, one rule file, and names the author (P5)

**Files:** `scripts/core/yara_runner.py` (rewritten on `yara_x`), `scripts/core/adapters/yara_adapter.py`
(→ `yara_x_adapter.py`), `scripts/core/tool_descriptors.py` (`_yara_repo` `:1335`, the row
`:1985-1998`, `REMOVED_TOOLS`), `tests/unit/test_yara_runner.py`, `tests/adapters/test_yara_adapter.py`

- [ ] **Step 1: Failing tests:**
  - `test_vendored_trees_are_read`: the canary in `src/` and in `node_modules/x/` → 2 matches; one in `.git/` → none; one in the results directory passed as `--exclude-dir` → none.
  - `test_a_single_rule_file`: `--rules <file>` matches, namespace = the file's stem (#1413).
  - `test_externals_are_set_per_file`: a rule `filename == "a.js"` matches `a.js` only.
  - `test_the_author_reaches_the_finding`: the finding's `context.author` and its message carry the rule's `author`.
  - `test_a_file_over_the_cap_is_counted_not_scanned`.
- [ ] **Step 2:** Implement; the runner's exit codes (0 / 1 / 2) are unchanged.
- [ ] **Step 3:** Rename the row `yara-x` (D8); `yara` → `REMOVED_TOOLS`, `per_tool.yara` warns.
- [ ] **Step 4:** Commit `feat!: yara-x reads vendored trees and names each rule's author`, body `Closes #1413`.

## Task Y4: The image carries the rules (P5)

**Files:** `Dockerfile` (fetch the pinned bundle at build time into an image-owned path
outside `~/.jmo`, e.g. `/opt/jmo/yara-rules`), `scripts/core/paths.py:21`
(`get_yara_rules_dir()` falls back to that path when `~/.jmo/yara-rules` is absent),
`tests/e2e/test_docker_workflows.py:54-60` (`KNOWN_NOT_READY` emptied)

`~/.jmo` is the documented persistence mount ("Docker persistence: mount `.jmo/`"; Phase 4
decision 6 relies on it for osv-scanner's database), so rules baked under it are hidden by a
bind mount, which is #1282 again: installed, never `execution_ready`. Hence J4's
image-owned path.

- [ ] **Step 1:** Build-time fetch, sha256-checked, filtered by Y1's code, into the image
  path; the fallback in `get_yara_rules_dir()` with a unit test (user rules win when present).
- [ ] **Step 2:** `KNOWN_NOT_READY` loses `yara`; `test_docker_image_tools` then requires
  every tool ready; a second `docker-smoke` case bind-mounts an empty directory on
  `/home/jmo/.jmo` and still reads yara-x `execution_ready`. Read `docker-smoke`'s log.
- [ ] **Step 3:** Commit `fix: the image ships yara-x's rules`, body `Closes #1282`.

## Task Y5: The canary through `jmo scan` (P5)

**Files:** `tests/integration/test_yara_x_canary.py` (new)

- [ ] **Step 1: Failing test**, through `tool_loop.run_tools` as the osv-scanner wiring
  tests do: a target with the canary in `node_modules/left-pad/index.js` and `src/`, the
  canary rule as `per_tool.yara-x.rules_path` → two findings, rule `JMO_Canary_Test`, each
  with its author.
- [ ] **Step 2:** Commit `test: yara-x reports a canary under node_modules through jmo scan`.

## Task Y6: Gates, then PR Y

- [ ] **Step 1:** Suite; ID-set diff.
- [ ] **Step 2: Through `jmo scan`:** app B with its `node_modules` (`npm ci
  --ignore-scripts` into a scratch copy) → 0 yara-x findings; juice-shop → the two
  measured (`EXPL_SUSP_JS_POC_Dec25`, `VULN_KeePass_DB_Brute_Forcible`); time and peak recorded.
- [ ] **Step 3: Windows (`.198`, a script Jimmy runs):** `jmo tools install` / first scan; Defender leaves the
  rules directory intact after 5 minutes (file count and sha256s equal the manifest:
  signature-base's webshell rules hold webshell text); the canary test passes; yara-x over
  a `.venv` on `.198` (which holds a real `python.exe`) → record the count; a false
  positive takes `.venv`/`venv` out of the walk (D4).
- [ ] **Step 4:** Push, open PR Y; body: the numbers, and what CI cannot provide (Steps 2-3).

## Task E1: Equivalence pairs that can actually merge (#1354) (P5)

**Files:** `scripts/core/rule_equivalence.py:57` (the false "DS013 absent" comment), `:75`
(`RULE_EQUIVALENCE`), `:77-143` (Dockerfile groups), `:187-228` (Kubernetes groups),
`scripts/core/adapters/checkov_adapter.py:192-198, 228` (carry `endLine` from
`file_line_range`), `scripts/core/dedup_enhanced.py:560-590` (location similarity),
`tests/unit/test_rule_equivalence_table.py`, `tests/adapters/test_checkov_adapter.py`

- [ ] **Step 1: Failing tests**, each from real tool output on one input (trivy 0.74.0
  emits the hyphenated ids `DS-0013`, `KSV-0013/14/15`, measured): `DS-0013` and hadolint
  `DL3003` on `RUN cd /x && make` → one finding; on a Pod with `nginx:latest`, no CPU
  request and a writable root filesystem, each of the four new pairs and the six existing
  Kubernetes pairs → one finding each; a negative (`KSV-0013` and an unrelated checkov id on
  the same lines) → two.
- [ ] **Step 2:** checkov findings carry `endLine`. The location rule for an equivalence
  pair becomes containment (trivy's container range inside checkov's resource range scores
  as a match), not Jaccard × gap. Measure the Pod before choosing; record the scores.
- [ ] **Step 3:** Add the four pairs; check each checkov id's meaning in the Kubernetes
  framework (`checkov --list --framework kubernetes`: `CKV_K8S_10` CPU requests, `_14`
  image tag, `_22` read-only filesystem; Terraform reuses the numbers for other checks).
- [ ] **Step 4:** Commit `fix: same-check trivy, checkov and hadolint findings merge, Kubernetes included`, body `Closes #1354`.

## Task E2: Compliance category by what a finding is (#1370) (P5)

**Files:** `scripts/core/compliance_mapper.py:893-933` (`get_tool_category`), the six
two-worded keys (`:556/:636`, `:650/:709,:721`, `:655/:714`, `:662/:735,:742,:749`,
`:781/:871`, `:797/:880`), `scripts/core/compliance_frameworks.py:274-290` (a second copy of
some tables: check for the same drift), tests

- [ ] **Step 1: Failing tests** through `gather_results` on a real trivy document with one
  vulnerability, one misconfiguration, one secret: categories `sca`, `iac`, `secrets`; a
  shellcheck and a zizmor finding get a category (today `None`); every key has one wording.
- [ ] **Step 2:** Categorise from the finding's tags and fields (`secret`, `misconfig`,
  `vulnerability`, `dependency`) before the tool name; give shellcheck and zizmor theirs.
- [ ] **Step 3:** Commit `fix: a trivy secret or misconfiguration is not filed as supply chain`, body `Closes #1370`.

## Task E3: Dockerfile spellings (#1410, its Dockerfile row) (P5)

**Files:** `scripts/core/tool_descriptors.py:1207-1232` (`DOCKERFILE_PATTERNS`, the walk's
glob, and `is_dockerfile`), `tests/cli/test_repository_scanner.py:1028-1067`, `docs/TOOLS.md`,
`docs/USER_GUIDE.md`

- [ ] **Step 1: Failing test:** `Dockerfile-dev`, `Dockerfile_prod`, `prod-Dockerfile`,
  `Containerfile` → True, and the walk collects each (the glob, not only the predicate);
  `Dockerfile.md`, `Dockerfile.j2`, `Dockerfile.template`, `.dockerignore` → False.
- [ ] **Step 2:** Implement both; hadolint and image discovery both use them.
- [ ] **Step 3:** Commit `fix: Dockerfile-dev, Dockerfile_prod and Containerfile are Dockerfiles`, body `Closes #1410`.

## Task E4: zap names an off-origin redirect (#1431) (P5)

**Files:** `scripts/core/tool_descriptors.py:1466-1515` (`_zap_context`), `:1518-1587`
(`zap_plan`), a zap `scanned_count`-style hook (`:494` holds semgrep's), `tests/fixtures/samples/zap/fixture_server.py`
(a redirecting mode), `tests/integration/test_zap_scans.py`

- [ ] **Step 1: Failing test** (`requires_tools`): the fixture server answers `/app/` with
  301 to `http://localhost:<port>/app/` while zap is given `http://127.0.0.1:<port>/app/` →
  the row is not a plain `ran`: its detail names the redirect target, and the active scan's
  request count is recorded. A non-redirecting run stays `ran` with no detail.
- [ ] **Step 2:** Implement detection from zap's report (the spider's first response, or
  0 active-scan requests in scope); whether to add `www.`, scheme and `127.0.0.1`/`localhost`
  spellings to the scope is measured in the test before it is chosen.
- [ ] **Step 3:** Commit `fix: a zap run that a redirect sent out of scope says so`, body `Closes #1431`.

## Task E5: A target's own tool config travels with the row (#1430) (P5)

**Files:** `scripts/cli/scan_jobs/tool_loop.py:277-321, 830` (`_announce_own_config` returns
what it found), `scripts/core/scan_timings.py:130-160` (the row's `detail`; schema v4),
`scripts/cli/scan_orchestrator.py` (`.scan_metadata.json` `tool_runs`),
`scripts/cli/report_orchestrator.py` and `scripts/core/reporters/basic_reporter.py`
(`findings.json` meta), `html_reporter.py`, `scripts/core/history_db.py` (`scan_tool_runs`
gains `detail`: a schema migration, tested on every historical shape)

- [ ] **Step 1: Failing test:** #1430's repository (a lockfile plus an `osv-scanner.toml`
  ignoring one advisory and one package) → the row's detail names the file and what it
  suppresses, `findings.json` meta carries it per target, the dashboard shows it, the history
  row stores it; a repository with no such file has none.
- [ ] **Step 2:** Implement for every descriptor with `own_config` (checkov, zizmor,
  osv-scanner) and gitleaks' `.gitleaks.toml` path.
- [ ] **Step 3:** Commit `feat: a repository's own scanner config is recorded with its results`, body `Closes #1430`.

## Task E6: KICS's Dockerfile and Kubernetes samples, line by line (J7) (P5)

**Files:** the answer-key fetch script (KICS v2.2.0
`453066aa9c66014ad7aee7dd0149ba1944c78050`, a sparse fetch of `assets/queries/dockerfile/`
and `assets/queries/k8s/` into the answer-key cache), `tests/integration/test_kics_line_floor.py`
(new, `requires_tools`), `tests/integration/baselines/kics-lines.json` (new: per query, each
expected line hit or missed, and by which tool)

- [ ] **Step 1:** Stage each positive sample as its own target so the walk finds it: a
  Dockerfile sample is written as `Dockerfile` (the sample names, `positive1.dockerfile`,
  are not Dockerfile spellings even after E3), a Kubernetes sample keeps its `.yaml` name.
- [ ] **Step 2: Failing test** through `jmo scan --tools hadolint trivy checkov` per
  target: for every expected (file, line) in `positive_expected_result.json`, whether any
  finding covers that line, using `endLine` (E1 gives checkov one). Record the table. The
  test fails when a line hit before is missed, and prints newly hit lines. Negative samples
  are not used (no id mapping; measured, 250 of 308 tool/negative pairs report something).
- [ ] **Step 3:** Record the floor in the PR: Dockerfile 181 of 242 (74%) with the bare
  binaries on 2026-10-29; the `jmo scan` number and the Kubernetes number are new. A line
  hit is not the same check, so the PR names it a floor, never recall.
- [ ] **Step 4:** Commit `test: KICS's expected Dockerfile and Kubernetes lines, graded through jmo scan`.

## Task E7: Gates, then PR E

- [ ] Suite; for E1 a real hadolint + trivy run on one Dockerfile and checkov + trivy on
  one manifest through `jmo scan`, recording which pairs merge; E6's table recorded. Push,
  open PR E.

## Task F1: Capture through `jmo scan` (P5)

**Files:** `scripts/dev/generate_golden.py` (rewritten), `tests/unit/test_generate_golden.py`

- [ ] **Step 1:** `generate_golden.py --tool <name>` runs `jmo scan --tools <name>` on the
  tool's sample (a table: tool → sample dir or pinned target), with an isolated HOME and
  scratch results, copies `individual-repos/<t>/<tool>.json` as `raw-output.json`, writes
  `expected-findings.json` from the adapter and `metadata.json` in Phase 0's shape. The
  hand-written `TOOL_CONFIGS` go. `--check` re-captures and reports a count change.
- [ ] **Step 2:** Commit `feat: golden fixtures are captured through jmo scan`.

## Task F2: The ten new fixtures (P5)

- [ ] **Step 1:** Capture trufflehog (`credential-patterns`), checkov (`terraform-misconfig`
  and `k8s-insecure-pod`), hadolint (`dockerfile-issues`), shellcheck (`shell-issues`), syft
  (`python-vulnerable`), jmo-native (`native`), yara-x (the canary), nuclei
  (`fixture_server.py` with one JMo template that matches it); re-home trivy's two and zap's
  one capture with metadata. Each `finding_count` > 0; a count of 0 is a finding to
  explain, not a fixture.
  Capture each at its `versions.yaml` pin: on `.199` checkov (3.3.29), syft (1.51.1) and
  trufflehog (3.97.1) sit behind theirs, so `jmo tools install <tool>` in the capture's
  isolated HOME first; the recorded version is the one that ran.
- [ ] **Step 2:** `pre-commit run --files tests/fixtures/golden/**` passes; trufflehog's
  directory joins gitleaks' `detect-private-key` exclusion (D11).
- [ ] **Step 3:** Commit `test: a golden fixture for every adapter in the matrix`.

## Task F3: The meta-guards (#1097) (P5)

**Files:** `tests/adapters/test_adapter_golden.py:45-91` (`ADAPTER_REGISTRY`), `:384-391`

- [ ] **Step 1: Failing tests:** every `TOOL_MATRIX` tool has an `ADAPTER_REGISTRY` entry
  (one name mapping: the directory is `osv_scanner`, the matrix name `osv-scanner`); every
  registry entry has a directory with at least one version, so a registered tool with no
  fixture fails instead of generating no test (today 6 do); every fixture's
  `expected-findings.json` holds > 0 findings and equals `metadata.finding_count` (`0 == 0`
  passed semgrep's empty fixture until PR B removed it; nothing stops the next one); every version directory has a raw output
  besides `expected-findings.json` and `metadata.json` (`get_golden_test_cases`,
  `test_adapter_golden.py:121`, counts `metadata.json` as the second JSON today).
- [ ] **Step 2:** Mutation-test each: delete one fixture directory, empty one expected
  file, drop one registry entry (from byte backups); each fails; restore.
- [ ] **Step 3:** Commit `test: a matrix tool with no golden fixture, or an empty one, fails`, body `Closes #1097`.

## Task F4: The smoke job (#1349) and the baseline test's CI (P5)

The job is deleted, not rebuilt (J6).

**Files:** `tests/integration/test_tool_smoke.py` (delete), `tests/integration/conftest.py:22,48`,
`.github/workflows/scheduled.yml:436-568` and `nightly-notify-failure`'s `needs`, `.gitignore:235`

- [ ] **Step 1:** Delete the job and the file; its purpose (each tool's real output parses)
  is F1's `--check`, which joins the nightly `tool-contract-tests` job. A job whose every
  test skips cannot exist after this: add a step that fails when pytest's summary has 0
  passed.
- [ ] **Step 2:** Re-derive T2's baseline and re-record T3's marker table on the final
  matrix (after G and Y); then the nightly runs T1–T3's juice-shop tests and T4's lockfile
  oracle (`requires_tools`, juice-shop at the pin), and E6's and F7's keys.
- [ ] **Step 3: The e2e gate counts errors (#1502):** "Fail the run if any e2e test failed"
  (`scheduled.yml:1436-1484`) sums `summary.error` with `summary.failed` (`:1360-1380`).
  At `c05aef28` that is 7 + 4 errors the gate read as 0, all `_guard_real_jmo_config`
  teardowns from e2e scans writing the runner's `~/.jmo/config.yml`. Their cause, #1506, is
  fixed by Task A6 in PR A, so the gate should land green: confirm it on the last nightly's
  error list, and route any error that remains before this step lands. Mutation-test: a report with one error and no failures → red.
- [ ] **Step 4:** Commit `test: the smoke job that skipped everything gives way to golden re-capture`, body `Closes #1349` and `Closes #1502`.

## Task F5: docker-smoke's weak test (#1365) (P5)

- [ ] Delete `TestDockerToolVerification::test_all_expected_tools_functional`; the strict
  `test_docker_image_tools` stays. Commit `test: drop a docker check that could not fail`, body `Closes #1365`.

## Task F6: The cheap answer keys (decision 9) (P5)

- [ ] **Step 1:** zizmor: at the pinned version, fetch `crates/zizmor/tests/integration`
  (MIT) by tag; run JMo's zizmor on each input and assert the (audit, line, col) set equals
  the insta snapshot's, the online-only audits excluded by name.
- [ ] **Step 2:** osv-scanner: its own fixtures (Apache-2.0) against the frozen
  `tests/fixtures/osv-db`, the wiring oracle.
- [ ] **Step 3:** Commit `test: zizmor and osv-scanner graded against their own answer keys`.

## Task F7: BenchProctor grades the rule bundle on TypeScript and JavaScript (J7) (P5)

**Files:** the answer-key fetch script (BenchProctor release 2026.07.22,
`Benchmarks/quicktest/{typescript,javascript}/benchproctor-*-quicktest-2026.07.22.zip`,
sha256 `80f417b0d7aa7dbaa5ab25898a9be559484a411c46c287a0c828f6df415859c4` and
`ce18f02c168f5bcf97674fa62428d70bebf67942ab5fcccd4f231cf37e9d3a3e`, verified before
extraction, every zip entry refused if absolute or holding `..`, into the answer-key
cache), `tests/integration/test_benchproctor.py`
(new, `requires_tools`, nightly only), `tests/integration/baselines/benchproctor.json` (new)

- [ ] **Step 1: Measure first:** one framework's `testcode` through `jmo scan --tools
  opengrep`, then `jmo report`; run the bundle's own `score_sarif.py` (as a subprocess,
  `python -I`, never imported) on JMo's `findings.sarif` against that framework's
  `expectedresults-2026.07.22.csv`. Check the scorer recovers a CWE from JMo's SARIF (its
  `ruleId`, `properties`/`tags` or `taxa`); if it does not, fix `sarif_reporter.py` to emit
  the CWE tag, and do not fall back to `--match-mode filename` (it rewards over-flagging).
  Record the time and peak memory per framework: Phase 7 owns them.
- [ ] **Step 2: Failing test:** every TypeScript and JavaScript framework → true-positive
  rate, false-positive rate and Youden's J per framework, recorded. The labels are
  generated, not auditable, so the gate is a drop, not a threshold: J may not fall by more
  than the spread of two identical runs (measured in Step 1) plus a recorded tolerance.
- [ ] **Step 3:** Commit `test: BenchProctor's TypeScript and JavaScript cases grade the rule bundle`.

## Task F8: Gates, then PR F

- [ ] Suite; `test_adapter_golden.py` runs 14 tools, 0 skipped; the nightly's
  `tool-contract-tests` log shows the re-capture step and F7's scores. Push, open PR F.

## Acceptance (Phase 6)

- grype gone: `jmo scan --tools grype` exits 2, "removed in v2.0.0"; `TOOL_MATRIX` = 14;
  app A and app B report the same dependency findings without it (25, 61).
- yara-x: the canary under `node_modules` reported through `jmo scan` on Linux and on
  `.198`; 0 signature-base findings on app B with its `node_modules`; a single rule file
  works; the image's yara-x `execution_ready`, with and without an empty `~/.jmo` bind mount,
  `KNOWN_NOT_READY` empty; every finding names its rule's author.
- Golden = 14 / 14, every `finding_count` > 0, each meta-guard mutation-tested.
- Seven answer keys run (J7): vibeproof (N2); zizmor's and osv-scanner's own fixtures (F6);
  juice-shop's 40 marked lines with a recorded detection table (T3); the 15 sca-kitchen-sink
  lockfiles giving exactly their 15 synthetic advisories offline (T4); KICS's Dockerfile and
  Kubernetes line floors recorded through `jmo scan` (E6); BenchProctor's TypeScript and
  JavaScript Youden's J recorded per framework (F7). Each fails on a regression from its
  recorded table.
- No CI job reads green on all skips.
- The 27 open issues closed by commit keywords, `phase_audit closers` MISSING 0.

## New defects found by the measurement (routing proposed; four filed)

| Defect | Evidence | Proposed routing |
|---|---|---|
| The e2e URL tests (U1, U5, M1, W1 in `tests/e2e/test_scan_workflows.py`) have never scanned juice-shop: `--repo` takes a path, the run is rc 1 "Every target was rejected", and the tests accept rc 1 and empty outputs; the steps are `continue-on-error: true` | `scheduled.yml:882,884,1003,1006`; `test_scan_workflows.py:59,119,138,183,213`; `tests/e2e/conftest.py:80-100` | **Filed as #1502** (2026-10-29), rostered in Phase 6 by PR #1503, widened to the e2e gate, which counts pytest's failures but not its errors (7 + 4 at `c05aef28` read as 0): the tests in T5, the gate in F4 (`scheduled.yml` is a P5 file). It is #1353's other half |
| A `jmo scan` rewrites the real `~/.jmo/config.yml` (the Ko-fi counter), the cause of those 11 errors | `scripts/cli/jmo.py:2505`, `:3492`; `tests/conftest.py:489` on `dev` | **Filed as #1506** (2026-10-29) from Phase 5's PR B, which rostered it in Phase 6: Task A6 |
| `jmo_runner`'s fake HOME hides `~/.jmo/bin` and moves every scanner's cache: with the scanners on PATH each scan test re-downloads grype's 3.2 GB and trivy's 1.6 GB database (24 GB per run of `test_linux_specific.py`, the ~21 GB seen 2026-10-30); without them the scan tests run no scanner and pass | `tests/conftest.py:106`; `tests/e2e/test_linux_specific.py`; measured 2026-10-30 at `8ac90d8c` | **Filed as #1517** (2026-10-30) from PR A's branch, rostered in Phase 6 by PR A: Task A7 |
| A scanner that raises before `run_tools` writes no `scan-timings.json`, so in a reused results directory the previous scan's rows and outputs survive together and A2's filter admits them | `scripts/cli/scan_orchestrator.py:1405-1420` (the except block records `failed_rows` in memory only); the only `write_scan_timings` callers are `tool_loop.py` and `gitlab_scanner.py`; read, not run (found building A2, 2026-10-30) | **Filed as #1518** (2026-10-30), rostered in Phase 6 by PR #1519: Task A2b |
| No known-vulnerable GitHub Actions check once grype leaves | github-actions-goat: 7 advisories; OSV `GitHub Actions/all.zip`, 56 advisories | after the tag: a `jmo-native` reader of `uses:` against that database, offline |
| `install_config.py:75-95` gives two false reasons for ReversingLabs | GitHub repo size with history; DRL unrecognised | none: Task Y1 removes the comment |
| signature-base reports two `WEBSHELL_PHP_Generic_Eval` findings on JMo's own yara tests | `tests/unit/test_yara_runner.py`, `tests/adapters/test_yara_adapter.py` hold webshell-like strings | none: Y6 decides whether a self-scan excludes them; not a product defect |

Found by the premise pass and folded into a task rather than filed: the Kubernetes halves of
the equivalence table never merge (E1); shellcheck and zizmor findings carry no compliance
category (E2); `validate_container_image` refuses single-character path components and
accepts upper case (D1); a stale output passes `ToolRunner`'s "wrote nothing" check,
inferred (A2); `tests/integration/conftest.py:22,48` holds a second dead juice-shop fixture
(F4); the baselines name tools outside the matrix (`njsscan`, `dependency-check`) and clone
WebGoat unpinned (T2).

## Decisions taken 2026-10-29 (Jimmy)

| # | Question | Decision |
|---|---|---|
| J1 | grype: drop outright, or keep it as `--with grype` | **Drop outright.** 0 grype-unique on both real apps under both keys, a 3.2 GB database; the residual (known-vulnerable GitHub Actions, 7 advisories on github-actions-goat) is recorded in KNOWN_LIMITATIONS (G2), and zizmor already flags those `uses:` as `unpinned-uses` |
| J2 | yara-x's install path: the PyPI wheel, or the `yr` static binary | **The wheel, as a runtime dependency of jmo-security** (Y2): no installer code, no `versions.yaml` binary row, `uv.lock` pins it and Dependabot bumps it, per-file externals as LOKI sets them, the runner stays Python. Costs ~10 MB per install and no musl or Windows ARM64 wheel. The `yr` binary's speed (5.1 s at `-p 4` against the bindings' 29.6 s on one thread, on 24,942 files) is Phase 7's to recover |
| J3 | signature-base's non-DRL rules | **Dropped at fetch time** (D6, Y1): CC BY-NC is non-commercial, and the others carry obligations JMo would have to track per rule |
| J4 | Where the rules live | **Fetched at install time into `~/.jmo/yara-rules`, and baked into the image at an image-owned path outside `~/.jmo`** (Y4), since `~/.jmo` is the persistence mount and a bind mount would hide them. Never committed: the webshell rules are webshell text, which Defender may quarantine on a contributor's clone, and JMo's own scanners would read them |
| J5 | #1007's `raw` field | **Redact the scan root in the dashboard; keep `raw` verbatim in `findings.json` and `findings.yaml`, and document it** (A4). The dashboard is the artifact people share; `raw` stays useful for debugging. #1007 closes with A4 |
| J6 | #1349's juice-shop smoke job: rebuild or delete | **Delete** (F4); F1's re-capture `--check` in the nightly does its job on tracked samples, so nothing needs a key-bearing fixture |
| J7 | Which of decision 9's other answer keys join Phase 6 | **Four join:** juice-shop's markers (T3), sca-kitchen-sink as a per-format wiring oracle (T4), KICS Dockerfile and Kubernetes as a line-level floor (E6), BenchProctor TypeScript and JavaScript quicktest (F7). **After the tag:** CredData, and KICS Terraform and CloudFormation. With vibeproof (N2) and zizmor's and osv-scanner's own fixtures (F6), Phase 6 carries seven keys |

## Unresolved (Jimmy)

1. **Filing.** #1502 (the e2e URL tests and gate) was filed 2026-10-29 on your word and
   rostered in Phase 6 by PR #1503. Still unfiled, each needing your word and a roster in
   the PR that files it (an unrostered issue reddens `phase_audit` on every open PR,
   Phase 5's included): after the tag, the offline known-vulnerable-Actions check, CredData,
   and KICS Terraform and CloudFormation. The e2e scans' write to the runner's real
   `~/.jmo/config.yml`, the cause of the 11 errors F4's gate fix surfaces, was filed from
   Phase 5's PR B as #1506.
2. **#1506's placement** (2026-10-30, after PR B merged): Task A6 in PR A, so it leaves `dev`
   before F4's gate counts errors. The alternative is beside T5, which makes the e2e tests
   scan for real. Veto in review.
