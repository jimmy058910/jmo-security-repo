# Known Limitations

Behaviour that is deliberate, unfinished, or environment-bound, and that you may
reasonably hit while using JMo Security. Each entry says what happens, why, and
what to do instead.

This file covers **limitations we intend to keep documenting**. Defects with a
fix planned are GitHub issues instead — a file has no close mechanism, so
anything trackable belongs where it can be closed. Search the
[issue tracker](https://github.com/jimmy058910/jmo-security-repo/issues) before
assuming something here is unfixable.

---

## Attestation

### Local signing needs a browser; CI signing does not

`jmo attest --sign` uses Sigstore keyless signing, which authenticates through an
OIDC redirect. In CI (GitHub Actions, GitLab CI) the ambient OIDC token is picked
up automatically and signing works unattended. Run locally, it opens a browser
for the OAuth redirect — so on a headless server, over SSH, or inside a container
it fails with sigstore's own error about being unable to complete the flow.

> This paragraph used to promise "a `RuntimeError` naming the missing browser".
> That exception lived in `SigstoreSigner._get_local_oidc_token`, which
> **nothing called** — `sign()` shells out to `sigstore sign` and lets sigstore
> run its own OIDC. The documented failure mode belonged to unreachable code,
> and that code has since been deleted (#944). The error you see is sigstore's
> own.

**What to do:** sign in CI, where the token is ambient. If you must sign on a
headless machine, run the command somewhere with a browser and transfer the
resulting bundle.

---

### Verifying a signature requires naming the signer you expect

`jmo verify` checks the subject digest, the attestation's shape and its tamper
indicators on every run. It checks the **signature** only when you pass both
`--cert-identity` and `--cert-oidc-issuer`; otherwise it prints
`Signature: NOT CHECKED` and says so in the output.

That is deliberate. Keyless signing proves *who* signed, so a bundle validated
without an expected signer establishes only that somebody signed it — which is
not a security property, and reporting it as "verified" would be worse than
reporting nothing. A bundle sitting next to an attestation is not evidence on
its own.

```bash
jmo verify results/summaries/findings.json \
  --cert-identity you@example.com \
  --cert-oidc-issuer https://oauth2.sigstore.dev/auth
```

---

## MCP server

### The server does not authenticate callers at all

**There is no way to turn authentication on.** Every client that can reach the
server process is trusted, and setting `JMO_MCP_API_KEYS` does not change that.

This section used to say the opposite — that setting `JMO_MCP_API_KEYS` would
"enable it" and that "keys are compared as SHA-256 hashes". The keys *are*
hashed at startup, and then nothing ever compares them against anything. MCP's
stdio transport hands the tool functions no request context, so there is no
caller credential to check a key against.

The startup line said `Authentication: enabled` in that state. It now says:

```text
WARNING  Authentication: NOT ENFORCED -- 1 key(s) configured via
         JMO_MCP_API_KEYS, but no transport supplies a caller credential to
         compare them against. EVERY caller is trusted.
```

`get_server_info()` reports the same thing as `authentication_enforced: false`,
which is the machine-readable form for a client to check.

**What to do:** treat the server the way you would treat a shell. Run it as a
subprocess of the client that needs it (the normal MCP arrangement — see
[MCP_SETUP.md](MCP_SETUP.md)), and do not expose the process to anything you
would not give a shell to. `JMO_MCP_RATE_LIMIT_*` works and is enforced; it is
a throttle, not an access control, and it uses one shared bucket for all
callers.

**One tool writes to your repository.** `mark_resolved` appends a suppression
entry to `jmo.suppress.yml`, so an unauthenticated caller can stop a security
finding being reported. Two things bound it, and neither is authentication:
every entry it writes **expires** (90 days by default, 365 at most — there is
no permanent option through the tool), and `jmo.suppress.yml` is a tracked
file, so the change shows up in `git diff` and in review like any other. No
other tool writes anything.

### `apply_fix` cannot apply a fix

`apply_fix` validates a patch and returns it for review. `dry_run=False` writes
nothing and returns `success: False`. Applying a patch needs traversal
validation, backup-and-rollback, and a post-apply test run — a patch-writing
subsystem, deliberately not built during an audit release. Tracked as
[#951](https://github.com/jimmy058910/jmo-security-repo/issues/951) and
deferred past v1.1.0.

**What to do:** treat it as a reviewer, not an applier. Take `dry_run_preview`
and apply it with `git apply` yourself.

### One client at a time

MCP's stdio transport is a single stdin/stdout pipe, so one server process serves
exactly one client. This is the transport's design, not a JMo restriction.

**What to do:** run one server instance per client.

### Memory use over long sessions is unmeasured

The server starts, serves and shuts down cleanly, and that path is tested — but
no extended profiling has been run, so there is no measured figure for growth
over a session lasting hours. Because stdio is single-client and sessions are
normally short, this has not mattered in practice; it is untested rather than
known-good.

**What to do:** if you keep a server alive for a long-running client, watch its
RSS and restart it between large batches. Report anything that grows without
bound — that would be a defect, not this limitation.

---

## Scanning

### Concurrent scans on Windows are not verified

Two scans writing into the same results directory or history database at once has
not been tested on Windows. SQLite provides its own locking and scan output files
are write-once, so the risk is low — but it is untested, not proven.

**What to do:** on Windows, give concurrent scans separate `--results-dir` paths.

### Secret scanning skips `.git/`, `.jmo/` and vendored trees

TruffleHog and Gitleaks read the working tree with `.git/` and `.jmo/` excluded,
and the vendored trees every source reader skips: `node_modules/`, `vendor/`,
`.venv/` and `venv/`, at any depth. They also skip the results directory when it
sits inside the scanned tree. A key committed inside a vendored package is
therefore not reported. This was measured on a real Next.js application: 253
TruffleHog findings before, 222 of them in `node_modules`, and a run of 281 s; 31
findings after, none in `node_modules`, in 12 s.

These exclusions are deliberate. A finding at `.git/objects/03/f8eab...` or
`.git/logs/HEAD` names no commit and no source file, so there is nothing to act
on, and the reflog's 40-character commit ids trip detectors that look for 40
characters of `[A-Za-z0-9_-]` — measured as 41 findings across five
repositories, every one of them a false positive. `.jmo/` is JMo's own state
directory: `history.db` stores raw findings, so scanning it re-reports every
secret JMo has previously recorded, and each scan feeds the next. On this
repository that was 394 of 773 findings.

Git history is read separately, and it names the commit (v2.0.0). When the scanned
repository has a `.git` of its own, both tools also run in git mode, with the same
exclusions. A secret that was committed and later removed is reported with the
commit that added it, its author and its date. A secret still in the tree is
reported once per tool, not twice: its history record is folded into the tree
finding, which gains the commit. Measured on this repository (1,258 commits), the
two secret scanners took 4 s without history and 17 s with it.

What history mode does not see:

- **A directory that is not a repository's root.** History is read only when the
  target itself holds `.git`, so `--repo some/subdir` scans that tree alone.
- **A shallow clone's history, at all.** Its oldest commit holds the whole tree, so both
  tools would name that commit, and its author, as having added every secret in it:
  whoever wrote the latest commit of a `--depth 1` clone. The scan reads the tree, logs a
  WARNING, and says `history not read` on the two tools' rows. GitLab targets are
  cloned with `--depth 1`, and `actions/checkout` fetches one commit unless told
  otherwise (`fetch-depth: 0`).
- **A repository git cannot read**: for example a worktree whose gitdir is not mounted,
  or, outside JMo's image, "dubious ownership" of a repository another user owns. The
  same WARNING and row detail name git's own message. JMo's Docker image sets
  `safe.directory '*'`, because a mounted repository always belongs to another UID
  there. So in the image git trusts every repository it is given, and honours that
  repository's own `.git/config`. Scan repositories you trust.
- **A multi-line key replaced in place.** Replacing a PEM key's body leaves its
  `BEGIN` and `END` lines unchanged, so the commit's diff never holds a whole key.
  The old key is reported from history, at the commit that added it; the new one
  is reported from the tree, with no commit (measured with both tools).

`.github/` is **not** excluded.

**What to do:** to audit a vendored tree, run TruffleHog or Gitleaks on that
directory directly. To read history for a subdirectory, scan the repository's
root. To read a shallow clone's history, fetch all of it first
(`git fetch --unshallow`). A history too large or too noisy to read can be
bounded with `per_tool.<tool>.history_flags` (TruffleHog's `--since-commit`,
Gitleaks' `--log-opts`), or skipped with `per_tool.<tool>.history: false`.

### Gitleaks extends a repository's own `.gitleaks.toml`

JMo passes Gitleaks a config of its own, to carry its exclusions, and Gitleaks
then reads no other. When the scanned repository has a `.gitleaks.toml`, JMo's
config extends it, so its rules and allowlists apply as they do when Gitleaks
runs alone (and the default rules, if it asks for them). Two consequences:

- **A repository's config narrows the audit.** A path or secret it allowlists
  is not reported by Gitleaks, and a config that does not ask for the default
  rules (`[extend] useDefault = true`) runs only its own. TruffleHog still reads
  everything. `.gitleaksignore` and inline `gitleaks:allow` comments already
  worked this way. JMo logs at INFO that it extended the repository's config,
  and a WARNING when that config leaves the default rules out.
- **One level of extension is lost.** Gitleaks follows `[extend]` only so deep,
  and JMo's config is one level above the repository's. If the repository's
  config extends another file that itself extends further (the default rules, or
  a third file), that last level is not loaded, with no error (measured, 8.30.1).
  JMo logs a WARNING naming the file when it sees this.

`--config` in `per_tool.gitleaks.flags` is dropped with a warning: it would
replace the config that carries JMo's exclusions.

### TruffleHog does not verify secrets by default

Verification sends each candidate secret to the service that issued it, to ask
whether it is live. Since v2.0.0, JMo passes `--no-verification`: a scan should
not send what it finds to third parties unasked, and git history multiplies the
candidates. A secret is graded HIGH whether or not it was verified, as a Gitleaks
one is, so `--fail-on HIGH` stops on any of them; the tags (`verified` or
`unverified`) and `risk.confidence` say which. The built-in `zero-secrets`
policy blocks **verified** secrets only, so without verification it blocks
nothing. Gitleaks never verifies. The policy says so: its message, a warning in
`POLICY_REPORT.md`, and the report's log line count the secrets it passed
because nothing verified them.

**What to do:** set `per_tool.trufflehog.verify: true` in `jmo.yml` to verify,
and `zero-secrets` then blocks the live ones. `--only-verified`, or `--results`
naming `verified`, in TruffleHog's flags counts as asking to verify.

### Most of the rule bundle is a frozen snapshot, JavaScript and TypeScript included

JMo's code scanner, opengrep, reads the rule bundle in `scripts/jmo_rules/`
([RULE_BUNDLE.md](RULE_BUNDLE.md)), and 1,286 of its 1,456 rules come from one
snapshot of opengrep-rules whose commit is dated 2025-01-26. Nothing refreshes
it: a rule written since is not in the bundle until someone moves the pin and
rebuilds. GitLab's `lgpl-cc` rules (v2.10.1, 100 rules) are maintained and
cover Java, Ruby, PHP and Python, with one rule each for JavaScript, YAML and
`.properties` files. Every other language is the snapshot's alone.

That includes JavaScript and TypeScript: `javascript.yaml` holds 176 snapshot
rules and 1 from GitLab, and `typescript.yaml` holds 18 snapshot rules. GitLab's
maintained JavaScript set, `rules/lgpl`, is not in the bundle. It is LGPL-3.0,
and its rules are to be scored one at a time after v2.0.0
([#1465](https://github.com/jimmy058910/jmo-security-repo/issues/1465)).
jmo-native runs beside the bundle, but it reads only Next.js, Supabase,
Firebase and browser LLM keys ([TOOLS.md](TOOLS.md#jmo-native)).

**What to do:** read an empty code-scanner result on JavaScript or TypeScript as
"nothing matched rules as of January 2025", not as current coverage. Dependency
scanning is separate and is not affected. To take newer rules, move a source's
pin in `scripts/dev/build_rule_bundle.py` and rebuild
([RULE_BUNDLE.md](RULE_BUNDLE.md#rebuilding)).

### Opengrep also skips tests, build output and vendored code

Opengrep brings its own ignore list, as Semgrep did. When the scanned directory
has no `.semgrepignore` (opengrep still reads that name), it skips `tests/` and
`test/` at any depth, `build/`, `dist/` and `node_modules/`, and two kinds of file by
name: Go test files (`*_test.go`) and minified JavaScript (`*.min.js`). JMo's own
exclusions are passed on top of it, so a flaw that lives only in test code is not
reported by opengrep.

Measured with opengrep 1.32.0 on a fixture with one Python file in each of `tests/`,
`test/`, `deep/tests/`, `build/`, `dist/` and `node_modules/` and two others (`src/`,
`docs/`): it scanned the two others and none of these. Given `main.go`,
`main_test.go`, `app.js`, `app.min.js`, `x_test.py` and `test_x.py`, it skipped
`main_test.go` and `app.min.js` and read the rest, so the Go convention is the only
test file name on the list. A repository whose only files are of the skipped kinds
(Go test files and nothing else) examines 0 files, and its row reads
`failed:examined 0 files`; under `--baseline-commit` the same result is
`skipped:no changed file opengrep reads since the baseline commit`
([SCAN_OPTIMIZATION.md](SCAN_OPTIMIZATION.md)). The list is matched against the
path opengrep is handed, so JMo runs it from inside the target and names the target
`.`: a repository checked out under a directory called `build/` or `tests/` is scanned
all the same.

JMo leaves the list on: it does not pass the flag that turns it off.

When the scanned directory lies inside a git work tree, opengrep also honours that
repository's `.gitignore`. A target that is itself gitignored, such as a `dist/` or
`vendor/` folder scanned on its own, examines 0 files, and its row reads
`failed:examined 0 files`; scanning the whole repository leaves the same folder out.
Measured with opengrep 1.32.0 in a scratch git repository whose `.gitignore` lists
`gen/`: a scan of `gen/` read `failed:examined 0 files`, and a scan of the repository
read `src/a.py` and not `gen/a.py`.

**What to do:** to have opengrep read the directories above, either put an empty
`.semgrepignore` at the root of the scanned repository, or add
`--x-ignore-semgrepignore-files` to `per_tool.opengrep.flags` in `jmo.yml`, which
changes nothing in the repository. Measured on 1.32.0 with the fixture above: with
either, all eight files were scanned. JMo still keeps the vendored trees and its
results directory out through its own flags.

For a gitignored target, add `--no-git-ignore` to `per_tool.opengrep.flags`. Measured on
1.32.0 through JMo's scan loop, which runs opengrep from inside the target: the `gen/`
scan above went from 0 files to 1, and the row from `failed` to `ran`. The flag reads
gitignored files for every repository that config scans, so set it for the one scan that
needs it.

### zizmor runs offline, so its online audits never run

JMo runs zizmor with `--offline`. zizmor reads `GH_TOKEN` and `GITHUB_TOKEN` from the
environment, and with a token set its online audits call GitHub's API. With
`--no-online-audits` instead, it still looked a commit up on GitHub (measured, zizmor
1.30.1). A scan makes no network call it was not asked to make, so the audits that need
GitHub, `ref-confusion` among them, do not run, whether or not a token is set.

**What to do:** for those audits, run zizmor yourself with a token.

### OSV-Scanner reads pom.xml and requirements.txt for direct dependencies only

JMo runs OSV-Scanner with `--no-resolve`. Without it, OSV-Scanner resolves a
`pom.xml` or a `requirements.txt` transitively through deps.dev, a network call, even
with `--offline-vulnerabilities` (measured, OSV-Scanner 2.6.0: under an unreachable
proxy it reported "failed resolution"). A scan makes no network call, so only the
dependencies those two files name are matched: two pinned packages in a
`requirements.txt` gave 18 findings, against 38 when resolved online. Lockfiles
(`package-lock.json`, `poetry.lock`, `gradle.lockfile` and the rest) already list
every dependency and lose nothing.

**What to do:** commit a file that lists every dependency (a `requirements.txt`
written by `pip-compile` or `uv pip compile`, a `uv.lock`, a `poetry.lock`, Gradle
dependency locking), or run OSV-Scanner yourself without `--no-resolve`.

**Conan lockfiles are not read at all.** OSV publishes no ConanCenter vulnerability
database, so JMo does not hand OSV-Scanner a `conan.lock` (the lockfiles it does read
are listed in [TOOLS.md](TOOLS.md#when-each-tool-runs)); a repository whose only
lockfile is a Conan one reads `skipped:no lockfile`.

### OSV-Scanner does not check an npm package whose lockfile entry has no `resolved` URL

From OSV-Scanner 2.7.0, a `package-lock.json` or `npm-shrinkwrap.json` entry is
classified by its `resolved` field: a registry or git URL is checked, and anything else
is taken for a local package, which is never matched against the database. An entry
with no `resolved` at all falls in the second group. npm writes no `resolved` for a
bundled dependency (`inBundle`), and none for any registry package when its
`omit-lockfile-registry-resolved` setting is on. Such a package is not checked, with no
error and exit code 0 (measured: a lockfile npm 12.2.1 wrote with that setting for
`lodash@4.17.20` gave 5 findings on OSV-Scanner 2.6.0 and none on 2.7.0). A package
whose same version also appears with a `resolved` URL elsewhere in the lockfile is still
checked.

JMo reads each npm lockfile before OSV-Scanner runs and names one that holds such
packages, with how many, at WARNING. The row stays `ran`, and its detail in
`scan-timings.json` reads `partly audited: <lockfile> (...)`.

**What to do:** for `omit-lockfile-registry-resolved`, turn the setting off and write the
lockfile again. Turning it off is not enough: `npm install --package-lock-only` does not
add `resolved` to an entry that already exists. Delete `package-lock.json` and run it
again; that can move each package to the newest version its range in `package.json`
allows (measured: `lodash` `^4.17.20` went from 4.17.20 to 4.18.1), so review the diff.
A bundled dependency has no such fix: check the package that bundles it, or scan its
source with another tool.

### Checkov's repository run misses several CI/CD and IaC dialects

On a repository, Checkov reads only Terraform and CloudFormation
(`--framework terraform terraform_json cloudformation`). Its other frameworks
never run there, so GitLab CI, CircleCI, Azure Pipelines, Bitbucket Pipelines,
ARM, Bicep, Ansible and serverless configs are read by no JMo tool on a
repository scan. It bites hardest on a GitLab target, since a `.gitlab-ci.yml`
is exactly what a GitLab-cloned repository has and no repository tool checks
it.

An `--iac` single-file target (`--terraform-state`, `--cloudformation`,
`--k8s-manifest`) is unaffected: Checkov keeps every framework there, so a
Kubernetes manifest given directly is still checked in full.

**What to do:** for one of the dropped dialects, run Checkov yourself with
`--framework <name>` outside JMo. See
[When each tool runs](TOOLS.md#when-each-tool-runs).

### On Windows, a Checkov or ZAP flag cannot hold cmd.exe's metacharacters

On Windows, Checkov is installed as `checkov.cmd` and ZAP's launcher is
`zap.bat`. Windows starts either through `cmd.exe`, which reads the whole
command line again and treats `& | ^ < > %` as its own: `--skip-check A|B`
would pipe into a command named `B`. A line break ends its command line,
dropping every argument after it. No quoting survives that second reading, so a
`per_tool.<tool>.flags` entry holding one of the six or a line break, for a
tool that resolved to a `.cmd` or `.bat` launcher, is dropped (with its value,
or its flag when the value is a token of its own) and named in a WARNING.
ZAP's flags are checked this way too, although JMo runs the java command
`zap.bat` holds rather than `zap.bat` itself.

The paths JMo builds stay off those command lines: Checkov runs from the
repository it scans, and ZAP's plan and home go to java. One cannot: an IaC
file (`--terraform-state`, `--cloudformation`, `--k8s-manifest`) whose own
name holds one of the six must be named to Checkov, so Checkov's row fails as
`could not be run`, naming it, and Checkov does not run. Linux and macOS are
unaffected.

**What to do:** where the tool takes a list, give it comma-separated:
`--skip-check CKV_AWS_1,CKV_AWS_2` for Checkov. Rename an IaC file whose name
holds one of the six.

### On Windows, Checkov cannot scan a UNC path

A repository or IaC file on a UNC path (`\\server\share\...`, or a WSL
directory as `\\wsl.localhost\<distro>\...`) cannot be scanned by
`checkov.cmd`. cmd.exe will not start in a UNC directory (it starts in
`C:\Windows` instead), and Checkov started on another drive fails on the path
(exit 2). So Checkov's row fails as `could not be run`, naming the path, and
Checkov does not run.

**What to do:** map the share to a drive letter (`net use Z: \\server\share`)
and scan `Z:\...`, or scan a local copy. From WSL, run JMo inside WSL.

### On Windows, ZAP's heap is always 512 MB

`zap.bat` takes ZAP's JVM options from `%USERPROFILE%\ZAP\.ZAP_JVM.properties`
when that file exists (a larger heap, say), and uses `-Xmx512m` otherwise. JMo
does not run `zap.bat` (see the entry on cmd.exe's metacharacters above): it
runs the same java command with `-Xmx512m` and does not read that file, so a
heap set there does not apply to a scan. On Linux and macOS JMo runs `zap.sh`,
and this does not apply.

**What to do:** JMo has no setting for ZAP's heap yet. For a site too large for
512 MB, run ZAP outside JMo.

### jmo-native reads one application, at the repository root

jmo-native decides what it reads by path from the scanned root
([TOOLS.md](TOOLS.md#jmo-native)), and four things follow from that.

- **A nested application is not seen as one.** Client code is looked for only
  under the root's `app/`, `src/`, `components/`, `pages/` or `lib/`, and the
  migrations are the root's `supabase/migrations/`. In a monorepo, `apps/web/src/...`
  is not client code, so the `service_role` check never runs on it, and
  `packages/db/supabase/migrations/` is not read, so no table is checked. The
  other checks still read their files wherever they sit: JS/TS source and `.env`
  files for the public-env check, JS/TS source for the browser-LLM check, and
  `firestore.rules`, `storage.rules` and `database.rules.json` for the Firebase
  check. Reading each application from its own root is
  [#1381](https://github.com/jimmy058910/jmo-security-repo/issues/1381).
- **Only `public`-schema tables are checked.** A table in another schema
  (`private.notes`) is skipped, since Supabase's API serves `public` by default. A
  schema exposed to the API by configuration is not checked.
- **Row Level Security set outside the migrations is invisible.** RLS enabled, or a
  policy created, in the Supabase dashboard or by a script outside
  `supabase/migrations/` is not read, so that table still reads as
  `table-without-rls` or `rls-without-policy`.
- **The public-env check reads names, not values.** It reports a public-prefixed
  variable whose name looks like a server secret (`NEXT_PUBLIC_STRIPE_SECRET_KEY`).
  A secret under an innocuous name (`NEXT_PUBLIC_CONFIG`) is not reported, and a
  harmless value under a secret-looking name is. TruffleHog and Gitleaks read the
  values.

**What to do:** in a monorepo, scan each application as a target of its own
(`jmo scan --repo apps/web`), and the package holding the migrations as another. For
Row Level Security managed outside the migrations, check the table's policies in the
Supabase dashboard.

---

## Deduplication

### Cross-tool clustering only ever merges findings from *different* tools

Clustering runs in two phases. Phase 1 deduplicates by exact content
fingerprint. Phase 2 clusters findings that different tools reported for the
same underlying issue, and **a cluster holds at most one finding per tool** — so
if one tool reports several distinct rules against the same line, they stay
several findings. That is deliberate: within a single tool, "same location" is
the normal case rather than evidence, and Phase 1 has already made the exact
judgment about that tool's own output.

Composite similarity is weighted **toward location** — `0.50` location, `0.25`
message, `0.25` metadata — so two tools agreeing on a `path:line` are most of
the way to the `0.65` default threshold before their wording is considered.
Trivy's `DS-0001` (`':latest' tag used`) and Hadolint's `DL3006` on the same
Dockerfile line score `0.79` and do cluster, via the rule-equivalence table in
`scripts/core/rule_equivalence.py`. (Measured 2026-09-28: trivy 0.74.0 and
hadolint run on one `FROM alpine` line, each output through its adapter,
scored by `SimilarityCalculator.calculate_similarity`: 0.793 with hadolint
2.14.0 and again with 2.15.1, the version `versions.yaml` pins.)

No findings are lost — anything not clustered is reported separately.

**Dependency findings are matched on identity, not similarity** (#1346). A
trivy, osv-scanner or grype vulnerability has no line, so location similarity
never let two of them cluster: on one real lockfile trivy and osv-scanner
reported the same 47 vulnerabilities and the report held 85. Each is now one
finding per lockfile, package, installed version and advisory, whichever of
those tools report it; two tools name one advisory when one's id is the
other's id or alias (a CVE and its GHSA), and every two reports folded into one
finding name a common id. `similarity_threshold` does not apply to them. The
same package in two lockfiles is two findings. osv-scanner files some
advisories other tools keep apart under one rule (NodeGoat's lodash
CVE-2021-23337 lists CVE-2026-4800, which trivy and grype report separately);
that rule joins the finding with its own id, and the other advisory stays a
finding of its own. A tool that names an advisory only by an id the other
tools' reports do not carry (a GHSA with no CVE beside one that has only the
CVE) stays a finding of its own.

**What to do:** lower `deduplication.similarity_threshold` toward `0.5` if you
would rather over-cluster than under-cluster, or raise it toward `1.0` for the
opposite. Values outside `0.5`–`1.0` are rejected at config load. How much
clustering you see depends heavily on how much the tools that ran overlap: a
scan whose tools examine different things (SBOM, secrets, SAST) will cluster
very little, because there is nothing for them to agree on.

> This section previously said clustering was "conservative", that similarity
> was "weighted toward message text", and that the Trivy/Hadolint pair scored
> "about `0.39`". All three were measured false — the weights favour location,
> and that pair scores `0.79` (measured as above). The sentence "no findings
> are lost" was
> also untrue until the one-finding-per-tool rule landed: clustering was
> merging distinct findings from a single tool and dropping them from the
> report.

---

## Comparing scans

### A finding whose message text changes is reported as resolved plus new

`jmo diff` matches findings by their id, and that id is a hash of
`tool | ruleId | path | line | message`, with the message truncated at 120
characters. So if a tool changes the wording of a finding — commonly after
upgrading the tool — the finding's identity changes with it, and the diff
reports one **resolved** and one **new** rather than one **modified**.

The engine does track a `message` change type, but it can only fire when the
message is longer than 120 characters *and* the edit falls entirely beyond that
point, leaving the hashed prefix intact. Measured on two real corpora: 6 of 34
findings from a `bandit` scan and 106 of 263 from a mixed one have messages long
enough to qualify at all.

**What to do about it.** When a diff shows a suspiciously symmetric jump — N
resolved and about N new, with the same rules and files on both sides — check
whether a scanner was upgraded between the two scans before treating any of it
as real movement.

This is not fixed because `path` and `message` are inputs to the fingerprint by
design: changing what goes into it invalidates every baseline and every row
already in the history database. See [#861](https://github.com/jimmy058910/jmo-security-repo/issues/861),
which has to solve the same migration for path normalization.

### Clustering keeps a finding's diff identity, but only through its members

Cross-tool clustering rewrites a consensus finding's id to
`cluster-<fingerprint>`. `jmo diff` accounts for that: it matches on the
representative's fingerprint recovered from the prefix, and on every id listed
in `context.duplicates`. A finding that gains or loses a corroborating tool
between two scans is therefore reported as unchanged, not as fixed-and-reopened.

The limit is that this depends on the cluster recording its members. A finding
that both joins a cluster **and** changes its own fingerprint in the same
interval — a tool upgrade that reworded it, say — is still reported as resolved
plus new, for the reason in the section above.

---

## Scheduling

### Exported workflows carry the paths you created the schedule with

`jmo schedule export --backend github-actions` writes the schedule's stored
target paths into the workflow verbatim. A schedule created on Windows against
`C:\Projects\myrepo` exports a workflow whose `--repo C:\Projects\myrepo` means
nothing on a Linux runner.

**What to do:** edit the exported workflow's paths for the CI environment before
committing it, or create the schedule with the paths the runner will see.

### Survival across a reboot is not verified automatically

`jmo schedule install` writes a normal crontab entry — Linux and macOS only;
there is no Windows Scheduled Task backend, so on Windows use
`jmo schedule export` and run the schedule from CI instead. Install/uninstall is
tested under WSL, but no automated test reboots a machine, because that is too
disruptive to run on a dev box or a CI runner. Standard crontab entries do
persist across reboots, so the expected behaviour is that your schedule simply
resumes; it is unproven here rather than doubtful.

**What to do:** after your first install, confirm it by hand once —
`jmo schedule list` (or `crontab -l`) following a reboot. Worth re-checking on a
machine where something else manages cron, such as a container or a hardened
image that resets `/var/spool/cron`.

---

## Dashboard

### A large scan's dashboard must be served over HTTP, not opened from disk

Below 1,000 findings, `dashboard.html` embeds its data and opens fine by
double-clicking. Above that, JMo writes the findings to `dashboard-data.json`
beside it — otherwise the HTML would be tens of megabytes — and the page loads
them with `fetch()`.

**Browsers refuse `fetch()` against a `file://` URL.** Chromium reports
`Fetch API cannot load file:///.../dashboard-data.json. URL scheme "file" is
not supported.` So double-clicking the file shows *Loading Failed* and zero
rows, for exactly the large scans where the dashboard is most useful. This is
browser security policy, not a JMo setting: nothing the page can do from
`file://` will make that request succeed.

**What to do:** serve the directory over HTTP.

```bash
cd results/summaries
python3 -m http.server 8000
# then open http://localhost:8000/dashboard.html
```

The dashboard says this itself when it detects it was opened from disk. Until
v1.1.0 it printed *"Make sure dashboard-data.json is in the same directory as
this HTML file"* — advice that was both useless and false, since the file was
already there ([#1129](https://github.com/jimmy058910/jmo-security-repo/issues/1129)).

### `raw` in `findings.json` and `findings.yaml` can hold the scanning machine's paths

`raw` in `findings.json` and `findings.yaml` is each tool's verbatim output and
can hold the scanning machine's paths; the dashboard redacts them. osv-scanner,
for one, names the directory it scanned, which is under the home directory of
whoever ran the scan. JMo keeps `raw` as written in those two files, so the
tool's own words are still there to compare. The directory that was scanned is
removed from every other field of a finding, so `findings.sarif`, `findings.csv`
and the rest carry none, and from the whole of `dashboard.html` and
`dashboard-data.json`, `raw` too
([#1007](https://github.com/jimmy058910/jmo-security-repo/issues/1007)).

The HTML and JSON outputs of `jmo diff` embed whole findings, `raw` included
(read from `findings.json` or from the history database), so they can carry the
scanned directory too.

**What to do:** read `findings.json`, `findings.yaml` and the output of
`jmo diff` as the scan's own output, and do not publish them from a personal
machine without looking at `raw`. The dashboard and the SARIF file are the ones
made for sharing.

---

## Defects shipping in v1.1.1

Everything above is behaviour we intend to keep documenting. **This section is
different.** These are open defects a user can hit in v1.1.1, listed because the
symptom is hard to interpret without knowing the cause. Each links to the issue
that will close it.

The v1.1.0 pre-release fix program
([the plan](superpowers/plans/2026-08-22-v1.1.0-pre-release-fix-program.md))
fixed every issue scheduled before the tag rather than shipping with
dispositions; the 42 issues this section listed at v1.0.8 are all closed. What
remains is scheduled in the v2.0.0 program, or after its tag. Regenerate it
rather than trust it:

```bash
gh issue list --repo jimmy058910/jmo-security-repo --state open --label user-reachable
```

- **Three output rough edges:** the scan progress line is written even when
  stderr is redirected, so a captured log carries `\r` frames; the history
  database flag is `--history-db` on `scan` and `ci` but `--db` on `diff` and
  `history list`; bulk tool warnings arrive as one long JSON line.
  [#1082](https://github.com/jimmy058910/jmo-security-repo/issues/1082)

---

## Reporting something not listed here

Open an issue with the `bug` label. If it is a limitation rather than a defect —
something that works as designed but surprised you — say so, and it may end up on
this page.
