# The rule bundle

> **Status.** This describes v2.0.0. Until v2.0.0 ships, JMo's code scanner is Semgrep, which does not read this bundle, and nothing in a scan reads `scripts/jmo_rules/` yet.

JMo's code scanner, opengrep, reads its rules from a bundle that ships with JMo, in `scripts/jmo_rules/`. A scan never fetches a rule: the bundle is committed to this repository and packaged with it. It holds 1,456 security rules in 25 files, about 2.5 MB.

The bundle is generated, not written by hand. `scripts/dev/build_rule_bundle.py` builds it from four rule sources, each pinned to a commit or tag and to the sha256 of its archive. [`SOURCES.json`](../scripts/jmo_rules/SOURCES.json), beside the rules, records those pins, the sha256 and rule count of every bundle file, and everything the builder left out, with the reason. This page is the readable form of that file. Where the two disagree, `SOURCES.json` is right.

## What is in it

| Source | Pinned at | License | Rules |
|--------|-----------|---------|-------|
| [opengrep-rules](https://github.com/opengrep/opengrep-rules), every language directory, and `problem-based-packs/` | commit `f1d2b562` | LGPL-2.1 with the Commons Clause | 1,286 |
| [GitLab sast-rules](https://gitlab.com/gitlab-org/security-products/sast-rules), `rules/lgpl-cc` | tag `v2.10.1` | LGPL-2.1 with the Commons Clause | 100 |
| [0xdea/semgrep-rules](https://github.com/0xdea/semgrep-rules), `rules/c` | commit `e0121ac1` | MIT | 48 |
| [elttam/semgrep-rules](https://github.com/elttam/semgrep-rules), `rules/` | commit `24426856` | MIT | 22 |
| | | Total | 1,456 |

The full pins are in `SOURCES.json`. The license texts, and what the builder changes in a rule, are in [THIRD_PARTY_LICENSES.md](../THIRD_PARTY_LICENSES.md).

Every rule is a security rule (`metadata.category: security`). The filter matters: on two real applications it removed 1,495 of 1,530 findings, mostly from style rules such as `jsx-not-internationalized` (1,120) and `react-props-spreading` (138).

A rule's id is its own id behind the path of the file it came from, so ids that repeat across frameworks stay distinct. Rules from the three newer sources also carry a prefix. For example, `java.lang.security.audit.cbc-padding-oracle.cbc-padding-oracle` is an opengrep-rules rule (as is `problem-based-packs.insecure-transport.go-stdlib.http-request.http-request`, where the id carries the framework directory because only 27 of that directory's 37 bare ids are distinct), and `lgpl-cc.python.django.security.injection.sql.rule-django-rawsql-used.python_django_rule-django-rawsql-used` is GitLab's. The prefixes are `lgpl-cc.`, `0xdea.` and `elttam.`.

The rules are merged into one file per language, named for the language. The counts below are from the rule ids in each file; their totals are `SOURCES.json`'s.

| File | Rules | opengrep-rules | GitLab `lgpl-cc` | 0xdea | elttam |
|------|-------|----------------|------------------|-------|--------|
| `apex.yaml` | 11 | 11 | - | - | - |
| `bash.yaml` | 3 | 3 | - | - | - |
| `c.yaml` | 60 | 12 | - | 48 | - |
| `clojure.yaml` | 5 | 5 | - | - | - |
| `csharp.yaml` | 48 | 48 | - | - | - |
| `dockerfile.yaml` | 6 | 6 | - | - | - |
| `generic.yaml` | 23 | 23 | - | - | - |
| `go.yaml` | 83 | 80 | - | - | 3 |
| `html.yaml` | 4 | 4 | - | - | - |
| `java.yaml` | 178 | 123 | 39 | - | 16 |
| `javascript.yaml` | 177 | 176 | 1 | - | - |
| `json.yaml` | 4 | 4 | - | - | - |
| `kotlin.yaml` | 14 | 14 | - | - | - |
| `ocaml.yaml` | 7 | 7 | - | - | - |
| `php.yaml` | 62 | 52 | 9 | - | 1 |
| `properties.yaml` | 1 | - | 1 | - | - |
| `python.yaml` | 273 | 264 | 9 | - | - |
| `ruby.yaml` | 103 | 63 | 40 | - | - |
| `rust.yaml` | 10 | 10 | - | - | - |
| `scala.yaml` | 26 | 26 | - | - | - |
| `solidity.yaml` | 35 | 35 | - | - | - |
| `swift.yaml` | 4 | 4 | - | - | - |
| `terraform.yaml` | 260 | 260 | - | - | - |
| `typescript.yaml` | 18 | 18 | - | - | - |
| `yaml.yaml` | 41 | 38 | 1 | - | 2 |
| Total, 25 files | 1,456 | 1,286 | 100 | 48 | 22 |

A scan reads the files for the languages it finds in the repository, plus `generic.yaml`. TypeScript also reads `javascript.yaml`, because opengrep runs a rule written for JavaScript on `.ts` files. The merge is also a memory saving. On one application at `-j 8`, the same unfiltered JavaScript and TypeScript rules took 575 to 598 MB merged into one file and 1,068 to 1,084 MB as separate per-directory configs, and gave the identical 212 findings in ten runs.

jmo-native, JMo's own pack for Next.js, Supabase, Firebase and browser LLM keys, is Python and runs beside the bundle. The bundle carries no JMo rules.

## How a rule gets in

The builder fetches each archive from its pinned URL and refuses it unless the sha256 matches. Then, for each source:

1. It reads the `.yaml` and `.yml` files that hold a `rules` list. Test targets (`*.test.yaml`) are not rules, and from GitLab only `rule-*.yml` files are read.
2. It keeps a rule only if its `metadata.category` is `security`.
3. It drops a rule whose `metadata.license` says "proprietary", in any casing, from any source. The bundle's notices grant the open-source licenses of its four sources and nothing else.
4. It puts the rule in the file named for its top directory under the source's rules root (`java/...` goes to `java.yaml`). Sources that share a language directory share the file. One directory is the exception: opengrep-rules' `problem-based-packs/` is laid out by problem (`insecure-transport/go-stdlib/...`), so its top directory names no language, and each of its rules goes to the file named by the first entry of its own `languages:` list. `[javascript]` and `[javascript, typescript]` both go to `javascript.yaml`, which a TypeScript scan reads too. No file is added: the 36 rules are in `go.yaml` (9), `java.yaml` (15), `javascript.yaml` (7) and `ruby.yaml` (5).
5. It drops a rule whose body equals a rule from a source it ranks higher. A rule's body is the rule minus `id`, `message`, `metadata` and `severity`, as canonical JSON. The order is GitLab `lgpl-cc`, then opengrep-rules, then the two MIT packs. GitLab gave every rule it took a new id, so only a match by body finds the overlap.
6. It writes each file sorted by id, as UTF-8 with LF endings, under a comment header. The header says the file is generated, names the sources that gave that file rules with their pins and licenses, lists what the builder changed and the date (`BUNDLE_DATE` in the builder), and points to [THIRD_PARTY_LICENSES.md](../THIRD_PARTY_LICENSES.md). Nothing in it depends on when the build ran, so two builds are byte for byte the same.

Of the opengrep-rules rules, 50 have the same body as a GitLab `lgpl-cc` rule and are dropped; GitLab's is kept because it is maintained. By the GitLab rule's language that is ruby 32, php 9, java 6, python 2 and properties 1. The MIT packs and the insecure-transport rules lost none. Two rules with the same body inside one source both stay.

## What is left out

The builder leaves these out, and `SOURCES.json` holds each one's reason.

| Left out | Rules | Why |
|----------|-------|-----|
| opengrep-rules `generic/secrets/` | 225 | Finding secrets is Gitleaks' and TruffleHog's job. These rules include private-key and Slack-webhook patterns, so with them the bundle trips JMo's own secret scanning. |
| opengrep-rules `scripts/`, `stats/`, `.github/` | 0 | Repository tooling, coverage statistics and CI workflows, not rules. |
| opengrep-rules `problem-based-packs/insecure-transport/js-node/using-http-server` | 1 | It matches any call on Node's `http` module, so it flags every plaintext server behind a TLS-terminating proxy, and it reports the same line `http-request` reports (measured on probes, 2026-10-29). The other 36 rules of `problem-based-packs/` are in the bundle. |
| Any rule whose `metadata.license` says "proprietary" | 1 | The bundle's notices grant only the open-source licenses of its sources. The one rule so far is opengrep-rules' `java.lang.security.audit.xss.no-direct-response-writer`, whose metadata says `proprietary license - copyright © Semgrep, Inc.`. The guard is general, so a rule from any source is dropped the same way, and `SOURCES.json` records its id and quotes the license text. |
| 0xdea `rules/noisy/` | 1 | The pack's own noisy tier, "potentially too noisy and unsuitable for general use". |
| 0xdea `raptor-use-after-free` | 1 | It overflows opengrep 1.31.0's stack on its own test file. |
| elttam `rules/yaml/kubernetes/` | 6 | The rules anchor on different lines from the same-named Kubernetes rules in opengrep-rules, so one pod spec would be reported twice. The bundle's Kubernetes rules, Checkov and Trivy already cover manifests. |
| elttam `jsp-likely-xss` | 1 | It is a `mode: join` rule. `opengrep scan --validate` rejects those ("Rule parse error ... missing languages", on 1.31.0 and 1.32.0), and every bundle file must validate. A scan itself loads and runs it, so the exclusion costs this one rule's coverage and nothing else. |

Nothing below is in the bundle. Trail of Bits' rules, the Semgrep registry and dgryski's pack are never downloaded. GitLab's other rule directories and elttam's `rules-audit/` are inside archives the builder does download, but it reads only `rules/lgpl-cc/` and `rules/` from them.

| Not taken | Why |
|-----------|-----|
| GitLab `rules/lgpl` (152 rules: JavaScript 83, Kotlin 58, Swift 5, Java 4, Objective-C 2), ports of njsscan, mobsfscan and find-sec-bugs | LGPL-3.0. On a TypeScript application 1 of its 31 findings was a real defect; on juice-shop it finds bugs the snapshot misses (zip slip, local file read, NoSQL operator injection). Its rules are to be scored one at a time after the v2.0.0 tag ([#1465](https://github.com/jimmy058910/jmo-security-repo/issues/1465)). |
| GitLab `rules/gitlab` | GitLab's Enterprise Edition license. |
| Trail of Bits rules | AGPL-3.0. |
| The Semgrep registry | Semgrep Rules License v1.0. |
| elttam `rules-audit/` (78 rules) | elttam's README says it is for "enumerating entrypoints, to augment manual source code review". Run through opengrep it gave 149 findings on juice-shop (111 of them `express-app-router-handler`, 19 and 19 from two Prisma rules on the same Sequelize `where` calls, each line reported under both), 6 on a TypeScript application (the same two Prisma rules, 3 lines each, none a real defect on review) and 0 on a third application. None of the 155 was a real finding. |
| dgryski/semgrep-go (66 Go rules) | None of its 66 rules has a `metadata.category`, so the security filter would keep none of them, and its last commit is from 2024-11-17. |

## What is not measured

The two MIT packs are written mostly for C, C++, Java and Go (elttam's also holds one PHP rule and two GitHub Actions rules), and their precision on those languages is unmeasured. No code in those languages was available to run them on. What was measured is JavaScript and TypeScript, where they cost nothing: on three JavaScript and TypeScript applications they gave 0 findings between them. Every rule loads (`opengrep scan --validate` reports 0 errors), and the packs' own test files pass under opengrep 1.31.0 (48 of 49 for 0xdea's `rules/c`, the 49th being the rule excluded above, and all 28 loadable rules of elttam's `rules/`). That shows the rules do what their authors meant, not that their findings on real code are right. Read the first finding from an `0xdea.` or `elttam.` rule before acting on it.

The 36 insecure-transport rules (Java 15, Go 9, JavaScript 7, Ruby 5) are in the same position. They pass their own test files (37 of 37, counting the one left out), cost nothing measurable in time or memory, and gave 0 findings on five codebases (juice-shop, three private applications and this repository). That is not evidence that they are precise: six of the seven JavaScript rules are written around a CommonJS `require(...)` and all five codebases use ESM `import`, none had a Java file, and the only Go and Ruby files were a test fixture and a Homebrew formula. Read the first finding from a `problem-based-packs.` rule before acting on it.

## How current it is

opengrep-rules is a snapshot. Its commit is dated 2025-01-26, and its README describes the rules as "intended for research, testing & benchmarking". GitLab's `lgpl-cc` set is maintained: at v2.10.1 it covers Java, Ruby, PHP and Python, with one rule each for JavaScript, YAML and `.properties` files. Every other language in the bundle is the snapshot's, JavaScript and TypeScript included: `javascript.yaml` holds 176 snapshot rules and 1 from `lgpl-cc`, and `typescript.yaml` is all snapshot. The two MIT packs are taken at one commit each, 2026-10-18 and 2026-08-03. [Known limitations](KNOWN_LIMITATIONS.md#most-of-the-rule-bundle-is-a-frozen-snapshot-javascript-and-typescript-included) says what that means for a scan.

## Rebuilding

```bash
python scripts/dev/build_rule_bundle.py --out scripts/jmo_rules
```

The first run downloads the four archives into `~/.cache/jmo-rule-sources` (`--cache` changes the directory) and checks each against its pinned sha256. Later runs use the cache. The exit code is 0 for a built bundle and 2 when an archive cannot be fetched, verified or unpacked, or when a rule in one cannot be read (for example a file that is not valid YAML, a rule without an id, or a value that JSON cannot hold, such as a bare date).

`--check` builds into a temporary directory instead and exits 1, naming each file that differs from the committed bundle. CI's `rule-bundle-reproducible` job runs it whenever `scripts/jmo_rules/` or the builder changes. It fails when a rule was edited by hand or the builder changed without a rebuild, and it fails with exit 2 when an upstream archive no longer matches its pinned sha256. Do not edit a rule file by hand: the next rebuild would erase the edit, and CI refuses it first.

To move a source to a newer commit, change that source's `url`, `sha256` and `pin` in `SOURCES` in the builder, set `BUNDLE_DATE` to the day of the change, rebuild, and read the `SOURCES.json` diff: the rule counts and the exclusions show what the new commit changed. Update `test_the_pins_are_exact` in `tests/unit/test_build_rule_bundle.py` too: it names each pin, so it fails until it agrees with the builder. Commit the builder, the test and the bundle together.

## Licenses, and replacing the rules

Two of the four sources, opengrep-rules and GitLab's `lgpl-cc`, are LGPL-2.1 with the Commons Clause, and they supply 1,386 of the 1,456 rules. The Commons Clause withholds "the right to Sell the Software", and it defines selling as providing a product or service "whose value derives, entirely or substantially, from the functionality of the Software", for a fee or other consideration. JMo is free and accepts that condition (decided 2026-09-12). This page does not say what counts as selling; the license text in [THIRD_PARTY_LICENSES.md](../THIRD_PARTY_LICENSES.md) does.

The bundle is one directory so that, if that condition ever stops fitting, the rules are what change and the tool does not. To replace them:

1. **Put the new rule files in `scripts/jmo_rules/`, one per language, under the names in the table above** (`python.yaml`, `javascript.yaml`, and so on). A scan finds a language's rules by file name.
2. **Make `SOURCES.json` true again.** The usual way is to change `SOURCES` in `scripts/dev/build_rule_bundle.py` to the new sources and rebuild, which keeps `--check` and `rule-bundle-reproducible` green. If you write the files yourself, update the sha256 and rule count of each file in `SOURCES.json` yourself too, and retire `rule-bundle-reproducible`, which rebuilds from the builder's sources and would fail. `tests/unit/test_jmo_rules_bundle.py` holds the directory to its manifest either way. It also wants the builder's license header on every file (`test_every_file_opens_with_the_license_header`), so files you write yourself need a header that names their own sources and licenses, or that test changes with them.
3. **Validate every file.** `opengrep scan --validate --config scripts/jmo_rules/<file>.yaml` must report "0 configuration error(s)". `test_every_file_validates` in that test file runs it for all of them where opengrep is installed.
4. **Run the fixture guard.** It arrives with Phase 5's second change, which switches the scanner to opengrep; until then there is nothing to run. It scans four files from juice-shop, an intentionally vulnerable web application, fetched by commit and sha256 (`routes/login.ts`, `routes/search.ts`, `lib/insecurity.ts` and `views/promotionVideo.pug`) through JMo, and requires four findings: `tainted-sql-string` at `login.ts` line 34 and at `search.ts` line 23, `hardcoded-jwt-secret` at `insecurity.ts` line 56, and `template-explicit-unescape` at `promotionVideo.pug` line 79. It compares rule, file and line, never the column. These are the findings an earlier merge of these rules lost, so the guard exists to catch that. A replacement set that does not contain these rules changes the expected list, and that change is a decision about coverage.
5. **Update [THIRD_PARTY_LICENSES.md](../THIRD_PARTY_LICENSES.md).** It carries a notice for each source in the bundle and none for a source that is gone.
