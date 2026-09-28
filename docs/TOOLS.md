# Tools

`jmo scan` and `jmo ci` work from one list of scanners, the tool matrix below. There are no scan profiles: every scan considers the whole matrix, and the target decides which tools actually run. A Dockerfile linter has nothing to do in a repository without Dockerfiles, and a DAST scanner has nothing to do without a running application, so neither runs there.

To narrow the list:

- `--tools trivy semgrep` (or `--tools trivy,semgrep`) replaces the list for one run
- `--skip-tools zap` drops names from it
- a top-level `tools:` list in `jmo.yml` replaces it for every run that reads that file

`--tools` wins over `jmo.yml`, and `jmo.yml` wins over the matrix. Names split on commas and spaces. A name that is not in the matrix stops the scan before it starts, exit code 2, naming it, and a [removed tool](#removed-in-v200) says it was removed.

## The tool matrix

| Tool | What it finds | Targets | Runs on a repository when | Install |
|------|---------------|---------|---------------------------|---------|
| TruffleHog | Secrets: API keys, tokens, credentials, in the working tree and git history | Repository, GitLab | Always | Release binary |
| Gitleaks | Secrets, by a second rule set, in the working tree and git history | Repository, GitLab | Always | Release binary |
| Semgrep | Code-level flaws (SAST), many languages | Repository, GitLab | Always | Isolated Python venv |
| Syft | Software bill of materials (SBOM) | Repository, image, GitLab | Always | Release binary or install script |
| Trivy | Vulnerable dependencies, secrets, misconfigurations | Repository, image, IaC, Kubernetes, GitLab | Always | Release binary or install script |
| Checkov | IaC misconfigurations: Terraform, CloudFormation (Kubernetes too, on a `--k8s-manifest` target) | Repository, IaC, GitLab | IaC is present | Isolated Python venv |
| Hadolint | Dockerfile problems | Repository, GitLab | Dockerfiles are present | Release binary |
| ShellCheck | Shell script bugs (unquoted expansions, unguarded `cd`) | Repository, GitLab | Shell scripts are present | Release binary |
| zizmor | GitHub Actions flaws: template injection, unpinned actions, dangerous triggers, credential persistence | Repository, GitLab | Workflows, composite actions or a Dependabot config are present | Release binary |
| Gosec | Go security issues | Repository, GitLab | Go sources or a `go.mod` are present | Release binary |
| YARA | Malware patterns: web shells, backdoors, cryptominers | Repository, GitLab | Always | `yara-python` via pip, plus a rule bundle |
| Grype | Vulnerable dependencies (Anchore database) | Repository, GitLab | Always | Release binary or install script |
| OSV-Scanner | Vulnerable dependencies, read from lockfiles against an offline OSV database | Repository, GitLab | A lockfile is present | Release binary |
| ZAP | Web application vulnerabilities (DAST) | URL | Never: URL targets only | Extracted application, needs Java 17+ |
| Nuclei | Template-based vulnerability probes (DAST) | URL | Never: URL targets only | Release binary |

Versions are pinned in [`versions.yaml`](../versions.yaml). OPA is installed alongside these tools but is not one of them: see [Policy engine (OPA)](#policy-engine-opa).

## When each tool runs

Being in the matrix makes a tool eligible. Two things then decide whether it runs on a given target: the target type (next section) and, for six tools on a repository, the target's content.

| Tool | Content it needs | Files it looks for |
|------|------------------|--------------------|
| Hadolint | Dockerfiles | `Dockerfile`, `Dockerfile.*`, `*.Dockerfile` |
| ShellCheck | Shell scripts | `*.sh`, `*.bash`, `*.ksh` |
| zizmor | GitHub Actions | `.github/workflows/*.yml` and `*.yaml` (the repository's own, not a subdirectory's), `action.yml` or `action.yaml` anywhere, `.github/dependabot.yml` or `.yaml` |
| OSV-Scanner | Lockfiles | anywhere: `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `requirements*.txt`, `poetry.lock`, `Pipfile.lock`, `pdm.lock`, `uv.lock`, `pylock.toml`, `go.mod`, `Cargo.lock`, `composer.lock`, `Gemfile.lock`, `gradle.lockfile`, `pom.xml`, `packages.lock.json`, `packages.config`, `pubspec.lock`, `mix.lock`, `renv.lock` |
| Gosec | Go code | any `.go` file, or a `go.mod` |
| Checkov | Infrastructure as code | `*.tf`, `*.tf.json`, or a YAML, JSON or `.template` file whose first 8 KB name `AWSTemplateFormatVersion` or an `AWS::` type (CloudFormation) |

When the content is absent, the tool is skipped for that target and contributes no findings. It is not an error. An IaC file target (`--terraform-state`, `--cloudformation`, `--k8s-manifest`) is itself the content, so Checkov always reads it.

On a repository, Checkov reads only Terraform (`.tf`, `.tf.json`) and CloudFormation, and only when at least one is present (`--framework terraform terraform_json cloudformation`). Every other framework it ships stops running there too, even alongside a Terraform file that does trigger it, among them: secrets (195.8 s alone on one measured repository), Kubernetes, Dockerfiles, Helm charts, GitHub Actions, GitLab CI, CircleCI, Azure Pipelines, Bitbucket Pipelines, ARM, Bicep, Ansible and serverless configs. Gitleaks and TruffleHog already cover secrets; Trivy covers Kubernetes, Helm charts and Dockerfiles (Hadolint covers Dockerfiles too); zizmor covers GitHub Actions. GitLab CI, CircleCI, Azure Pipelines, Bitbucket Pipelines, ARM/Bicep and serverless configs are read by no JMo tool on a repository scan.

Given an IaC file target directly (`--terraform-state`, `--cloudformation`, `--k8s-manifest`), Checkov keeps every framework, so it still evaluates Kubernetes there. Helm was dropped rather than narrowed to: no helm binary exists on the host or in the image, and Checkov disables the framework without a word, so a chart-only repository triggering it read `ran` and found nothing.

Vendored trees are never content: `.git`, `node_modules`, `vendor`, `.venv` and `venv` are excluded before anything is looked for, and so is the results directory when it sits inside the scanned tree.

zizmor reads only the files JMo hands it, since it has no way to exclude a directory itself, and it runs offline, so its audits that call GitHub do not run ([Known limitations](KNOWN_LIMITATIONS.md#zizmor-runs-offline-so-its-online-audits-never-run)).

OSV-Scanner reads only the lockfiles JMo hands it (given a directory on Windows it finds none), and a scan never downloads: it matches them against the offline databases in `~/.jmo/osv-db`. Call analysis is off (`--no-call-analysis=all`), so every vulnerable version is reported whether or not the code calls it, on any machine. A lockfile whose ecosystem has no database there is left out, and the row reads `failed:offline database missing`, naming the ecosystem and the lockfile; the other lockfiles are still read. So is a lockfile it cannot parse: the row fails naming it, and the others' findings are kept. It reads `pom.xml` and `requirements.txt` for their direct dependencies only ([Known limitations](KNOWN_LIMITATIONS.md#osv-scanner-reads-pomxml-and-requirementstxt-for-direct-dependencies-only)). `jmo tools update` (and installing osv-scanner) fills `~/.jmo/osv-db` from OSV's own hosted zips, one ecosystem at a time (~280 MB across all eleven); the image never carries it, so a Docker container needs `jmo tools update` run once against a persistent volume ([Docker: osv-scanner's Offline Databases](DOCKER_README.md#osv-scanners-offline-databases)).

### What a scan records

Every requested tool leaves one row per target, in `scan-timings.json`, in `.scan_metadata.json` and, when history is on, in the `scan_tool_runs` table (`jmo history show <scan-id>`):

| Row | Meaning |
|-----|---------|
| `ran` | It ran and its output is beside the row. |
| `skipped:<reason>` | It did not apply: `needs --url`, `not for this target type`, `no Dockerfiles`, `no shell scripts`, `no GitHub Actions workflows`, `no lockfile`, `no Go sources`, `no IaC files`, or `not installed` under `--allow-missing-tools`. |
| `failed:<reason>` | It applied and produced nothing you can trust: `not installed`, `timed out`, `no files to scan`, `examined 0 files`, `offline database missing`, `unaccepted exit code`, `no output`, and a few rarer ones. |

`failed:no files to scan` means the repository had no file outside the excluded directories, so no tool ran against it. `failed:examined 0 files` means the tool's own output reports that it read nothing. Semgrep and Gosec report that count, and it is how a run that scanned nothing stops passing for a clean one.

ZAP and Nuclei are DAST scanners: they find vulnerabilities by exercising a **running application** over HTTP, so they run only on `--url` and `--urls-file` targets and never on a repository, where their row reads `skipped:needs --url`. Point them at a deployed or local instance:

```bash
jmo scan --url https://staging.example.com
```

The remaining repository tools (TruffleHog, Gitleaks, Semgrep, Syft, Trivy, YARA, Grype) run on every repository scan. When the repository has a `.git` of its own, TruffleHog and Gitleaks read its history too and name the commit that added each secret; see [Known limitations](KNOWN_LIMITATIONS.md#secret-scanning-skips-git-jmo-and-vendored-trees).

## Target types

| Target | Flags | Tools that run |
|--------|-------|----------------|
| Repository | `--repo`, `--repos-dir`, `--targets`, `--tsv` | TruffleHog, Gitleaks, Semgrep, Syft, Trivy, YARA, Grype; Hadolint, ShellCheck, zizmor, OSV-Scanner, Gosec and Checkov when their content is present |
| Container image | `--image`, `--images-file` | Trivy, Syft |
| IaC file | `--terraform-state`, `--cloudformation`, `--k8s-manifest` | Trivy (`trivy config`), Checkov |
| URL | `--url`, `--urls-file` | ZAP, Nuclei |
| Kubernetes cluster | `--k8s-context`, optionally with `--k8s-namespace` or `--k8s-all-namespaces` | Trivy (`trivy k8s`) |
| GitLab | `--gitlab-repo` or `--gitlab-group` (token from `--gitlab-token` or `GITLAB_TOKEN`) | The repository tools on the clone. The container images it references are discovered but not scanned ([#1311](https://github.com/jimmy058910/jmo-security-repo/issues/1311)) |

Targets combine in one run: `jmo scan --repo . --image myapp:latest` scans both, each with its own tools.

## Installation

The [Docker image](DOCKER_README.md) carries every tool in the matrix plus OPA, so it needs no installation. For a native install:

```bash
jmo tools install   # the matrix plus OPA, skipping what is already installed
jmo tools check     # what is installed, at which version, and what is missing
```

| Tool | How `jmo tools install` installs it | Where it goes |
|------|-------------------------------------|---------------|
| TruffleHog, Gitleaks, Hadolint, ShellCheck, zizmor, OSV-Scanner, Gosec, Nuclei | Pinned release binary from GitHub | `~/.jmo/bin/` |
| Syft, Trivy, Grype | Windows: pinned release binary. Linux and macOS: the tool's own install script, run with the pinned version | `~/.jmo/bin/` |
| Semgrep, Checkov | Pinned PyPI package in a virtual environment of its own, so their dependencies cannot conflict with JMo's or each other's | `~/.jmo/tools/venvs/<tool>/` |
| YARA | Pinned `yara-python` package, installed into the Python environment JMo runs from, plus a pinned rule bundle (reversinglabs-yara-rules, MIT) | rules in `~/.jmo/yara-rules/` |
| ZAP | Pinned cross-platform release archive, extracted | `~/.jmo/bin/zap/` |
| OPA | Pinned release binary | `~/.jmo/bin/` |

Platform differences:

- **Linux:** ShellCheck is installed with `sudo apt-get install shellcheck` when passwordless sudo is available, which gives the distribution's version. Otherwise it is the pinned binary.
- **zizmor has no Windows arm64 build.** On Windows, `jmo tools install` fetches the x86_64 one whatever the architecture, as it does for Hadolint and ShellCheck.
- **Gosec needs a Go toolchain** (`go` on `PATH`) to load packages, which neither `jmo tools install` nor the Docker image provides. Without one it examines 0 files, and its row reads `failed:examined 0 files` ([#1310](https://github.com/jimmy058910/jmo-security-repo/issues/1310)).
- **ZAP needs Java 17 or newer** at runtime, which `jmo tools install` does not provide. Install it yourself (`winget install Microsoft.OpenJDK.17`, `sudo apt-get install default-jre-headless`, or `brew install openjdk@17`); `jmo wizard` offers to do it for you.
- **YARA without rules finds nothing.** If the rule bundle download fails, the install reports failure rather than leaving a scanner that silently matches nothing. To use your own rules, set `per_tool.yara.rules_path` in `jmo.yml`.

Every tool installs natively on Windows, Linux and macOS. For installing a tool by hand, see [MANUAL_INSTALLATION.md](MANUAL_INSTALLATION.md).

## Policy engine (OPA)

[Open Policy Agent](https://www.openpolicyagent.org/) evaluates policy-as-code: the Rego policies in `policies/`, `jmo policy ...`, and `jmo report --policy`. It runs in the report phase against findings that the scanners have already produced. It scans nothing, so it is not in the matrix and `--tools` cannot select it.

It is still part of every installation, because policy evaluation is on by default (`policy.auto_evaluate: true` in `jmo.yml`):

- `jmo tools install` installs OPA with the scanners.
- `jmo tools check` lists the scanners in its table and OPA on its own "Policy engine" line below it.
- The Docker image includes it.

See [POLICY_AS_CODE.md](POLICY_AS_CODE.md) for writing and applying policies.

## Removed in v2.0.0

These tools are no longer installed, run or parsed. A `per_tool` block for one of them in `jmo.yml` has nothing left to configure. Naming one in `--tools`, `--skip-tools` or `tools:` is a usage error (exit code 2) that says it was removed.

| Tool | What it did | Why it was removed |
|------|-------------|--------------------|
| kubescape | Kubernetes hardening checks | Trivy's config scan covers the same ground, and kubescape fetched its rules at scan time |
| semgrep-secrets | Semgrep with secret-detection rules | It scanned 0 files; SAST moves to a vendored rule bundle in a later release |
| bandit (as a scanner) | Python SAST | Its results were dominated by `.venv` noise; SAST moves to a vendored rule bundle in a later release |
| trivy-rbac | Kubernetes RBAC checks | Its output was identical to Trivy's config scan |
| checkov-cicd | Checkov on CI/CD pipelines | Folded into Checkov, which never actually read `.github/workflows` under JMo (its `.git` exclusion also matched `.github`, #1313); Checkov's repository run was then narrowed to Terraform and CloudFormation only ([above](#when-each-tool-runs)), dropping its other CI/CD and secrets frameworks there. zizmor now audits workflows |

Each tool below was never installable on Windows, not a repository scanner, a duplicate of a kept tool, or abandoned upstream:

| Tool | What it did |
|------|-------------|
| noseyparker | Secrets scanning |
| prowler | Cloud account auditing (AWS, Azure, GCP) |
| akto | API security testing |
| scancode | License and copyright detection |
| cdxgen | SBOM generation |
| dependency-check | Dependency vulnerability scanning (OWASP) |
| horusec | Multi-language SAST |
| falco (with falcoctl) | Runtime threat detection |
| afl++ | Coverage-guided fuzzing |
| mobsf | Mobile application security |
| lynis | Host hardening audit |

Bandit is still this repository's own pre-commit hook and lint step. Only bandit as a JMo scanner is gone.

The `jmo.yml` keys, CLI flags and Docker tags that went with scan profiles are listed in [UPGRADE.md](../UPGRADE.md#upgrading-to-v200).
