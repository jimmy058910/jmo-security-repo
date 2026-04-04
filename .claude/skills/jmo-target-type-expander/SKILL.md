---
name: jmo-target-type-expander
description: Add new target types to JMo Security multi-target scanning architecture (cloud accounts, mobile apps, host audits, etc.). Use when extending scanning to new infrastructure types.
argument-hint: <target-type>
user-invocable: true
context: fork
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

## Execution

Add target type: **$ARGUMENTS**

---

## Purpose

Add new target types to JMo Security's multi-target scanning architecture.
Use this skill when adding new asset types (cloud accounts, package registries,
API endpoints, config management), expanding infrastructure coverage, or understanding
the multi-target scanning pattern.

**Approach:** Follow the existing pattern precisely. Study how the most recent target type was added, replicate exactly.

## Current Target Types (v1.0.0)

JMo Security currently supports 9 target types:

| Target Type | CLI Flags | Directory | Tools | Example |
|-------------|-----------|-----------|-------|---------|
| **Repositories** | `--repo`, `--repos-dir`, `--targets` | `individual-repos/` | trufflehog, semgrep, bandit | `--repo ./myapp` |
| **Container Images** | `--image`, `--images-file` | `individual-images/` | trivy, syft | `--image nginx:latest` |
| **IaC Files** | `--terraform-state`, `--cloudformation`, `--k8s-manifest` | `individual-iac/` | checkov, trivy | `--terraform-state infra.tfstate` |
| **Web URLs** | `--url`, `--urls-file`, `--api-spec` | `individual-web/` | zap, nuclei | `--url https://example.com` |
| **GitLab Repos** | `--gitlab-repo`, `--gitlab-group`, `--gitlab-token` | `individual-gitlab/` | trufflehog | `--gitlab-repo mygroup/repo` |
| **Kubernetes Clusters** | `--k8s-context`, `--k8s-namespace`, `--k8s-all-namespaces` | `individual-k8s/` | trivy | `--k8s-context prod` |
| **Cloud Accounts** | `--aws-account`, `--azure-subscription`, `--gcp-project` | `individual-cloud/` | prowler, kubescape, scoutsuite | `--aws-account 123456789012` |
| **Mobile Apps** | `--mobile-src`, `--apk`, `--ipa` | `individual-mobile/` | mobsf | `--apk app-release.apk` |
| **Host Audits** | `--host-audit` | `individual-hosts/` | lynis | `--host-audit` |

## Architecture Overview

### Key Principles

1. **Consistent Pattern:** All target types follow the same 4-function pattern
2. **Parallel Execution:** ThreadPoolExecutor scans targets concurrently
3. **Directory Isolation:** Each target instance gets its own directory
4. **Unified Reporting:** All findings deduplicated across target types
5. **Error Resilience:** `--allow-missing-tools` writes stubs for missing tools

### Scan Flow

```text
jmo scan --repo ./app --image nginx --url https://api.com
                           |
    +----------------------+----------------------+
    v                      v                      v
 Repos Scanner       Images Scanner        URLs Scanner
    |                      |                      |
    v                      v                      v
 results/individual-repos/   individual-images/   individual-web/
                           |
                           v
              normalize_and_report.py
              (scans all target dirs, deduplicates, enriches)
                           |
                           v
              results/summaries/ (findings.json, dashboard.html, etc.)
```

### Scan Types

Each target type maps to specific security scanning categories. The scan orchestrator
selects tools based on target type and profile. See [scripts/cli/jmo.py](../../scripts/cli/jmo.py)
for the `cmd_scan()` function that coordinates all target types.

### Results Directory Structure

```text
results/
├── individual-repos/          # Repository scanning
├── individual-images/         # Container image scanning
├── individual-iac/            # Infrastructure-as-Code scanning
├── individual-web/            # Web/API scanning
├── individual-gitlab/         # GitLab-specific scanning
├── individual-k8s/            # Kubernetes cluster scanning
├── individual-cloud/          # Cloud account scanning
├── individual-mobile/         # Mobile app scanning
├── individual-hosts/          # Host audit scanning
├── individual-<type>s/        # YOUR NEW TARGET TYPE
│   └── <sanitized-name>/
│       ├── tool1.json
│       └── tool2.json
└── summaries/                 # Aggregated reports (all targets)
```

## 4-Step Implementation Pattern

Every target type follows this exact pattern in [scripts/cli/jmo.py](../../scripts/cli/jmo.py):

### Step 1: Target Collection Function

Collect target identifiers from CLI arguments. Supports single target (`--<type>`)
and batch file (`--<type>s-file`) with `#` comments.

```python
def _iter_<type>(args) -> list[str]:
    """Collect <type> targets from CLI arguments."""
    targets = []

    if getattr(args, "<type>", None):
        targets.append(args.<type>)

    if getattr(args, "<type>s_file", None):
        path = Path(args.<type>s_file)
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)

    return targets
```

### Step 2: Scan Job Function

Scan a single target with appropriate tools. Creates isolated output directory,
handles tool existence checks, supports `--allow-missing-tools`.

```python
def job_<type>(target: str) -> tuple[str, dict[str, bool]]:
    """Scan a single <type> target."""
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", str(target))
    out_dir = results_dir / "individual-<type>s" / safe_name
    out_dir.mkdir(parents=True, exist_ok=True)

    statuses: dict[str, bool] = {}

    if "tool1" in tools:
        out = out_dir / "tool1.json"
        if _tool_exists("tool1"):
            flags = (
                pt.get("tool1", {}).get("flags", [])
                if isinstance(pt.get("tool1", {}), dict)
                else []
            )
            cmd = [
                "tool1", "<subcommand>",
                "--format", "json",
                "--output", str(out),
                *([str(x) for x in flags] if isinstance(flags, list) else []),
                str(target),
            ]
            rc, _, _, used = _run_cmd(
                cmd, t_override("tool1", to),
                retries=retries, ok_rcs=(0, 1),
            )
            ok = rc in (0, 1)
            if ok:
                statuses["tool1"] = True
                attempts_map["tool1"] = used
            elif args.allow_missing_tools:
                _write_stub("tool1", out)
                statuses["tool1"] = True
            else:
                statuses["tool1"] = False
        elif args.allow_missing_tools:
            _write_stub("tool1", out)
            statuses["tool1"] = True

    return str(target), statuses
```

**Directory Naming:** Always sanitize with `re.sub(r"[^a-zA-Z0-9._-]", "_", target)`.

### Step 3: Parallel Execution with ThreadPoolExecutor

Submit scan jobs concurrently, collect results as they complete.

```python
<type>s = _iter_<type>(args)

if <type>s:
    _log(args, "INFO", f"Scanning {len(<type>s)} <type> target(s)...")

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = []
        for target in <type>s:
            futures.append(ex.submit(job_<type>, target))

        for fut in as_completed(futures):
            try:
                name, statuses = fut.result()
                _log(args, "INFO", f"scanned <type> {name}: {statuses}")
            except Exception as e:
                _log(args, "ERROR", f"<type> scan failed: {e}")
```

**Thread Safety:** `Path.mkdir()`, `Path.write_text()`, `subprocess.run()`, and
GIL-protected dict writes are safe. Avoid shared file handles, counters, or list
appends without locks.

### Step 4: CLI Argument Registration

Add flags to **both** `scan` and `ci` subcommands in `parse_args()`.

```python
# Scan subcommand
scan_parser.add_argument("--<type>", type=str, help="Single <type> target")
scan_parser.add_argument("--<type>s-file", type=str, help="Batch file")

# CI subcommand (MUST mirror scan args)
ci_parser.add_argument("--<type>", type=str, help="<type> target")
ci_parser.add_argument("--<type>s-file", type=str, help="Batch file")
```

**Argument Naming Conventions:**

| Pattern | Example | Description |
|---------|---------|-------------|
| `--<type>` | `--aws-account` | Single target identifier |
| `--<type>s-file` | `--aws-accounts-file` | Batch file with multiple targets |
| `--<type>-token` | `--gitlab-token` | Authentication token |
| `--<type>-url` | `--gitlab-url` | Base URL for API |
| `--<type>-context` | `--k8s-context` | Context/environment selector |

### Step 5: Reporting Integration (normalize_and_report.py)

Add the new target directory to `target_dirs` in `scripts/core/normalize_and_report.py`.
Existing tool loaders and deduplication work automatically across all target types.

```python
target_dirs = [
    results_dir / "individual-repos",
    results_dir / "individual-images",
    results_dir / "individual-iac",
    results_dir / "individual-web",
    results_dir / "individual-gitlab",
    results_dir / "individual-k8s",
    results_dir / "individual-cloud",
    results_dir / "individual-mobile",
    results_dir / "individual-hosts",
    results_dir / "individual-<type>s",  # ADD NEW TARGET TYPE HERE
]
```

## Reference Documentation

Detailed guidance extracted into supporting files for readability:

**[references/tool-selection.md](references/tool-selection.md)** --
Tool selection matrix by target type, selection criteria (native support, security
domains, CI/CD speed, JSON output), and configuration examples.

**[references/authentication-patterns.md](references/authentication-patterns.md)** --
Three authentication patterns: environment variables (recommended), CLI arguments,
and credential files. Includes examples for AWS, GitLab, and npm.

**[references/common-pitfalls.md](references/common-pitfalls.md)** --
Six common mistakes: unsafe directory names, missing CI args, forgetting
normalize_and_report.py, thread-unsafe operations, hardcoded credentials,
unsanitized batch input.

**[examples/real-world-examples.md](examples/real-world-examples.md)** --
Five complete end-to-end implementations: AWS account scanning (Prowler),
npm package scanning (npm audit + Snyk), GraphQL API scanning (GraphQL Cop),
mobile app scanning (MobSF), and host audit scanning (Lynis).

**[references/memory-integration.md](references/memory-integration.md)** --
Memory caching for learned patterns, tool compatibility, and API structures.
Namespace, storage format, cache workflow, and invalidation rules.

## Complete Checklist

When adding a new target type, verify all items:

### Implementation

- [ ] **Step 1:** `_iter_<type>(args)` collection function created
- [ ] **Step 2:** `job_<type>(target)` scan function created
- [ ] **Step 3:** ThreadPoolExecutor parallel execution added
- [ ] **Step 4:** CLI arguments added to `scan` AND `ci` subcommands
- [ ] **Step 5:** Results directory structure created (`individual-<type>s/`)
- [ ] **Step 6:** Target directory added to `normalize_and_report.py`

### Tool Integration

- [ ] Tool adapters exist for new tools (if needed)
- [ ] Test suites created for new adapters (if needed)
- [ ] Tool loaders called in `normalize_and_report.py`
- [ ] `_write_stub()` handles new tool output formats

### Configuration

- [ ] Tools added to appropriate profiles (fast/balanced/deep)
- [ ] Timeout and flags configured for new tools
- [ ] Authentication pattern implemented (env vars/CLI/files)

### Documentation

- [ ] README.md updated with new target type
- [ ] QUICKSTART.md updated with usage examples (if commonly used)
- [ ] CHANGELOG.md updated with feature addition
- [ ] docs/USER_GUIDE.md updated with new CLI flags

### Testing

- [ ] Manual testing: scanned real targets, verified findings in dashboard
- [ ] Integration test added in `tests/integration/`
- [ ] Multi-target scanning works with multiple target types
- [ ] `--fail-on` threshold works in CI mode
- [ ] `--allow-missing-tools` works correctly

### Quality Assurance

- [ ] Pre-commit hooks pass (`make fmt && make lint`)
- [ ] Full test suite passes (`make test` with >=85% coverage)
- [ ] CI pipeline passes
