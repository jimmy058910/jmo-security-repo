# Real-World Examples

Complete end-to-end implementations for adding new target types to JMo Security.
Each example shows all 6 steps of the implementation pattern.

## Example 1: npm Package Registry Scanning

**Use Case:** Scan npm packages for vulnerabilities as part of supply chain security.

### Implementation

```python
# Step 1: Target Collection
def _iter_npm_packages(args) -> list[str]:
    """Collect npm package names from CLI arguments."""
    packages = []

    if getattr(args, "npm_package", None):
        packages.append(args.npm_package)

    if getattr(args, "npm_packages_file", None):
        path = Path(args.npm_packages_file)
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    packages.append(line)

    return packages


# Step 2: Scan Job
def job_npm_package(package: str) -> tuple[str, dict[str, bool]]:
    """Scan npm package with npm audit and Snyk."""
    # Sanitize package name (may contain @ and /)
    # Example: @angular/core -> _angular_core
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", package)
    out_dir = results_dir / "individual-npm-packages" / safe_name
    out_dir.mkdir(parents=True, exist_ok=True)

    statuses: dict[str, bool] = {}

    # npm audit (built-in, fast)
    if "npm-audit" in tools:
        out = out_dir / "npm-audit.json"
        if _tool_exists("npm"):
            cmd = [
                "npm",
                "audit",
                package,
                "--json",
            ]

            rc, stdout, _, used = _run_cmd(
                cmd,
                t_override("npm-audit", to),
                retries=retries,
                ok_rcs=(0, 1),  # 0 = clean, 1 = vulns
                capture_stdout=True,  # npm audit writes to stdout
            )

            # npm ran -- record its real result, never a stub. Empty stdout on
            # an otherwise-OK exit is still a failure: nothing to normalize.
            ok = rc in (0, 1) and bool(stdout)
            if ok:
                out.write_text(stdout, encoding="utf-8")
            statuses["npm-audit"] = ok
            attempts_map["npm-audit"] = used
        elif args.allow_missing_tools:
            _write_stub("npm-audit", out)
            statuses["npm-audit"] = True

    # Snyk (comprehensive, requires token)
    if "snyk" in tools:
        out = out_dir / "snyk.json"
        if _tool_exists("snyk"):
            cmd = [
                "snyk",
                "test",
                package,
                "--json",
            ]

            # `snyk test --json` writes to stdout. Capture it and persist it to
            # `out` -- exactly as npm audit does above. Without this, snyk.json
            # is never created and the report phase finds nothing, while the
            # scan still reports the tool as successful.
            rc, stdout, _, used = _run_cmd(
                cmd,
                t_override("snyk", to),
                retries=retries,
                ok_rcs=(0, 1),
                capture_stdout=True,
            )

            ok = rc in (0, 1) and bool(stdout)
            if ok:
                out.write_text(stdout, encoding="utf-8")
            statuses["snyk"] = ok
            attempts_map["snyk"] = used
        elif args.allow_missing_tools:
            _write_stub("snyk", out)
            statuses["snyk"] = True

    return package, statuses


# Step 3: Parallel Execution
npm_packages = _iter_npm_packages(args)

if npm_packages:
    _log(args, "INFO", f"Scanning {len(npm_packages)} npm package(s)...")

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = []
        for package in npm_packages:
            futures.append(ex.submit(job_npm_package, package))

        for fut in as_completed(futures):
            try:
                name, statuses = fut.result()
                _log(args, "INFO", f"scanned npm package {name}: {statuses}")
            except Exception as e:
                _log(args, "ERROR", f"npm package scan failed: {e}")


# Step 4: CLI Arguments
scan_parser.add_argument(
    "--npm-package",
    type=str,
    help="npm package name to scan (e.g., lodash or @angular/core)",
)
scan_parser.add_argument(
    "--npm-packages-file",
    type=str,
    help="File containing npm package names (one per line)",
)

ci_parser.add_argument("--npm-package", type=str, help="npm package name")
ci_parser.add_argument("--npm-packages-file", type=str, help="npm packages file")


# Step 5 & 6: Results + Reporting

# results/individual-npm-packages/
#   ├── lodash/
#   │   ├── npm-audit.json
#   │   └── snyk.json
#   └── _angular_core/  # Sanitized name
#       ├── npm-audit.json
#       └── snyk.json

# Add to normalize_and_report.py target_dirs
```

### Usage

```bash
# Scan single package
jmo scan --npm-package lodash --tools npm-audit snyk

# Scan multiple packages
jmo scan --npm-packages-file critical-deps.txt

# Supply chain audit (repos + packages)
jmo scan --repo ./myapp --npm-packages-file dependencies.txt
```

`_iter_npm_packages` skips **whole-line** comments only: it tests
`line.startswith("#")` after stripping, and does nothing else to the line. An
entry written as `lodash  # pinned by security` is therefore collected
verbatim, comment and all, and no package resolves. Put the annotation on its
own line.

The parser is right not to strip trailing `#`: `#` is legal inside other target
identifiers (a URL fragment being the obvious one), so a blanket strip would
silently truncate them.

---

## Example 2: GraphQL API Scanning

**Use Case:** Security testing of GraphQL APIs for authentication, injection, and info disclosure.

### Implementation

```python
# Step 1: Target Collection
def _iter_graphql_apis(args) -> list[str]:
    """Collect GraphQL API endpoints from CLI arguments."""
    apis = []

    if getattr(args, "graphql_api", None):
        apis.append(args.graphql_api)

    if getattr(args, "graphql_apis_file", None):
        path = Path(args.graphql_apis_file)
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    apis.append(line)

    return apis


# Step 2: Scan Job
def job_graphql_api(api_url: str) -> tuple[str, dict[str, bool]]:
    """Scan GraphQL API with GraphQL Cop and InQL."""
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", api_url)
    out_dir = results_dir / "individual-graphql-apis" / safe_name
    out_dir.mkdir(parents=True, exist_ok=True)

    statuses: dict[str, bool] = {}

    if "graphql-cop" in tools:
        out = out_dir / "graphql-cop.json"
        if _tool_exists("graphql-cop"):
            flags = pt.get("graphql-cop", {}).get("flags", [])

            auth_token = getattr(args, "graphql_token", None)

            cmd = [
                "graphql-cop",
                "--target", api_url,
                "--output-format", "json",
                "--output", str(out),
            ]

            # WARNING (CWE-214): this puts the bearer token in argv, where
            # every local user can read it for the lifetime of the process
            # (`ps -ef`, /proc/<pid>/cmdline, Get-CimInstance Win32_Process).
            #
            # Before copying this shape, check whether your tool can take the
            # credential from the environment or a credentials file instead --
            # that is Pattern 1 in references/authentication-patterns.md, and
            # it is the one to prefer. Pass it via the subprocess `env=`
            # argument rather than exporting it process-wide.
            #
            # Only fall back to a header on argv when the tool genuinely
            # offers no other route, and never log the resulting command.
            if auth_token:
                cmd.extend(["--header", f"Authorization: Bearer {auth_token}"])

            cmd.extend([str(x) for x in flags] if isinstance(flags, list) else [])

            rc, _, _, used = _run_cmd(
                cmd,
                t_override("graphql-cop", to),
                retries=retries,
                ok_rcs=(0, 1),
            )

            # graphql-cop ran -- record its real result, never a stub.
            statuses["graphql-cop"] = rc in (0, 1)
            attempts_map["graphql-cop"] = used
        elif args.allow_missing_tools:
            _write_stub("graphql-cop", out)
            statuses["graphql-cop"] = True

    return api_url, statuses


# Step 3-4: Parallel Execution + CLI Arguments
scan_parser.add_argument("--graphql-api", type=str,
    help="GraphQL API endpoint URL (e.g., https://api.example.com/graphql)")
scan_parser.add_argument("--graphql-apis-file", type=str,
    help="File containing GraphQL API URLs (one per line)")
scan_parser.add_argument("--graphql-token", type=str,
    help="Authentication token for GraphQL API access")

ci_parser.add_argument("--graphql-api", type=str, help="GraphQL API URL")
ci_parser.add_argument("--graphql-apis-file", type=str, help="GraphQL APIs file")
ci_parser.add_argument("--graphql-token", type=str, help="Auth token")
```

### Usage

```bash
# Scan single API
jmo scan --graphql-api https://api.example.com/graphql --tools graphql-cop

# Scan with authentication
jmo scan --graphql-api https://api.example.com/graphql \
  --graphql-token "your-token-here" \
  --tools graphql-cop

# Multi-target: repos + APIs
jmo scan --repo ./backend --graphql-api https://api.example.com/graphql
```
