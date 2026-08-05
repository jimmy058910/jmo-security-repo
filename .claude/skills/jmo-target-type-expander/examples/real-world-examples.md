# Real-World Examples

Complete end-to-end implementations for adding new target types to JMo Security.
Each example shows all 6 steps of the implementation pattern.

## Example 1: AWS Account Scanning

**Use Case:** Scan multiple AWS accounts for misconfigurations and compliance violations.

### Implementation

```python
# ========================================
# Step 1: Target Collection
# ========================================

def _iter_aws_accounts(args) -> list[str]:
    """Collect AWS account IDs from CLI arguments."""
    accounts = []

    if getattr(args, "aws_account", None):
        accounts.append(args.aws_account)

    if getattr(args, "aws_accounts_file", None):
        path = Path(args.aws_accounts_file)
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    accounts.append(line)

    return accounts


# ========================================
# Step 2: Scan Job
# ========================================

def job_aws_account(account_id: str) -> tuple[str, dict[str, bool]]:
    """Scan AWS account with Prowler."""
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", account_id)
    out_dir = results_dir / "individual-aws-accounts" / safe_name
    out_dir.mkdir(parents=True, exist_ok=True)

    statuses: dict[str, bool] = {}

    if "prowler" in tools:
        out = out_dir / "prowler.json"
        if _tool_exists("prowler"):
            flags = pt.get("prowler", {}).get("flags", [])

            # Get AWS region from CLI args or default
            region = getattr(args, "aws_region", "us-east-1")

            cmd = [
                "prowler",
                "aws",
                "--profile", account_id,  # AWS CLI profile name
                "--region", region,
                "--output-formats", "json",
                "--output-directory", str(out_dir),
                "--output-filename", "prowler",
                "--no-banner",  # Suppress ASCII art
                "--quiet",      # Less verbose
                *([str(x) for x in flags] if isinstance(flags, list) else []),
            ]

            rc, _, _, used = _run_cmd(
                cmd,
                t_override("prowler", to),
                retries=retries,
                ok_rcs=(0, 1),  # 0 = pass, 1 = findings
            )

            if rc in (0, 1):
                statuses["prowler"] = True
                attempts_map["prowler"] = used
            elif args.allow_missing_tools:
                _write_stub("prowler", out)
                statuses["prowler"] = True
        elif args.allow_missing_tools:
            _write_stub("prowler", out)
            statuses["prowler"] = True

    return account_id, statuses


# ========================================
# Step 3: Parallel Execution
# ========================================

# In cmd_scan()
aws_accounts = _iter_aws_accounts(args)

if aws_accounts:
    _log(args, "INFO", f"Scanning {len(aws_accounts)} AWS account(s)...")

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = []
        for account in aws_accounts:
            futures.append(ex.submit(job_aws_account, account))

        for fut in as_completed(futures):
            try:
                name, statuses = fut.result()
                _log(args, "INFO", f"scanned AWS account {name}: {statuses}")
            except Exception as e:
                _log(args, "ERROR", f"AWS account scan failed: {e}")


# ========================================
# Step 4: CLI Arguments
# ========================================

# In parse_args()
scan_parser.add_argument(
    "--aws-account",
    type=str,
    help="AWS account ID or profile name (e.g., 123456789012 or prod)",
)
scan_parser.add_argument(
    "--aws-accounts-file",
    type=str,
    help="File containing AWS account IDs (one per line, # comments supported)",
)
scan_parser.add_argument(
    "--aws-region",
    type=str,
    default="us-east-1",
    help="AWS region for scanning (default: us-east-1)",
)

# CI subcommand
ci_parser.add_argument("--aws-account", type=str, help="AWS account ID")
ci_parser.add_argument("--aws-accounts-file", type=str, help="AWS accounts file")
ci_parser.add_argument("--aws-region", type=str, default="us-east-1", help="AWS region")


# ========================================
# Step 5: Results Directory
# ========================================

# results/individual-aws-accounts/
#   └── 123456789012/
#       └── prowler.json


# ========================================
# Step 6: Reporting Integration
# ========================================

# In normalize_and_report.py
target_dirs = [
    results_dir / "individual-repos",
    results_dir / "individual-images",
    results_dir / "individual-iac",
    results_dir / "individual-web",
    results_dir / "individual-gitlab",
    results_dir / "individual-k8s",
    results_dir / "individual-aws-accounts",  # NEW
]
```

### Usage

```bash
# Scan single account
jmo scan --aws-account 123456789012 --tools prowler

# Scan multiple accounts from file
jmo scan --aws-accounts-file aws-accounts.txt --tools prowler --profile-name balanced

# Multi-target scan (repos + AWS accounts)
jmo scan --repo ./myapp --aws-account 123456789012 --profile-name deep

# CI mode with threshold
jmo ci --aws-account 123456789012 --fail-on HIGH --profile-name balanced
```

### Batch File (aws-accounts.txt)

```text
# Production accounts
123456789012  # Main prod
234567890123  # Backup

# Staging (commented out)
# 345678901234
```

---

## Example 2: npm Package Registry Scanning

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

            if rc in (0, 1) and stdout:
                out.write_text(stdout, encoding="utf-8")
                statuses["npm-audit"] = True
                attempts_map["npm-audit"] = used
            elif args.allow_missing_tools:
                _write_stub("npm-audit", out)
                statuses["npm-audit"] = True
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

            rc, _, _, used = _run_cmd(
                cmd,
                t_override("snyk", to),
                retries=retries,
                ok_rcs=(0, 1),
            )

            if rc in (0, 1):
                statuses["snyk"] = True
                attempts_map["snyk"] = used
            elif args.allow_missing_tools:
                _write_stub("snyk", out)
                statuses["snyk"] = True
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
jmo scan --npm-package lodash --tools npm-audit,snyk

# Scan multiple packages
jmo scan --npm-packages-file critical-deps.txt --profile-name balanced

# Supply chain audit (repos + packages)
jmo scan --repo ./myapp --npm-packages-file dependencies.txt
```

---

## Example 3: GraphQL API Scanning

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

            if auth_token:
                cmd.extend(["--header", f"Authorization: Bearer {auth_token}"])

            cmd.extend([str(x) for x in flags] if isinstance(flags, list) else [])

            rc, _, _, used = _run_cmd(
                cmd,
                t_override("graphql-cop", to),
                retries=retries,
                ok_rcs=(0, 1),
            )

            if rc in (0, 1):
                statuses["graphql-cop"] = True
                attempts_map["graphql-cop"] = used
            elif args.allow_missing_tools:
                _write_stub("graphql-cop", out)
                statuses["graphql-cop"] = True
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

---

## Example 4: Mobile App Scanning (v1.0.0)

**Use Case:** Scan Android APK and iOS IPA files for security vulnerabilities using MobSF.

### Implementation

```python
# Step 1: Target Collection
def _iter_mobile_apps(args) -> list[Path]:
    """Collect mobile app files from CLI arguments."""
    apps = []

    if getattr(args, "mobile_src", None):
        apps.append(Path(args.mobile_src))

    if getattr(args, "apk", None):
        apps.append(Path(args.apk))

    if getattr(args, "ipa", None):
        apps.append(Path(args.ipa))

    if getattr(args, "mobile_apps_file", None):
        path = Path(args.mobile_apps_file)
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    apps.append(Path(line))

    return apps

# Step 2: Scan Job
def job_mobile_app(app_path: Path) -> tuple[str, dict[str, bool]]:
    """Scan mobile app with MobSF."""
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", app_path.stem)
    out_dir = results_dir / "individual-mobile" / safe_name
    out_dir.mkdir(parents=True, exist_ok=True)

    statuses: dict[str, bool] = {}

    if "mobsf" in tools:
        out = out_dir / "mobsf.json"
        if _tool_exists("mobsf"):
            cmd = [
                "mobsf",
                "scan",
                "--file", str(app_path),
                "--json",
                "--output", str(out)
            ]

            rc, _, _, used = _run_cmd(
                cmd,
                t_override("mobsf", to),
                retries=retries,
                ok_rcs=(0,)
            )

            if rc == 0:
                statuses["mobsf"] = True
                attempts_map["mobsf"] = used
            elif args.allow_missing_tools:
                _write_stub("mobsf", out)
                statuses["mobsf"] = True
        elif args.allow_missing_tools:
            _write_stub("mobsf", out)
            statuses["mobsf"] = True

    return app_path.name, statuses

# Step 4: CLI Arguments
scan_parser.add_argument("--mobile-src", help="Mobile app source directory")
scan_parser.add_argument("--apk", help="Android APK file")
scan_parser.add_argument("--ipa", help="iOS IPA file")
scan_parser.add_argument("--mobile-apps-file", help="File with mobile app paths")
```

### Usage

```bash
# Scan Android APK
jmo scan --apk app-release.apk --tools mobsf

# Scan iOS IPA
jmo scan --ipa MyApp-v1.0.ipa --tools mobsf

# Scan multiple mobile apps
jmo scan --mobile-apps-file mobile-apps.txt --profile-name deep
```

---

## Example 5: Host Audit Scanning (v1.0.0)

**Use Case:** Run system hardening audits on localhost using Lynis.

### Implementation

```python
# Step 1: Target Collection
def _should_run_host_audit(args) -> bool:
    """Check if host audit should run."""
    return getattr(args, "host_audit", False)

# Step 2: Scan Job
def job_host_audit() -> tuple[str, dict[str, bool]]:
    """Run system hardening audit with Lynis."""
    import socket
    hostname = socket.gethostname()
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", hostname)

    out_dir = results_dir / "individual-hosts" / safe_name
    out_dir.mkdir(parents=True, exist_ok=True)

    statuses: dict[str, bool] = {}

    if "lynis" in tools:
        out = out_dir / "lynis.json"
        if _tool_exists("lynis"):
            cmd = [
                "lynis",
                "audit",
                "system",
                "--quiet",
                "--no-colors",
                "--output", str(out)
            ]

            rc, _, _, used = _run_cmd(
                cmd,
                t_override("lynis", to),
                retries=retries,
                ok_rcs=(0,)
            )

            if rc == 0:
                statuses["lynis"] = True
                attempts_map["lynis"] = used
            elif args.allow_missing_tools:
                _write_stub("lynis", out)
                statuses["lynis"] = True
        elif args.allow_missing_tools:
            _write_stub("lynis", out)
            statuses["lynis"] = True

    return hostname, statuses

# Step 3: Execution (No parallelism - single host)
if _should_run_host_audit(args):
    _log(args, "INFO", "Running host audit...")
    hostname, statuses = job_host_audit()
    _log(args, "INFO", f"scanned host {hostname}: {statuses}")

# Step 4: CLI Arguments
scan_parser.add_argument("--host-audit", action="store_true",
                        help="Run system hardening audit on localhost")
```

### Usage

```bash
# Run host audit
jmo scan --host-audit --tools lynis

# Combine with repository scan
jmo scan --repo ./myapp --host-audit --profile-name deep
```
