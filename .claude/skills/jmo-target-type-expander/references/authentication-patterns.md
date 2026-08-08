# Authentication Patterns

Many target types require authentication (cloud accounts, private repos, APIs).
This reference covers the three standard patterns used in JMo Security.

## Pattern 1: Environment Variables (Recommended)

```python
# In job_<type>() function

# Check for required credentials in environment.
# `not os.environ.get(...)` -- NOT `not in os.environ`. A CI secret that
# failed to resolve is exported as an EMPTY STRING, which `in` accepts; the
# scan then runs unauthenticated and reports success over partial results.
if not os.environ.get("<TYPE>_TOKEN"):
    _log(args, "WARN", f"<TYPE>_TOKEN not set, skipping <type> {target}")
    return target, {}

# Tool picks up credentials from environment automatically
cmd = ["tool", "scan", str(target)]
```

**Pros:**

- Secure (credentials not in command line)
- Works with CI/CD secret managers
- Tool-native (most tools support env vars)

**Cons:**

- Requires pre-configuration
- Less flexible than CLI args

**Example: AWS Accounts**

```python
def job_aws_account(account_id: str) -> tuple[str, dict[str, bool]]:
    """Scan AWS account using credentials from environment."""

    # Prowler uses standard AWS credential chain:
    # 1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    # 2. AWS CLI config (~/.aws/credentials)
    # 3. IAM role (if running on EC2/ECS/Lambda)

    # No explicit credential passing needed
    cmd = [
        "prowler",
        "aws",
        "--profile", account_id,  # Uses AWS CLI profile
        # Credentials come from standard AWS credential chain
    ]
```

## Pattern 2: CLI Arguments from Config

```python
# In job_<type>() function

# Get token from CLI args (passed through from parse_args)
token = getattr(args, "<type>_token", None)
if not token:
    _log(args, "WARN", f"--<type>-token not provided, skipping")
    return target, {}

# Pass token to tool
cmd = [
    "tool",
    "scan",
    "--token", token,
    str(target),
]
```

**Pros:**

- Explicit configuration
- Can use different tokens per run
- Good for testing

**Cons:**

- **Token in process list (CWE-214).** `argv` is world-readable on a shared
  host — `ps -ef`, `/proc/<pid>/cmdline`, and `Get-CimInstance Win32_Process`
  all expose it, to any local user, for as long as the scan runs. It also
  reaches shell history and any log that echoes the command.
- Harder to manage in CI/CD

**Prefer Pattern 1 whenever the tool supports it.** Use this pattern only for a
tool that offers no environment or credential-file route, and say so in the
adapter's docstring. If you must pass a secret through `argv`, do not also log
the command.

**Example: GitLab Repos**

```python
def job_gitlab_repo(repo: str) -> tuple[str, dict[str, bool]]:
    """Scan GitLab repository with TruffleHog."""

    # Get GitLab token from CLI args
    token = getattr(args, "gitlab_token", None)
    url = getattr(args, "gitlab_url", "https://gitlab.com")

    if not token:
        _log(args, "WARN", "GitLab token not provided, skipping")
        return repo, {}

    cmd = [
        "trufflehog",
        "gitlab",
        "--repo", f"{url}/{repo}",
        "--token", token,  # Passed to tool
        "--json",
    ]
```

## Pattern 3: Credential Files

```python
# In job_<type>() function

# Check for credential file
cred_file = Path.home() / ".config" / "<tool>" / "credentials"
if not cred_file.exists():
    _log(args, "WARN", f"Credentials not found at {cred_file}")
    return target, {}

# Tool reads credentials from file
cmd = ["tool", "scan", "--config", str(cred_file), str(target)]
```

**Pros:**

- Secure (not in command line or env)
- Persistent configuration
- Supports multiple credential sets

**Cons:**

- Requires file management
- Tool must support file-based credentials

**Example: npm Registry Scanning**

```python
def job_npm_package(package: str) -> tuple[str, dict[str, bool]]:
    """Scan npm package with Snyk (uses ~/.snyk/config)."""

    # Snyk reads token from ~/.config/configstore/snyk.json
    # No explicit credential passing needed

    cmd = [
        "snyk",
        "test",
        package,
        "--json",
    ]
```
