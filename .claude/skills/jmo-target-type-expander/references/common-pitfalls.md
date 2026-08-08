# Common Pitfalls and Solutions

Frequent mistakes when adding new target types to JMo Security, with fixes.

## Pitfall 1: Unsafe Directory Names

**Problem:**

```python
# Special characters in target names break filesystem
target = "https://api.example.com/graphql"
out_dir = results_dir / "individual-graphql-apis" / target  # ERROR: / in path
out_dir.mkdir(parents=True, exist_ok=True)  # Crashes!
```

**Solution:**

```python
# Always sanitize target names
safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", target)
# "https://api.example.com/graphql" -> "https___api_example_com_graphql"
out_dir = results_dir / "individual-graphql-apis" / safe_name
out_dir.mkdir(parents=True, exist_ok=True)  # Works!
```

## Pitfall 2: Missing CI Subcommand Arguments

**Problem:**

```python
# Only added to scan subcommand
scan_parser.add_argument("--aws-account", ...)
# Forgot to add to ci subcommand!

# User tries:
# $ jmo ci --aws-account 123456789012 --fail-on HIGH
# Error: unrecognized arguments: --aws-account
```

**Solution:**

```python
# Always add to BOTH scan and ci subcommands
scan_parser.add_argument("--aws-account", ...)
ci_parser.add_argument("--aws-account", ...)  # Don't forget CI!
```

## Pitfall 3: Forgetting to Add to normalize_and_report.py

**Problem:**

```python
# Implemented Steps 1-4, but forgot Step 6
# Scan runs successfully, creates results/individual-aws-accounts/...
# But normalize_and_report.py doesn't read them!

# $ jmo report results
# Output: 0 findings (none from AWS accounts!)
```

**Solution:**

```python
# Always add new target directory to normalize_and_report.py
target_dirs = [
    results_dir / "individual-repos",
    results_dir / "individual-images",
    results_dir / "individual-iac",
    results_dir / "individual-web",
    results_dir / "individual-gitlab",
    results_dir / "individual-k8s",
    results_dir / "individual-aws-accounts",  # DON'T FORGET!
]
```

## Pitfall 4: Thread-Unsafe Operations

**Problem:**

```python
# Shared state across threads - NOT thread-safe!
total_findings = 0  # Global counter

def job_<type>(target):
    global total_findings
    # ... scan logic ...
    total_findings += len(findings)  # RACE CONDITION!
```

**Solution:**

```python
# Return data from job, aggregate in main thread
def job_<type>(target):
    # ... scan logic ...
    return target, statuses  # Return, don't mutate shared state

# Aggregate in main thread (thread-safe)
total_findings = 0
for fut in as_completed(futures):
    name, statuses = fut.result()
    total_findings += sum(1 for s in statuses.values() if s)
```

## Pitfall 5: Hardcoded Credentials

**Problem:**

```python
# Credentials in code or config - SECURITY RISK!
API_TOKEN = "ghp_abc123..."  # Hardcoded in source

def job_<type>(target):
    cmd = ["tool", "--token", API_TOKEN, target]  # BAD!
```

**Solution:**

```python
# Use environment variables -- and let the tool READ them itself
def job_<type>(target):
    if not os.environ.get("<TYPE>_TOKEN"):
        _log(args, "WARN", "Token not set, skipping")
        return target, {}

    # Best: the tool picks the credential up from the environment, so it
    # never appears in argv at all.
    cmd = ["tool", "scan", target]
    rc, *_ = _run_cmd(cmd, timeout, env={**os.environ})
```

**Reading from the environment is only half the fix.** Sourcing the token from
`os.environ` instead of a literal keeps it out of *git*, but

```python
cmd = ["tool", "--token", token, target]   # still exposed
```

puts it straight back into the **process list** (CWE-214), where any local user
can read it with `ps -ef`, `/proc/<pid>/cmdline`, or
`Get-CimInstance Win32_Process` for as long as the scan runs. Hand the tool the
environment and let it read the variable; pass the secret on the command line
only if the tool supports nothing else. See
[authentication-patterns.md](authentication-patterns.md) Pattern 1 vs Pattern 2.

## Pitfall 6: Not Sanitizing Batch File Input

**Problem:**

```python
# No input validation - security risk!
def _iter_<type>(args):
    targets = []
    if args.<type>s_file:
        for line in open(args.<type>s_file):  # No validation!
            targets.append(line)  # Includes newlines, comments, etc.
    return targets
```

**Solution:**

```python
# Always validate and sanitize input
def _iter_<type>(args):
    targets = []
    if args.<type>s_file:
        path = Path(args.<type>s_file)
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()  # Remove whitespace
                if line and not line.startswith("#"):  # Skip empty/comments
                    targets.append(line)
    return targets
```
