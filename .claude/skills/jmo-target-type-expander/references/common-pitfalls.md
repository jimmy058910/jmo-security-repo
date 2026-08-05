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
# Use environment variables
def job_<type>(target):
    token = os.environ.get("<TYPE>_TOKEN")
    if not token:
        _log(args, "WARN", "Token not set, skipping")
        return target, {}

    cmd = ["tool", "--token", token, target]  # Good!
```

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
