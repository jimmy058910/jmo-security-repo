# Sample Test Fixtures

This directory contains **intentionally vulnerable code** for golden test fixture generation.

## Purpose

These samples serve as **static test targets** that produce deterministic, reproducible security findings when scanned by various tools. They are used by the golden test infrastructure to:

1. Verify adapters correctly parse tool outputs
2. Detect silent failures when tool output formats change
3. Ensure expected findings are actually produced

## Directory Structure

```text
samples/
├── python-vulnerable/     # Python security issues (Bandit, Semgrep)
│   ├── vulnerable_app.py  # SAST findings (SQL injection, RCE, etc.)
│   └── requirements.txt   # CVE-affected dependencies (Trivy, Grype)
├── dockerfile-issues/     # Dockerfile best practices (Hadolint, Trivy)
│   └── Dockerfile         # Missing healthcheck, running as root, etc.
├── terraform-misconfig/   # IaC misconfigurations (Checkov, Trivy)
│   └── main.tf           # S3 public access, open security groups, etc.
├── credential-patterns/       # Secret detection (TruffleHog, Semgrep secrets)
│   └── config.py         # Fake AWS keys, tokens, passwords
└── shell-issues/          # Shell script issues (ShellCheck)
    └── vulnerable_script.sh  # Quoting, word splitting, unsafe patterns
```

## Security Warning

**DO NOT USE THIS CODE IN PRODUCTION**

All code in this directory contains deliberate security vulnerabilities, misconfigurations, and exposed (fake) credentials. It exists solely for automated testing purposes.

## Tools Coverage

| Sample Directory | Tools That Should Find Issues |
|-----------------|------------------------------|
| python-vulnerable/ | Bandit, Semgrep, Trivy (CVEs), Grype |
| dockerfile-issues/ | Hadolint, Trivy (misconfig) |
| terraform-misconfig/ | Checkov, Trivy (config) |
| credential-patterns/ | TruffleHog, Semgrep secrets, Trivy (secrets) |
| shell-issues/ | ShellCheck |

## Usage

These samples are used by `scripts/dev/generate_golden.py` to create golden test fixtures:

```bash
# Generate golden files for all tools
python scripts/dev/generate_golden.py --all

# Generate for specific tool
python scripts/dev/generate_golden.py --tool trivy
```

## Updating Samples

When adding new sample vulnerabilities:

1. Add code with clear, intentional vulnerabilities
2. Document which tools should detect each issue (with rule IDs if known)
3. Regenerate golden files: `python scripts/dev/generate_golden.py --update`
4. Verify tests pass: `pytest tests/adapters/test_adapter_golden.py -v`
