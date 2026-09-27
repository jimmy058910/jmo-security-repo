# Tool Selection Reference

Guidelines for choosing security tools when adding new target types to JMo Security.

## Tool Selection Matrix

| Target Type | Primary Category | Recommended Tools | Alternative Tools |
|-------------|------------------|-------------------|-------------------|
| Repositories | Secrets, SAST | trufflehog, semgrep | gitleaks, trivy |
| Container Images | Vuln, SBOM | trivy, syft | grype, snyk |
| IaC Files | Misconfig, Policy | checkov, trivy | tfsec, terrascan |
| Web URLs | DAST | zap | burp, nikto |
| GitLab Repos | Secrets | trufflehog | gitleaks |
| Kubernetes | K8s Security | trivy | kubesec, kube-bench |
| **AWS Accounts** | Cloud Security | scoutsuite (cmd: `scout`) | cloudmapper |
| **npm Packages** | SCA | npm audit, snyk | retire.js |
| **GraphQL APIs** | API Security | graphql-cop, inql | graphw00f |

## Tool Selection Criteria

### 1. Does the tool support the target type natively?

```bash
# Check tool documentation
trivy k8s --help            # Yes: has k8s subcommand
trivy image --help          # Yes: has image subcommand
semgrep scan --help         # No: only scans local files
```

### 2. What security domains are relevant?

| Target Type | Relevant Domains |
|-------------|------------------|
| Cloud Accounts | Misconfigurations, IAM policies, network rules |
| Package Registries | Dependency vulns, license compliance |
| APIs | Authentication, injection, rate limiting |
| Config Management | Secrets, privilege escalation |

### 3. Is the tool fast enough for CI/CD?

```text
Fast (<5 min):
- npm audit, pip-audit (local package managers)
- hadolint (Dockerfile linting)
- checkov (IaC scanning)

Medium (5-20 min):
- trivy (comprehensive scanning)
- zap (web app scanning)

Slow (>20 min):
- ScoutSuite (multi-cloud auditing)
```

### 4. Does the tool output JSON?

```bash
# Required: JSON output for adapter integration
trivy image --format json nginx    # Yes
scout aws --report-dir .           # Yes (generates JSON)
nmap -oX output.xml                # No (XML only, needs conversion)
```

## Tool Assignment Example: npm Packages

**Primary Tool: npm audit**

- Native npm support (`npm audit --json`)
- JSON output built-in
- Fast (seconds per package)
- Ships with npm, so nothing extra to install

**Secondary Tool: Snyk**

- Broader vulnerability database than the npm advisory feed
- JSON output via `--json`
- Needs an auth token (see [authentication-patterns.md](authentication-patterns.md))
- Complementary findings to npm audit

**Configuration:**

```yaml
# jmo.yml -- scan settings are top-level; there are no profiles
per_tool:
  npm-audit:
    flags:
      - --audit-level
      - high
    timeout: 300  # 5 min
  snyk:
    flags:
      - --severity-threshold=high
    timeout: 900  # 15 min
```

A tool runs by default only if it is in `TOOL_MATRIX`
(`scripts/core/tool_registry.py`). A tool outside it runs when named with
`--tools`, or listed under a top-level `tools:` key in `jmo.yml`.
