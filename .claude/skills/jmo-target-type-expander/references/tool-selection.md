# Tool Selection Reference

Guidelines for choosing security tools when adding new target types to JMo Security.

## Tool Selection Matrix

| Target Type | Primary Category | Recommended Tools | Alternative Tools |
|-------------|------------------|-------------------|-------------------|
| Repositories | Secrets, SAST | trufflehog, semgrep, bandit | noseyparker, trivy |
| Container Images | Vuln, SBOM | trivy, syft | grype, snyk |
| IaC Files | Misconfig, Policy | checkov, trivy | tfsec, terrascan |
| Web URLs | DAST | zap | burp, nikto |
| GitLab Repos | Secrets | trufflehog | gitleaks |
| Kubernetes | K8s Security | trivy | kubesec, kube-bench |
| **AWS Accounts** | Cloud Security | prowler, scoutsuite | cloudmapper |
| **npm Packages** | SCA | npm audit, snyk | retire.js |
| **GraphQL APIs** | API Security | graphql-cop, inql | graphw00f |

## Tool Selection Criteria

### 1. Does the tool support the target type natively?

```bash
# Check tool documentation
prowler aws --help          # Yes: has aws subcommand
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
- prowler (AWS account scanning)
- zap (web app scanning)

Slow (>20 min):
- noseyparker (deep secret scanning)
- ScoutSuite (multi-cloud auditing)
- afl++ (fuzzing campaigns)
```

### 4. Does the tool output JSON?

```bash
# Required: JSON output for adapter integration
prowler aws --output-formats json  # Yes
scoutsuite aws --report-dir .      # Yes (generates JSON)
nmap -oX output.xml                # No (XML only, needs conversion)
```

## Tool Assignment Example: AWS Accounts

**Primary Tool: Prowler**

- Native AWS support (`prowler aws`)
- JSON output built-in
- Fast (5-10 min per account)
- Comprehensive coverage (300+ checks)
- Active maintenance

**Secondary Tool: ScoutSuite**

- Multi-cloud support (AWS, Azure, GCP)
- JSON output via report directory
- Slower (15-20 min per account)
- Complementary checks to Prowler
- Good for multi-cloud environments

**Configuration:**

```yaml
# jmo.yml
profiles:
  balanced:
    tools: [prowler]  # Fast, single tool
  deep:
    tools: [prowler, scoutsuite]  # Comprehensive, both tools

per_tool:
  prowler:
    flags:
      - --severity
      - high,critical
    timeout: 900  # 15 min
  scoutsuite:
    flags:
      - --force
      - --report-name
      - scoutsuite
    timeout: 1800  # 30 min
```
