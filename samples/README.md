# JMo Security - Sample Targets for Benchmarking

This directory contains sample targets for testing and benchmarking JMo Security across all 6 supported target types without exposing real applications or private data.

## Overview

JMo Security supports 6 target types. This directory provides safe, ethical test targets for each type:

| Target Type | Sample File/Directory | Description |
|-------------|----------------------|-------------|
| **Repositories** | [repos.txt](repos.txt) | Public vulnerable repos + local synthetic repos |
| **Container Images** | [images.txt](images.txt) | Docker Hub public images (base + vulnerable) |
| **IaC Files** | [iac-files/](iac-files/) | Terraform, CloudFormation, K8s manifests with issues |
| **Web URLs** | [web-urls.txt](web-urls.txt) | Public test sites + local vulnerable apps |
| **GitLab Repos** | N/A (skip) | Use repos.txt with `--gitlab-repo` if you have access |
| **Kubernetes** | [k8s/README.md](k8s/README.md) | Local minikube/kind cluster scanning |

## Benchmarking Strategy

### Goals

1. **No public app exposure** - All tests use public/local resources
2. **Comprehensive coverage** - Test all 6 target types and all 12 tools
3. **Reproducible** - Anyone can run the same benchmarks
4. **Ethical** - Only scan resources we own or have permission to test

### Quick Start

```bash
# 1. Clone public vulnerable repos
mkdir -p /tmp/test-repos
cd /tmp/test-repos
git clone https://github.com/OWASP/NodeGoat.git
git clone https://github.com/OWASP/juice-shop.git

# 2. Scan repositories
jmotools balanced --repos-dir /tmp/test-repos --results-dir results-repos

# 3. Scan container images
jmotools balanced --images-file samples/images.txt --results-dir results-images

# 4. Scan IaC files
jmotools balanced --terraform-state samples/iac-files/terraform-aws-ec2.tf --results-dir results-iac
jmotools balanced --cloudformation samples/iac-files/cloudformation-s3.yaml --results-dir results-iac-cf
jmotools balanced --k8s-manifest samples/iac-files/kubernetes-deployment.yaml --results-dir results-iac-k8s

# 5. Scan web URLs (requires running local apps first)
docker run -d -p 3000:3000 bkimminich/juice-shop
jmotools balanced --url http://localhost:3000 --results-dir results-web

# 6. Scan Kubernetes cluster (requires local cluster)
minikube start
kubectl apply -f samples/iac-files/kubernetes-deployment.yaml
jmotools balanced --k8s-context minikube --k8s-namespace test-namespace --results-dir results-k8s
```

## Target Type Details

### 1. Repositories (repos.txt)

**Public Vulnerable Repos:**

- OWASP NodeGoat (Node.js vulnerabilities)
- OWASP Juice Shop (modern web app vulnerabilities)
- DVWA (PHP vulnerabilities)
- WebGoat (Java vulnerabilities)
- RailsGoat (Ruby on Rails vulnerabilities)

**Synthetic Test Repos (create locally):**

```bash
# Create synthetic repos with known issues
mkdir -p dev-only/test-repos/fake-vulnerable-app
cd dev-only/test-repos/fake-vulnerable-app
git init

# Add files with secrets, SAST issues, etc.
echo 'API_KEY="sk-1234567890abcdef"' > .env
echo 'eval(user_input)' > app.py
git add . && git commit -m "Initial commit"

# Scan
jmotools fast --repo ./dev-only/test-repos/fake-vulnerable-app
```

**Your Own Repos:**

- Use `dev-only/ai-repos-20251013-213317.tsv` for your private test repos
- Never scan repos you don't own without permission

### 2. Container Images (images.txt)

**Base Images (Public Docker Hub):**

- `nginx:latest`, `nginx:1.25-alpine` - Popular web server
- `node:14`, `node:18-alpine` - Node.js runtime
- `python:3.9`, `python:3.11-slim` - Python runtime
- `alpine:latest`, `ubuntu:22.04`, `debian:bullseye-slim` - Base OS images

**Known Vulnerable Images (for testing ONLY):**

- `vulnerables/web-dvwa:latest` - Damn Vulnerable Web Application
- `bkimminich/juice-shop:latest` - OWASP Juice Shop
- `webgoat/webgoat-8.0:latest` - WebGoat

**Scanning:**

```bash
# Scan single image
jmotools balanced --image nginx:latest --results-dir results-nginx

# Scan batch from file
jmotools balanced --images-file samples/images.txt --results-dir results-images

# Tools used: trivy (vulnerabilities), syft (SBOM)
```

### 3. IaC Files (iac-files/)

**Files Included:**

- [terraform-aws-ec2.tf](iac-files/terraform-aws-ec2.tf) - Terraform with AWS misconfigurations
- [cloudformation-s3.yaml](iac-files/cloudformation-s3.yaml) - CloudFormation with S3/RDS issues
- [kubernetes-deployment.yaml](iac-files/kubernetes-deployment.yaml) - K8s manifests with security issues

**Issues Included (intentional):**

- Overly permissive security groups (0.0.0.0/0)
- Unencrypted storage (EBS, S3, RDS)
- Hardcoded secrets in user_data/env vars
- Publicly accessible resources
- Missing resource limits
- Privileged containers
- Wildcard IAM/RBAC permissions

**Scanning:**

```bash
# Terraform
jmotools balanced --terraform-state samples/iac-files/terraform-aws-ec2.tf

# CloudFormation
jmotools balanced --cloudformation samples/iac-files/cloudformation-s3.yaml

# Kubernetes manifest
jmotools balanced --k8s-manifest samples/iac-files/kubernetes-deployment.yaml

# Tools used: checkov (policy-as-code), trivy (misconfigurations)
```

### 4. Web URLs (web-urls.txt)

**Public Test Sites:**

- `http://testhtml5.vulnweb.com` - HTML5 vulnerabilities
- `http://testphp.vulnweb.com` - PHP vulnerabilities
- `http://testasp.vulnweb.com` - ASP.NET vulnerabilities

**Local Vulnerable Apps (requires Docker):**

```bash
# OWASP Juice Shop
docker run -d -p 3000:3000 bkimminich/juice-shop
# Then scan: jmotools balanced --url http://localhost:3000

# DVWA
docker run -d -p 80:80 vulnerables/web-dvwa
# Then scan: jmotools balanced --url http://localhost
```

**IMPORTANT:**

- Only scan URLs you own or have explicit permission to test
- Unauthorized scanning is illegal and unethical
- Use `--url` for single URLs or `--urls-file` for batch

**Scanning:**

```bash
# Single URL
jmotools balanced --url http://testphp.vulnweb.com --results-dir results-web

# Batch from file
jmotools balanced --urls-file samples/web-urls.txt --results-dir results-web-batch

# Tools used: OWASP ZAP (DAST), Nuclei (API security)
```

### 5. GitLab Repos (N/A - Skip or Use Your Own)

**Why Skip:**

- Requires GitLab access token
- Similar to GitHub repos (use repos.txt instead)
- Not needed for benchmarking core functionality

**If You Want to Test:**

```bash
# Use your own GitLab repos
jmotools balanced \
  --gitlab-repo mygroup/myrepo \
  --gitlab-token YOUR_TOKEN \
  --gitlab-url https://gitlab.com

# Tools used: Full repo scanner (10/12 tools)
```

### 6. Kubernetes Clusters (k8s/)

**Local Cluster Options:**

1. **Minikube** (easiest, most common)
2. **Kind** (Kubernetes in Docker)
3. **Docker Desktop** (built-in K8s)

**See [k8s/README.md](k8s/README.md) for complete setup and scanning guide.**

**Quick Example:**

```bash
# Start minikube
minikube start

# Deploy test workload with issues
kubectl apply -f samples/iac-files/kubernetes-deployment.yaml

# Scan cluster
jmotools balanced \
  --k8s-context minikube \
  --k8s-namespace test-namespace \
  --results-dir results-k8s

# Cleanup
kubectl delete namespace test-namespace
minikube stop
```

## Multi-Target Benchmarking

Scan multiple target types in one command:

```bash
# Comprehensive scan across all types
jmotools balanced \
  --repos-dir /tmp/test-repos \
  --images-file samples/images.txt \
  --terraform-state samples/iac-files/terraform-aws-ec2.tf \
  --url http://localhost:3000 \
  --k8s-context minikube \
  --k8s-namespace test-namespace \
  --results-dir results-comprehensive

# Results aggregated in results-comprehensive/summaries/
open results-comprehensive/summaries/dashboard.html
```

## Performance Benchmarking

Use `--profile` flag to capture timing data:

```bash
jmotools balanced --repos-dir /tmp/test-repos --profile --results-dir results

# View timings
cat results/summaries/timings.json
```

**Typical Scan Times:**

- **fast** profile: 5-8 minutes (3 tools)
- **balanced** profile: 15-20 minutes (8 tools)
- **deep** profile: 30-60 minutes (12 tools)

## Ethical Guidelines

**DO:**

- Scan public vulnerable repos (OWASP, etc.)
- Scan public Docker images
- Scan local clusters/apps you own
- Use public test sites (vulnweb.com)
- Create synthetic test repos

**DON'T:**

- Scan production apps without authorization
- Scan third-party websites without permission
- Share scan results of third-party apps publicly
- Use vulnerabilities discovered for malicious purposes
- Run DAST scans on sites you don't own

## Coverage Matrix

| Target Type | Tools Used | Expected Findings |
|-------------|------------|-------------------|
| Repositories | trufflehog, semgrep, trivy, bandit, syft, checkov, hadolint, noseyparker, falco, afl++ | Secrets, SAST issues, dependencies |
| Container Images | trivy, syft | CVEs, outdated packages, SBOM |
| IaC Files | checkov, trivy | Misconfigurations, hardcoded secrets |
| Web URLs | zap, nuclei | XSS, SQLi, CSRF, API issues |
| GitLab Repos | Full repo scanner | Same as Repositories |
| Kubernetes | trivy | Image vulnerabilities, RBAC issues, network policies |

## Next Steps

1. **Run Quick Benchmark:**

   ```bash
   make test-samples  # TODO: Create this Makefile target
   ```

2. **Create Your Own Test Repo:**

   ```bash
   scripts/dev/create_test_repos.sh  # TODO: Create this script
   ```

3. **View Results:**

   ```bash
   open results/summaries/dashboard.html
   ```

4. **Compare Profiles:**

   ```bash
   # Fast
   jmotools fast --repos-dir /tmp/test-repos --profile --results-dir results-fast

   # Balanced
   jmotools balanced --repos-dir /tmp/test-repos --profile --results-dir results-balanced

   # Deep
   jmotools full --repos-dir /tmp/test-repos --profile --results-dir results-deep

   # Compare timings
   diff results-fast/summaries/timings.json results-balanced/summaries/timings.json
   ```

## Future Enhancements

### Automation Scripts (TODO)

**1. Synthetic Test Repo Generator (`scripts/dev/create_test_repos.sh`)**

Create local test repos with known vulnerabilities for benchmarking:

```bash
# Proposed usage:
scripts/dev/create_test_repos.sh --output dev-only/test-repos

# Creates:
# - fake-vulnerable-app/ (secrets, SAST issues, vulnerable deps)
# - python-secrets-demo/ (various secret patterns)
# - dockerfile-issues-demo/ (Dockerfile best practice violations)
# - iac-misconfig-demo/ (Terraform/CloudFormation issues)
```

**Features to include:**

- Hardcoded secrets (API keys, passwords, tokens)
- SAST issues (SQL injection, XSS, command injection)
- Vulnerable dependencies (outdated packages with CVEs)
- Dockerfile anti-patterns (running as root, no HEALTHCHECK)
- IaC misconfigurations (overly permissive security groups)
- Git history pollution (secrets in old commits)

**2. Makefile Target (`make test-samples`)**

Automated benchmarking workflow:

```makefile
# Proposed Makefile addition:
.PHONY: test-samples
test-samples:
 @echo "Running comprehensive benchmarking across all 6 target types..."
 # 1. Clone public repos
 mkdir -p /tmp/jmo-benchmark-repos
 cd /tmp/jmo-benchmark-repos && \
  git clone --depth 1 https://github.com/OWASP/NodeGoat.git && \
  git clone --depth 1 https://github.com/OWASP/juice-shop.git

 # 2. Scan repos
 jmotools balanced --repos-dir /tmp/jmo-benchmark-repos --results-dir results/benchmark-repos

 # 3. Scan images
 jmotools balanced --images-file samples/images.txt --results-dir results/benchmark-images

 # 4. Scan IaC
 jmotools balanced --terraform-state samples/iac-files/terraform-aws-ec2.tf --results-dir results/benchmark-iac

 # 5. Generate report
 @echo "Benchmark complete! View results at results/benchmark-*/summaries/dashboard.html"

.PHONY: test-samples-full
test-samples-full: test-samples
 # Additional: Start local apps, scan web URLs, K8s cluster
 docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
 sleep 10
 jmotools balanced --url http://localhost:3000 --results-dir results/benchmark-web
 docker stop juice-shop && docker rm juice-shop
```

**3. Benchmark Comparison Script (`scripts/dev/compare_benchmarks.py`)**

Compare performance across profiles and versions:

```python
# Proposed usage:
python3 scripts/dev/compare_benchmarks.py \
  --baseline results/benchmark-v0.6.0/ \
  --current results/benchmark-v0.7.0/ \
  --output benchmark-comparison.md

# Generates markdown report with:
# - Finding count deltas (new/fixed/changed)
# - Scan time comparisons (faster/slower)
# - Tool reliability metrics (timeouts, errors)
# - Coverage improvements
```

**4. GitLab Testing Support (Optional)**

If GitLab benchmarking is needed:

```bash
# Create test GitLab project
scripts/dev/setup_gitlab_test_repo.sh

# Proposed features:
# - Create public GitLab repo with known issues
# - Or: Use GitLab.com OWASP repos (if they exist)
# - Generate test token with read-only access
# - Document in samples/gitlab/README.md
```

### Documentation Improvements (TODO)

**1. Add Benchmarking Examples to Main Docs**

Update these files to reference samples/:

- `README.md` - Add "Benchmarking" section
- `QUICKSTART.md` - Reference samples/repos.txt
- `docs/USER_GUIDE.md` - Add "Testing and Benchmarking" chapter
- `SAMPLE_OUTPUTS.md` - Use samples/ targets for examples

**2. Performance Baseline Documentation**

Create `docs/PERFORMANCE_BASELINES.md`:

- Expected scan times per profile (fast/balanced/deep)
- Finding counts for known test repos
- Resource usage (CPU, memory, disk)
- Regression testing thresholds

**3. CI/CD Integration Examples**

Add `samples/ci-examples/`:

- `github-actions-benchmark.yml` - Automated benchmarking workflow
- `gitlab-ci-benchmark.yml` - GitLab CI equivalent
- `jenkins-benchmark.groovy` - Jenkins pipeline
- `compare-benchmarks.sh` - Script to detect regressions

### Testing Improvements (TODO)

**1. Integration Tests Using samples/**

```python
# tests/e2e/test_samples.py
def test_scan_sample_repos():
    """Scan samples/repos.txt and verify expected findings."""
    result = subprocess.run([
        "jmotools", "fast",
        "--repos-dir", "/tmp/test-repos",
        "--results-dir", "/tmp/results"
    ])
    assert result.returncode == 0
    # Verify findings.json exists and has expected structure
    findings = json.load(open("/tmp/results/summaries/findings.json"))
    assert len(findings) > 0
    assert any(f["tool"] == "trufflehog" for f in findings)
```

**2. Regression Testing**

```bash
# tests/e2e/regression_test.sh
# Run benchmarks before/after code changes
# Compare results and fail if:
# - Scan time increases >20%
# - New false positives introduced
# - Known findings no longer detected
```

### Community Contributions (TODO)

**Ideas for community-submitted samples:**

1. **Language-Specific Examples**
   - `samples/repos-python.txt` - Python-specific test repos
   - `samples/repos-nodejs.txt` - Node.js test repos
   - `samples/repos-java.txt` - Java test repos

2. **Framework-Specific Examples**
   - `samples/iac-files/aws/` - AWS-specific IaC
   - `samples/iac-files/azure/` - Azure-specific IaC
   - `samples/iac-files/gcp/` - GCP-specific IaC

3. **Industry-Specific Examples**
   - `samples/compliance/` - PCI DSS, HIPAA, SOC2 test cases
   - `samples/fintech/` - Financial services security patterns

### Metrics and Analytics (TODO)

**Track benchmarking data over time:**

```bash
# Store benchmark results
mkdir -p benchmarks/v0.6.2/
cp -r results/summaries/ benchmarks/v0.6.2/

# Generate trend analysis
scripts/dev/analyze_benchmark_trends.py \
  --benchmarks-dir benchmarks/ \
  --output docs/BENCHMARK_TRENDS.md
```

**Proposed metrics:**

- Scan time per tool per profile
- Finding counts by severity
- False positive rate (if ground truth available)
- Tool reliability (success/timeout/error rates)
- Resource consumption (CPU, memory, network)

## Contributing Improvements

Have ideas for better benchmarking targets or automation? Please:

1. Open an issue describing the improvement
2. Submit a PR with new sample files or scripts
3. Share your benchmarking results in discussions

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development setup.

## Troubleshooting

**"Tool not found" errors:**

```bash
make verify-env  # Check which tools are installed
make tools       # Install missing tools
```

**Docker image pull failures:**

```bash
docker pull nginx:latest  # Test connectivity
docker login              # Authenticate if private registry
```

**K8s cluster not reachable:**

```bash
kubectl cluster-info      # Verify cluster running
kubectl config get-contexts  # List available contexts
```

**ZAP/Nuclei timeouts:**

```bash
# Increase timeout in jmo.yml
per_tool:
  zap:
    timeout: 1200  # 20 minutes
  nuclei:
    timeout: 900   # 15 minutes
```

## Additional Resources

- Main README: [../README.md](../README.md)
- User Guide: [../docs/USER_GUIDE.md](../docs/USER_GUIDE.md)
- Quick Start: [../QUICKSTART.md](../QUICKSTART.md)
- Sample Outputs: [../SAMPLE_OUTPUTS.md](../SAMPLE_OUTPUTS.md)
