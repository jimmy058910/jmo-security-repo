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
jmo balanced --repos-dir /tmp/test-repos --results-dir results-repos

# 3. Scan container images
jmo balanced --images-file samples/images.txt --results-dir results-images

# 4. Scan IaC files
jmo balanced --terraform-state samples/iac-files/terraform-aws-ec2.tf --results-dir results-iac
jmo balanced --cloudformation samples/iac-files/cloudformation-s3.yaml --results-dir results-iac-cf
jmo balanced --k8s-manifest samples/iac-files/kubernetes-deployment.yaml --results-dir results-iac-k8s

# 5. Scan web URLs (requires running local apps first)
docker run -d -p 3000:3000 bkimminich/juice-shop
jmo balanced --url http://localhost:3000 --results-dir results-web

# 6. Scan Kubernetes cluster (requires local cluster)
minikube start
kubectl apply -f samples/iac-files/kubernetes-deployment.yaml
jmo balanced --k8s-context minikube --k8s-namespace test-namespace --results-dir results-k8s
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
jmo fast --repo ./dev-only/test-repos/fake-vulnerable-app
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
jmo balanced --image nginx:latest --results-dir results-nginx

# Scan batch from file
jmo balanced --images-file samples/images.txt --results-dir results-images

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
jmo balanced --terraform-state samples/iac-files/terraform-aws-ec2.tf

# CloudFormation
jmo balanced --cloudformation samples/iac-files/cloudformation-s3.yaml

# Kubernetes manifest
jmo balanced --k8s-manifest samples/iac-files/kubernetes-deployment.yaml

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
# Then scan: jmo balanced --url http://localhost:3000

# DVWA
docker run -d -p 80:80 vulnerables/web-dvwa
# Then scan: jmo balanced --url http://localhost
```

**IMPORTANT:**

- Only scan URLs you own or have explicit permission to test
- Unauthorized scanning is illegal and unethical
- Use `--url` for single URLs or `--urls-file` for batch

**Scanning:**

```bash
# Single URL
jmo balanced --url http://testphp.vulnweb.com --results-dir results-web

# Batch from file
jmo balanced --urls-file samples/web-urls.txt --results-dir results-web-batch

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
jmo balanced \
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
jmo balanced \
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
jmo balanced \
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
jmo balanced --repos-dir /tmp/test-repos --profile --results-dir results

# View timings
cat results/summaries/timings.json
```

**Typical Scan Times:**

- **fast** profile: 5-10 minutes (8 tools)
- **slim** profile: 12-18 minutes (14 tools)
- **balanced** profile: 18-25 minutes (18 tools)
- **deep** profile: 40-70 minutes (28 tools)

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
   make regenerate-samples  # Full scan + report + verify
   make samples-scan        # Scan only (5-15 min)
   make samples-report      # Generate reports from existing scan
   make samples-verify      # Verify v1.0.0 output format
   ```

2. **Create Your Own Test Repo:**

   See [docs/USER_GUIDE.md](../docs/USER_GUIDE.md) for creating custom test repositories.

3. **View Results:**

   ```bash
   open results/summaries/dashboard.html
   ```

4. **Compare Profiles:**

   ```bash
   # Fast
   jmo fast --repos-dir /tmp/test-repos --profile --results-dir results-fast

   # Balanced
   jmo balanced --repos-dir /tmp/test-repos --profile --results-dir results-balanced

   # Deep
   jmo full --repos-dir /tmp/test-repos --profile --results-dir results-deep

   # Compare timings
   diff results-fast/summaries/timings.json results-balanced/summaries/timings.json
   ```

## Future Enhancements

### Future Enhancements

The following areas are planned for future development. See [docs/USER_GUIDE.md](../docs/USER_GUIDE.md) for detailed examples of current capabilities.

- **Automation scripts** -- Synthetic test repo generation, automated benchmarking workflows, benchmark comparison tooling
- **Documentation improvements** -- Benchmarking examples in main docs, performance baseline documentation, CI/CD integration examples
- **Testing improvements** -- Integration tests using samples/, regression testing with before/after comparisons
- **Community contributions** -- Language-specific examples, framework-specific IaC, industry-specific compliance test cases
- **Metrics and analytics** -- Scan time tracking per tool/profile, finding count trends, tool reliability metrics

## Contributing Improvements

Have ideas for better benchmarking targets or automation? Please:

1. Open an issue describing the improvement
2. Submit a PR with new sample files or scripts
3. Share your benchmarking results in discussions

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development setup.

## Troubleshooting

**"Tool not found" errors:**

```bash
jmo tools check --profile balanced    # Check which tools are installed
jmo tools install --profile balanced  # Install missing tools
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
