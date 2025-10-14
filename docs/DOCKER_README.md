# JMo Security Suite - Docker Images

[![Docker Pulls](https://img.shields.io/docker/pulls/jimmy058910/jmo-security)](https://hub.docker.com/r/jimmy058910/jmo-security)
[![Image Size](https://img.shields.io/docker/image-size/jimmy058910/jmo-security/latest)](https://hub.docker.com/r/jimmy058910/jmo-security)

**Terminal-first security audit toolkit with 11+ pre-installed security scanners.**

All-in-one Docker images eliminate installation friction and provide consistent, reproducible scans across any environment.

## Quick Start

```bash
# Pull the image
docker pull ghcr.io/jimmy058910/jmo-security:latest

# Scan current directory
docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results --profile balanced

# View results
open results/summaries/dashboard.html
```

## Available Image Variants

| Variant | Size | Tools | Use Case |
|---------|------|-------|----------|
| **latest** (full) | ~500MB | 11+ scanners | Complete scanning with all tools |
| **slim** | ~200MB | 6 core scanners | Fast CI/CD, essential tools only |
| **alpine** | ~150MB | 6 core scanners | Minimal footprint, resource-constrained |

### Full Image Tools

- **Secrets:** gitleaks, trufflehog, noseyparker (via Docker)
- **SAST:** semgrep, bandit
- **SBOM/Vuln:** syft, trivy
- **IaC:** checkov, tfsec
- **Dockerfile:** hadolint
- **Dependencies:** osv-scanner

### Slim/Alpine Image Tools

Core security essentials:
- gitleaks, semgrep, syft, trivy, checkov, hadolint

## Multi-Architecture Support

All images support:
- `linux/amd64` (x86_64)
- `linux/arm64` (ARM64, Apple Silicon)

Docker automatically pulls the correct architecture for your platform.

## Usage Examples

### Basic Scan

```bash
docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results --profile balanced --human-logs
```

### CI Mode with Threshold Gating

```bash
docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest \
  ci --repo /scan --fail-on HIGH --profile
```

Exit codes:
- `0` - No findings above threshold
- `1` - Findings above threshold detected
- `2` - Scan error

### Scan Multiple Repositories

```bash
docker run --rm \
  -v ~/repos:/repos:ro \
  -v $(pwd)/results:/results \
  ghcr.io/jimmy058910/jmo-security:latest \
  scan --repos-dir /repos --results /results --profile deep
```

### Generate Report Only

```bash
docker run --rm -v $(pwd)/results:/results ghcr.io/jimmy058910/jmo-security:latest \
  report /results --profile --human-logs
```

### Interactive Shell

```bash
docker run --rm -it -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest bash
```

## Docker Compose

Save this as `docker-compose.yml`:

```yaml
version: '3.8'
services:
  jmo-scan:
    image: ghcr.io/jimmy058910/jmo-security:latest
    volumes:
      - .:/scan:ro
      - ./results:/scan/results
    command:
      - scan
      - --repo
      - /scan
      - --results
      - /scan/results
      - --profile
      - balanced
      - --human-logs
```

Run:

```bash
docker-compose run --rm jmo-scan
```

## GitHub Actions Integration

### Basic Workflow

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    container:
      image: ghcr.io/jimmy058910/jmo-security:latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run security scan
        run: |
          jmo scan --repo . --results results --profile balanced --human-logs

      - name: Upload results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-results
          path: results/
```

### With Failure Threshold

```yaml
      - name: Run security scan with gating
        run: |
          jmo ci --repo . --fail-on HIGH --profile --human-logs
```

### SARIF Upload to GitHub Security

```yaml
      - name: Generate SARIF report
        run: |
          jmo scan --repo . --results results --profile balanced
          jmo report results --profile

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results/summaries/findings.sarif
```

## GitLab CI Integration

```yaml
security-scan:
  image: ghcr.io/jimmy058910/jmo-security:latest
  stage: test
  script:
    - jmo scan --repo . --results results --profile balanced --human-logs
  artifacts:
    reports:
      sast: results/summaries/findings.sarif
    paths:
      - results/
    expire_in: 1 week
  allow_failure: true
```

## Configuration

### Custom Profile

Mount a custom `jmo.yml` configuration:

```bash
docker run --rm \
  -v $(pwd):/scan \
  -v $(pwd)/custom-jmo.yml:/scan/jmo.yml:ro \
  ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --profile-name custom --results /scan/results
```

### Environment Variables

```bash
docker run --rm \
  -e PYTHONUNBUFFERED=1 \
  -e LOG_LEVEL=DEBUG \
  -v $(pwd):/scan \
  ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results --log-level DEBUG
```

## Performance Tips

### Use Slim Variant for CI

```yaml
container:
  image: ghcr.io/jimmy058910/jmo-security:slim  # 60% smaller
```

### Cache Results Between Runs

```bash
docker run --rm \
  -v $(pwd):/scan \
  -v jmo-cache:/root/.cache \
  ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results
```

### Parallel Scanning

```bash
docker run --rm \
  -v $(pwd):/scan \
  ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results --threads 8
```

## Building Custom Images

### Add Additional Tools

Create a `Dockerfile.custom`:

```dockerfile
FROM ghcr.io/jimmy058910/jmo-security:latest

# Add custom security tool
RUN curl -sSL https://example.com/tool | sh

# Install custom Python package
RUN pip install --no-cache-dir custom-scanner

# Copy custom configuration
COPY custom-jmo.yml /etc/jmo/jmo.yml
```

Build:

```bash
docker build -f Dockerfile.custom -t my-org/jmo-security:custom .
```

### Build from Source

```bash
git clone https://github.com/jimmy058910/jmo-security-repo.git
cd jmo-security-repo

# Full image
docker build -t jmo-security:local .

# Slim variant
docker build -f Dockerfile.slim -t jmo-security:local-slim .

# Alpine variant
docker build -f Dockerfile.alpine -t jmo-security:local-alpine .
```

## Troubleshooting

### Permission Issues

If results directory has permission issues:

```bash
# Run as current user
docker run --rm --user $(id -u):$(id -g) \
  -v $(pwd):/scan \
  ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results
```

### Tool Not Found

Check which tools are available:

```bash
docker run --rm ghcr.io/jimmy058910/jmo-security:latest bash -c \
  "gitleaks version && semgrep --version && trivy --version"
```

### Large Repositories

Increase timeout for large repos:

```bash
docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results --timeout 1800 --profile deep
```

## Security Considerations

### Image Provenance

All images are built with:
- SBOM (Software Bill of Materials)
- Provenance attestations
- Signature verification available

Verify image signature:

```bash
cosign verify ghcr.io/jimmy058910/jmo-security:latest \
  --certificate-identity-regexp="https://github.com/jimmy058910/jmo-security-repo/*" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

### Vulnerability Scanning

Images are scanned on every build with Trivy. View latest scan results in [GitHub Security](https://github.com/jimmy058910/jmo-security-repo/security/code-scanning).

### Running as Non-Root

Images support running as non-root user:

```bash
docker run --rm --user 1000:1000 \
  -v $(pwd):/scan \
  ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan --results /scan/results
```

## Registry Locations

- **GitHub Container Registry (recommended):** `ghcr.io/jimmy058910/jmo-security`
- **Docker Hub:** `docker.io/jimmy058910/jmo-security` (coming soon)

## Tags

- `latest` - Latest stable full image (main branch)
- `slim` - Latest stable slim image
- `alpine` - Latest stable Alpine image
- `v0.3.2` - Specific version (semantic versioning)
- `v0.3` - Major.minor (tracks latest patch)
- `v0` - Major version (tracks latest minor/patch)
- `main-abc1234` - Git commit SHA from main branch

## Support

- Documentation: <https://jmotools.com>
- Issues: <https://github.com/jimmy058910/jmo-security-repo/issues>
- Discussions: <https://github.com/jimmy058910/jmo-security-repo/discussions>

## License

MIT License - see [LICENSE](https://github.com/jimmy058910/jmo-security-repo/blob/main/LICENSE)
