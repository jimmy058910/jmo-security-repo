# SLSA Attestation Workflows

Complete examples for SLSA attestation in different deployment scenarios.

## Table of Contents

- [GitHub Actions Workflows](#github-actions-workflows)
- [GitLab CI Workflows](#gitlab-ci-workflows)
- [Docker Workflows](#docker-workflows)
- [Multi-Stage Pipelines](#multi-stage-pipelines)
- [Compliance Scenarios](#compliance-scenarios)
- [Verification Workflows](#verification-workflows)

## GitHub Actions Workflows

### Basic Scan with Attestation

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * 1'  # Weekly on Monday 2 AM

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write  # CRITICAL for Sigstore OIDC

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for attribution

      - name: Install JMo Security
        run: |
          pip install --user jmo-security
          echo "$HOME/.local/bin" >> $GITHUB_PATH

      - name: Run security scan
        run: |
          jmo scan --repo . --profile balanced --attest --sign

      - name: Upload attestations
        uses: actions/upload-artifact@v4
        with:
          name: security-attestations-${{ github.sha }}
          path: |
            results/summaries/findings.json
            results/summaries/findings.json.att.json
            results/summaries/findings.json.att.sigstore.json
          retention-days: 90

      - name: Upload scan results
        uses: actions/upload-artifact@v4
        with:
          name: security-results-${{ github.sha }}
          path: results/
          retention-days: 30
```

### Multi-Target Scan with Attestation

```yaml
# .github/workflows/comprehensive-security.yml
name: Comprehensive Security Scan

on:
  push:
    branches: [main]
  workflow_dispatch:

jobs:
  comprehensive-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
      packages: read  # For pulling private images

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Log in to GitHub Container Registry
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Install JMo Security
        run: |
          pip install --user jmo-security
          echo "$HOME/.local/bin" >> $GITHUB_PATH

      - name: Scan repository + images + IaC
        run: |
          jmo scan \
            --repo . \
            --image ghcr.io/${{ github.repository }}/app:latest \
            --terraform-state infrastructure/terraform.tfstate \
            --url https://staging.example.com \
            --profile balanced \
            --attest \
            --sign

      - name: Verify attestations
        run: |
          jmo verify \
            results/summaries/findings.json \
            results/summaries/findings.json.att.json \
            --signature results/summaries/findings.json.att.sigstore.json \
            --check-rekor

      - name: Store attestations long-term
        uses: actions/upload-artifact@v4
        with:
          name: attestations-${{ github.sha }}
          path: |
            results/summaries/*.att.json
            results/summaries/*.sigstore.json
          retention-days: 180  # 6 months for compliance
```

### PR Comment with Attestation Verification

```yaml
# .github/workflows/pr-security-check.yml
name: PR Security Check

on:
  pull_request:
    branches: [main]

jobs:
  security-check:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
      pull-requests: write  # For PR comments

    steps:
      - name: Checkout PR branch
        uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      - name: Install JMo Security
        run: |
          pip install --user jmo-security
          echo "$HOME/.local/bin" >> $GITHUB_PATH

      - name: Scan PR branch
        run: |
          jmo scan --repo . --profile fast --attest --sign

      - name: Verify attestation
        id: verify
        run: |
          jmo verify \
            results/summaries/findings.json \
            results/summaries/findings.json.att.json \
            --signature results/summaries/findings.json.att.sigstore.json \
            --check-rekor \
            --enable-tamper-detection | tee verification-result.txt

      - name: Post verification status to PR
        uses: actions/github-script@v7
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          script: |
            const fs = require('fs');
            const verification = fs.readFileSync('verification-result.txt', 'utf8');

            const body = `## 🔒 Security Scan Attestation

            **Status:** ✅ Verified

            \`\`\`
            ${verification}
            \`\`\`

            **Rekor Entry:** https://rekor.sigstore.dev/api/v1/log/entries/...
            **Builder:** \`https://github.com/${{ github.repository }}\`
            **Commit:** \`${{ github.event.pull_request.head.sha }}\`

            📦 Attestation artifacts stored for 90 days.
            `;

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: body
            });
```

## GitLab CI Workflows

### Basic Scan with Attestation

```yaml
# .gitlab-ci.yml
security-scan:
  stage: test
  image: python:3.11-slim
  before_script:
    - pip install jmo-security
  script:
    - jmo scan --repo . --profile balanced --attest --sign
  artifacts:
    paths:
      - results/summaries/findings.json
      - results/summaries/findings.json.att.json
      - results/summaries/findings.json.att.sigstore.json
    reports:
      # SARIF report for GitLab Security Dashboard
      sast: results/summaries/findings.sarif
    expire_in: 90 days
  only:
    - main
    - merge_requests
```

### Multi-Stage with Verification

```yaml
# .gitlab-ci.yml
stages:
  - scan
  - verify
  - deploy

security-scan:
  stage: scan
  image: python:3.11-slim
  before_script:
    - pip install jmo-security
  script:
    - |
      jmo scan \
        --repo . \
        --image $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA \
        --profile balanced \
        --attest \
        --sign
  artifacts:
    paths:
      - results/
    expire_in: 30 days

attestation-verify:
  stage: verify
  image: python:3.11-slim
  dependencies:
    - security-scan
  before_script:
    - pip install jmo-security
  script:
    - |
      jmo verify \
        results/summaries/findings.json \
        results/summaries/findings.json.att.json \
        --signature results/summaries/findings.json.att.sigstore.json \
        --check-rekor \
        --enable-tamper-detection
  artifacts:
    reports:
      # Store verification result
      junit: verification-report.xml
  only:
    - main

deploy:
  stage: deploy
  dependencies:
    - attestation-verify
  script:
    - echo "Deploying with verified attestation..."
    - ./deploy.sh
  only:
    - main
  when: on_success
```

## Docker Workflows

### Standalone Docker Scan

```bash
#!/bin/bash
# scan-with-attestation.sh

docker run --rm \
  -v $PWD:/scan \
  -v $PWD/results:/results \
  jmo-security:latest \
  scan --repo /scan --profile balanced --attest

echo "Attestation generated: results/summaries/findings.json.att.json"

# Verify locally
docker run --rm \
  -v $PWD/results:/results \
  jmo-security:latest \
  verify \
    /results/summaries/findings.json \
    /results/summaries/findings.json.att.json
```

### Docker with Sigstore in CI

```bash
#!/bin/bash
# github-actions-docker-scan.sh

# GitHub Actions provides OIDC token via environment
docker run --rm \
  -v $PWD:/scan \
  -v $PWD/results:/results \
  -e ACTIONS_ID_TOKEN_REQUEST_URL \
  -e ACTIONS_ID_TOKEN_REQUEST_TOKEN \
  -e GITHUB_REPOSITORY \
  jmo-security:latest \
  scan --repo /scan --profile balanced --attest --sign

echo "Signed attestation: results/summaries/findings.json.att.sigstore.json"
```

### Docker Compose with Attestation

```yaml
# docker-compose.security.yml
version: '3.8'

services:
  jmo-scan:
    image: jmo-security:latest
    command: scan --repo /scan --profile balanced --attest
    volumes:
      - ./:/scan
      - ./results:/results
    environment:
      - JMO_ATTEST_ENABLED=true
```

## Multi-Stage Pipelines

### Nightly Deep Scan with Historical Comparison

```yaml
# .github/workflows/nightly-deep-scan.yml
name: Nightly Deep Security Scan

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:

jobs:
  deep-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Install JMo Security
        run: |
          pip install --user jmo-security
          echo "$HOME/.local/bin" >> $GITHUB_PATH

      - name: Download previous attestations
        uses: actions/download-artifact@v4
        with:
          name: historical-attestations
          path: previous-attestations/
        continue-on-error: true  # First run may not have history

      - name: Run deep scan
        run: |
          jmo scan --repo . --profile deep --attest --sign

      - name: Verify with historical comparison
        run: |
          jmo verify \
            results/summaries/findings.json \
            results/summaries/findings.json.att.json \
            --signature results/summaries/findings.json.att.sigstore.json \
            --historical-attestations previous-attestations/ \
            --enable-tamper-detection

      - name: Store attestation history
        run: |
          mkdir -p attestation-history
          cp results/summaries/findings.json.att.json \
             attestation-history/$(date +%Y-%m-%d).att.json

      - name: Upload historical attestations
        uses: actions/upload-artifact@v4
        with:
          name: historical-attestations
          path: attestation-history/
          retention-days: 365

      - name: Send notification on tamper detection
        if: failure()
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: '🚨 CRITICAL: Tamper detected in security scan',
              body: 'Historical attestation verification failed. Review logs immediately.',
              labels: ['security', 'critical']
            })
```

### Release Pipeline with Attestation

```yaml
# .github/workflows/release.yml
name: Release with Attestation

on:
  push:
    tags:
      - 'v*'

jobs:
  security-audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write

    steps:
      - name: Checkout tag
        uses: actions/checkout@v4
        with:
          ref: ${{ github.ref }}

      - name: Install JMo Security
        run: |
          pip install --user jmo-security
          echo "$HOME/.local/bin" >> $GITHUB_PATH

      - name: Run release security audit
        run: |
          jmo scan \
            --repo . \
            --image ghcr.io/${{ github.repository }}:${{ github.ref_name }} \
            --profile deep \
            --attest \
            --sign

      - name: Verify attestation
        run: |
          jmo verify \
            results/summaries/findings.json \
            results/summaries/findings.json.att.json \
            --signature results/summaries/findings.json.att.sigstore.json \
            --check-rekor \
            --enable-tamper-detection

      - name: Create release with attestation
        uses: softprops/action-gh-release@v2
        with:
          files: |
            results/summaries/findings.json
            results/summaries/findings.json.att.json
            results/summaries/findings.json.att.sigstore.json
          body: |
            ## Security Attestation

            This release includes SLSA Level 2 attestation:

            - **Provenance:** [findings.json.att.json](./findings.json.att.json)
            - **Signature Bundle:** [findings.json.att.sigstore.json](./findings.json.att.sigstore.json)
            - **Rekor Entry:** https://rekor.sigstore.dev/api/v1/log/entries/...

            Verify with:
            ```bash
            jmo verify findings.json findings.json.att.json \
              --signature findings.json.att.sigstore.json \
              --check-rekor
            ```
```

## Compliance Scenarios

### SOC 2 Audit Trail

```bash
#!/bin/bash
# quarterly-compliance-audit.sh

# Generate attestations for Q4 2025
for repo in project-a project-b project-c; do
  echo "Scanning $repo..."

  jmo scan \
    --repo ~/repos/$repo \
    --profile deep \
    --attest \
    --sign \
    --results-dir compliance-scans/$repo

  # Verify immediately
  jmo verify \
    compliance-scans/$repo/summaries/findings.json \
    compliance-scans/$repo/summaries/findings.json.att.json \
    --signature compliance-scans/$repo/summaries/findings.json.att.sigstore.json \
    --check-rekor
done

# Package for auditors
tar czf attestations-q4-2025.tar.gz \
  compliance-scans/*/summaries/findings.json.att.json \
  compliance-scans/*/summaries/findings.json.att.sigstore.json

echo "Compliance package: attestations-q4-2025.tar.gz"
echo "Auditors can verify independently with jmo verify"
```

### PCI DSS Supply Chain Verification

```yaml
# .github/workflows/pci-compliance.yml
name: PCI DSS Supply Chain Compliance

on:
  schedule:
    - cron: '0 0 1 * *'  # Monthly on 1st
  workflow_dispatch:

jobs:
  pci-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Install JMo Security
        run: |
          pip install --user jmo-security
          echo "$HOME/.local/bin" >> $GITHUB_PATH

      - name: Run PCI-focused scan
        run: |
          jmo scan \
            --repo . \
            --image ${{ secrets.PAYMENT_APP_IMAGE }} \
            --url https://payment-api.example.com \
            --profile deep \
            --attest \
            --sign

      - name: Verify attestation
        run: |
          jmo verify \
            results/summaries/findings.json \
            results/summaries/findings.json.att.json \
            --signature results/summaries/findings.json.att.sigstore.json \
            --check-rekor \
            --enable-tamper-detection

      - name: Extract PCI DSS report
        run: |
          # PCI_DSS_COMPLIANCE.md generated by jmo report
          cat results/summaries/PCI_DSS_COMPLIANCE.md > pci-compliance-report.md

      - name: Store compliance evidence
        uses: actions/upload-artifact@v4
        with:
          name: pci-compliance-${{ github.run_number }}
          path: |
            results/summaries/findings.json
            results/summaries/findings.json.att.json
            results/summaries/findings.json.att.sigstore.json
            pci-compliance-report.md
          retention-days: 2555  # 7 years per PCI DSS requirement
```

## Verification Workflows

### Independent Third-Party Verification

```bash
#!/bin/bash
# verify-vendor-scan.sh

# Download attestations from vendor
curl -LO https://vendor.example.com/scans/findings.json
curl -LO https://vendor.example.com/scans/findings.json.att.json
curl -LO https://vendor.example.com/scans/findings.json.att.sigstore.json

# Verify attestation integrity
jmo verify \
  findings.json \
  findings.json.att.json \
  --signature findings.json.att.sigstore.json \
  --check-rekor \
  --enable-tamper-detection

# Check Rekor transparency log independently
REKOR_ENTRY=$(jq -r '.rekorEntry' findings.json.att.sigstore.json)
curl https://rekor.sigstore.dev/api/v1/log/entries/$REKOR_ENTRY

echo "✅ Vendor attestation verified independently"
```

### Automated Regression Detection

```yaml
# .github/workflows/regression-detection.yml
name: Security Regression Detection

on:
  pull_request:
    branches: [main]

jobs:
  regression-check:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
      pull-requests: write

    steps:
      - name: Checkout PR branch
        uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      - name: Download main branch attestation
        uses: dawidd6/action-download-artifact@v3
        with:
          workflow: security-scan.yml
          branch: main
          name: main-branch-attestation
          path: baseline-attestations/

      - name: Install JMo Security
        run: |
          pip install --user jmo-security
          echo "$HOME/.local/bin" >> $GITHUB_PATH

      - name: Scan PR branch
        run: |
          jmo scan --repo . --profile balanced --attest --sign

      - name: Detect regressions via attestation comparison
        id: regression
        run: |
          jmo verify \
            results/summaries/findings.json \
            results/summaries/findings.json.att.json \
            --historical-attestations baseline-attestations/ \
            --enable-tamper-detection | tee regression-report.txt

      - name: Check for tool rollback
        run: |
          # Extract tool versions from current attestation
          CURRENT_TRIVY=$(jq -r '.predicate.buildDefinition.externalParameters.tools[] | select(contains("trivy"))' results/summaries/findings.json.att.json)

          # Extract tool versions from baseline
          BASELINE_TRIVY=$(jq -r '.predicate.buildDefinition.externalParameters.tools[] | select(contains("trivy"))' baseline-attestations/findings.json.att.json)

          echo "Current: $CURRENT_TRIVY"
          echo "Baseline: $BASELINE_TRIVY"

          # Compare versions (simplified - use semver in production)
          if [[ "$CURRENT_TRIVY" < "$BASELINE_TRIVY" ]]; then
            echo "::error::Tool rollback detected: trivy downgraded"
            exit 1
          fi

      - name: Post regression analysis to PR
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('regression-report.txt', 'utf8');

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## 🔍 Security Regression Analysis\n\n\`\`\`\n${report}\n\`\`\`\n\n✅ No tool rollback detected.`
            });
```

## Additional Resources

- **SLSA Specification:** <https://slsa.dev>
- **Sigstore Documentation:** <https://docs.sigstore.dev>
- **Rekor Transparency Log:** <https://rekor.sigstore.dev>
- **in-toto Attestation Framework:** <https://in-toto.io>
- **JMo Security USER_GUIDE.md:** [SLSA Attestation Section](../USER_GUIDE.md#slsa-attestation-v100)
