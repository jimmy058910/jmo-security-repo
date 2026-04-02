# SLSA Attestation Guide

**Supply chain attestation using SLSA provenance and Sigstore keyless signing. Proves who scanned what, when, and with which tools - making scan results tamper-evident and verifiable.**

---

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [CLI Commands](#cli-commands)
  - [jmo attest](#jmo-attest)
  - [jmo verify](#jmo-verify)
- [Configuration](#configuration)
- [Provenance Format](#provenance-format)
- [Tamper Detection](#tamper-detection)
- [Keyless Signing (Sigstore)](#keyless-signing-sigstore)
- [Docker Integration](#docker-integration)
- [Wizard Integration](#wizard-integration)
- [Use Cases](#use-cases)
- [Performance](#performance)
- [Troubleshooting](#troubleshooting)
- [Related Documentation](#related-documentation)

---

## Overview

**Target compliance:** SLSA Level 2 (signed provenance with tamper detection)

### Why SLSA Attestation Matters

| Benefit | Description |
|---------|-------------|
| **Tamper Evidence** | Detect if scan results were modified after generation |
| **Audit Trail** | Full provenance (commit, tools, profile, CI environment) |
| **Compliance** | Meet SOC 2, ISO 27001, PCI DSS supply chain requirements |
| **Keyless Signing** | Sigstore OIDC - no key management, uses GitHub/GitLab identity |
| **Public Transparency** | Rekor transparency log provides independent verification |

---

## Quick Start

### Generate Attestation Manually

```bash
# Scan and attest (creates findings.json.att.json)
jmo scan --repo ./myapp --profile balanced
jmo attest results/summaries/findings.json

# Sign with Sigstore (requires GitHub Actions or GitLab CI)
jmo attest results/summaries/findings.json --sign

# Verify attestation
jmo verify results/summaries/findings.json results/summaries/findings.json.att.json
```

### Auto-Attestation in CI (Recommended)

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write  # Required for Sigstore OIDC
    steps:
      - uses: actions/checkout@v4

      - name: Run JMo scan with auto-attestation
        run: |
          jmo scan --repo . --profile balanced --attest --sign

      - name: Upload attestations
        uses: actions/upload-artifact@v4
        with:
          name: attestations
          path: |
            results/summaries/findings.json.att.json
            results/summaries/findings.json.att.sigstore.json
```

---

## CLI Commands

### jmo attest

**Generate SLSA provenance attestation.**

```bash
# Generate attestation
jmo attest results/summaries/findings.json
# Output: results/summaries/findings.json.att.json

# With signing (requires CI environment)
jmo attest results/summaries/findings.json --sign
# Output:
#   results/summaries/findings.json.att.json
#   results/summaries/findings.json.att.sigstore.json

# Custom options
jmo attest results/summaries/findings.json \
  --output custom.att.json \
  --sign \
  --rekor-url https://rekor.sigstore.dev
```

---

### jmo verify

**Verify attestation integrity and signatures.**

```bash
# Basic verification (digest + structure)
jmo verify results/summaries/findings.json results/summaries/findings.json.att.json

# With signature verification (requires .sigstore.json bundle)
jmo verify results/summaries/findings.json results/summaries/findings.json.att.json \
  --signature results/summaries/findings.json.att.sigstore.json

# With tamper detection (checks timestamps, builder consistency, tool versions)
jmo verify results/summaries/findings.json results/summaries/findings.json.att.json \
  --enable-tamper-detection

# With historical comparison (detect tool rollback attacks)
jmo verify results/summaries/findings.json results/summaries/findings.json.att.json \
  --historical-attestations previous-attestations/

# Check Rekor transparency log
jmo verify results/summaries/findings.json results/summaries/findings.json.att.json \
  --signature results/summaries/findings.json.att.sigstore.json \
  --check-rekor
```

---

## Configuration

### jmo.yml Configuration

```yaml
# SLSA attestation configuration
attestation:
  # Enable auto-attestation in CI environments
  auto_attest: true

  # Enable auto-signing (requires CI OIDC)
  auto_sign: true

  # Sigstore endpoints (defaults to production)
  fulcio_url: "https://fulcio.sigstore.dev"
  rekor_url: "https://rekor.sigstore.dev"

  # Tamper detection settings
  tamper_detection:
    enabled: true
    max_age_days: 90  # Flag attestations older than 90 days
    max_duration_hours: 24  # Flag scans taking >24 hours
```

### Priority System

1. CLI flags (`--attest`, `--sign`) override all
2. Environment variables (`JMO_ATTEST_ENABLED=true`) override config
3. Config file settings (`auto_attest: true`) lowest priority

---

## Provenance Format

### SLSA v1.0 in-toto Statement

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "subject": [
    {
      "name": "findings.json",
      "digest": {
        "sha256": "abc123...",
        "sha384": "def456...",
        "sha512": "ghi789..."
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://jmotools.com/jmo-scan/v1@slsa/v1",
      "externalParameters": {
        "profile": "balanced",
        "tools": ["trivy", "semgrep", "trufflehog"],
        "targets": ["repo1"]
      },
      "internalParameters": {
        "version": "1.0.0",
        "threads": 4,
        "timeout": 600
      }
    },
    "runDetails": {
      "builder": {
        "id": "https://github.com/myorg/myrepo",
        "version": {
          "jmo": "1.0.0",
          "python": "3.11.13"
        }
      },
      "metadata": {
        "invocationId": "550e8400-e29b-41d4-a716-446655440000",
        "startedOn": "2025-11-05T12:34:56Z",
        "finishedOn": "2025-11-05T12:45:23Z"
      }
    }
  }
}
```

---

## Tamper Detection

**Advanced verification with multiple strategies:**

### Timestamp Anomaly Detection

| Anomaly | Description |
|---------|-------------|
| Future timestamps | Clock manipulation |
| Finish-before-start | Impossible condition |
| Impossible duration | >24h default |
| Stale attestations | >90 days default |

### Builder Consistency Checks

| Check | Detects |
|-------|---------|
| CI platform changes | GitHub -> GitLab |
| Builder version changes | Version mismatch |
| Repository URL changes | Repo tampering |

### Tool Version Rollback Detection

- Critical tool downgrades (trivy, semgrep, trufflehog)
- Bypass attack detection (reverting to vulnerable versions)

### Suspicious Patterns

- Empty findings with many tools run
- Path traversal in subject names
- Missing required fields
- Localhost builder IDs

### Severity Levels

| Level | Meaning | Action |
|-------|---------|--------|
| CRITICAL | Definite attack | Fail verification immediately |
| HIGH | Strong indicator | Logged, verification continues |
| MEDIUM | Suspicious pattern | Logged |
| LOW | Minor anomaly | Logged |

### Example Verification Output

```bash
$ jmo verify findings.json findings.json.att.json --enable-tamper-detection

Attestation verified successfully
Subject: findings.json
Digest: abc123... (SHA-256)
Builder: https://github.com/myorg/myrepo
Build Time: 2025-11-05T12:45:23Z

Tamper Detection Results:
  [OK] Timestamp validation: PASSED
  [OK] Builder consistency: PASSED
  [!]  Tool version check: trivy downgraded from 0.68.0 to 0.65.0 (MEDIUM)
  [OK] Suspicious patterns: PASSED

No CRITICAL indicators detected.
```

---

## Keyless Signing (Sigstore)

### How It Works

1. **OIDC Token**: GitHub Actions/GitLab CI provides identity token
2. **Fulcio CA**: Issues short-lived certificate (10 minutes)
3. **Signing**: Creates signature bundle with certificate
4. **Rekor Log**: Uploads signature to public transparency log
5. **Verification**: Check signature + Rekor entry

### Requirements

- GitHub Actions with `id-token: write` permission
- GitLab CI with `GITLAB_CI` environment
- No long-lived keys needed (keyless!)

### GitHub Actions Setup

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write  # CRITICAL for Sigstore
    steps:
      - name: Scan with attestation
        run: jmo scan --repo . --attest --sign
```

### GitLab CI Setup

```yaml
security-scan:
  script:
    - jmo scan --repo . --attest --sign
  artifacts:
    paths:
      - results/summaries/findings.json.att.json
      - results/summaries/findings.json.att.sigstore.json
    expire_in: 30 days
```

### Verification Workflow

```bash
# Verify signature + Rekor entry
jmo verify findings.json findings.json.att.json \
  --signature findings.json.att.sigstore.json \
  --check-rekor

# Output:
# [OK] Signature verified
# [OK] Certificate valid
# [OK] Rekor entry found: https://rekor.sigstore.dev/api/v1/log/entries/...
# [OK] Attestation verified
```

---

## Docker Integration

### Volume Mounts (Critical)

```bash
# MUST mount attestations directory for persistence
docker run --rm \
  -v $PWD:/scan \
  -v $PWD/results:/results \
  jmo-security:latest scan --repo /scan --attest

# Attestation written to: /results/summaries/findings.json.att.json
```

### Auto-Attestation in Docker (No Signing)

```bash
# jmo.yml in project root
docker run --rm \
  -v $PWD:/scan \
  -v $PWD/results:/results \
  jmo-security:latest scan --repo /scan

# Reads auto_attest: true from /scan/jmo.yml
```

### Docker with Sigstore (GitHub Actions)

```yaml
- name: Scan with Docker + attestation
  env:
    ACTIONS_ID_TOKEN_REQUEST_URL: ${{ env.ACTIONS_ID_TOKEN_REQUEST_URL }}
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: ${{ env.ACTIONS_ID_TOKEN_REQUEST_TOKEN }}
  run: |
    docker run --rm \
      -v $PWD:/scan \
      -v $PWD/results:/results \
      -e ACTIONS_ID_TOKEN_REQUEST_URL \
      -e ACTIONS_ID_TOKEN_REQUEST_TOKEN \
      jmo-security:latest scan --repo /scan --attest --sign
```

---

## Wizard Integration

### Interactive Attestation Setup

```bash
$ jmo wizard

[Step 6/7] Attestation Configuration
------------------------------------
SLSA attestation provides tamper-evident scan results with full provenance.

Enable auto-attestation in CI? [Y/n]: y
Enable auto-signing (Sigstore keyless)? [Y/n]: y

Attestation configured in jmo.yml
```

### Post-Scan Attestation Prompt

```bash
$ jmo scan --repo ./myapp --profile balanced

Scan complete! 42 findings detected.
Results: /home/user/myapp/results/summaries/

Generate attestation? [Y/n]: y
Sign with Sigstore? (requires CI) [y/N]: n

Attestation generated: results/summaries/findings.json.att.json

Next steps:
  - Verify: jmo verify results/summaries/findings.json results/summaries/findings.json.att.json
  - View: cat results/summaries/findings.json.att.json | jq
```

---

## Use Cases

### 1. Compliance Audits (SOC 2, ISO 27001)

```bash
# Generate attestation with full provenance
jmo scan --repo . --profile deep --attest --sign

# Provide attestations to auditors
tar czf attestations-q4-2025.tar.gz results/summaries/*.att.json results/summaries/*.sigstore.json

# Auditor verification (independent)
jmo verify findings.json findings.json.att.json --signature findings.json.att.sigstore.json --check-rekor
```

### 2. Supply Chain Security (SBOM + Attestation)

```bash
# Scan with syft + trivy
jmo scan --image myapp:latest --profile balanced --attest --sign

# Attestation proves:
#   - Who scanned (CI identity via Sigstore)
#   - When (timestamp in provenance)
#   - What tools (trivy 0.68.0, syft 1.0.1)
#   - Which image (digest in subject)
```

### 3. Regression Prevention (Historical Comparison)

```bash
# Verify current attestation against history
jmo verify findings.json findings.json.att.json \
  --historical-attestations previous-scans/ \
  --enable-tamper-detection

# Detects:
#   - Tool rollback attacks (trivy 0.68.0 -> 0.65.0)
#   - Builder changes (GitHub -> GitLab)
#   - Anomalous scan durations
```

### 4. Multi-Organization Trust (Open Source Projects)

```bash
# Maintainer generates attestation
jmo scan --repo . --attest --sign
git add results/summaries/findings.json.att.json results/summaries/findings.json.att.sigstore.json
git commit -m "chore: add scan attestation"

# Downstream consumer verifies
git clone https://github.com/org/project
cd project
jmo verify results/summaries/findings.json results/summaries/findings.json.att.json \
  --signature results/summaries/findings.json.att.sigstore.json \
  --check-rekor

# Rekor provides:
#   - Independent timestamp proof
#   - Non-repudiation (cannot backdate)
#   - Public audit log
```

---

## Performance

### Attestation Generation

| Operation | Time |
|-----------|------|
| Provenance only | <50ms |
| With Sigstore signing | <5s |
| Overhead | ~2% of total scan time |

### Verification

| Operation | Time |
|-----------|------|
| Digest verification | <10ms |
| Full verification | <100ms |
| With Rekor check | <500ms (network latency) |
| Tamper detection | <200ms (historical comparison) |

### Storage

| Item | Size |
|------|------|
| Attestation file | ~2-5 KB (provenance) |
| Signature bundle | ~10-20 KB (certificate chain) |
| Multi-hash digests | 3x hash algorithms (defense-in-depth) |

---

## Troubleshooting

### "OIDC token acquisition failed"

- Ensure `id-token: write` permission in GitHub Actions
- Check `GITLAB_CI` environment variable in GitLab CI
- Local signing not supported (keyless requires CI identity)

### "Rekor unavailable"

- Check Rekor status: `https://status.sigstore.dev`
- Retry with `--rekor-url https://rekor.sigstage.dev` (staging)
- Skip Rekor check: remove `--check-rekor` flag (less secure)

### "Signature verification failed"

- Ensure signature bundle path correct (`--signature findings.json.att.sigstore.json`)
- Check certificate expiry (10-minute validity)
- Verify with Sigstore directly: `sigstore verify --bundle findings.json.att.sigstore.json findings.json.att.json`

### "CRITICAL tamper detected"

| Indicator | Meaning |
|-----------|---------|
| Digest mismatch | findings.json modified after attestation |
| Finish-before-start | Clock manipulation or corrupted attestation |
| Tool rollback | Security bypass attempt (critical tool downgraded) |
| Builder change | CI environment inconsistency |

### "Attestation file not found"

- Check output path: `ls results/summaries/*.att.json`
- Auto-attestation requires `auto_attest: true` in jmo.yml
- Docker: verify volume mount `-v $PWD/results:/results`

---

## Related Documentation

- [Historical Storage Guide](HISTORY_GUIDE.md) - Database storage for scan results
- [Trend Analysis Guide](TRENDS_GUIDE.md) - Statistical trend analysis over time
- [Machine-Readable Diffs Guide](DIFF_GUIDE.md) - Compare two scans
- [Results Guide](RESULTS_GUIDE.md) - Understanding scan output formats
- [CI/CD Integration](USER_GUIDE.md#cicd-pipeline-integration-strategy) - CI/CD integration help
- [Attestation Workflows Examples](examples/attestation-workflows.md) - Complete workflow examples
- [User Guide](USER_GUIDE.md) - Complete reference documentation
