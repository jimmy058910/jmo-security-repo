# JMo Security Testing & Usage Matrices

**Generated:** 2025-12-22
**Purpose:** Comprehensive coverage analysis for testing and usage patterns across all dimensions

## Executive Summary

**Dimensions:**

- **6 Target Types:** Repositories, Container Images, IaC Files, Web URLs, GitLab Repos, Kubernetes Clusters
- **28 Tools:** Organized across 4 profiles (fast: 8, slim: 14, balanced: 18, deep: 28)
- **3 OS Platforms:** Linux, macOS, WSL (Windows Subsystem for Linux)
- **5 Execution Modes:** CLI (native), Docker (fast), Docker (slim), Docker (balanced), Docker (deep)
- **6 Compliance Frameworks:** OWASP Top 10 2021, CWE Top 25 2024, CIS Controls v8.1, NIST CSF 2.0, PCI DSS 4.0, MITRE ATT&CK v16.1

**Total Possible Combinations:** 6 x 28 x 3 x 5 x 6 = **15,120 test scenarios**
**Current Test Suite:** 2,981 tests across unit/adapters/reporters/integration
**Coverage:** 87% (CI enforced minimum: 85%)

---

## Tool Profiles Reference

> **Canonical source:** [PROFILES_AND_TOOLS.md](PROFILES_AND_TOOLS.md)

### Fast Profile (8 tools, 5-10 min)

trufflehog, semgrep, syft, trivy, checkov, hadolint, nuclei, shellcheck

### Slim Profile (14 tools, 12-18 min)

Fast + prowler, kubescape, grype, bearer, horusec, dependency-check

### Balanced Profile (18 tools, 18-25 min)

Slim + zap, scancode, cdxgen, gosec

### Deep Profile (28 tools, 40-70 min)

Core (14): trufflehog, semgrep, syft, trivy, checkov, hadolint, nuclei, prowler, kubescape, grype, bearer, horusec, dependency-check, zap

Extended (6): scancode, cdxgen, gosec, yara, noseyparker, bandit

Variants (4): semgrep-secrets, trivy-rbac, checkov-cicd, falco

Specialized (4): akto, afl++, mobsf, lynis

---

## Matrix 1: Target Types x Tools (Compatibility Matrix)

This matrix shows which tools can scan which target types.

### Legend

- **Yes** = Supported
- **-** = Not applicable

| Tool | Repos | Images | IaC | URLs | GitLab | K8s |
|------|-------|--------|-----|------|--------|-----|
| trufflehog | Yes | - | - | - | Yes | - |
| semgrep | Yes | - | - | - | Yes | - |
| syft | Yes | Yes | - | - | Yes | - |
| trivy | Yes | Yes | Yes | - | Yes | Yes |
| checkov | Yes | - | Yes | - | Yes | - |
| hadolint | Yes | - | - | - | Yes | - |
| nuclei | - | - | - | Yes | - | - |
| shellcheck | Yes | - | - | - | Yes | - |
| prowler | - | - | Yes | - | - | Yes |
| kubescape | - | - | Yes | - | - | Yes |
| grype | Yes | Yes | - | - | Yes | - |
| bearer | Yes | - | - | - | Yes | - |
| horusec | Yes | - | - | - | Yes | - |
| dependency-check | Yes | - | - | - | Yes | - |
| zap | - | - | - | Yes | - | - |
| scancode | Yes | - | - | - | Yes | - |
| cdxgen | Yes | Yes | - | - | Yes | - |
| gosec | Yes | - | - | - | Yes | - |
| yara | Yes | - | - | - | Yes | - |
| noseyparker | Yes | - | - | - | Yes | - |
| bandit | Yes | - | - | - | Yes | - |
| semgrep-secrets | Yes | - | - | - | Yes | - |
| trivy-rbac | - | - | - | - | - | Yes |
| checkov-cicd | Yes | - | Yes | - | Yes | - |
| falco | - | - | - | - | - | Yes |
| akto | - | - | - | Yes | - | - |
| afl++ | Yes | - | - | - | - | - |
| mobsf | Yes | - | - | - | - | - |
| lynis | - | - | - | - | - | - |

**Coverage Summary:**

- **Repositories:** 22/28 tools
- **Container Images:** 4/28 tools (trivy, syft, grype, cdxgen)
- **IaC Files:** 5/28 tools (trivy, checkov, prowler, kubescape, checkov-cicd)
- **Web URLs:** 3/28 tools (nuclei, zap, akto)
- **GitLab Repos:** 20/28 tools (same as repos minus specialized)
- **Kubernetes Clusters:** 5/28 tools (trivy, prowler, kubescape, trivy-rbac, falco)

---

## Matrix 2: Target Types x OS Platforms x Execution Modes

This matrix shows test coverage for each target type across OS platforms and execution modes.

### Legend

- **Tested** = Explicit tests exist in test suite
- **Partial** = Some tests exist, incomplete coverage
- **Untested** = No tests for this combination

### 2.1: Repositories Target Type

| OS Platform | CLI (native) | Docker (deep) | Docker (balanced) | Docker (slim) | Docker (fast) |
|-------------|--------------|---------------|-------------------|---------------|---------------|
| **Linux** | Tested | Tested | Partial | Partial | Partial |
| **macOS** | Tested | Partial | Untested | Untested | Untested |
| **WSL** | Partial | Untested | Untested | Untested | Untested |

### 2.2: Container Images Target Type

| OS Platform | CLI (native) | Docker (deep) | Docker (balanced) | Docker (slim) | Docker (fast) |
|-------------|--------------|---------------|-------------------|---------------|---------------|
| **Linux** | Tested | Partial | Untested | Untested | Untested |
| **macOS** | Partial | Untested | Untested | Untested | Untested |
| **WSL** | Untested | Untested | Untested | Untested | Untested |

### 2.3: IaC Files Target Type

| OS Platform | CLI (native) | Docker (deep) | Docker (balanced) | Docker (slim) | Docker (fast) |
|-------------|--------------|---------------|-------------------|---------------|---------------|
| **Linux** | Tested | Partial | Untested | Untested | Untested |
| **macOS** | Partial | Untested | Untested | Untested | Untested |
| **WSL** | Untested | Untested | Untested | Untested | Untested |

### 2.4: Web URLs Target Type

| OS Platform | CLI (native) | Docker (deep) | Docker (balanced) | Docker (slim) | Docker (fast) |
|-------------|--------------|---------------|-------------------|---------------|---------------|
| **Linux** | Tested | Partial | Untested | Untested | Untested |
| **macOS** | Partial | Untested | Untested | Untested | Untested |
| **WSL** | Untested | Untested | Untested | Untested | Untested |

### 2.5: GitLab Repos Target Type

| OS Platform | CLI (native) | Docker (deep) | Docker (balanced) | Docker (slim) | Docker (fast) |
|-------------|--------------|---------------|-------------------|---------------|---------------|
| **Linux** | Tested | Partial | Untested | Untested | Untested |
| **macOS** | Partial | Untested | Untested | Untested | Untested |
| **WSL** | Untested | Untested | Untested | Untested | Untested |

### 2.6: Kubernetes Clusters Target Type

| OS Platform | CLI (native) | Docker (deep) | Docker (balanced) | Docker (slim) | Docker (fast) |
|-------------|--------------|---------------|-------------------|---------------|---------------|
| **Linux** | Tested | Partial | Untested | Untested | Untested |
| **macOS** | Partial | Untested | Untested | Untested | Untested |
| **WSL** | Untested | Untested | Untested | Untested | Untested |

### Platform-Specific Coverage Summary

| OS Platform | CLI (native) | Docker (deep) | Docker (balanced) | Docker (slim) | Docker (fast) |
|-------------|--------------|---------------|-------------------|---------------|---------------|
| **Linux** | 100% (6/6) | 50% (3/6) | 0% (0/6) | 0% (0/6) | 0% (0/6) |
| **macOS** | 50% (3/6) | 0% (0/6) | 0% (0/6) | 0% (0/6) | 0% (0/6) |
| **WSL** | 0% (0/6) | 0% (0/6) | 0% (0/6) | 0% (0/6) | 0% (0/6) |

---

## Matrix 3: Tools x OS Platforms x Execution Modes

This matrix shows which tools are tested on which platforms and execution modes.

### 3.1: Linux Platform (Core Tools)

| Tool | CLI (native) | Docker (deep) | Docker (balanced) | Docker (slim) | Docker (fast) |
|------|--------------|---------------|-------------------|---------------|---------------|
| trufflehog | Tested | Tested | Partial | Partial | Partial |
| semgrep | Tested | Tested | Partial | Partial | Partial |
| syft | Tested | Tested | Partial | Partial | Partial |
| trivy | Tested | Tested | Partial | Partial | Partial |
| checkov | Tested | Partial | Untested | Untested | Untested |
| hadolint | Tested | Partial | Untested | Untested | Untested |
| nuclei | Tested | Partial | Untested | Untested | Untested |
| shellcheck | Tested | Partial | Untested | Untested | Untested |

### 3.2: Linux Platform (Extended Tools - Slim+)

| Tool | CLI (native) | Docker (deep) | Docker (balanced) | Docker (slim) | Docker (fast) |
|------|--------------|---------------|-------------------|---------------|---------------|
| prowler | Tested | Partial | Untested | Untested | N/A |
| kubescape | Tested | Partial | Untested | Untested | N/A |
| grype | Tested | Partial | Untested | Untested | N/A |
| bearer | Tested | Partial | Untested | Untested | N/A |
| horusec | Partial | Partial | Untested | Untested | N/A |
| dependency-check | Tested | Partial | Untested | Untested | N/A |

### 3.3: Linux Platform (Extended Tools - Balanced+)

| Tool | CLI (native) | Docker (deep) | Docker (balanced) | Docker (slim) | Docker (fast) |
|------|--------------|---------------|-------------------|---------------|---------------|
| zap | Tested | Partial | Untested | N/A | N/A |
| scancode | Tested | Partial | Untested | N/A | N/A |
| cdxgen | Tested | Partial | Untested | N/A | N/A |
| gosec | Tested | Partial | Untested | N/A | N/A |

### 3.4: Linux Platform (Deep-Only Tools)

| Tool | CLI (native) | Docker (deep) | Notes |
|------|--------------|---------------|-------|
| noseyparker | Tested | Partial | |
| bandit | Tested | Partial | |
| yara | Partial | Untested | |
| semgrep-secrets | Tested | Partial | Variant of semgrep |
| trivy-rbac | Partial | Untested | Variant of trivy |
| checkov-cicd | Tested | Partial | Variant of checkov |
| falco | Partial | Untested | Runtime rules only |
| akto | Untested | Untested | Manual installation |
| afl++ | Partial | Untested | Manual installation |
| mobsf | Untested | Untested | Manual installation |
| lynis | Tested | Partial | |

### Tool Coverage Summary

| Profile | Total Tools | CLI Tested | Docker Tested | Overall Coverage |
|---------|-------------|------------|---------------|------------------|
| **Fast** | 8 | 8/8 (100%) | 4/8 (50%) | 75% |
| **Slim** | 14 | 13/14 (93%) | 6/14 (43%) | 68% |
| **Balanced** | 18 | 17/18 (94%) | 8/18 (44%) | 69% |
| **Deep** | 28 | 22/28 (79%) | 10/28 (36%) | 57% |

---

## Matrix 4: Compliance Frameworks x Tools

All 28 tools benefit from universal compliance enrichment via [scripts/core/compliance_mapper.py](../scripts/core/compliance_mapper.py).

**Supported Frameworks:**

- OWASP Top 10 2021
- CWE Top 25 2024
- CIS Controls v8.1
- NIST CSF 2.0
- PCI DSS 4.0
- MITRE ATT&CK v16.1

**Test Coverage:**

- [tests/unit/test_compliance_mapper_direct.py](../tests/unit/test_compliance_mapper_direct.py) - Direct mapper tests
- [tests/reporters/test_compliance_reporter.py](../tests/reporters/test_compliance_reporter.py) - Compliance report generation

**Compliance Coverage:** 100% (all tools x all frameworks)

---

## Matrix 5: Profiles x Tools x Target Types

### 5.1: Fast Profile (8 tools, 5-10 min)

| Target Type | Tools Available | Coverage |
|-------------|-----------------|----------|
| **Repositories** | trufflehog, semgrep, syft, trivy, checkov, hadolint, shellcheck | 7/8 (88%) |
| **Container Images** | syft, trivy | 2/8 (25%) |
| **IaC Files** | trivy, checkov | 2/8 (25%) |
| **Web URLs** | nuclei | 1/8 (13%) |
| **GitLab Repos** | trufflehog, semgrep, syft, trivy, checkov, hadolint, shellcheck | 7/8 (88%) |
| **Kubernetes** | trivy | 1/8 (13%) |

### 5.2: Slim Profile (14 tools, 12-18 min)

| Target Type | Tools Available | Coverage |
|-------------|-----------------|----------|
| **Repositories** | Fast + bearer, horusec, dependency-check, grype | 11/14 (79%) |
| **Container Images** | syft, trivy, grype | 3/14 (21%) |
| **IaC Files** | trivy, checkov, prowler, kubescape | 4/14 (29%) |
| **Web URLs** | nuclei | 1/14 (7%) |
| **GitLab Repos** | Same as repos | 11/14 (79%) |
| **Kubernetes** | trivy, prowler, kubescape | 3/14 (21%) |

### 5.3: Balanced Profile (18 tools, 18-25 min)

| Target Type | Tools Available | Coverage |
|-------------|-----------------|----------|
| **Repositories** | Slim + scancode, cdxgen, gosec | 14/18 (78%) |
| **Container Images** | syft, trivy, grype, cdxgen | 4/18 (22%) |
| **IaC Files** | trivy, checkov, prowler, kubescape | 4/18 (22%) |
| **Web URLs** | nuclei, zap | 2/18 (11%) |
| **GitLab Repos** | Same as repos | 14/18 (78%) |
| **Kubernetes** | trivy, prowler, kubescape | 3/18 (17%) |

### 5.4: Deep Profile (28 tools, 40-70 min)

| Target Type | Tools Available | Coverage |
|-------------|-----------------|----------|
| **Repositories** | 22 tools | 22/28 (79%) |
| **Container Images** | trivy, syft, grype, cdxgen | 4/28 (14%) |
| **IaC Files** | trivy, checkov, prowler, kubescape, checkov-cicd | 5/28 (18%) |
| **Web URLs** | nuclei, zap, akto | 3/28 (11%) |
| **GitLab Repos** | 20 tools | 20/28 (71%) |
| **Kubernetes** | trivy, prowler, kubescape, trivy-rbac, falco | 5/28 (18%) |

---

## Matrix 6: CI/CD Integration Matrix

| CI Platform | Docker | Native CLI | Profiles | Multi-Target | Compliance | SARIF Upload | Coverage |
|-------------|--------|------------|----------|--------------|------------|--------------|----------|
| **GitHub Actions** | Tested | Tested | Tested | Partial | Tested | Tested | 83% (5/6) |
| **GitLab CI** | Partial | Partial | Untested | Untested | Untested | Partial | 17% (1/6) |
| **Jenkins** | Untested | Partial | Untested | Untested | Untested | Untested | 8% (0.5/6) |
| **CircleCI** | Untested | Untested | Untested | Untested | Untested | Untested | 0% (0/6) |
| **Azure Pipelines** | Untested | Untested | Untested | Untested | Untested | Untested | 0% (0/6) |

**Test Files:**

- [.github/workflows/ci.yml](../.github/workflows/ci.yml) - GitHub Actions primary CI
- [.github/workflows/release.yml](../.github/workflows/release.yml) - GitHub Actions release automation

---

## Coverage Gap Analysis

### Critical Gaps (High Impact)

1. **Docker Profile Variants Untested**
   - Impact: 4 Docker variants (fast/slim/balanced/deep) have incomplete integration tests
   - Priority: HIGH

2. **WSL Platform Untested**
   - Impact: No explicit WSL tests despite Windows user base
   - Priority: HIGH

3. **Manual Installation Tools Untested**
   - Impact: akto, afl++, mobsf require manual installation and lack tests
   - Priority: MEDIUM

### Important Gaps (Medium Impact)

1. **Deep Profile Tools Partially Tested**
   - Impact: yara, trivy-rbac, falco have minimal test coverage
   - Priority: MEDIUM

2. **GitLab CI/Jenkins Integration**
   - Impact: Only GitHub Actions fully documented/tested
   - Priority: MEDIUM

---

## Test Suite Metrics

**Current State:**

- **Total Tests:** 2,981
- **Coverage:** 87% (CI enforced minimum: 85%)
- **CI Platforms:** 2 OS (Linux, macOS) x 3 Python versions (3.10, 3.11, 3.12) = 6 matrix jobs
- **Test Categories:**
  - Unit tests
  - Adapter tests (28 tools)
  - Reporter tests
  - Integration tests
  - CLI tests

---

## Conclusion

**Strengths:**

- Excellent adapter coverage for all 28 tools
- Strong Linux CLI testing across all 6 target types
- Universal compliance enrichment (100% tool x framework coverage)
- Robust integration tests for GitHub Actions

**Weaknesses:**

- Docker variant testing incomplete
- WSL platform untested
- Manual installation tools (akto, afl++, mobsf) lack tests
- GitLab/Jenkins/CircleCI undocumented

**Recommended Focus:**

1. Add Docker variant integration tests
2. Document WSL testing procedures
3. Expand GitLab CI examples

---

**Matrix Generated:** 2025-12-22
**JMo Security:** v1.0.0
**Maintainer:** See [CONTRIBUTING.md](../CONTRIBUTING.md)
