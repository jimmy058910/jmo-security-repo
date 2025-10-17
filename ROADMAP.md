# JMo Security Suite — Roadmap

---

## Overview

This roadmap tracks planned enhancements for the JMo Security Audit Tool Suite. All completed features are documented in [CHANGELOG.md](CHANGELOG.md).

**Current Status:** v0.6.1 (unreleased) with 5-layer version management system and 6-framework compliance integration.

**Recent Releases:**
- **v0.6.0** (October 16, 2025): Multi-target unified scanning (repos, containers, IaC, web apps, GitLab, K8s)
- **v0.5.1** (October 16, 2025): 6-framework compliance integration (OWASP, CWE, CIS, NIST CSF, PCI DSS, MITRE ATT&CK)
- **v0.5.0** (October 15, 2025): Tool suite consolidation with DAST, runtime security, and fuzzing
- **v0.4.0** (October 14, 2025): Docker all-in-one images and interactive wizard

**Documentation:**
- [CHANGELOG.md](CHANGELOG.md) — Complete version history with implementation details
- [CONTRIBUTING.md](CONTRIBUTING.md) — Development setup and contribution guidelines
- [docs/USER_GUIDE.md](docs/USER_GUIDE.md) — Comprehensive feature reference

---

## Implementation Order

Items are ordered by implementation priority based on user value, dependencies, and logical progression.

### Quick Reference

**Active Development Items:**

| # | Feature | Status | Phase | GitHub Issue |
|---|---------|--------|-------|--------------|
| 1 | Docker Image Optimization | 📋 **Next Priority** | A - Foundation | [#48](https://github.com/jimmy058910/jmo-security-repo/issues/48) |
| 2 | CI Linting - Full Pre-commit | 🚧 In Progress | A - Foundation | [#31](https://github.com/jimmy058910/jmo-security-repo/issues/31) |
| 3 | Machine-Readable Diff Reports | 📋 Planned | B - CI/CD | [#32](https://github.com/jimmy058910/jmo-security-repo/issues/32) |
| 4 | Scheduled Scans & Cron | 📋 Planned | B - CI/CD | [#33](https://github.com/jimmy058910/jmo-security-repo/issues/33) |
| 5 | Plugin System | 📋 Planned | C - Extensibility | [#34](https://github.com/jimmy058910/jmo-security-repo/issues/34) |
| 6 | Policy-as-Code (OPA) | 📋 Planned | C - Extensibility | [#35](https://github.com/jimmy058910/jmo-security-repo/issues/35) |
| 7 | Supply Chain Attestation (SLSA) | 📋 Planned | D - Enterprise | [#36](https://github.com/jimmy058910/jmo-security-repo/issues/36) |
| 8 | GitHub App Integration | 📋 Planned | D - Enterprise | [#37](https://github.com/jimmy058910/jmo-security-repo/issues/37) |
| 9 | Web UI for Results | 📋 Planned | E - Advanced UI | [#38](https://github.com/jimmy058910/jmo-security-repo/issues/38) |
| 10 | React/Vue Dashboard | 📋 Planned | E - Advanced UI | [#39](https://github.com/jimmy058910/jmo-security-repo/issues/39) |

**Note:** Original ROADMAP #12 and #13 were consolidated/renumbered during v0.6.0 reorganization.

---

## 1. Docker Image Optimization (Size/Performance) 🎯 **NEXT PRIORITY**

**Status:** 📋 Planned
**Priority:** 🔴 **HIGH** (Infrastructure improvement, top development priority)
**GitHub Issue:** [#48](https://github.com/jimmy058910/jmo-security-repo/issues/48)
**Dependencies:** ✅ Tool Version Consistency (v0.6.1 complete)

**Objective:** Reduce Docker image size by 40-50% (1.5GB → 800MB full, 400MB Alpine) and improve scan performance by 30s through multi-stage builds, layer optimization, and caching strategies.

### Current State Analysis

**Problem:**

- Full image: ~1.5GB (large download, slow CI pulls)
- Cold scan: 2-3 minutes (Trivy DB download every run)
- All tools included even for fast/balanced profiles
- No layer caching optimization

**Root Causes:**

- Single-stage build includes build dependencies
- Trivy vulnerability DB rebuilt on every scan
- Package manager caches not cleared
- Alpine variant not optimized

### Optimization Strategies

#### Strategy 1: Multi-Stage Builds

**Current:** Single stage with all build + runtime dependencies

**Improved:**

```dockerfile
# Stage 1: Build environment (tools compilation)
FROM ubuntu:22.04 AS builder

RUN apt-get update && apt-get install -y curl tar gzip
RUN curl -sSL "https://..." -o trivy.tar.gz && tar -xzf trivy.tar.gz
# ... install all tools ...

# Stage 2: Runtime environment (minimal dependencies)
FROM ubuntu:22.04 AS runtime

COPY --from=builder /usr/local/bin/trivy /usr/local/bin/
COPY --from=builder /usr/local/bin/gitleaks /usr/local/bin/
# ... copy only compiled binaries, not build tools ...

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip git \
    && rm -rf /var/lib/apt/lists/*
```

**Expected Savings:** 300-400MB (removes curl, tar, build toolchains)

---

#### Strategy 2: Layer Optimization & Cache Cleanup

**Current:** Package caches remain in layers

**Improved:**

```dockerfile
RUN apt-get update && apt-get install -y python3 python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir semgrep checkov bandit \
    && find /usr/local/lib/python3* -type d -name '__pycache__' -exec rm -rf {} + \
    && find /usr/local/lib/python3* -type f -name '*.pyc' -delete
```

**Expected Savings:** 100-200MB (apt cache, pip cache, Python bytecode)

---

#### Strategy 3: Trivy Database Caching

**Problem:** Trivy downloads vulnerability DB on every scan (30-60s delay)

**Solution:** Pre-download DB in image build + support volume mounting

```dockerfile
# Pre-download Trivy DB at build time
RUN trivy image --download-db-only

# At runtime, use cached DB
VOLUME ["/root/.cache/trivy"]
```

**Usage:**

```bash
# First run: downloads DB to named volume
docker run --rm -v trivy-cache:/root/.cache/trivy \
  ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan

# Subsequent runs: reuses cached DB (30s faster)
docker run --rm -v trivy-cache:/root/.cache/trivy \
  ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan
```

**Expected Speedup:** 30s per scan (after first run)

---

### Implementation Phases

#### Phase 1: Multi-Stage + Layer Optimization

**Tasks:**

1. Refactor `Dockerfile` to multi-stage build
2. Add cache cleanup to all RUN commands
3. Verify all tools still work post-optimization
4. Update CI to build optimized image
5. Benchmark before/after (size + scan time)

**Deliverables:**

- Optimized `Dockerfile` (multi-stage)
- CI builds both old (for comparison) and new images
- Documentation: `docs/DOCKER_README.md` updated with size metrics

**Expected Results:**

- Full image: 1.5GB → 1.0GB (~33% reduction)
- Build time: Same or faster (layer caching)

---

#### Phase 2: Alpine + Trivy Caching

**Tasks:**

1. Optimize `Dockerfile.alpine` (Alpine variant)
2. Add Trivy DB pre-download to all variants
3. Document volume mounting for cache persistence
4. Add CI benchmarks for scan performance (with/without cache)

**Deliverables:**

- Alpine variant: ~400MB (73% reduction from 1.5GB)
- All images include pre-downloaded Trivy DB
- Documentation for volume mounting patterns

**Expected Results:**

- Alpine: ~400MB
- Scan performance: 30s faster on subsequent runs (Trivy cache hit)

---

### Success Criteria

- Full image size reduced by ≥40% (1.5GB → 900MB or less)
- Alpine variant ≤500MB
- Trivy scan 30s faster with caching
- All tools still functional in full image
- Multi-arch builds (amd64/arm64) for all variants
- Documentation includes size comparison table
- CI builds complete in <15 minutes (all variants)

### Benefits

1. **Faster CI/CD:** Smaller images = faster pulls (3× faster in GitHub Actions)
2. **Cost Savings:** Reduced bandwidth and storage costs
3. **User Experience:** Faster first-time setup
4. **Performance:** Cached Trivy DB eliminates 30s delay

---

## 2. CI Linting - Full Pre-commit Coverage

**Status:** 🚧 In Progress (monitoring automated rollout)
**GitHub Issue:** [#31](https://github.com/jimmy058910/jmo-security-repo/issues/31)

**Why Second:** Establishes quality baseline before adding more features.

**Current State:**

- `quick-checks` job runs actionlint, yamllint, deps-compile check
- `lint-full` job exists but only runs on nightly schedule

**Objective:** Move all pre-commit hooks to run on every PR (not just nightly) while maintaining fast feedback loops.

**Remaining Work:**

- Move shellcheck, markdownlint, black, ruff to PR checks
- Optimize for speed (parallel execution)
- Monitor nightly runs for 1-2 weeks per user request

---

## 3. Machine-Readable Diff Reports

**Status:** 📋 Planned
**GitHub Issue:** [#32](https://github.com/jimmy058910/jmo-security-repo/issues/32)

**Why Third:** Essential for PR reviews and CI/CD workflows, builds on reporting foundation.

**Objective:** Enable finding-level diffs between scan runs for PR workflows and CI/CD integration.

**Scope:**

- Diff engine: Compare two `findings.json` files
- Detect new/fixed/changed findings
- JSON diff format for CI consumption
- Markdown diff summary for PRs
- CI integration examples

**Expected Deliverables:**

- `jmo diff` command
- JSON/Markdown diff reporters
- GitHub Actions workflow examples
- PR comment integration guide

---

## 4. Scheduled Scans & Cron Support

**Status:** 📋 Planned
**GitHub Issue:** [#33](https://github.com/jimmy058910/jmo-security-repo/issues/33)

**Why Fourth:** Natural extension of diff reports, enables continuous monitoring.

**Objective:** Enable automated scheduled scanning with trend analysis.

**Scope:**

- GitHub Actions scheduled workflow templates
- Cron mode for CLI (`jmo cron --schedule daily`)
- Historical results storage
- Trend analysis integration with diff reports

---

## 5. Plugin System for Custom Adapters

**Status:** 📋 Planned
**GitHub Issue:** [#34](https://github.com/jimmy058910/jmo-security-repo/issues/34)

**Why Fifth:** Enables community contributions and proprietary tool support, unlocks ecosystem.

**Objective:** Allow users to add custom tool adapters without modifying core code.

**Scope:**

- Plugin architecture for custom adapters
- Plugin discovery and loading
- Plugin validation and sandboxing
- Example custom adapter (e.g., CodeQL)

---

## 6. Policy-as-Code Integration (OPA)

**Status:** 📋 Planned
**GitHub Issue:** [#35](https://github.com/jimmy058910/jmo-security-repo/issues/35)

**Why Sixth:** Builds on plugin system, provides advanced flexibility for teams.

**Objective:** Enable custom security policies using Open Policy Agent (OPA).

**Scope:**

- OPA policy engine integration
- Custom policy definitions (Rego)
- Policy validation in CI
- Policy violation reporting

---

## 7. Supply Chain Attestation (SLSA)

**Status:** 📋 Planned
**GitHub Issue:** [#36](https://github.com/jimmy058910/jmo-security-repo/issues/36)

**Why Seventh:** Enterprise compliance feature, requires mature scanning foundation.

**Objective:** Generate SLSA provenance and artifact attestations.

**Scope:**

- SLSA provenance generation
- Artifact signing (Sigstore)
- SBOM attestation
- Verification workflow

---

## 8. GitHub App Integration

**Status:** 📋 Planned
**GitHub Issue:** [#37](https://github.com/jimmy058910/jmo-security-repo/issues/37)

**Why Eighth:** Revenue driver, requires all CI/CD features to be mature.

**Objective:** One-click GitHub App for automated PR comments and checks.

**Scope:**

- GitHub App for automated PR comments
- Check runs API integration
- Auto-fix suggestions in PR reviews
- One-click installation

---

## 9. Web UI for Results Exploration

**Status:** 📋 Planned
**GitHub Issue:** [#38](https://github.com/jimmy058910/jmo-security-repo/issues/38)

**Why Ninth:** Advanced feature for large result sets, requires server infrastructure.

**Objective:** Web-based UI for exploring scan results with multi-scan history.

**Scope:**

- Backend API for serving results
- Multi-scan history viewer
- Live filtering and search
- Export/share capabilities

---

## 10. React/Vue Dashboard Alternative

**Status:** 📋 Planned
**GitHub Issue:** [#39](https://github.com/jimmy058910/jmo-security-repo/issues/39)

**Why Last:** Polish/modernization, existing HTML dashboard works well.

**Objective:** Modern SPA framework for enhanced interactivity.

**Scope:**

- Modern SPA framework
- Interactive visualizations
- Real-time updates
- Mobile responsive

---

## Future Ideation & Research

The following ideas are under consideration for future development but require additional research, user feedback, or dependency completion before formal planning.

### Executive Dashboard & Trend Analysis

**Concept:** Integrated executive summary view combining elements from enhanced Markdown summaries with visual trend charts and risk scoring.

**Potential Features:**

- **Risk Score Dashboard**: Weighted severity calculations (e.g., "Risk Score: 78/100")
- **Trend Charts**: Multi-run history visualization showing findings over time
- **Top Risks Panel**: Priority-ranked actionable items with drivers
- **Compliance Status**: OWASP Top 10 coverage, regulatory mapping
- **Integration Point**: Could be integrated with Enhanced Markdown Summary or Web UI

**User Value:** C-level visibility, justification for remediation efforts, compliance reporting

**Dependencies:** Multi-run history storage, risk scoring algorithm, charting library

**Status:** Ideation - awaiting user feedback on Enhanced Markdown Summary implementation

---

### Performance Profiling Enhancements

**Concept:** Enhanced profiling and optimization recommendations for scan performance.

**Potential Features:**

- **Always-on profiling**: Track scan/report duration even without `--profile` flag
- **Performance recommendations**: "Current thread count (4) is optimal" based on analysis
- **Slow tool alerts**: "⚠️ Warning: trivy took 45s (timeout: 60s)"
- **CI/CD optimization insights**: Suggestions for parallelization, timeout tuning
- **Profiling dashboard**: Visual breakdown of tool execution times

**User Value:** Better CI/CD pipeline optimization, faster feedback loops

**Dependencies:** Timing infrastructure (already exists), recommendation engine

**Status:** Ideation - low priority, nice-to-have for power users

---

## Contributing to the Roadmap

Want to help implement these features? Check out our [good first issues](https://github.com/jimmy058910/jmo-security-repo/labels/good%20first%20issue) and [help wanted](https://github.com/jimmy058910/jmo-security-repo/labels/help%20wanted) labels:

**Good First Issues (Easy Contributions):**

- [#17](https://github.com/jimmy058910/jmo-security-repo/issues/17) - Docs: Add "Try it with fixtures" snippet to README
- [#18](https://github.com/jimmy058910/jmo-security-repo/issues/18) - Tests: Add smoke test for `dashboard.html` generation
- [#20](https://github.com/jimmy058910/jmo-security-repo/issues/20) - Docs: Packaging note for `long_description_content_type`
- [#23](https://github.com/jimmy058910/jmo-security-repo/issues/23) - Tests: Add unit test for fingerprint stability
- [#24](https://github.com/jimmy058910/jmo-security-repo/issues/24) - CI: Add `make lint` check to tests workflow

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and workflow.

---

**Status:** All roadmap items are planned. Implementation will proceed in order based on user feedback and business priorities. See individual GitHub issues for detailed tracking.

**For Complete Version History:** See [CHANGELOG.md](CHANGELOG.md) for detailed implementation notes on all completed features.
