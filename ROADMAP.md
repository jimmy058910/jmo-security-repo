# JMo Security Suite — Roadmap

**Strategic Focus:** Open-source growth, community contributions, developer experience

---

## Overview

This roadmap tracks planned enhancements for the JMo Security Audit Tool Suite. All completed features are documented in [CHANGELOG.md](CHANGELOG.md).

**Current Status:** v0.8.0-dev with SARIF validation, improved error messages, and enhanced reporting

**Recent Releases:**

- **v0.7.1** (October 23, 2025): Telemetry opt-out model, enhanced exception logging, SHA256 Homebrew verification
- **v0.7.0** (October 23, 2025): Privacy-first telemetry, real-time progress tracking, auto-detect CPU threads, cross-platform Docker docs
- **v0.6.0** (October 16, 2025): Multi-target unified scanning (repos, containers, IaC, web apps, GitLab, K8s)
- **v0.5.1** (October 16, 2025): 6-framework compliance integration (OWASP, CWE, CIS, NIST CSF, PCI DSS, MITRE ATT&CK)

**Documentation:**

- [CHANGELOG.md](CHANGELOG.md) — Complete version history with implementation details
- [CONTRIBUTING.md](CONTRIBUTING.md) — Development setup and contribution guidelines
- [docs/USER_GUIDE.md](docs/USER_GUIDE.md) — Comprehensive feature reference
- **[dev-only/VERSION_ROADMAP_0.8.0-1.0.0.md](dev-only/VERSION_ROADMAP_0.8.0-1.0.0.md)** — Detailed implementation plan for v0.8.0-v1.0.0

---

## Strategic Direction

**Focus:** Distribution, adoption, community contributions, developer experience

**Key Principles:**

- ✅ Open-source first, community-driven development
- ✅ Amazing developer experience
- ✅ Viral growth through shareability
- ✅ Sustainable long-term project growth

---

## Version Roadmap

### v0.8.0 — CI/CD Excellence (Target: April 2026)

**Theme:** Make JMo the best security tool for CI/CD pipelines

**Priority Features:**

| # | Feature | Effort | Status | GitHub Issue |
|---|---------|--------|--------|--------------|
| 1 | Scheduled Scans & Cron Support | 4-6 hours | 📋 Planned | [#33](https://github.com/jimmy058910/jmo-security-repo/issues/33) |
| 2 | Machine-Readable Diff Reports | 8-12 hours | 📋 Planned | [#32](https://github.com/jimmy058910/jmo-security-repo/issues/32) |
| 3 | Rewrite Skipped Integration Tests | 2-4 hours | ⚠️ Partial (5 tests skipped) | [#69](https://github.com/jimmy058910/jmo-security-repo/issues/69) |

**Growth Targets:**

- 5K+ installs (Docker + pip)
- 5K+ GitHub stars
- 50+ contributors
- 100+ community repos using JMo in CI

**Details:** See [dev-only/VERSION_ROADMAP_0.8.0-1.0.0.md#v080--cicd-excellence](dev-only/VERSION_ROADMAP_0.8.0-1.0.0.md#v080--cicd-excellence)

---

### v0.9.0 — Developer Experience & Orchestration (Target: July 2026)

**Theme:** Make JMo delightful to use and extend

**Priority Features:**

| # | Feature | Effort | Status | GitHub Issue |
|---|---------|--------|--------|--------------|
| 1 | **Refactoring cmd_scan + wizard.py** | 2-3 weeks | 📋 Planned | TBD |
| 2 | **Plugin System for Custom Adapters** | 2-3 weeks | 📋 Planned | [#34](https://github.com/jimmy058910/jmo-security-repo/issues/34) |
| 3 | **Homebrew + Winget Packaging** ⚠️ | 2-3 weeks | 📋 Planned | TBD |
| 4 | **Wizard V2** (Multi-target, Workflows, Artifacts) | 3-4 weeks | 📋 Planned | TBD |
| 5 | Intelligent Prioritization (EPSS/KEV) | 1-2 weeks | 📋 Planned | [#49](https://github.com/jimmy058910/jmo-security-repo/issues/49) |
| 6 | **Schedule Management Completion** | 1-2 weeks | 📋 Planned | [#33](https://github.com/jimmy058910/jmo-security-repo/issues/33) (continuation) |

⚠️ **Note:** Homebrew + Winget packaging ONLY after plugin system is complete (stable API required)

**Growth Targets:**

- 25K+ installs (Homebrew + Winget + Docker + pip)
- 10K+ GitHub stars
- 100+ contributors
- 20+ community plugins
- Featured in 3+ conferences

**Details:** See [dev-only/VERSION_ROADMAP_0.8.0-1.0.0.md#v090--developer-experience--orchestration](dev-only/VERSION_ROADMAP_0.8.0-1.0.0.md#v090--developer-experience--orchestration)

---

### v1.0.0 — Production-Ready Platform (Target: January 2027)

**Theme:** Enterprise-grade stability, modern UI, AI-powered features

**Flagship Features:**

| # | Feature | Effort | Status | GitHub Issue |
|---|---------|--------|--------|--------------|
| 1 | **React/Vue Dashboard** ⭐ FLAGSHIP | 4-6 weeks | 📋 Planned | [#39](https://github.com/jimmy058910/jmo-security-repo/issues/39) |
| 2 | AI Remediation Orchestration (MCP Server) | 4-6 weeks | 📋 Planned | [#50](https://github.com/jimmy058910/jmo-security-repo/issues/50) |
| 3 | Cross-Tool Deduplication Enhancement | 2-3 weeks | 📋 Planned | [#51](https://github.com/jimmy058910/jmo-security-repo/issues/51) |
| 4 | Policy-as-Code Integration (OPA) | 3-4 weeks | 📋 Planned | [#35](https://github.com/jimmy058910/jmo-security-repo/issues/35) |
| 5 | **Docker Image Optimization Phase 2** | 2-3 weeks | 📋 Planned | [#48](https://github.com/jimmy058910/jmo-security-repo/issues/48) |

**Supporting Features:**

- Supply Chain Attestation (SLSA) — [#36](https://github.com/jimmy058910/jmo-security-repo/issues/36)
- Web UI for Results — [#38](https://github.com/jimmy058910/jmo-security-repo/issues/38)
- IDE Integration (LSP) — [#52](https://github.com/jimmy058910/jmo-security-repo/issues/52)

**Growth Targets:**

- 50K+ installs
- 20K+ GitHub stars
- 200+ contributors
- 100+ community plugins
- 10+ enterprise users (Fortune 500)
- Trending on HackerNews/Reddit/ProductHunt
- 1000+ Vercel deployments (React dashboard)

**Details:** See [dev-only/VERSION_ROADMAP_0.8.0-1.0.0.md#v100--production-ready-platform](dev-only/VERSION_ROADMAP_0.8.0-1.0.0.md#v100--production-ready-platform)

---

## Completed Features

### v0.8.0-dev Series (October 2025)

| Feature | Version | GitHub Issue |
|---------|---------|--------------|
| SARIF schema validation in CI | v0.8.0-dev | [#87](https://github.com/jimmy058910/jmo-security-repo/issues/87) |
| Improved tool error messages | v0.8.0-dev | [#86](https://github.com/jimmy058910/jmo-security-repo/issues/86) |
| CI Linting - Full pre-commit coverage (nightly) | v0.8.0-dev | [#31](https://github.com/jimmy058910/jmo-security-repo/issues/31) |
| Enhanced markdown summary (risk breakdown) | v0.8.0-dev | [#45](https://github.com/jimmy058910/jmo-security-repo/issues/45) |
| HTML Dashboard v2 (actionable findings) | v0.8.0-dev | [#44](https://github.com/jimmy058910/jmo-security-repo/issues/44) |

### v0.7.x Series (October 2025)

| Feature | Version | GitHub Issue |
|---------|---------|--------------|
| Telemetry opt-out model | v0.7.1 | — |
| Enhanced exception logging | v0.7.1 | — |
| SHA256 Homebrew verification | v0.7.1 | — |
| Privacy-first telemetry system | v0.7.0 | — |
| Real-time progress tracking | v0.7.0 | — |
| Auto-detect CPU threads | v0.7.0 | — |

### v0.6.x Series (October 2025)

| Feature | Version | GitHub Issue |
|---------|---------|--------------|
| Fix Deep Profile Tool Execution | v0.6.1 | [#42](https://github.com/jimmy058910/jmo-security-repo/issues/42) |
| Docker Image Optimization Phase 1 | v0.6.1 | [#48](https://github.com/jimmy058910/jmo-security-repo/issues/48) (partial) |
| Multi-target unified scanning | v0.6.0 | — |
| Nuclei integration (API security) | v0.6.0 | — |
| GitLab container discovery | v0.6.2 | — |

### v0.5.x Series (October 2025)

| Feature | Version | GitHub Issue |
|---------|---------|--------------|
| 6-framework compliance integration | v0.5.1 | — |
| tfsec → Trivy migration | v0.5.0 | [#41](https://github.com/jimmy058910/jmo-security-repo/issues/41) |
| DAST + Runtime Security + Fuzzing | v0.5.0 | — |
| Profile-based configuration | v0.5.0 | — |

### v0.4.x Series (October 2025)

| Feature | Version | GitHub Issue |
|---------|---------|--------------|
| Docker all-in-one images | v0.4.0 | [#29](https://github.com/jimmy058910/jmo-security-repo/issues/29) |
| Interactive wizard | v0.4.0 | [#30](https://github.com/jimmy058910/jmo-security-repo/issues/30) |

---

## Implementation Timeline

### Q2 2026 (Apr-Jun) — v0.8.0 Development

- **April:** Scheduled scans + Diff reports
- **May:** Skipped tests + CI linting
- **June:** Release v0.8.0 + community outreach

### Q3 2026 (Jul-Sep) — v0.9.0 Development

- **July:** Refactoring + Plugin system
- **August:** Homebrew/Winget + Wizard V2
- **September:** EPSS/KEV + Release v0.9.0

### Q4 2026 (Oct-Dec) — v1.0.0 Development (Part 1)

- **October:** React dashboard development
- **November:** AI remediation (MCP server)
- **December:** Cross-tool deduplication

### Q1 2027 (Jan-Mar) — v1.0.0 Development (Part 2)

- **January:** Policy-as-Code (OPA)
- **February:** Supporting features (SLSA, Web UI, LSP)
- **March:** Release v1.0.0 + Product Hunt launch

---

## Contributing to the Roadmap

Want to help implement these features? Check out:

- **Good First Issues:** [github.com/jimmy058910/jmo-security-repo/labels/good first issue](https://github.com/jimmy058910/jmo-security-repo/labels/good%20first%20issue)
- **Help Wanted:** [github.com/jimmy058910/jmo-security-repo/labels/help wanted](https://github.com/jimmy058910/jmo-security-repo/labels/help%20wanted)
- **Detailed Plan:** [dev-only/VERSION_ROADMAP_0.8.0-1.0.0.md](dev-only/VERSION_ROADMAP_0.8.0-1.0.0.md)

**Contributing Guide:** See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and workflow.

---

## Feedback & Discussions

- **GitHub Discussions:** Share your feedback on priorities and features
- **Feature Requests:** Open an issue with the `enhancement` label
- **Community Chat:** Join our discussions to help shape the roadmap

---

**Last Updated:** 2025-10-30
**Review Cadence:** Monthly (first Monday of each month)
**Maintained By:** Jimmy ([@jimmy058910](https://github.com/jimmy058910))
