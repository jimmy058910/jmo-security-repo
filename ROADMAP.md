# JMo Security Suite — Roadmap

**Strategic Focus:** Community growth, developer experience, enterprise adoption

---

## Current Status

**Latest Stable Release:** v1.0.0 (November 2025) — Production-Ready Platform

v1.0.0 delivered all core features for production security scanning:

- 28 security scanners with unified CLI
- SQLite historical storage with trend analysis
- Machine-readable diffs for CI/CD integration
- Policy-as-Code (OPA integration)
- SLSA attestation for supply chain security
- MCP server for AI-assisted remediation
- React dashboard with interactive filtering
- Cross-tool deduplication (30-40% noise reduction)

**Documentation:** [CHANGELOG.md](CHANGELOG.md) for complete version history

---

## Completed (v1.1.0) — Pending Release

**Theme:** Dashboard polish, accessibility, and wizard hardening

All v1.1.0 features are implemented on the `dev` branch and pending release.

| Feature | Description |
|---------|-------------|
| KEV-first sorting | Critical vulnerabilities (CISA KEV) always sorted first |
| Dual pagination | Top and bottom pagination controls |
| Radix UI tooltips | Accessible hover tooltips for truncated content |
| Simple HTML reporter | Email-compatible static HTML (Gmail, Outlook, etc.) |
| Wizard dependency auto-install | Detects and installs Java/Node.js/bash runtime deps |
| Wizard `--db` flag | Custom history database path for wizard |
| Wizard refactoring (Phase 3) | Trend flow extracted to dedicated module |
| Windows terminal compatibility | ANSI detection, `NO_COLOR` support, dynamic width |
| Archive extraction hardening | CWE-22 path traversal defense (Zip Slip protection) |
| Python 3.12 minimum | Stdlib `tomllib`, `tar filter="data"` |
| Docker Ubuntu 24.04 | PEP 668, UID 1000 fix, shellcheck binary install |

---

## Planned (v1.2.0+)

**Theme:** Developer experience and extensibility

| Feature | Priority | GitHub Issue |
|---------|----------|--------------|
| Plugin system for custom adapters | High | [#34](https://github.com/jimmy058910/jmo-security-repo/issues/34) |
| Homebrew + Winget packaging | High | TBD |
| Intelligent prioritization (EPSS/KEV scoring) | Medium | [#49](https://github.com/jimmy058910/jmo-security-repo/issues/49) |
| IDE integration (LSP) | Medium | [#52](https://github.com/jimmy058910/jmo-security-repo/issues/52) |
| Docker image optimization | Medium | [#48](https://github.com/jimmy058910/jmo-security-repo/issues/48) |
| Remediation adapter framework | Low | [#53](https://github.com/jimmy058910/jmo-security-repo/issues/53) |
| Web UI for results viewing | Low | [#38](https://github.com/jimmy058910/jmo-security-repo/issues/38) |

---

## Future (v2.0+)

**Theme:** Enterprise and advanced features

| Feature | GitHub Issue |
|---------|--------------|
| GitHub App integration | [#37](https://github.com/jimmy058910/jmo-security-repo/issues/37) |
| Contextual security education | [#54](https://github.com/jimmy058910/jmo-security-repo/issues/54) |
| Secret management integration | [#55](https://github.com/jimmy058910/jmo-security-repo/issues/55) |
| `jmo fix` CLI (AI remediation) | Deferred from v1.0.0 |
| SLSA Level 3 compliance | Hardware attestation, FedRAMP path |
| Fly.io dashboard deployment | Cloud-hosted results viewing |

---

## Completed Features

### v1.0.0 (November 2025)

All v1.0.0 features are documented in [CHANGELOG.md](CHANGELOG.md#100---2025-11-10).

Key highlights:

- **28 security scanners** — Unified CLI orchestrating tools across 6 scan types
- **Metadata wrapper** — Standardized `{"meta": {...}, "findings": [...]}` output
- **CSV reporter** — Spreadsheet-friendly export for compliance workflows
- **HTML dashboard dual-mode** — Inline (<=1000) or external JSON (>1000 findings)
- **Machine-readable diffs** — JSON/MD/HTML/SARIF diff formats
- **Trend analysis** — Mann-Kendall statistical trends, security scoring
- **SLSA attestation** — Sigstore keyless signing, Rekor transparency log
- **Policy-as-Code** — OPA 1.0+ with Rego v1 syntax
- **AI remediation** — MCP server for Copilot/Claude integration
- **Cross-tool deduplication** — Similarity clustering, 30-40% noise reduction

---

## Contributing

Want to help? Check out:

- **Good First Issues:** [github.com/jimmy058910/jmo-security-repo/labels/good first issue](https://github.com/jimmy058910/jmo-security-repo/labels/good%20first%20issue)
- **Help Wanted:** [github.com/jimmy058910/jmo-security-repo/labels/help wanted](https://github.com/jimmy058910/jmo-security-repo/labels/help%20wanted)
- **Contributing Guide:** [CONTRIBUTING.md](CONTRIBUTING.md)

---

## Feedback

- **GitHub Discussions:** Share feedback and ideas
- **Feature Requests:** Open an issue with the `enhancement` label

---

**Last Updated:** February 2026
**Maintained By:** Jimmy ([@jimmy058910](https://github.com/jimmy058910))
