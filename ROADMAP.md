# JMo Security Suite — Roadmap

**Strategic Focus:** Community growth, developer experience, enterprise adoption

---

## Current Status

**Latest Release:** v1.0.0 (November 2025) — Production-Ready Platform

v1.0.0 delivered all core features for production security scanning:

- 28 security scanners with unified CLI
- SQLite historical storage with trend analysis
- Machine-readable diffs for CI/CD integration
- Policy-as-Code (OPA integration)
- SLSA attestation for supply chain security
- MCP server for AI-assisted remediation
- React dashboard with interactive filtering

**Documentation:** [CHANGELOG.md](CHANGELOG.md) for complete version history

---

## In Progress (v1.1.0)

**Theme:** Dashboard polish and accessibility

| Feature | Status | Description |
|---------|--------|-------------|
| KEV-first sorting | Done | Critical vulnerabilities (CISA KEV) always sorted first |
| Dual pagination | Done | Top and bottom pagination controls |
| Radix UI tooltips | Done | Accessible hover tooltips for truncated content |
| Simple HTML reporter | Done | Email-compatible static HTML (Gmail, Outlook, etc.) |

**Target:** Q1 2026

---

## Planned (v1.2.0+)

**Theme:** Developer experience and extensibility

| Feature | Priority | GitHub Issue |
|---------|----------|--------------|
| Plugin system for custom adapters | High | [#34](https://github.com/jimmy058910/jmo-security-repo/issues/34) |
| Homebrew + Winget packaging | High | TBD |
| Intelligent prioritization (EPSS/KEV scoring) | Medium | [#49](https://github.com/jimmy058910/jmo-security-repo/issues/49) |
| IDE integration (LSP) | Medium | [#52](https://github.com/jimmy058910/jmo-security-repo/issues/52) |
| Web UI for results viewing | Low | [#38](https://github.com/jimmy058910/jmo-security-repo/issues/38) |

---

## Completed Features (v1.0.0)

All v1.0.0 features are documented in [CHANGELOG.md](CHANGELOG.md#100---2025-11-10).

Key highlights:

- **Metadata wrapper** — Standardized `{"meta": {...}, "findings": [...]}` output
- **CSV reporter** — Spreadsheet-friendly export for compliance workflows
- **HTML dashboard dual-mode** — Inline (<=1000) or external JSON (>1000 findings)
- **Machine-readable diffs** — JSON/MD/HTML/SARIF diff formats
- **Trend analysis** — Mann-Kendall statistical trends, security scoring
- **SLSA attestation** — Sigstore keyless signing, Rekor transparency log
- **Policy-as-Code** — OPA 1.0+ with Rego v1 syntax
- **AI remediation** — MCP server for Copilot/Claude integration

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

**Last Updated:** December 2025
**Maintained By:** Jimmy ([@jimmy058910](https://github.com/jimmy058910))
