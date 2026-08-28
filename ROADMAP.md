# JMo Security Suite — Roadmap

**Strategic Focus:** Community growth, developer experience, enterprise adoption

---

## Current Status

**Latest Stable Release:** v1.0.8 (August 2026)

The project ships on a **patch cadence** — each release hardens what is already
there rather than accumulating toward a version milestone. The next release is
v1.0.9. There is no v1.1.0 in flight; features that would once have been held
for one now ship in the next patch.

v1.0 delivers the full production scanning platform:

- 28 security scanners with unified CLI
- SQLite historical storage with trend analysis
- Machine-readable diffs for CI/CD integration
- Policy-as-Code (OPA integration)
- SLSA attestation for supply chain security
- MCP server for AI-assisted remediation
- React dashboard with interactive filtering
- Cross-tool deduplication (similarity clustering into consensus findings)

**Documentation:** [CHANGELOG.md](CHANGELOG.md) is the authoritative record of
what shipped in which release. This file covers only what has *not* shipped yet.

---

## Planned

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

## Future

**Theme:** Enterprise and advanced features. Larger than a patch — these need a
design pass before they are schedulable.

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

Every shipped feature lives in [CHANGELOG.md](CHANGELOG.md), release by release —
it is not duplicated here, so there is nothing to keep in sync.

Highlights of the v1.0 line:

- **28 security scanners** — Unified CLI orchestrating tools across 6 scan types
- **Metadata wrapper** — Standardized `{"meta": {...}, "findings": [...]}` output
- **CSV reporter** — Spreadsheet-friendly export for compliance workflows
- **HTML dashboard dual-mode** — Inline (<=1000) or external JSON (>1000 findings)
- **Machine-readable diffs** — JSON/MD/HTML/SARIF diff formats
- **Trend analysis** — Mann-Kendall statistical trends, security scoring
- **SLSA attestation** — Sigstore keyless signing, Rekor transparency log
- **Policy-as-Code** — OPA 1.0+ with Rego v1 syntax
- **AI remediation** — MCP server for Copilot/Claude integration
- **Cross-tool deduplication** — Similarity clustering into consensus findings
- **Scan accounting** — every declared tool lands in exactly one accounted state,
  so a tool can no longer vanish between running and reporting (v1.0.8)

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

**Last Updated:** August 2026 (v1.0.8)
**Maintained By:** Jimmy ([@jimmy058910](https://github.com/jimmy058910))
