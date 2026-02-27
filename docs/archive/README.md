# Documentation Archive

This directory contains archived documentation from JMo Security.

## Archive Structure

```text
docs/archive/
├── README.md                  # This file - archive index
├── ROADMAP_pre-v1.0.0.md      # Original roadmap (outdated after v1.0.0 release)
└── merged/                    # Files consolidated during v1.0.0 unification
```

## Why Archive?

Documentation is archived when:

- **Consolidated**: Multiple overlapping documents merged into single authoritative sources
- **Superseded**: Content replaced by newer, more comprehensive documentation
- **Historical**: Version-specific documentation preserved for reference

## Archived Files

| File | Reason | Replacement |
|------|--------|-------------|
| `ROADMAP_pre-v1.0.0.md` | Outdated (referenced v0.8.0-dev, v1.0.0 target 2027) | New `ROADMAP.md` in repo root |

---

## v1.0.0 Documentation Unification

In December 2025, the documentation was unified to treat v1.0.0 as the definitive release.

### Files Consolidated (Not Archived)

The following files were **merged** into existing documents and deleted (not archived, as their content lives on):

| Deleted File | Merged Into |
|--------------|-------------|
| `DOCKER_VARIANTS_MASTER.md` | `DOCKER_README.md` |
| `OUTPUT_FORMATS.md` | `RESULTS_GUIDE.md` |
| `PLATFORM_SPECIFIC.md` | `MANUAL_INSTALLATION.md` |
| `packaging/TOOL_INSTALLATION.md` | `MANUAL_INSTALLATION.md` |
| `MCP_QUICK_REFERENCE.md` | `MCP_SETUP.md` |
| `scripts/dev/TELEMETRY_QUICK_REFERENCE.md` | `TELEMETRY.md` |
| `GIT_WORKFLOW.md` | `CONTRIBUTING.md` |

### Result

- **Before**: 14 overlapping documentation files
- **After**: 8 consolidated, authoritative documents

## Current Documentation

For current documentation, see [docs/index.md](../index.md).

---

**Last Updated:** February 2026
