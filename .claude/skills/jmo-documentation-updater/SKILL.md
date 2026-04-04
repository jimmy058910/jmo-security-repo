---
name: jmo-documentation-updater
description: Keep documentation synchronized with code changes by identifying which docs need updates and generating content. Use after adding features, making breaking changes, or when asked what docs need updating.
user-invocable: true
context: fork
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

## Purpose

This skill ensures documentation stays synchronized with code changes by identifying which docs need updates and generating appropriate content following JMo Security's "Perfect Documentation Structure" principles.

**Approach:** Accuracy over completeness. Better to update 3 documents correctly than touch 10 with guesses.

## When to Use

Use this skill when:

- Adding a new feature (adapter, target type, CLI flag, profile, output format)
- Making breaking changes to APIs or behavior
- Refactoring that affects user-facing workflows
- Asked "what docs need updating?"
- CI markdownlint failures after documentation changes
- User reporting outdated or inconsistent documentation
- Quick reference needed: See [dev-only/DOCUMENTATION_STRUCTURE.md](../../dev-only/DOCUMENTATION_STRUCTURE.md) for visual hierarchy

## Internal Reference Documentation (dev-only/)

These docs are gitignored and NOT part of user-facing documentation. They serve as internal reference for maintainers:

- **[dev-only/COMPREHENSIVE_FEATURE_GUIDE.md](../../dev-only/COMPREHENSIVE_FEATURE_GUIDE.md)** -- 40+ page technical reference (all CLI commands, tools, adapters, compliance frameworks)
- **[dev-only/QUICK_REFERENCE_SUMMARY.md](../../dev-only/QUICK_REFERENCE_SUMMARY.md)** -- 8-page executive summary
- **[dev-only/TESTING_AND_DEMO_PLAN.md](../../dev-only/TESTING_AND_DEMO_PLAN.md)** -- QA strategy (manual testing, demos, benchmarks)
- **[dev-only/DOCUMENTATION_INDEX.md](../../dev-only/DOCUMENTATION_INDEX.md)** -- Navigation hub

**Do NOT** link to dev-only docs from user-facing documentation or duplicate their content.

## Core Principle: User Journey-Based Documentation

Documentation is organized by **user persona and journey**, not by technical category:

| Persona | Entry Point | Update Trigger |
|---------|-------------|----------------|
| Complete Beginner | [DOCKER_README.md#quick-start](../../docs/DOCKER_README.md) or `jmo wizard` | Wizard, Docker, beginner workflows |
| Developer | [QUICKSTART.md](../../QUICKSTART.md) | Installation, basic commands, defaults |
| DevOps/SRE | [DOCKER_README.md](../../docs/DOCKER_README.md) | Docker variants, CI examples, env vars |
| Advanced User | [USER_GUIDE.md](../../docs/USER_GUIDE.md) | Config options, advanced features |
| Contributor | [CONTRIBUTING.md](../../CONTRIBUTING.md) | Dev tooling, testing, pre-commit, CI |

## Complete Documentation Structure

```text
/
├── README.md                          # First impression, value prop, quick nav (~400 lines)
├── QUICKSTART.md                      # 5-minute guide for ALL user types (~300 lines)
├── CONTRIBUTING.md                    # Contributor onboarding (~250 lines)
├── CHANGELOG.md                       # Version history (Keep-a-Changelog format)
├── ROADMAP.md                         # Future plans and milestones
├── TEST.md                            # Testing guide for contributors
├── DOCKER_HUB_README.md              # Docker Hub repository description (synced via release.yml)
└── docs/
    ├── index.md                       # Documentation hub (ALWAYS update when docs added/moved)
    ├── USER_GUIDE.md                  # Comprehensive reference (~800 lines)
    ├── RESULTS_GUIDE.md               # Example outputs from real scans
    ├── DOCKER_README.md               # Docker deep-dive (~400 lines)
    ├── CLI_REFERENCE.md               # CLI reference and wizard implementation details
    ├── PLATFORM_SPECIFIC.md           # Platform troubleshooting (macOS, Windows, WSL, Linux)
    ├── RELEASE.md                     # Release process for maintainers
    ├── MCP_SETUP.md                   # MCP server setup
    ├── examples/                      # Copy-paste ready examples
    ├── screenshots/                   # Screenshot capture guide
    └── schemas/
        └── common_finding.v1.json     # CommonFinding data schema
```

## Update Triggers

Each trigger type has a checklist of files to update and example content. For detailed templates with full examples, see [templates/doc-update-templates.md](templates/doc-update-templates.md).

| Trigger | Key Files | Template Section |
|---------|-----------|------------------|
| New Tool Adapter | README, QUICKSTART, CHANGELOG, docs/index.md, DOCKER_HUB_README | Section 1 |
| New CLI Flag | USER_GUIDE, QUICKSTART (if basic workflow), CHANGELOG | Section 2 |
| New Target Type | README, QUICKSTART, USER_GUIDE, CHANGELOG, CLAUDE.md | Section 3 |
| Breaking Change | CHANGELOG (migration guide), all affected docs, USER_GUIDE | Section 4 |
| New Output Format | README, QUICKSTART, USER_GUIDE, CHANGELOG, docs/RESULTS_GUIDE | Section 5 |
| Bug Fix | CHANGELOG, USER_GUIDE troubleshooting (if common issue) | Section 6 |
| Profile Change | README, QUICKSTART, USER_GUIDE, CHANGELOG | Section 7 |
| Docker Image Change | DOCKER_README, README, CHANGELOG, CI examples | Section 8 |
| Tool Count Change | DOCKER_HUB_README (2 locations), release.yml, README, CLAUDE.md | Section 9 |

## Technical Debt and Linting

When linting/validation fails, fix ALL issues found -- not just new ones. Common markdown lint rules (MD036, MD032, MD040, MD031, MD033) and the full fix workflow are documented in [references/technical-debt-breaking-changes.md](references/technical-debt-breaking-changes.md).

Key rule: Run `pre-commit run markdownlint --files <changed_files>` after every documentation change and fix every violation before committing.

## Documentation Cross-References

### Relative Link Best Practices

Always use relative links from repository root:

```markdown
# Correct (relative links)
[QUICKSTART.md](QUICKSTART.md)
[docs/USER_GUIDE.md](docs/USER_GUIDE.md)
[USER_GUIDE - Configuration](docs/USER_GUIDE.md#configuration-jmoyml)

# Wrong (absolute GitHub URLs - breaks in forks/offline)
[QUICKSTART.md](https://github.com/jimmy058910/jmo-security-repo/blob/main/QUICKSTART.md)
```

### Anchor Links

```markdown
# Header anchors: lowercase, hyphens, no special chars
# "AWS Account Scanning (v0.7.0)" -> #aws-account-scanning-v070
[AWS Scanning](docs/USER_GUIDE.md#aws-account-scanning-v070)
```

### Bi-Directional Links

Maintain navigation paths between related docs:

```text
README.md -> QUICKSTART.md -> docs/USER_GUIDE.md -> docs/examples/
(each links back to the previous)
```

## Files NOT to Create (Anti-Pattern)

These files are BANNED unless explicitly requested (each topic already has a canonical location):

| Banned File | Already Covered In |
|-------------|-------------------|
| ARCHITECTURE.md | CLAUDE.md |
| INSTALLATION.md | QUICKSTART.md |
| CONFIGURATION.md | USER_GUIDE.md |
| API.md | N/A (CLI tool, not library) |
| FAQ.md | docs/index.md |
| TUTORIAL.md | DOCKER_README (beginners), examples/ (specific) |
| DEVELOPMENT.md | CONTRIBUTING.md |
| BEGINNER_GUIDE.md | DOCKER_README #quick-start-absolute-beginners |

**Rationale:** Single source of truth for each topic avoids duplication, link rot, and user confusion. If content is missing, add it to the canonical location rather than creating a new file.

## Managing Skills Documentation

Skills documentation must practice what it preaches. Standards for maintaining skill files and the self-improvement workflow are in [references/managing-skills-docs.md](references/managing-skills-docs.md).

## Update Checklist

When making documentation changes:

- [ ] Identified trigger type (adapter, CLI flag, target type, breaking change, etc.)
- [ ] Updated docs/index.md if file added/moved/removed
- [ ] Updated CHANGELOG.md if user-facing change
- [ ] Verified all cross-references work (clicked links in preview)
- [ ] Checked for duplicate content (consolidated if found)
- [ ] Used relative links (no absolute GitHub URLs)
- [ ] Added section to table of contents if new major section
- [ ] Ran `pre-commit run markdownlint --files <changed_files>`
- [ ] Fixed ALL linting issues found (not just new ones)
- [ ] Verified examples are copy-pasteable (tested commands)
- [ ] Updated CLAUDE.md if documentation structure changed significantly
- [ ] Checked affected user persona journeys still make sense
- [ ] No new files created that duplicate existing docs

## Example Workflow

**Scenario:** User adds Snyk adapter for dependency scanning.

1. **Identify trigger:** New tool adapter, balanced + deep profiles, requires auth token
2. **Determine files:** README.md (tool table), QUICKSTART.md (example), CHANGELOG.md, docs/index.md (tool count), docs/USER_GUIDE.md (auth config)
3. **Generate content:** Use templates from [templates/doc-update-templates.md](templates/doc-update-templates.md) Section 1
4. **Run linting:** `pre-commit run markdownlint --files README.md QUICKSTART.md CHANGELOG.md docs/index.md docs/USER_GUIDE.md`
5. **Fix ALL violations** (new and pre-existing)
6. **Verify and commit:** `git commit -m "docs: add Snyk adapter documentation"`

## Trigger Patterns

Use this skill when you see these phrases:

- "Update documentation for [feature]"
- "Document [new functionality]"
- "Fix documentation for [topic]"
- "Documentation is outdated"
- "Which documentation file should this go in?"

## Notes

- **Documentation is part of the feature:** Incomplete docs = incomplete feature
- **Technical debt prevention:** Fix ALL linting issues, not just new ones
- **User journey matters:** Organize by persona, not technical structure
- **Single source of truth:** Each topic has ONE canonical location
- **Relative links always:** Breaks in forks/offline otherwise
- **Examples must work:** Test every command before committing
- **Accessibility matters:** Screen readers rely on proper heading hierarchy
