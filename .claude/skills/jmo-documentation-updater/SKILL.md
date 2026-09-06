---
name: jmo-documentation-updater
description: Keep documentation synchronized with code changes by identifying which docs need updates and generating content. Use after adding features, making breaking changes, or when asked what docs need updating.
user-invocable: true
context: fork
allowed-tools: Read, Write, Edit, Glob, Grep, Bash
---

## Purpose

This skill ensures documentation stays synchronized with code changes by identifying which docs need updates and generating appropriate content following § Complete Documentation Structure below.

**Approach:** Accuracy over completeness. Better to update 3 documents correctly than touch 10 with guesses.

## When to Use

Use this skill when:

- Adding a new feature (adapter, target type, CLI flag, profile, output format)
- Making breaking changes to APIs or behavior
- Refactoring that affects user-facing workflows
- Asked "what docs need updating?"
- CI markdownlint failures after documentation changes
- User reporting outdated or inconsistent documentation

## The dev-only/ Boundary

`dev-only/` is an untracked maintainer workspace. A contributor's clone does not
contain it, so **never link to a `dev-only/` path from anything tracked** and
never duplicate its content into user-facing docs. A link that resolves on the
maintainer's disk and nowhere else is worse than no link: it reads as a real
pointer and is a dead end for everyone who follows it.

`scripts/dev/check_doc_links.py` enforces this in CI and pre-commit -- it
resolves links against `git ls-files`, not against the local filesystem.

## Core Principle: User Journey-Based Documentation

Documentation is organized by **user persona and journey**, not by technical category:

| Persona | Entry Point | Update Trigger |
|---------|-------------|----------------|
| Complete Beginner | [DOCKER_README.md — Quick Start](../../../docs/DOCKER_README.md#quick-start-absolute-beginners) or `jmo wizard` | Wizard, Docker, beginner workflows |
| Developer | [QUICKSTART.md](../../../QUICKSTART.md) | Installation, basic commands, defaults |
| DevOps/SRE | [DOCKER_README.md](../../../docs/DOCKER_README.md) | Docker variants, CI examples, env vars |
| Advanced User | [USER_GUIDE.md](../../../docs/USER_GUIDE.md) | Config options, advanced features |
| Contributor | [CONTRIBUTING.md](../../../CONTRIBUTING.md) | Dev tooling, testing, pre-commit, CI |

## Complete Documentation Structure

**Complete Beginner**

- [docs/DOCKER_README.md](../../../docs/DOCKER_README.md) - Docker deep-dive; its Quick Start is the beginner path and the DevOps/SRE entry point

**Developer**

- [README.md](../../../README.md) - project overview, value proposition, and the supported-tools table
- [QUICKSTART.md](../../../QUICKSTART.md) - five-minute guide for every user type

**DevOps/SRE**

- [DOCKER_HUB_README.md](../../../DOCKER_HUB_README.md) - Docker Hub repository description, synced by release.yml
- [docs/examples/](../../../docs/examples/) - copy-paste CI/CD workflows and scan scripts

**Advanced User**

- [docs/USER_GUIDE.md](../../../docs/USER_GUIDE.md) - comprehensive reference: configuration, advanced features, troubleshooting
- [docs/PROFILES_AND_TOOLS.md](../../../docs/PROFILES_AND_TOOLS.md) - complete tool lists per profile and the selection philosophy
- [docs/RESULTS_GUIDE.md](../../../docs/RESULTS_GUIDE.md) - example outputs from real scans

**Contributor**

- [CHANGELOG.md](../../../CHANGELOG.md) - version history in Keep-a-Changelog format; every user-facing change lands here
- [docs/index.md](../../../docs/index.md) - documentation hub; update it when a doc is added, moved, or removed
- [CLAUDE.md](../../../CLAUDE.md) - agent context: architecture overview, guardrails, scan profiles

The full inventory is [docs/index.md](../../../docs/index.md).

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

Use relative links — but **relative to the file holding them, not to the
repository root.** Markdown resolves a link against its own file's directory,
so `[QUICKSTART.md](QUICKSTART.md)` written *here* points at
`.claude/skills/jmo-documentation-updater/QUICKSTART.md`, which does not exist.
`scripts/dev/check_doc_links.py` fails CI and pre-commit on exactly that.

Count the depth from the file itself. From a skill's `SKILL.md` the repo root
is three levels up; from a file under that skill's `references/` it is four:

```markdown
# Correct - from THIS file (.claude/skills/<skill>/SKILL.md)
[QUICKSTART.md](../../../QUICKSTART.md)
[docs/USER_GUIDE.md](../../../docs/USER_GUIDE.md)

# Correct - from a doc at the repository root
[QUICKSTART.md](QUICKSTART.md)

# Wrong (absolute GitHub URLs - breaks in forks/offline)
[QUICKSTART.md](https://github.com/jimmy058910/jmo-security-repo/blob/main/QUICKSTART.md)
```

The "Where to Start" table above is the worked example: every entry there
carries `../../../` for this reason.

### Anchor Links

Anchors are derived from the heading text: lowercased, spaces to hyphens,
punctuation dropped. Derive them from the **actual** heading — a plausible
guess is how you get a link that resolves to the top of the page instead:

Both examples below were checked against the real headings before being written
here, which is the whole point:

```markdown
# docs/DOCKER_README.md heading: "## Quick Start (Absolute Beginners)"
# -> parentheses dropped, spaces become hyphens
[Docker quick start](../../../docs/DOCKER_README.md#quick-start-absolute-beginners)

# docs/USER_GUIDE.md heading: "## Tool Management"
[Tool management](../../../docs/USER_GUIDE.md#tool-management)
```

Confirm the heading exists before writing the link:

```bash
grep -nE '^#{1,6} ' docs/USER_GUIDE.md | grep -i 'tool management'
```

> **`check_doc_links.py` validates the file, not the `#fragment`.** A wrong
> anchor is silent — it degrades to "jump to the top of the page", which looks
> like a working link.
>
> This is not hypothetical. The previous version of this very section cited
> `docs/USER_GUIDE.md#aws-account-scanning-v070`; that file has **no AWS heading
> at all**. A fabricated anchor sat inside the passage warning against
> fabricated anchors, and CI was green. Repo-wide there are **28** such links
> across 328 fragment links — so treat a `#fragment` as unverified until you
> have grepped for its heading.

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
