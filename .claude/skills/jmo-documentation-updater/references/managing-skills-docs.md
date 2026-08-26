# Managing Skills Documentation

Referenced from the main [SKILL.md](../SKILL.md).

## Documentation Standards for Skills

`.claude/*` is ignored by default, but `.gitignore` re-includes an explicit
allowlist: contributor skills, the agents, and `rules/` are **tracked and ship
to every clone**. Maintainer-only skills stay ignored. Check which side a file
is on before assuming it is local — `git ls-files .claude/` is the answer, and
`scripts/dev/check_doc_links.py` fails CI if tracked documentation links to
anything the allowlist leaves out.

Skill documentation files (SKILL.md, README.md) should:

1. **Pass markdownlint checks** -- Skills teach documentation best practices; they must be exemplary. This applies to tracked skills whether or not you remember they are tracked: markdownlint runs over `.claude/` in CI and pre-commit
2. **Follow Perfect Documentation Structure** -- Same principles as main repo docs
3. **Include working examples** -- Test all commands before committing
4. **Use relative links** -- Enable offline/fork compatibility. Count the depth from the file itself: a `SKILL.md` reaches the repo root with `../../../`, and a file under `references/` needs `../../../../`
5. **Link only to tracked paths** -- A link to `dev-only/` or to an unpublished skill resolves on a maintainer's disk and nowhere else, which is worse than no link at all

## When to Update Skill Documentation

Update skill files when:

- **Skill behavior changes** -- New features, changed workflows, deprecated patterns
- **Repository structure changes** -- New doc locations, renamed files, updated .gitignore paths
- **Documentation policies change** -- New rules in CLAUDE.md, updated Perfect Documentation Structure
- **Examples become outdated** -- Commands change, file paths move, tools update
- **Linting issues found** -- Fix immediately to maintain exemplary status

## Skill Self-Improvement Pattern

Skills should be self-aware and self-correcting:

```bash
# Step 1: Detect issues in own documentation
pre-commit run markdownlint --files .claude/skills/jmo-documentation-updater/SKILL.md

# Step 2: Fix ALL violations
# ... edit file ...

# Step 3: Verify fixes
pre-commit run markdownlint --files .claude/skills/jmo-documentation-updater/SKILL.md

# Step 4: record the change in the repository CHANGELOG.md, if it is
#         user-visible. Skills do not keep their own changelogs.
```

> **Skill files carry no changelog section, by decision.** Measured: none of the
> tracked skills or agents has one. A per-skill changelog would duplicate git
> history with no mechanism to keep it honest, and the earlier wording here
> stated a requirement that every file in the repository violated — which
> teaches contributors to ignore the rule rather than follow it. Skill history
> is `git log -- .claude/skills/<skill>/`; the repository `CHANGELOG.md` covers
> anything a *user* would notice.

## Files to Maintain in .claude/skills/

**MUST maintain:**

- `SKILL.md` -- Comprehensive skill instructions
- `README.md` -- Brief skill overview and quick reference (if exists)

**Can create (temporary):**

- Auto-fix scripts in `/tmp/`
- Test outputs for verification

**Do NOT create:**

- Session summaries
- Execution logs (put anything durable in the repository `CHANGELOG.md`)
- Duplicate documentation (consolidate into SKILL.md)
