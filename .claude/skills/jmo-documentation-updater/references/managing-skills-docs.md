# Managing Skills Documentation

Referenced from the main [SKILL.md](../SKILL.md).

## Documentation Standards for Skills

Even though `.claude/skills/` is gitignored, skill documentation files (SKILL.md, README.md) should:

1. **Pass markdownlint checks** -- Skills teach documentation best practices; they must be exemplary
2. **Follow Perfect Documentation Structure** -- Same principles as main repo docs
3. **Include working examples** -- Test all commands before committing
4. **Use relative links** -- Enable offline/fork compatibility
5. **Document their own changes** -- Maintain changelog section for transparency

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

# Step 4: Document self-improvement in Changelog
```

## Files to Maintain in .claude/skills/

**MUST maintain:**

- `SKILL.md` -- Comprehensive skill instructions
- `README.md` -- Brief skill overview and quick reference (if exists)

**Can create (temporary):**

- Auto-fix scripts in `/tmp/`
- Test outputs for verification

**Do NOT create:**

- Session summaries
- Execution logs (document in Changelog instead)
- Duplicate documentation (consolidate into SKILL.md)
