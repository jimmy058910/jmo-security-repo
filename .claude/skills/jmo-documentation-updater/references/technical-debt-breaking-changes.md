# Technical Debt and Markdown Linting Patterns

Referenced from the main [SKILL.md](../SKILL.md).

## Core Principle: Fix ALL Issues

**CRITICAL RULE: When linting/validation fails, fix ALL issues found, not just new ones.**

### Why This Matters

1. **Compound Growth:** Technical debt grows exponentially if left unaddressed
2. **Boy Scout Rule:** Leave codebase better than you found it
3. **Future Cost:** Next contributor shouldn't fix your accumulated debt
4. **Real Problems:** Linting issues indicate actual problems:
   - **MD036** (emphasis as heading): Breaks screen readers (accessibility)
   - **MD032** (blanks around lists): Inconsistent rendering across platforms
   - **MD040** (code fence language): No syntax highlighting, copy errors

### Example Scenario

User adds new content to CHANGELOG.md and pre-commit finds 8 violations (2 new, 6 pre-existing):

**Wrong:** Fix only the 2 new violations.

**Correct:** Fix all 8 violations, then verify with `pre-commit run markdownlint --files CHANGELOG.md`.

## Common Markdown Linting Fixes

### MD036: Emphasis as Heading

```markdown
# Wrong
**Installation**

Some text here

# Correct
## Installation

Some text here
```

### MD032: Blank Lines Around Lists

```markdown
# Wrong
Here are the steps:
- Step 1
- Step 2
Continuing text.

# Correct
Here are the steps:

- Step 1
- Step 2

Continuing text.
```

### MD040: Code Fence Language

````markdown
# Wrong - no language specified
```
pip install jmo-security
```

# Correct - language specified
```bash
pip install jmo-security
```
````

### MD031: Blank Lines Around Code Fences

````markdown
# Wrong
Some text
```bash
code here
```
More text

# Correct
Some text

```bash
code here
```

More text
````

### MD033: Inline HTML

```markdown
# Wrong
<b>Important</b>: Read this.
<a href="https://example.com">Link</a>

# Correct
**Important**: Read this.
[Link](https://example.com)
```

## Linting Workflow

```bash
# 1. Make changes to documentation
vim docs/USER_GUIDE.md

# 2. Run markdownlint on changed file
pre-commit run markdownlint --files docs/USER_GUIDE.md

# 3. If violations found, fix ALL (not just new ones)

# 4. Re-run to verify
pre-commit run markdownlint --files docs/USER_GUIDE.md

# 5. Run on all markdown to catch related issues
pre-commit run markdownlint --all-files

# 6. Commit ONLY after all checks pass
git add docs/USER_GUIDE.md
git commit -m "docs: add AWS account scanning guide"
```
