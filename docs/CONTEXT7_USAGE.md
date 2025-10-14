# Context7 MCP - Quick Usage Guide

**TL;DR:** Context7 libraries are **automatic and on-demand**. Just say "use context7" in your prompt!

## How Context7 Works

Context7 maintains a **curated database of popular libraries** that is **already available** - you don't need to manually add libraries!

### What's Already Available

Context7 has **thousands of popular libraries** pre-indexed, including:

#### Security Tools (Relevant to This Project)
- ✅ **Semgrep** - SAST scanner
- ✅ **Trivy** - Container vulnerability scanner
- ✅ **Checkov** - IaC scanner
- ✅ **Bandit** - Python security linter
- ✅ **TruffleHog** - Secret scanner

#### Python Ecosystem
- ✅ **pytest** - Testing framework
- ✅ **black** - Code formatter
- ✅ **ruff** - Linter
- ✅ **mypy** - Type checker
- ✅ **PyYAML** - YAML parser
- ✅ **jsonschema** - JSON validation
- ✅ **subprocess** - Python stdlib

#### Container/DevOps
- ✅ **Docker** - Container platform
- ✅ **GitHub Actions** - CI/CD
- ✅ **Kubernetes** - Container orchestration

#### And Many More!
- Next.js, React, Vue, Angular
- Node.js, Express, FastAPI, Django
- PostgreSQL, MongoDB, Redis
- And 1000+ other popular libraries

## How to Use Context7

### Basic Pattern

**Simply add "use context7" to your prompt when asking about any supported library:**

```text
"How do I use pytest fixtures? use context7"
```

Context7 will:
1. Automatically detect you're asking about pytest
2. Fetch the latest pytest documentation
3. Inject it into the context
4. Claude responds with up-to-date information

### Real Examples for This Project

#### 1. Testing with pytest

```text
"How do I use pytest parametrize with fixtures? use context7"
"What's the syntax for pytest tmp_path fixture? use context7"
"Show me pytest mark.skip examples. use context7"
```

#### 2. Security Tool APIs

```text
"What's the JSON output format for Semgrep? use context7"
"How do I run Trivy with --severity flag? use context7"
"Show me Bandit configuration options. use context7"
```

#### 3. Python Standard Library

```text
"What's the secure way to use subprocess.run? use context7"
"How do I validate JSON with jsonschema? use context7"
"Show me PyYAML safe_load usage. use context7"
```

#### 4. Docker and CI/CD

```text
"What's the syntax for multi-stage Dockerfile? use context7"
"How do I configure GitHub Actions matrix builds? use context7"
"Show me Docker COPY vs ADD differences. use context7"
```

## What Context7 CANNOT Do

❌ **Upload your custom project documentation**
- Context7 only supports libraries in its public database
- It cannot learn from your CLAUDE.md, README.md, or custom docs

❌ **Index private repositories**
- Only public, popular libraries are supported

❌ **Store project-specific patterns**
- Your adapter pattern, CommonFinding schema, etc. are not in Context7

## How Your Project Docs Work

**Good news:** Your project documentation is **already provided** to Claude Code automatically through:

1. **CLAUDE.md** - Shown in system reminders
2. **Read tool** - Can read any file (README.md, USER_GUIDE.md, etc.)
3. **Glob/Grep tools** - Can search through your codebase

**No MCP needed for project docs!**

## When to Use What

| Scenario | Tool to Use | Example |
|----------|-------------|---------|
| External library API | Context7 | "How does pytest parametrize work? use context7" |
| Project architecture | Read tool | "Read CLAUDE.md to understand two-phase architecture" |
| Code navigation | Serena MCP | "Find all functions that construct CommonFinding" |
| Project configuration | Read tool | "Show me the jmo.yml profile structure" |
| GitHub operations | GitHub MCP | "Create an issue for osv-scanner support" |

## Advanced Context7 Features

### Version-Specific Queries

Context7 supports version-specific documentation:

```text
"Show me Next.js 14 server actions. use context7"
"What's new in pytest 8.x fixtures? use context7"
```

### Topic Filtering

You can focus on specific topics:

```text
"Show me pytest fixtures documentation. use context7"
"Explain Trivy vulnerability scanning. use context7"
```

## How Context7 Resolves Libraries

Behind the scenes, Context7:

1. **Resolves library name** → Context7 format
   - "pytest" → "/pytest-dev/pytest"
   - "semgrep" → "/semgrep/semgrep"
   - "trivy" → "/aquasecurity/trivy"

2. **Fetches documentation** from official sources
   - Latest version by default
   - Or specific version if requested

3. **Injects into context** for Claude to use

**You don't need to know the format - just use the library name!**

## Checking What's Available

To see if a library is in Context7's database:

```text
"Is <library-name> available in context7?"
```

Or just try using it:

```text
"How do I use <library-name>? use context7"
```

If not available, Context7 will let you know, and you can use web search or read official docs manually.

## Performance Tips

1. **Use sparingly for external libraries only**
   - ✅ "How does semgrep SARIF work? use context7"
   - ❌ "How does our adapter pattern work?" (use Read on CLAUDE.md)

2. **Be specific in your queries**
   - ✅ "Show me pytest parametrize decorator syntax. use context7"
   - ⚠️ "Tell me about pytest. use context7" (too broad)

3. **Combine with project knowledge**
   - "Read CLAUDE.md for adapter pattern, then use context7 for pytest best practices"

## Common Patterns for This Project

### Adding a New Tool Adapter

```text
"I'm adding a new adapter for <tool-name>.
Read scripts/core/adapters/gitleaks_adapter.py to see the pattern.
Then use context7 to show me <tool-name> JSON output format."
```

### Writing Tests

```text
"I need to write tests for the new adapter.
Read tests/adapters/test_gitleaks_adapter.py for the pattern.
Then use context7 to show me pytest fixture best practices."
```

### Updating CI/CD

```text
"I want to add a new GitHub Actions workflow.
Read .github/workflows/tests.yml to see our current setup.
Then use context7 to show me GitHub Actions matrix build syntax."
```

## Troubleshooting

### "Library not found" Error

**Solution:** The library may not be in Context7's database. Options:
1. Use web search to find official docs
2. Use the library's GitHub repository documentation
3. Ask without "use context7" and Claude will use training data

### Outdated Information Despite Context7

**Solution:**
1. Specify the version: "Show me pytest 8.x fixtures. use context7"
2. Check if the library is actively maintained
3. Verify the library name matches Context7's format

### Context7 Not Responding

**Solution:**
1. Check MCP server status: `/mcp` in Claude Code
2. Verify npx is installed: `npx --version`
3. Restart Claude Code
4. Check MCP Server logs in settings

## Summary

**Key Takeaways:**

1. ✅ **Context7 libraries are automatic** - No manual setup needed!
2. ✅ **Just say "use context7"** when asking about external libraries
3. ✅ **Thousands of libraries already available** (pytest, semgrep, trivy, etc.)
4. ❌ **Cannot upload custom docs** - Your project docs work differently
5. ✅ **Project docs via Read tool** - CLAUDE.md, README.md automatically available

**Simple Rule:**
- External library question → "use context7"
- Project-specific question → Use Read tool or ask directly

---

**Related Documentation:**
- [MCP_SETUP.md](MCP_SETUP.md) - Full MCP server setup guide
- [CLAUDE.md](../CLAUDE.md) - Project architecture and conventions
- [Context7 GitHub](https://github.com/upstash/context7) - Official Context7 docs

**Last Updated:** October 14, 2025
