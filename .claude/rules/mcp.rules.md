---
title: MCP Server (Security Findings API)
paths:
  - scripts/jmo_mcp/**/*.py
  # tests/jmo_mcp/ by directory, NOT by filename: none of its ten test files
  # has "mcp" in its name (test_auth, test_rate_limiter, test_server_*, ...),
  # so a `test_*mcp*.py` glob matched 0 of them and this rule would have been
  # inert for the entire MCP suite. The line below still catches the two that
  # do carry the substring, in tests/cli/.
  - tests/jmo_mcp/**/*.py
  - tests/**/test_*mcp*.py
references:
  - scripts/jmo_mcp/jmo_server.py (all entry points)
  - jmo.suppress.yml (mark_resolved writes here)
---

# MCP Server Rules

**What this covers:** the shipped `@mcp.tool()` surface and the measured state of
each entry point. Ask `get_server_info()` for `authentication_enforced` rather
than inferring it.

## MCP Server (Security Findings API)

Five `@mcp.tool()` entry points plus one `@mcp.resource`, all in
`scripts/jmo_mcp/jmo_server.py`. **stdio transport only, and callers are not
authenticated** — `JMO_MCP_API_KEYS` is hashed at import and compared against
nothing, so no setting turns access control on. Ask `get_server_info()` for
`authentication_enforced` rather than inferring it.

| Entry point | State |
|---|---|
| `get_security_findings` | working — filters + pagination; page with the **returned** `limit`, not the requested one |
| `query_findings_db` | working — read-only SQL (`mode=ro` + statement validation, both verified) |
| `get_finding_context` (`finding://{id}`) | working — `related_findings` is always `[]` |
| `get_server_info` | working |
| `apply_fix` | **preview only.** `dry_run=False` writes nothing and returns `success: False`; deferred past v1.1.0 (#951) |
| `mark_resolved` | working — appends an id-keyed entry to `jmo.suppress.yml`. Entries **always expire** (90d default, 365 cap), and `resolution="fixed"` writes nothing by design |
