# MCP Quick Reference Card

## One-page guide for developers using JMo Security's MCP server

---

## Quick Start (3 Steps)

```bash
# 1. Run a scan
jmo scan --repo . --profile-name fast

# 2. Add config file (choose your AI assistant)
# For GitHub Copilot: Create .vscode/mcp.json
# For Claude Code: Edit ~/.config/Claude/claude_desktop_config.json

# 3. Reload AI assistant
# Copilot: Ctrl+Shift+P → "Developer: Reload Window"
# Claude Code: Restart Claude Desktop app
```

---

## Installation Methods

| Method | Command | When to Use |
|--------|---------|-------------|
| **pip** | `pip install jmo-security[mcp]` | Local Python |
| **uv** | `uv pip install jmo-security[mcp]` | Fast install |
| **Docker** | `docker pull ghcr.io/jimmy058910/jmo-security` | Zero install |
| **WinGet** | `winget install jmo-security` | Windows |
| **Homebrew** | `brew install jmo-security` | macOS/Linux |

---

## Configuration Files

### GitHub Copilot (`.vscode/mcp.json`)

```json
{
  "mcpServers": {
    "jmo-security": {
      "command": "jmo",
      "args": ["mcp-server"],
      "env": {
        "MCP_RESULTS_DIR": "${workspaceFolder}/results",
        "MCP_REPO_ROOT": "${workspaceFolder}"
      }
    }
  }
}
```

### Claude Code (`~/.config/Claude/claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "jmo-security": {
      "command": "jmo",
      "args": ["mcp-server", "--results-dir", "./results", "--repo-root", "."],
      "cwd": "/path/to/your/project"
    }
  }
}
```

### Docker Configuration (Both Copilot & Claude)

```json
{
  "mcpServers": {
    "jmo-security": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "${workspaceFolder}:/workspace",
        "ghcr.io/jimmy058910/jmo-security:latest",
        "mcp-server", "--results-dir", "/workspace/results", "--repo-root", "/workspace"
      ]
    }
  }
}
```

---

## Common AI Queries

### Basic Queries

```text
@jmo-security What's the server status?
@jmo-security Show me all security findings
@jmo-security What are the CRITICAL and HIGH severity findings?
@jmo-security Show me all semgrep findings
@jmo-security What findings are in src/api/auth.py?
```

### Advanced Queries

```text
@jmo-security Get full context for finding fingerprint-abc123
@jmo-security Suggest fix for XSS in src/app.js line 42
@jmo-security What's the severity distribution of our findings?
@jmo-security Show me SQL injection findings
@jmo-security Mark fingerprint-abc123 as false_positive "Test code"
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_RESULTS_DIR` | `./results` | Directory with `findings.json` |
| `MCP_REPO_ROOT` | `.` | Repository root for code context |
| `MCP_LOG_LEVEL` | `INFO` | Log level (DEBUG/INFO/WARN/ERROR) |
| `MCP_API_KEY` | *(none)* | Optional API key for auth |
| `MCP_ENABLE_FIXES` | `false` | Enable write operations (`apply_fix`) |

---

## MCP Server CLI Commands

```bash
# Start MCP server manually (for testing)
jmo mcp-server --results-dir ./results --repo-root .

# With debug logging
jmo mcp-server --results-dir ./results --repo-root . --log-level DEBUG

# Enable write operations (apply_fix tool)
jmo mcp-server --results-dir ./results --repo-root . --enable-fixes

# Custom API key
jmo mcp-server --results-dir ./results --repo-root . --api-key YOUR_KEY
```

---

## Troubleshooting Checklist

| Problem | Solution |
|---------|----------|
| Copilot not recognizing `@jmo-security` | Check config, reload, view logs |
| `ERROR: MCP SDK not installed` | `pip install jmo-security[mcp]` |
| `ERROR: Scan results not found` | Run scan, verify findings.json exists |
| Docker connection fails | Check `-i` flag, verify volumes, check logs |
| Permission denied | `chmod 644 results/summaries/findings.json` |
| Windows: `jmo not found` | Check PATH, use `.exe` in config |

---

## MCP Tools Reference

| Tool | Purpose | Example Query |
|------|---------|---------------|
| `get_security_findings` | Query with filters | `Show HIGH in src/` |
| `get_finding_context` | Get code context | `Get context for abc123` |
| `apply_fix` | Apply AI patches | `Fix CWE-79 in app.js:42` |
| `mark_resolved` | Track remediation | `Mark as false_positive` |
| `get_server_info` | Server status | `Server status?` |

---

## Workflow Example

```text
# 1. Run scan
jmo scan --repo ~/myproject --profile-name balanced

# 2. Configure AI assistant
# Create .vscode/mcp.json (see above)

# 3. Reload AI assistant
# Copilot: Reload VS Code window

# 4. Query findings
User: @jmo-security Show me CRITICAL findings
Copilot: Found 3 CRITICAL findings:
  1. fingerprint-abc123 - SQL Injection in src/db.py:120
  2. fingerprint-def456 - XSS in src/app.js:42
  3. fingerprint-ghi789 - Path Traversal in src/upload.py:88

# 5. Get context
User: @jmo-security Get full context for fingerprint-abc123
Copilot: [Shows 20 lines of source code around vulnerability]

# 6. Request fix
User: @jmo-security Suggest a fix with high confidence
Copilot: Here's a secure fix using parameterized queries:
[Shows code patch with confidence: 0.95]

# 7. Apply fix manually
# Copy suggested code → Paste into editor → Save

# 8. Mark resolved
User: @jmo-security Mark finding fingerprint-abc123 as fixed
Copilot: ✅ Finding marked as fixed
```

---

## Key Design Principles

| Principle | Why It Matters |
|-----------|----------------|
| **MCP is optional** | Regular workflows work without MCP |
| **Read-only by default** | `apply_fix` needs `--enable-fixes` |
| **Local execution** | No data sent externally (privacy-first) |
| **AI runs MCP** | AI invokes `jmo mcp-server` automatically |
| **Scan first** | Always run `jmo scan` before MCP |

---

## Next Steps

- **Full Guides**:
  - [GitHub Copilot Integration](integrations/GITHUB_COPILOT.md)
  - [Claude Code Integration](integrations/CLAUDE_CODE.md)
- **User Guide**: [USER_GUIDE.md — AI Integration](USER_GUIDE.md#ai-integration)
- **Homepage**: <https://jmotools.com>
- **GitHub**: <https://github.com/jimmy058910/jmo-security-repo>

---

**Version**: v1.0.0 | **Last Updated**: 2025-01-XX | **License**: MIT
