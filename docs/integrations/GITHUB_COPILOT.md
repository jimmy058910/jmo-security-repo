# GitHub Copilot Integration Guide

Connect GitHub Copilot to JMo Security's MCP server for AI-powered security
remediation directly in VS Code.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Installation Methods](#installation-methods)
  - [Method 1: Local Python Installation](#method-1-local-python-installation)
  - [Method 2: Docker Container](#method-2-docker-container)
  - [Method 3: Package Managers (WinGet/Homebrew)](#method-3-package-managers-wingethomebrew)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [Troubleshooting](#troubleshooting)
- [Advanced Configuration](#advanced-configuration)

---

## Overview

The JMo Security MCP server provides GitHub Copilot with direct access to
security scan results, enabling:

- **Query Findings**: Ask Copilot "What are the HIGH severity findings in
  src/api?"

- **Get Context**: Request full source code context around vulnerabilities
- **Fix Suggestions**: Get AI-generated remediation suggestions with
  confidence scores

- **Track Resolutions**: Mark findings as fixed, false positive, or
  accepted risk

**Architecture:**

```text
┌─────────────────┐      MCP Protocol      ┌──────────────────┐
│ GitHub Copilot  │ ←─────────────────────→ │  JMo MCP Server  │
│   (VS Code)     │      (stdio/JSON-RPC)   │  (FastMCP)       │
└─────────────────┘                         └──────────────────┘
                                                      │
                                                      ↓
                                            ┌──────────────────┐
                                            │  results/        │
                                            │  findings.json   │
                                            └──────────────────┘
```

---

## Prerequisites

### Required

- **GitHub Copilot Subscription**: Individual, Business, or Enterprise
- **VS Code**: Version 1.85.0 or later
- **GitHub Copilot Extension**: Version 1.140.0 or later (MCP support)

### Optional (depending on installation method)

- **Python 3.10+**: For local installation
- **Docker**: For containerized deployment
- **WinGet (Windows)** or **Homebrew (macOS/Linux)**: For package manager
  installation

### Verify GitHub Copilot MCP Support

```bash
# In VS Code, open Command Palette (Ctrl+Shift+P / Cmd+Shift+P)
# Type: "Copilot: Check MCP Support"
# Expected: "MCP protocol supported (v1.0.0+)"
```

If MCP is not supported, update GitHub Copilot extension:

```text
Extensions → GitHub Copilot → Update
```

---

## Quick Start

### 1. Run a Security Scan

First, generate findings for Copilot to analyze:

```bash
# Interactive wizard (recommended for first-time users)
jmo wizard

# Or quick scan
jmo fast --repo ./myapp
```

This creates `results/summaries/findings.json` that the MCP server will read.

### 2. Configure GitHub Copilot MCP

Create or edit `.vscode/mcp.json` in your project:

```json
{
  "mcpServers": {
    "jmo-security": {
      "command": "jmo",
      "args": ["mcp-server", "--results-dir", "./results", "--repo-root", "."],
      "env": {
        "MCP_LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### 3. Reload VS Code

```text
Command Palette → Developer: Reload Window
```

### 4. Verify Connection

Open GitHub Copilot Chat and ask:

```text
@jmo-security How many security findings do we have?
```

**Expected Response:**

```text
The JMo Security scan found 23 findings:
- 3 CRITICAL
- 7 HIGH
- 10 MEDIUM
- 3 LOW
```

---

## Installation Methods

Choose the method that matches how you installed JMo Security.

### Method 1: Local Python Installation

**When to use:** You installed JMo via `pip install jmo-security` or
`uv add jmo-security`.

#### Setup Instructions

**Step 1: Verify JMo CLI is accessible:**

```bash
jmo --help
# Should show CLI help output
```

**Step 2: Install MCP dependencies (if not already installed):**

```bash
pip install jmo-security[mcp]
# Or with uv:
uv pip install jmo-security[mcp]
```

**Step 3: Create MCP configuration in `.vscode/mcp.json`:**

```json
{
  "mcpServers": {
    "jmo-security": {
      "command": "jmo",
      "args": ["mcp-server"],
      "cwd": "${workspaceFolder}",
      "env": {
        "MCP_RESULTS_DIR": "${workspaceFolder}/results",
        "MCP_REPO_ROOT": "${workspaceFolder}",
        "MCP_LOG_LEVEL": "INFO"
      }
    }
  }
}
```

**Step 4: Test the server manually (optional):**

```bash
jmo mcp-server --results-dir ./results --repo-root .
# Should output: "Starting JMo Security MCP Server..."
# Press Ctrl+C to stop
```

**Step 5: Reload VS Code and verify:**

```text
Command Palette → Developer: Reload Window
```

Ask Copilot: `@jmo-security get_server_info`

---

### Method 2: Docker Container

**When to use:** You prefer containerized deployment or don't want to install
Python locally.

#### Docker Setup

**Step 1: Pull the JMo Security Docker image:**

```bash
docker pull ghcr.io/jimmy058910/jmo-security:latest
```

**Step 2: Run a scan to generate findings:**

```bash
docker run --rm \
  -v "$(pwd):/scan" \
  ghcr.io/jimmy058910/jmo-security:latest \
  fast --repo /scan --results-dir /scan/results
```

**Step 3: Create MCP configuration in `.vscode/mcp.json`:**

```json
{
  "mcpServers": {
    "jmo-security": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "-v", "${workspaceFolder}:/workspace",
        "-e", "MCP_RESULTS_DIR=/workspace/results",
        "-e", "MCP_REPO_ROOT=/workspace",
        "ghcr.io/jimmy058910/jmo-security:latest",
        "mcp-server",
        "--results-dir", "/workspace/results",
        "--repo-root", "/workspace"
      ]
    }
  }
}
```

**Key Docker Notes:**

- `-i`: Required for stdio transport (MCP uses stdin/stdout)
- `--rm`: Auto-removes container after exit
- `-v`: Mounts workspace to `/workspace` in container
- Environment variables propagate to MCP server

**Step 4: Test Docker connectivity:**

```bash
docker run --rm -i \
  -v "$(pwd):/workspace" \
  ghcr.io/jimmy058910/jmo-security:latest \
  mcp-server --results-dir /workspace/results --repo-root /workspace
# Should start server, press Ctrl+C to stop
```

**Step 5: Reload VS Code and verify.**

---

### Method 3: Package Managers (WinGet/Homebrew)

#### Windows (WinGet)

**Installation:**

```powershell
# Install JMo Security
winget install JMoSecurity

# Verify installation
jmo --version
```

**MCP Configuration (`.vscode/mcp.json`):**

```json
{
  "mcpServers": {
    "jmo-security": {
      "command": "jmo.exe",
      "args": ["mcp-server", "--results-dir", ".\\results", "--repo-root", "."],
      "cwd": "${workspaceFolder}",
      "env": {
        "MCP_LOG_LEVEL": "INFO"
      }
    }
  }
}
```

**Windows-Specific Notes:**

- Use `jmo.exe` as command (explicit .exe extension)
- Use backslashes `\\` for Windows paths in JSON
- Verify `jmo.exe` is in PATH: `where jmo`

#### macOS/Linux (Homebrew)

**Installation:**

```bash
# Add JMo Security tap
brew tap jimmy058910/jmo-security

# Install
brew install jmo-security

# Verify
jmo --version
```

**MCP Configuration (`.vscode/mcp.json`):**

```json
{
  "mcpServers": {
    "jmo-security": {
      "command": "jmo",
      "args": ["mcp-server", "--results-dir", "./results", "--repo-root", "."],
      "cwd": "${workspaceFolder}",
      "env": {
        "MCP_LOG_LEVEL": "INFO"
      }
    }
  }
}
```

**Homebrew Notes:**

- Installs to `/usr/local/bin/jmo` (Intel) or
  `/opt/homebrew/bin/jmo` (Apple Silicon)

- Automatically adds to PATH
- Updates via `brew upgrade jmo-security`

---

## Configuration

### MCP Configuration Options

The `.vscode/mcp.json` file supports these fields:

```json
{
  "mcpServers": {
    "jmo-security": {
      "command": "jmo",                    // Binary/script to execute
      "args": ["mcp-server", "..."],       // CLI arguments
      "cwd": "${workspaceFolder}",         // Working directory
      "env": {                             // Environment variables
        "MCP_RESULTS_DIR": "./results",    // Path to scan results
        "MCP_REPO_ROOT": ".",              // Repository root
        "MCP_LOG_LEVEL": "INFO",           // Logging: DEBUG|INFO|WARN|ERROR
        "MCP_API_KEY": "<optional>"        // API key (for production mode)
      }
    }
  }
}
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_RESULTS_DIR` | `./results` | Directory with findings.json |
| `MCP_REPO_ROOT` | `.` | Repository root for code context |
| `MCP_LOG_LEVEL` | `INFO` | Log level (DEBUG/INFO/WARN/ERROR) |
| `MCP_API_KEY` | *(none)* | Optional API key |

### VS Code Variables

The MCP configuration supports VS Code variables:

- `${workspaceFolder}` - Absolute path to workspace root
- `${workspaceFolderBasename}` - Workspace folder name
- `${file}` - Current file absolute path
- `${relativeFile}` - Current file relative to workspace
- `${fileBasename}` - Current file name

**Example with variables:**

```json
{
  "mcpServers": {
    "jmo-security": {
      "command": "jmo",
      "args": ["mcp-server"],
      "cwd": "${workspaceFolder}",
      "env": {
        "MCP_RESULTS_DIR": "${workspaceFolder}/results",
        "MCP_REPO_ROOT": "${workspaceFolder}"
      }
    }
  }
}
```

---

## Usage Examples

### Basic Queries

**Get server status:**

```text
@jmo-security What's the server status?
```

**Query all findings:**

```text
@jmo-security Show me all security findings
```

**Filter by severity:**

```text
@jmo-security What are the CRITICAL and HIGH severity findings?
```

**Filter by tool:**

```text
@jmo-security Show me all semgrep findings
```

**Filter by file:**

```text
@jmo-security What findings are in src/api/auth.py?
```

### Advanced Queries

**Get full context for a finding:**

```text
@jmo-security Get full context for finding fingerprint-abc123
```

**Request fix suggestion:**

```text
@jmo-security Suggest a fix for the XSS vulnerability in src/app.js line 42
```

**Mark finding resolved:**

```text
@jmo-security Mark finding fingerprint-abc123 as false_positive with
  comment "This is test code"
```

**Severity distribution:**

```text
@jmo-security What's the severity distribution of our findings?
```

### Workflow Examples

#### Example 1: Investigating a Specific Vulnerability

```text
User: @jmo-security Show me SQL injection findings
Copilot: Found 2 SQL injection findings:
  1. fingerprint-def456 in src/db.py:120 (CRITICAL)
  2. fingerprint-xyz789 in src/api/users.py:55 (HIGH)

User: @jmo-security Get full context for fingerprint-def456
Copilot: [Shows source code context with 20 lines around the vulnerability]

User: @jmo-security Suggest a fix with high confidence
Copilot: [Provides patch using parameterized queries, confidence: 0.95]
```

#### Example 2: Triaging Findings

```text
User: @jmo-security How many findings per severity?
Copilot: Severity distribution:
  - CRITICAL: 3
  - HIGH: 7
  - MEDIUM: 10
  - LOW: 5

User: @jmo-security Show me CRITICAL findings
Copilot: [Lists 3 CRITICAL findings with IDs and locations]

User: @jmo-security Mark fingerprint-ghi789 as risk_accepted with
  comment "Mitigated by WAF"
Copilot: ✅ Finding marked as risk_accepted
```

#### Example 3: Fixing Multiple Issues

```text
User: @jmo-security What XSS vulnerabilities do we have?
Copilot: Found 4 XSS findings in:
  - src/app.js:42
  - src/templates/user.html:15
  - src/api/search.py:88
  - src/components/Comment.tsx:120

User: @jmo-security For each XSS finding, suggest a fix and apply if
  confidence > 0.9
Copilot: [Generates fixes for all 4, applies 3 with confidence ≥0.9,
  flags 1 for manual review]
```

---

## Troubleshooting

### Connection Issues

**Problem:** Copilot doesn't recognize `@jmo-security`

**Solution:**

1. Check `.vscode/mcp.json` exists and is valid JSON
2. Reload VS Code: `Developer: Reload Window`
3. Check GitHub Copilot extension logs:

   ```text
   Output Panel → GitHub Copilot → MCP Connections
   ```

**Problem:** `ERROR: MCP SDK not installed`

**Solution:**

```bash
# Local Python install
pip install jmo-security[mcp]

# Or with Docker, ensure image has MCP support
docker pull ghcr.io/jimmy058910/jmo-security:latest
```

**Problem:** `ERROR: Scan results not found`

**Solution:**

```bash
# Run a scan first
jmo fast --repo . --results-dir ./results

# Verify findings.json exists
ls -la results/summaries/findings.json
```

### Docker-Specific Issues

**Problem:** `docker: Error response from daemon: invalid mount config`

**Solution:**

- Verify volume mount paths are absolute
- Use `$(pwd)` or `${PWD}` for current directory
- On Windows, use Git Bash or WSL for `$(pwd)` expansion

**Problem:** MCP server starts but Copilot can't connect

**Solution:**

- Ensure `-i` flag is present (interactive mode for stdio)
- Verify container has access to findings.json via volume mount
- Check Docker logs: `docker logs <container-id>`

### Permission Issues

**Problem:** Permission denied reading `results/summaries/findings.json`

**Solution:**

```bash
# Fix file permissions
chmod 644 results/summaries/findings.json
chmod 755 results/summaries

# Or regenerate with correct permissions
jmo fast --repo .
```

### Windows-Specific Issues

**Problem:** `'jmo' is not recognized as an internal or external command`

**Solution:**

1. Verify installation:

   ```powershell
   where jmo
   ```

2. Add to PATH if missing:

   ```powershell
   # Find Python Scripts directory
   python -m site --user-site
   # Add Scripts directory to PATH in System Properties
   ```

3. Use absolute path in `.vscode/mcp.json`:

   ```json
   "command": "C:\\Users\\<username>\\AppData\\Local\\Programs\\Python\\Python311\\Scripts\\jmo.exe"
   ```

---

## Advanced Configuration

### Multi-Repository Setup

If you scan multiple repositories, configure separate MCP servers:

```json
{
  "mcpServers": {
    "jmo-frontend": {
      "command": "jmo",
      "args": ["mcp-server"],
      "env": {
        "MCP_RESULTS_DIR": "${workspaceFolder}/frontend/results",
        "MCP_REPO_ROOT": "${workspaceFolder}/frontend"
      }
    },
    "jmo-backend": {
      "command": "jmo",
      "args": ["mcp-server"],
      "env": {
        "MCP_RESULTS_DIR": "${workspaceFolder}/backend/results",
        "MCP_REPO_ROOT": "${workspaceFolder}/backend"
      }
    }
  }
}
```

Query specific servers:

```text
@jmo-frontend Show me findings
@jmo-backend Show me findings
```

### Production Mode with API Key

For team deployments with authentication:

```json
{
  "mcpServers": {
    "jmo-security": {
      "command": "jmo",
      "args": ["mcp-server"],
      "env": {
        "MCP_API_KEY": "${env:JMO_API_KEY}",  // Read from environment
        "MCP_RESULTS_DIR": "./results",
        "MCP_REPO_ROOT": "."
      }
    }
  }
}
```

Set the API key in your shell:

```bash
export JMO_API_KEY="your-api-key-here"
```

### Custom Profiles

Run scans with different profiles, point MCP to specific results:

```bash
# Fast scan
jmo fast --repo . --results-dir ./results-fast

# Deep scan
jmo full --repo . --results-dir ./results-deep
```

Switch MCP configuration:

```json
{
  "mcpServers": {
    "jmo-fast": {
      "env": { "MCP_RESULTS_DIR": "./results-fast" }
    },
    "jmo-deep": {
      "env": { "MCP_RESULTS_DIR": "./results-deep" }
    }
  }
}
```

### Logging Configuration

Enable debug logging for troubleshooting:

```json
{
  "mcpServers": {
    "jmo-security": {
      "env": {
        "MCP_LOG_LEVEL": "DEBUG"
      }
    }
  }
}
```

View logs:

```bash
# MCP server logs to stderr
jmo mcp-server --results-dir ./results 2>&1 | tee mcp-server.log
```

---

## Next Steps

- **[Claude Code Integration](./CLAUDE_CODE.md)** - Set up JMo with Claude Code
- **[USER_GUIDE.md](../USER_GUIDE.md)** - Complete JMo Security documentation
- **[MCP Protocol Spec](https://spec.modelcontextprotocol.io/)** - Official MCP specification

## Support

- **Issues**: [GitHub Issues](https://github.com/jimmy058910/jmo-security-repo/issues)
- **Discussions**: [GitHub Discussions](https://github.com/jimmy058910/jmo-security-repo/discussions)
- **Documentation**: [docs.jmotools.com](https://docs.jmotools.com)
