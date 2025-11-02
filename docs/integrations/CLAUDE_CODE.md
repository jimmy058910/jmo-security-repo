# JMo Security + Claude Code Integration Guide

Complete guide for integrating JMo Security's MCP server with Claude Code
for AI-powered security remediation.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Installation Methods](#installation-methods)
  - [Method 1: Local Python Installation](#method-1-local-python-installation)
  - [Method 2: Docker Container](#method-2-docker-container)
  - [Method 3: Package Managers](#method-3-package-managers-winget-homebrew)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [Troubleshooting](#troubleshooting)
- [Advanced Configuration](#advanced-configuration)

## Overview

JMo Security's MCP server enables Claude Code to:

- **Query security findings** from your scan results with filters
- **Analyze vulnerable code** with full source context
- **Suggest fixes** based on industry best practices
- **Track remediation status** across findings

**Architecture:**

```text
┌─────────────────┐     MCP Protocol      ┌──────────────────┐
│  Claude Code    │ ◄─────(stdio)───────► │  JMo MCP Server  │
│  (Terminal UI)  │                       │                  │
└─────────────────┘                       └──────────────────┘
                                                     │
                                                     ▼
                                          ┌──────────────────┐
                                          │  JMo Results     │
                                          │  - findings.json │
                                          │  - Source code   │
                                          └──────────────────┘
```

**Key Features:**

- **Terminal-native workflow** - Works seamlessly in your terminal with
  Claude Code
- **Context-aware suggestions** - AI analyzes 20 lines of context around
  each finding
- **Multi-framework compliance** - Maps findings to OWASP, CWE, NIST CSF,
  PCI DSS, CIS Controls, MITRE ATT&CK
- **Flexible deployment** - Local Python, Docker, or system package managers

## Prerequisites

### Required

1. **Claude Code CLI** - [Download from Anthropic](https://claude.ai/code)
2. **JMo Security scan results** - Run a scan first:

   ```bash
   # Run a scan to generate results
   jmo scan --repo . --profile-name balanced

   # Verify findings.json exists
   ls -la results/summaries/findings.json
   ```

3. **One of these installation methods:**
   - Python 3.10+ with pip/uv
   - Docker
   - WinGet (Windows) or Homebrew (macOS/Linux)

### Verify Prerequisites

```bash
# Check Claude Code
claude --version
# Should show: claude-code v1.x.x or similar

# Check JMo results
ls results/summaries/findings.json
# Should exist after running a scan

# Check Python version (if using local installation)
python3 --version
# Should show: Python 3.10.x or higher
```

## Quick Start

**3-step setup for terminal-based AI remediation:**

1. **Install JMo Security** (choose one method below)
2. **Configure Claude Code** (add MCP server to config)
3. **Start using AI remediation** (query findings, get fixes)

## Installation Methods

### Method 1: Local Python Installation

**Using pip:**

```bash
# Install JMo Security with MCP support
pip install jmo-security[mcp]

# Verify installation
jmo mcp-server --help
```

**Using uv (recommended for faster installs):**

```bash
# Install uv if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create virtual environment and install
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
uv pip install jmo-security[mcp]

# Verify installation
jmo mcp-server --help
```

**Configure Claude Code:**

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "jmo-security": {
      "command": "jmo",
      "args": ["mcp-server", "--results-dir", "./results", "--repo-root", "."],
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

**Note:** Claude Code configuration file locations:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

### Method 2: Docker Container

**Best for:** Users without Python installed, containerized workflows,
CI/CD integration.

**Prerequisites:**

- Docker installed and running
- Docker image pulled: `ghcr.io/jimmy058910/jmo-security:latest`

**Pull Image:**

```bash
docker pull ghcr.io/jimmy058910/jmo-security:latest
```

**Configure Claude Code:**

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "jmo-security": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "${workspaceFolder}:/workspace",
        "ghcr.io/jimmy058910/jmo-security:latest",
        "mcp-server",
        "--results-dir", "/workspace/results",
        "--repo-root", "/workspace"
      ],
      "env": {
        "MCP_LOG_LEVEL": "INFO"
      }
    }
  }
}
```

**Important Docker Flags:**

- `-i` - Required for stdio MCP transport (interactive mode)
- `--rm` - Cleanup container after exit
- `-v ${workspaceFolder}:/workspace` - Mount your project directory

**Test Docker Setup:**

```bash
# Test Docker MCP server manually
docker run --rm -i \
  -v $(pwd):/workspace \
  ghcr.io/jimmy058910/jmo-security:latest \
  mcp-server --results-dir /workspace/results --repo-root /workspace
```

### Method 3: Package Managers (WinGet, Homebrew)

**Windows (WinGet):**

```powershell
# Install JMo Security
winget install jimmy058910.jmo-security

# Verify installation
jmo --version

# Install MCP support
pip install mcp[cli]
```

**macOS/Linux (Homebrew):**

```bash
# Add tap (when available)
brew tap jimmy058910/jmo-security
brew install jmo-security

# Install MCP support
pip install mcp[cli]

# Verify installation
jmo --version
```

**Configure Claude Code:**

Same configuration as Method 1 (Local Python Installation).

## Configuration

### Basic Configuration

**Minimal setup** (uses current directory):

```json
{
  "mcpServers": {
    "jmo-security": {
      "command": "jmo",
      "args": ["mcp-server"]
    }
  }
}
```

**Defaults:**

- `--results-dir` defaults to `./results`
- `--repo-root` defaults to `.` (current directory)
- Logging level defaults to `INFO`

### Custom Paths Configuration

**Custom results directory:**

```json
{
  "mcpServers": {
    "jmo-security": {
      "command": "jmo",
      "args": [
        "mcp-server",
        "--results-dir", "/path/to/custom/results",
        "--repo-root", "/path/to/your/repo"
      ]
    }
  }
}
```

### Environment Variables

**Available environment variables:**

| Variable | Description | Default |
|----------|-------------|---------|
| `MCP_RESULTS_DIR` | Path to results directory | `./results` |
| `MCP_REPO_ROOT` | Path to repository root | `.` |
| `MCP_API_KEY` | Optional API key for authentication | None |
| `MCP_LOG_LEVEL` | Logging verbosity | `INFO` |

**Example with environment variables:**

```json
{
  "mcpServers": {
    "jmo-security": {
      "command": "jmo",
      "args": ["mcp-server"],
      "env": {
        "MCP_RESULTS_DIR": "/custom/results",
        "MCP_REPO_ROOT": "/custom/repo",
        "MCP_LOG_LEVEL": "DEBUG"
      }
    }
  }
}
```

## Usage Examples

### Basic Workflow

**1. Run a security scan:**

```bash
# Navigate to your project
cd /path/to/your/project

# Run JMo scan
jmo scan --repo . --profile-name balanced

# Verify results
cat results/summaries/findings.json
```

**2. Start Claude Code:**

```bash
# Start Claude Code in your terminal
claude

# MCP server auto-connects
```

**3. Query findings in Claude Code:**

```text
You: Show me all CRITICAL security findings

Claude: [Uses JMo MCP server to query findings]

Found 3 CRITICAL findings:
1. SQL Injection in src/db.py:120
   - Tool: semgrep
   - Rule: CWE-89
   - Confidence: HIGH

2. Hardcoded AWS Credentials in config/settings.py:8
   - Tool: trufflehog
   - Rule: secret-aws-key
   - Verified: true

3. ...
```

### Advanced Queries

**Filter by severity:**

```text
You: Show HIGH and CRITICAL findings in the authentication module

Claude: [Queries with filters: severity=["HIGH", "CRITICAL"], path="auth/"]
```

**Get detailed finding context:**

```text
You: Show me the full context for finding fingerprint-abc123

Claude: [Uses finding:// resource to get source code + remediation]

Finding: CWE-79 XSS in src/app.js:42
Severity: HIGH
Tool: semgrep

Source Code Context (lines 39-45):
```javascript
app.get('/user', (req, res) => {
  const userInput = req.query.name;
  // Vulnerable line
  res.send(`<h1>Hello, ${userInput}!</h1>`);  // CWE-79: XSS
});
```

Remediation:

- Use a sanitization library like DOMPurify
- Encode user input before rendering
- Set Content-Security-Policy headers

References:

- <https://owasp.org/www-community/attacks/xss/>
- <https://cwe.mitre.org/data/definitions/79.html>

```text

### Fix Suggestion Workflow

**Request AI-generated fix:**

```text
You: Suggest a fix for the XSS vulnerability in src/app.js:42

Claude: Here's a secure fix using output encoding:
```

```javascript
const escapeHtml = (unsafe) => {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
};

app.get('/user', (req, res) => {
  const userInput = req.query.name;
  const safeInput = escapeHtml(userInput);
  res.send(`<h1>Hello, ${safeInput}!</h1>`);
});
```

```text
This fix:

- Escapes HTML special characters
- Prevents script injection
- Maintains functionality
- Follows OWASP best practices

Confidence: 95%
```

### Bulk Analysis

**Analyze all findings by category:**

```text
You: Categorize all findings by OWASP Top 10 2021

Claude: [Queries all findings, groups by compliance.owaspTop10_2021]

OWASP Top 10 2021 Breakdown:
- A03:2021 (Injection): 12 findings
  - CWE-79 (XSS): 5 findings
  - CWE-89 (SQL Injection): 4 findings
  - CWE-78 (Command Injection): 3 findings

- A01:2021 (Broken Access Control): 8 findings
  - CWE-22 (Path Traversal): 5 findings
  - CWE-863 (Authorization Bypass): 3 findings

- A02:2021 (Cryptographic Failures): 6 findings
  - CWE-798 (Hardcoded Credentials): 4 findings
  - CWE-327 (Weak Crypto): 2 findings

Total: 26 findings across 3 OWASP categories
```

## Troubleshooting

### Connection Issues

**Problem:** Claude Code can't connect to MCP server

**Solutions:**

1. **Verify JMo installation:**

   ```bash
   jmo mcp-server --help
   # Should show usage without errors
   ```

2. **Check configuration file location:**

   ```bash
   # macOS
   cat ~/Library/Application\ Support/Claude/claude_desktop_config.json

   # Windows
   type %APPDATA%\Claude\claude_desktop_config.json

   # Linux
   cat ~/.config/Claude/claude_desktop_config.json
   ```

3. **Validate JSON syntax:**

   Use a JSON validator (e.g., `jq`) to check config:

   ```bash
   jq . < ~/Library/Application\ Support/Claude/claude_desktop_config.json
   ```

4. **Test server manually:**

   ```bash
   jmo mcp-server --results-dir ./results --repo-root .
   # Should start without errors, press Ctrl+C to exit
   ```

### Docker-Specific Issues

**Problem:** Docker container can't access scan results

**Solution:** Verify volume mount path:

```bash
# Check if results directory exists
ls -la results/summaries/findings.json

# Test Docker mount
docker run --rm -i \
  -v $(pwd):/workspace \
  ghcr.io/jimmy058910/jmo-security:latest \
  ls -la /workspace/results/summaries/findings.json
```

**Problem:** Docker stdio not working

**Solution:** Ensure `-i` flag is present:

```json
{
  "args": ["run", "--rm", "-i", ...]
}
```

### Missing Findings

**Problem:** "No findings found" but scan completed successfully

**Solutions:**

1. **Verify findings.json exists and has content:**

   ```bash
   cat results/summaries/findings.json
   # Should show JSON array of findings
   ```

2. **Check results directory path:**

   ```bash
   # In Claude Code config, verify paths match:
   ls -la ./results/summaries/findings.json
   ```

3. **Re-run scan:**

   ```bash
   jmo scan --repo . --profile-name balanced --human-logs
   ```

### Windows-Specific Issues

**Problem:** Path separators causing issues

**Solution:** Use forward slashes in config:

```json
{
  "args": ["mcp-server", "--results-dir", "./results", "--repo-root", "."]
}
```

**Problem:** WSL vs Windows paths

**Solution for WSL:**

```json
{
  "mcpServers": {
    "jmo-security": {
      "command": "wsl",
      "args": [
        "-e", "jmo", "mcp-server",
        "--results-dir", "/mnt/c/Users/You/projects/myapp/results",
        "--repo-root", "/mnt/c/Users/You/projects/myapp"
      ]
    }
  }
}
```

### Logging and Debugging

**Enable debug logging:**

```json
{
  "mcpServers": {
    "jmo-security": {
      "command": "jmo",
      "args": ["mcp-server"],
      "env": {
        "MCP_LOG_LEVEL": "DEBUG"
      }
    }
  }
}
```

**Check MCP server logs:**

```bash
# Logs go to stderr by default
jmo mcp-server 2> mcp-debug.log
```

## Advanced Configuration

### Multi-Repository Setup

**Managing multiple projects:**

Create project-specific configurations:

**Project 1 (web-app):**

```json
{
  "mcpServers": {
    "jmo-web-app": {
      "command": "jmo",
      "args": [
        "mcp-server",
        "--results-dir", "/path/to/web-app/results",
        "--repo-root", "/path/to/web-app"
      ]
    }
  }
}
```

**Project 2 (api-backend):**

```json
{
  "mcpServers": {
    "jmo-api-backend": {
      "command": "jmo",
      "args": [
        "mcp-server",
        "--results-dir", "/path/to/api-backend/results",
        "--repo-root", "/path/to/api-backend"
      ]
    }
  }
}
```

**Switch between projects in Claude Code:**

```text
You: Use jmo-web-app to show findings

Claude: [Connects to web-app MCP server]

You: Switch to jmo-api-backend

Claude: [Connects to api-backend MCP server]
```

### API Key Authentication (Future)

**When implemented in Phase 2:**

```json
{
  "mcpServers": {
    "jmo-security": {
      "command": "jmo",
      "args": ["mcp-server", "--api-key", "${API_KEY}"],
      "env": {
        "API_KEY": "your-api-key-here"
      }
    }
  }
}
```

### Custom Scan Profiles

**Run scan with custom profile before MCP analysis:**

```bash
# Create custom profile in jmo.yml
cat > jmo.yml <<EOF
profiles:
  ai-focused:
    tools: [semgrep, bandit, trufflehog, trivy]
    threads: 8
    timeout: 300
    per_tool:
      semgrep:
        flags: ["--config", "auto", "--exclude", "tests/"]
EOF

# Run scan with custom profile
jmo scan --repo . --profile-name ai-focused

# MCP server will use these results
```

### Continuous Scanning Workflow

**Automated scan + AI analysis:**

```bash
#!/bin/bash
# scan-and-analyze.sh

# 1. Run scan
jmo scan --repo . --profile-name balanced

# 2. Start Claude Code with MCP server
# (MCP server auto-starts via config)
claude

# 3. In Claude Code, run automated analysis:
# "Analyze all CRITICAL findings and suggest fixes"
```

### Integration with CI/CD

**GitHub Actions example:**

```yaml
name: Security Scan + AI Analysis

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run JMo Security Scan
        run: |
          pip install jmo-security[mcp]
          jmo scan --repo . --profile-name balanced

      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: jmo-results
          path: results/

      - name: AI Analysis (Optional)
        run: |
          # Use Claude Code API (when available) to analyze findings
          # For now, results are available for manual review
          cat results/summaries/SUMMARY.md
```

## Next Steps

1. **Explore MCP Resources:**
   - [MCP Specification](https://spec.modelcontextprotocol.io/)
   - [Anthropic MCP SDK](https://github.com/anthropics/mcp-sdk-python)

2. **Customize Your Workflow:**
   - Create custom scan profiles
   - Set up automated scans
   - Integrate with your CI/CD pipeline

3. **Provide Feedback:**
   - Report issues: [GitHub Issues](https://github.com/jimmy058910/jmo-security-repo/issues)
   - Feature requests: [Discussions](https://github.com/jimmy058910/jmo-security-repo/discussions)

4. **Stay Updated:**
   - Watch for Phase 2 features (automatic patching, PR generation)
   - Follow [ROADMAP.md](../../ROADMAP.md) for upcoming features

---

**Related Documentation:**

- [GitHub Copilot Integration](./GITHUB_COPILOT.md) - Similar setup for VSCode users
- [User Guide](../USER_GUIDE.md) - Complete JMo Security reference
- [Docker Guide](../DOCKER_README.md) - Docker deployment deep-dive
- [Quick Start](../../QUICKSTART.md) - 5-minute setup guide
