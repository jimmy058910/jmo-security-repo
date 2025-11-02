# MCP Server Setup Guide

This guide explains how to set up and use Model Context Protocol (MCP) servers with Claude Code in the jmo-security-repo project.

## Overview

MCP servers extend Claude Code's capabilities by providing additional context and tools. This guide covers two types of MCP servers:

**JMo Security MCP Server** (provided by this project):
- **AI Remediation Orchestration** - Query security findings, apply fixes, track resolutions

**Third-Party MCP Servers** (optional integrations):
1. **Context7** - Up-to-date code documentation for libraries and frameworks
2. **GitHub** - GitHub API integration for repos, issues, PRs, and more
3. **Chrome DevTools** - Browser automation and debugging capabilities

## JMo Security MCP Server (AI Remediation)

The JMo Security MCP server enables AI-powered security remediation workflows. It provides tools for querying findings, applying fixes, and tracking resolutions.

### Features

- 🔍 **Query Security Findings** - Filter and paginate scan results
- 🔧 **Apply Fixes** - AI-suggested patches with dry-run preview
- ✅ **Track Resolutions** - Mark findings as resolved with reason
- 🛡️ **Rate Limiting** - Token bucket algorithm (100 req/min default)
- 🔐 **Authentication** - API key validation (optional, for production)

### Quick Start

**Development Mode (No Authentication):**

```bash
# Run MCP server with default settings
uv run mcp dev scripts/mcp/server.py

# Or via environment variables
export MCP_RESULTS_DIR=./results
export MCP_REPO_ROOT=.
uv run mcp dev scripts/mcp/server.py
```

**Production Mode (With Authentication + Rate Limiting):**

```bash
# Set API keys (comma-separated)
export JMO_MCP_API_KEYS="key1,key2,key3"

# Enable rate limiting (default: enabled)
export JMO_MCP_RATE_LIMIT_ENABLED="true"
export JMO_MCP_RATE_LIMIT_CAPACITY="100"        # Burst capacity
export JMO_MCP_RATE_LIMIT_REFILL_RATE="1.67"    # Tokens/sec (100 req/min)

# Run server
export MCP_RESULTS_DIR=./results
export MCP_REPO_ROOT=.
uv run mcp dev scripts/mcp/server.py
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_RESULTS_DIR` | `./results` | Path to JMo Security scan results |
| `MCP_REPO_ROOT` | `.` | Path to repository root (for source context) |
| `JMO_MCP_API_KEYS` | *(empty)* | Comma-separated API keys for authentication |
| `JMO_MCP_RATE_LIMIT_ENABLED` | `true` | Enable rate limiting |
| `JMO_MCP_RATE_LIMIT_CAPACITY` | `100` | Burst capacity (max requests before throttling) |
| `JMO_MCP_RATE_LIMIT_REFILL_RATE` | `1.67` | Tokens per second (1.67 = 100 req/min) |

### Available Tools

#### 1. `get_security_findings`

Query security findings with filters and pagination.

**Parameters:**
- `severity`: Filter by severity levels (e.g., `["HIGH", "CRITICAL"]`)
- `tool`: Filter by tool name (e.g., `"semgrep"`, `"trivy"`)
- `rule_id`: Filter by rule ID (e.g., `"CWE-79"`)
- `path`: Filter by file path (substring match)
- `limit`: Maximum findings to return (default: 100, max: 1000)
- `offset`: Pagination offset (default: 0)

**Example:**

```python
# Get all HIGH and CRITICAL findings
get_security_findings(severity=["HIGH", "CRITICAL"], limit=10)

# Get findings from semgrep in src/api
get_security_findings(tool="semgrep", path="src/api")
```

#### 2. `apply_fix`

Apply AI-suggested fix patch to resolve a security finding.

**Parameters:**
- `finding_id`: Fingerprint ID of the finding
- `patch`: Unified diff patch (git diff format)
- `confidence`: AI confidence score (0.0-1.0)
- `explanation`: Human-readable explanation of the fix
- `dry_run`: Preview patch without applying (default: False)

**Example:**

```python
# Step 1: Preview patch
apply_fix(
    finding_id="fingerprint-abc123",
    patch="diff --git a/src/app.js...\n-  res.send(userInput)\n+  res.send(sanitize(userInput))",
    confidence=0.95,
    explanation="Added sanitization to prevent XSS",
    dry_run=True
)

# Step 2: Apply if preview looks good
apply_fix(..., dry_run=False)
```

#### 3. `mark_resolved`

Mark a security finding as resolved without applying a patch.

**Parameters:**
- `finding_id`: Fingerprint ID of the finding
- `resolution`: Resolution type (`fixed`, `false_positive`, `wont_fix`, `risk_accepted`)
- `comment`: Optional comment explaining the resolution

**Example:**

```python
mark_resolved(
    finding_id="fingerprint-abc123",
    resolution="false_positive",
    comment="This is a test file, not production code"
)
```

#### 4. `get_server_info`

Get server configuration and status.

**Returns:**
- Server name, version, MCP version
- Rate limiting configuration
- Total findings count
- Findings file status

### Rate Limiting

Rate limiting uses a **token bucket algorithm** with burst capacity and sustained rate:

- **Burst Capacity:** Maximum requests allowed in a burst (default: 100)
- **Refill Rate:** Tokens added per second (default: 1.67 = 100 req/min)
- **Per-Client:** Separate buckets for each client (by API key or IP)

**Examples:**

```bash
# High-traffic production (1000 req/min)
export JMO_MCP_RATE_LIMIT_CAPACITY="1000"
export JMO_MCP_RATE_LIMIT_REFILL_RATE="16.67"

# Low-traffic development (10 req/min)
export JMO_MCP_RATE_LIMIT_CAPACITY="10"
export JMO_MCP_RATE_LIMIT_REFILL_RATE="0.167"

# Disable rate limiting (development only)
export JMO_MCP_RATE_LIMIT_ENABLED="false"
```

### Authentication (v1.0.2+)

**Note:** Full authentication enforcement awaits FastMCP middleware support (v1.0.2). Currently, only rate limiting is enforced.

**Infrastructure Ready:**
- API keys are SHA-256 hashed on server startup
- Decorator pattern applied to all MCP tools
- Authentication checks will be enabled when FastMCP adds middleware hooks

**Setting API Keys:**

```bash
# Generate secure keys (example)
export JMO_MCP_API_KEYS="$(openssl rand -hex 32),$(openssl rand -hex 32)"

# Or use static keys
export JMO_MCP_API_KEYS="prod-key-1,prod-key-2,prod-key-3"
```

**Security Best Practices:**
- ✅ Use long, random keys (≥32 bytes)
- ✅ Rotate keys regularly (quarterly minimum)
- ✅ Store keys in environment variables, not files
- ✅ Use different keys per environment (dev/staging/prod)
- ❌ Never commit keys to version control

### Client Configuration

To use the JMo Security MCP server in Claude Code, add to `.claude/mcp.json`:

```json
{
  "mcpServers": {
    "jmo-security": {
      "command": "uv",
      "args": ["run", "mcp", "dev", "scripts/mcp/server.py"],
      "env": {
        "MCP_RESULTS_DIR": "./results",
        "MCP_REPO_ROOT": ".",
        "JMO_MCP_RATE_LIMIT_ENABLED": "true",
        "JMO_MCP_RATE_LIMIT_CAPACITY": "100",
        "JMO_MCP_RATE_LIMIT_REFILL_RATE": "1.67"
      },
      "description": "JMo Security AI remediation orchestration"
    }
  }
}
```

### Troubleshooting

**Error:** `MCP SDK not installed`

**Solution:**

```bash
pip install 'mcp[cli]>=1.0.0'
# or
uv add 'mcp[cli]>=1.0.0'
```

**Error:** `No scan results found`

**Solution:** Run a scan first to generate `results/summaries/findings.json`:

```bash
jmo scan --repo . --profile balanced
```

**Error:** `Rate limit exceeded`

**Solution:** Increase capacity or wait for tokens to refill:

```bash
# Option 1: Increase capacity
export JMO_MCP_RATE_LIMIT_CAPACITY="200"

# Option 2: Disable temporarily (dev only)
export JMO_MCP_RATE_LIMIT_ENABLED="false"
```

---

## Third-Party MCP Servers

## Configuration Method

We use **project-scoped configuration** via `.mcp.json` for the following reasons:

- ✅ Syncs across multiple development machines via git
- ✅ Consistent setup for all developers
- ✅ Version-controlled (via `.mcp.json.example`)
- ✅ Works seamlessly with Claude Code CLI

### Why Not VS Code Extensions?

VS Code marketplace has MCP server extensions, but they are:

- ❌ Not syncable across machines via git
- ❌ Installed per-machine, not per-project
- ❌ Less flexible for team collaboration

## Setup Instructions

### Prerequisites

1. **Node.js** >= v18.0.0 (for Context7 and Chrome DevTools)
2. **Docker** (for GitHub MCP server)
3. **GitHub Personal Access Token** set as `GH_TOKEN` environment variable (for GitHub MCP server)

### Step 1: Verify GitHub Token Environment Variable

This project uses the `GH_TOKEN` environment variable for GitHub authentication. Verify it's set:

```bash
# Verify token is set
echo $GH_TOKEN
```

If not set, create a GitHub Personal Access Token:

1. Go to GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Click "Generate new token (classic)"
3. Select scopes:
   - `repo` (Full control of private repositories)
   - `read:org` (Read org and team membership)
   - `read:packages` (Download packages from GitHub Package Registry)
4. Copy the token and add to your shell environment:

**For bash/zsh** (`~/.bashrc` or `~/.zshrc`):

```bash
export GH_TOKEN="ghp_your_token_here"
```

**For fish** (`~/.config/fish/config.fish`):

```fish
set -gx GH_TOKEN "ghp_your_token_here"
```

Reload your shell or run `source ~/.bashrc` (or equivalent).

### Step 2: Copy and Configure MCP Files

```bash
cd /path/to/jmo-security-repo
cp .mcp.json.example .mcp.json
cp .mcp.json.example .claude/mcp.json
```

The MCP configuration files are already set up with all three servers. **Note:** Both files are gitignored to protect your tokens. Claude Code reads from `.claude/mcp.json` for project-scoped servers.

### Step 3: Verify Setup

Claude Code will automatically detect `.claude/mcp.json` in your project. To verify:

```bash
# List configured MCP servers
claude mcp list

# Get details about a specific server
claude mcp get context7
claude mcp get github
claude mcp get chrome-devtools
```

Alternatively, in Claude Code (VS Code or CLI), use:

```text
/mcp
```

## Usage

### Context7 - Up-to-Date Library Documentation

Context7 dynamically fetches **version-specific, up-to-date documentation** from official sources and injects it directly into your prompt context. This eliminates outdated API information and hallucinated functions.

#### How to Use Context7

Simply add "use context7" to your prompt when asking about external libraries:

```text
"How do I use pytest fixtures with tmp_path? use context7"
"What's the correct way to use subprocess.run securely? use context7"
"Show me the latest Trivy JSON output format. use context7"
```

#### Best Use Cases for This Project

Context7 is **particularly valuable** for:

1. **External Security Tool Integration**
   - "How do I parse the latest Semgrep SARIF output? use context7"
   - "What fields are available in Trivy JSON v2 schema? use context7"
   - "Show me Checkov's current CLI flags. use context7"

2. **Python Library Updates**
   - "What's new in pytest 8.x for fixtures? use context7"
   - "How do I use the latest jsonschema validation API? use context7"
   - "Show me PyYAML safe loading best practices. use context7"

3. **Docker/Container Tooling**
   - "What's the correct Dockerfile syntax for multi-stage Python builds? use context7"
   - "How do I configure GitHub Actions Docker builds? use context7"

4. **CI/CD Integration**
   - "Show me the latest GitHub Actions workflow syntax for matrix builds. use context7"
   - "How do I configure Codecov uploads with OIDC? use context7"

#### Important Limitations

⚠️ **Context7 only supports public libraries in its database.** It **cannot**:

- ❌ Upload your custom project documentation
- ❌ Index private repositories
- ❌ Learn from your CLAUDE.md or README.md
- ❌ Store project-specific patterns

**Your project's documentation (CLAUDE.md, USER_GUIDE.md, etc.) is already provided to Claude Code through conversation context and file reads - no MCP needed!**

#### Available Tools

Context7 provides two tools:

1. **`resolve-library-id`** - Converts library name to Context7 format
   - Example: "pytest" → "/pytest-dev/pytest"
   - Example: "semgrep" → "/semgrep/semgrep"

2. **`get-library-docs`** - Fetches documentation for specific library
   - Supports version-specific queries: "/vercel/next.js/v14.3.0"
   - Supports topic filtering: `topic: "hooks"`

#### When NOT to Use Context7

- ❌ "How does our adapter pattern work?" → Use `Read` tool on CLAUDE.md
- ❌ "Explain the two-phase architecture" → Already documented in project
- ❌ "Show me the CommonFinding schema" → Read docs/schemas/common_finding.v1.json
- ✅ "How does pytest parametrize work?" → use context7 (external library)

### GitHub MCP Server

Provides tools for GitHub operations. Example prompts:

```text
"List all open issues in this repository"
"Create a new issue titled 'Bug: test failure'"
"Show me the latest pull requests"
"Search for code containing 'CommonFinding'"
```

**Available Toolsets:**

- `context` - Repository context and file operations
- `repos` - Repository management
- `issues` - Issue tracking
- `pull_requests` - PR management
- `users` - User information

### Chrome DevTools

Enables browser automation and debugging. Example prompts:

```text
"Check the LCP of web.dev"
"Take a screenshot of the dashboard at localhost:8000"
"Analyze network requests for this page"
"Record a performance trace"
```

## Troubleshooting

### Context7 Not Working

**Error:** `Command not found: npx`

**Solution:** Install Node.js >= v18.0.0

```bash
# macOS
brew install node

# Ubuntu/Debian
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verify
node --version  # Should be >= v18.0.0
```

### GitHub MCP Server Not Working

**Error:** `Cannot connect to the Docker daemon`

**Solution:** Install and start Docker

```bash
# macOS
brew install --cask docker
open /Applications/Docker.app

# Ubuntu/Debian
sudo apt-get update
sudo apt-get install docker.io
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group (logout required)
sudo usermod -aG docker $USER
```

**Error:** `Authentication failed`

**Solution:** Check your GitHub token:

```bash
# Verify token is set
echo $GH_TOKEN

# If empty, add to your shell config and reload
```

### Chrome DevTools Not Working

**Error:** `Chrome not found`

**Solution:** Install Google Chrome

```bash
# macOS
brew install --cask google-chrome

# Ubuntu/Debian
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo dpkg -i google-chrome-stable_current_amd64.deb
sudo apt-get install -f
```

### MCP Servers Not Detected

**Error:** `No MCP servers configured`

**Solution:**

1. Ensure `.claude/mcp.json` exists in the project
2. Restart Claude Code / VS Code completely
3. Try using `/mcp` within Claude Code to see server status
4. Check VS Code Output panel (View → Output → select "MCP Servers") for error logs

## Multi-Computer Setup

Since MCP configuration files are gitignored, you need to set them up on each machine:

1. Clone/pull the repository
2. Copy configuration files:

   ```bash
   cp .mcp.json.example .mcp.json
   cp .mcp.json.example .claude/mcp.json
   ```

3. Set `GH_TOKEN` environment variable
4. Restart VS Code
5. Verify with `/mcp` in Claude Code

The configuration is identical across machines, ensuring consistency.

## Security Considerations

- ✅ `.mcp.json` is gitignored to prevent token leaks
- ✅ `.mcp.json.example` is committed for reference
- ✅ GitHub token is stored in environment variables, not in files
- ✅ Pre-commit hooks check for leaked secrets

**Never commit `.mcp.json` or any file containing your GitHub token.**

## Advanced Configuration

### Customizing GitHub Toolsets

Edit `.mcp.json` to enable only specific GitHub toolsets:

```json
{
  "mcpServers": {
    "github": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "-e",
        "GITHUB_PERSONAL_ACCESS_TOKEN",
        "-e",
        "GITHUB_TOOLSETS=repos,issues",
        "ghcr.io/github/github-mcp-server"
      ],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "${GH_TOKEN}",
        "GITHUB_TOOLSETS": "repos,issues"
      }
    }
  }
}
```

### Using a Different Chrome Profile

For Chrome DevTools with a specific user profile:

```json
{
  "mcpServers": {
    "chrome-devtools": {
      "command": "npx",
      "args": ["-y", "chrome-devtools-mcp@latest"],
      "env": {
        "CHROME_USER_DATA_DIR": "/path/to/chrome/profile"
      }
    }
  }
}
```

## Should You Add Serena MCP Server?

### What is Serena?

Serena is a **semantic code analysis and editing toolkit** that transforms AI assistants into fully-featured coding agents. It provides:

- 🔍 **Semantic code search** via Language Server Protocol (LSP)
- 📝 **Intelligent code editing** with symbol understanding
- 🧠 **Codebase memory** through persistent onboarding
- 🔧 **Multi-language support:** Python, TypeScript/JavaScript, PHP, Go, Rust, C/C++, Java

### Recommendation: YES, for Heavy Development

**TL;DR:** Add Serena if you do frequent refactoring or cross-file analysis. Skip if you're comfortable with current Read/Glob/Grep tools.

### ✅ Benefits for This Project

1. **Python LSP Integration**
   - Navigate symbol definitions across `scripts/core/` and `scripts/cli/`
   - Find all references to CommonFinding schema
   - Rename functions/classes with semantic awareness

2. **Better Refactoring**
   - Intelligent code transformations
   - Symbol-aware search and replace
   - Understands Python imports and scopes

3. **Faster Navigation**
   - Jump to adapter definitions by tool name
   - Find all usages of a reporter function
   - Trace data flow through the two-phase architecture

4. **No Cost**
   - Runs locally, no API keys needed
   - Works with Claude's free tier
   - Privacy-preserving (stays on your machine)

### ⚠️ Considerations

1. **Setup Complexity**
   - Requires Python language server (Pyright or Pylance)
   - Needs initial codebase indexing/onboarding
   - More moving parts than simple MCP servers

2. **Resource Usage**
   - Language server runs in background
   - Indexes entire codebase (may take 1-2 minutes initially)
   - Uses memory for persistent index

3. **Overlap with Existing Tools**
   - Claude Code already has Read/Glob/Grep tools
   - Your IDE (VS Code) already provides LSP features
   - May be redundant if comfortable with current workflow

### When to Use Serena

**High Value Scenarios:**

1. **Large Refactoring Tasks**
   - "Rename `gather_results` to `aggregate_findings` across all files"
   - "Find all adapter functions that parse 'severity' and standardize them"
   - "Trace how fingerprint IDs flow from adapters → normalize → reporters"

2. **Cross-File Analysis**
   - "Show me all places where CommonFinding schema is constructed"
   - "Find inconsistent error handling patterns across adapters"
   - "List all CLI flags and their usage in subcommands"

3. **Code Understanding**
   - "Explain the data flow from scan → normalize → report"
   - "Show me the call graph for the report command"
   - "Which adapters use CVSS scoring?"

**Lower Value Scenarios:**

- ❌ Simple file edits (regular Read/Write tools work fine)
- ❌ Documentation updates (not code analysis)
- ❌ Configuration changes (jmo.yml, Dockerfiles, etc.)

### Installation

To add Serena to your MCP configuration, edit `.claude/mcp.json`:

```json
{
  "mcpServers": {
    "context7": {
      "command": "npx",
      "args": ["-y", "@upstash/context7-mcp"],
      "description": "Up-to-date code documentation for libraries and frameworks"
    },
    "github": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "GITHUB_PERSONAL_ACCESS_TOKEN",
        "ghcr.io/github/github-mcp-server"
      ],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "${GH_TOKEN}"
      }
    },
    "serena": {
      "command": "npx",
      "args": ["-y", "@oraios/serena-mcp"],
      "description": "Semantic code analysis and editing via LSP"
    },
    "chrome-devtools": {
      "command": "npx",
      "args": ["-y", "chrome-devtools-mcp@latest"],
      "description": "Browser automation and debugging capabilities"
    }
  }
}
```

**Initial Setup Steps:**

1. Install Serena: `npx -y @oraios/serena-mcp`
2. Ensure Python language server is available:

   ```bash
   # Option 1: Install Pyright
   pip install pyright

   # Option 2: Use Pylance (VS Code extension)
   # Serena auto-detects which LSP is available
   ```

3. First use triggers codebase onboarding (1-2 minutes indexing)
4. Subsequent queries use cached index (fast)

**Resources:**

- [Serena GitHub](https://github.com/oraios/serena)
- [Serena Documentation](https://github.com/oraios/serena/blob/main/README.md)

### Comparison: When to Use Each MCP

| Task | Best Tool | Example |
|------|-----------|---------|
| External library docs | Context7 | "Show me latest pytest fixtures API use context7" |
| Semantic refactoring | Serena | "Rename all occurrences of `load_gitleaks` to `parse_gitleaks`" |
| Symbol navigation | Serena | "Find all functions that construct CommonFinding objects" |
| Project documentation | Read tool | "Read CLAUDE.md to understand architecture" |
| GitHub operations | GitHub MCP | "Create an issue for adding osv-scanner adapter" |
| Dashboard testing | Chrome DevTools | "Screenshot dashboard with mobile viewport" |

## Additional Resources

- [MCP Official Documentation](https://modelcontextprotocol.io/)
- [Context7 GitHub](https://github.com/upstash/context7)
- [GitHub MCP Server](https://github.com/github/github-mcp-server)
- [Chrome DevTools MCP](https://github.com/ChromeDevTools/chrome-devtools-mcp)
- [Claude Code MCP Guide](https://docs.claude.com/en/docs/claude-code/mcp)

## Summary and Recommendations

### Quick Decision Guide

**Minimal Setup (Most Users):**

```json
{
  "mcpServers": {
    "context7": { /* ... */ },
    "github": { /* ... */ }
  }
}
```

✅ Context7 for external library docs
✅ GitHub for repo operations
⏩ Skip Serena unless doing heavy refactoring
⏩ Skip Chrome DevTools unless testing dashboard

**Full Setup (Heavy Development):**

```json
{
  "mcpServers": {
    "context7": { /* ... */ },
    "github": { /* ... */ },
    "serena": { /* ... */ },
    "chrome-devtools": { /* ... */ }
  }
}
```

✅ All four MCP servers enabled
✅ Best for frequent codebase refactoring
✅ Useful for automated testing workflows

### Key Takeaways

1. **Context7 Limitations:**
   - ❌ Cannot upload custom project docs
   - ❌ Does not index private repos
   - ✅ Your project docs are already provided via CLAUDE.md and file reads!
   - ✅ Use only for external libraries (pytest, semgrep, trivy, etc.)

2. **Serena Benefits:**
   - ✅ Semantic code search and refactoring
   - ✅ LSP-powered navigation (Python, JS, Go, etc.)
   - ✅ Free and local (no API keys)
   - ⚠️ Setup overhead and resource usage
   - ⚠️ Most valuable for cross-file analysis and large refactoring

3. **When to Use Each:**
   - **Context7** → "How does pytest parametrize work? use context7"
   - **Serena** → "Rename all `load_*` functions to `parse_*` across adapters"
   - **Read tool** → "Show me the CommonFinding schema" (project docs)
   - **GitHub MCP** → "Create an issue for adding osv-scanner support"

### Performance Tips

1. **Context7:** Use sparingly for external libs only
   - ✅ "How does semgrep SARIF work? use context7"
   - ❌ "How does our adapter pattern work?" (use Read instead)

2. **Serena:** Let it index once, reuse cached results
   - First query may be slow (indexing)
   - Subsequent queries are fast (cached)

3. **Combine Tools:** Use Read for project docs + Context7 for external
   - "Read CLAUDE.md for adapter pattern, then use context7 for pytest best practices"

## Support

For issues or questions:

1. Check this guide first
2. Review the troubleshooting section
3. Open an issue in the repository with details about your setup

---

**Last Updated:** October 14, 2025
**Related Docs:** [CLAUDE.md](../CLAUDE.md), [CONTRIBUTING.md](../CONTRIBUTING.md)

**Documentation Hub:** [docs/index.md](index.md) | **Project Home:** [README.md](../README.md)
