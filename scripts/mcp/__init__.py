"""
JMo Security MCP Server

AI-powered remediation orchestration via Model Context Protocol (MCP).
Provides standardized interface for AI tools to query security findings
and suggest fixes.

Supported AI Tools:
- GitHub Copilot
- Claude Code
- OpenAI Codex 5
- Custom MCP clients

Architecture:
- FastMCP framework (Official Anthropic SDK)
- Tools: get_security_findings, apply_fix, mark_resolved
- Resources: finding://{id} for full context
- Transport: stdio, HTTP, SSE
"""

__version__ = "1.0.0"
__all__ = ["server"]
