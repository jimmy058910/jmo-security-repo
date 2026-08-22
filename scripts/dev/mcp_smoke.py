#!/usr/bin/env python3
"""Start the MCP server as a real process and speak stdio to it.

**Why this exists.** Every `tests/jmo_mcp/` test imports the tool functions and
calls them as plain Python. None of them starts a server, so `mcp.run()`, the
SDK handshake and tool *registration* were reachable by nothing -- and no
workflow ran the CLI either. Measured at chunk 20: `grep -rn "mcp"
.github/workflows/` returned exactly one hit, and it was a comment. That is how
`jmo mcp-server --api-key` set an environment variable no code read, for its
entire life, with CI green throughout (#716, #954).

What it proves, in order, so a failure says *where*:

1. `jmo mcp-server` starts and completes the MCP initialize handshake.
2. `tools/list` returns **exactly** the five expected tools -- a missing one is
   a registration break, an extra one is an undocumented surface.
3. The `finding://{finding_id}` resource template is registered. It is the one
   entry point declared with `@mcp.resource` rather than `@mcp.tool`, and it
   was the one the rate limiter did not cover.
4. A tool actually runs end to end over the wire and returns usable content.

Run it locally exactly as CI does:

    python scripts/dev/mcp_smoke.py

Exit codes: 0 all checks passed, 1 a check failed, 2 the server could not be
started at all.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Derived from the module, not restated. A hand-written list is a mirror, and
# chunk 11 found what mirrors do: `jmo ci` parsed nine flags its hand-written
# copy had never listed, and the tests that enumerated the copy could not
# notice. The registry below is the *expectation*; the assertion compares it
# against what the running server advertises, and the two come from different
# places on purpose.
EXPECTED_TOOLS = {
    "get_security_findings",
    "apply_fix",
    "mark_resolved",
    "query_findings_db",
    "get_server_info",
}
EXPECTED_RESOURCE_TEMPLATE = "finding://{finding_id}"

# The server refuses to answer before a scan exists, so give it one finding.
FIXTURE_FINDINGS = {
    "findings": [
        {
            "id": "0000eba9addb92a7",
            "severity": "HIGH",
            "title": "Smoke fixture finding",
            "description": "Present so the loader has something to load.",
            "tool": "bandit",
            "ruleId": "B101",
            "location": {"path": "smoke/app.py", "startLine": 1},
        }
    ],
    "summary": {"total": 1},
}

HANDSHAKE_TIMEOUT_S = 60.0


def _fail(step: str, detail: str) -> None:
    print(f"FAIL [{step}] {detail}", file=sys.stderr)


def _flatten(exc: BaseException) -> list[str]:
    """Render an exception, unwrapping ExceptionGroups.

    anyio wraps everything raised inside its task groups, twice over here, and
    the outer message is always the same uninformative "unhandled errors in a
    TaskGroup (1 sub-exception)". A smoke test whose failure output does not
    name the failure is barely better than no smoke test.
    """
    if isinstance(exc, BaseExceptionGroup):
        return [msg for sub in exc.exceptions for msg in _flatten(sub)]
    return [f"{type(exc).__name__}: {exc}"]


async def _probe(results_dir: Path, repo_root: Path) -> list[str]:
    """Return a list of failure messages; empty means every check passed."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    failures: list[str] = []

    # `-u` matters: a block-buffered stdout deadlocks the handshake, and the
    # symptom is an indistinguishable timeout.
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-u",
            "-m",
            "scripts.cli.jmo",
            "mcp-server",
            "--results-dir",
            str(results_dir),
            "--repo-root",
            str(repo_root),
        ],
        cwd=str(REPO_ROOT),
        env={**os.environ, "PYTHONIOENCODING": "utf-8", "JMO_NON_INTERACTIVE": "1"},
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(
            read, write, read_timeout_seconds=HANDSHAKE_TIMEOUT_S
        ) as session:
            info = await session.initialize()
            print(f"  initialize OK -- server: {info.server_info.name}")

            listed = {t.name for t in (await session.list_tools()).tools}
            print(f"  tools/list   -- {sorted(listed)}")
            if missing := sorted(EXPECTED_TOOLS - listed):
                failures.append(f"tools not registered: {missing}")
            if extra := sorted(listed - EXPECTED_TOOLS):
                failures.append(
                    f"tools registered but undocumented: {extra} "
                    "(add them to docs/MCP_SETUP.md and to EXPECTED_TOOLS)"
                )

            templates = {
                t.uri_template
                for t in (await session.list_resource_templates()).resource_templates
            }
            print(f"  resources    -- {sorted(templates)}")
            if EXPECTED_RESOURCE_TEMPLATE not in templates:
                failures.append(
                    f"resource template {EXPECTED_RESOURCE_TEMPLATE!r} not registered"
                )

            # Call one for real. A registered-but-broken tool passes every
            # check above; this is the one that needs the server to work.
            result = await session.call_tool("get_server_info", {})
            if getattr(result, "is_error", False):
                failures.append(f"get_server_info returned an error: {result.content}")
            else:
                payload = json.loads(result.content[0].text)
                print(f"  call_tool    -- get_server_info -> {sorted(payload)}")
                for key in ("version", "authentication_enforced"):
                    if key not in payload:
                        failures.append(f"get_server_info has no {key!r} key")

    return failures


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="jmo-mcp-smoke-"))
    try:
        summaries = tmp / "results" / "summaries"
        summaries.mkdir(parents=True)
        (summaries / "findings.json").write_text(
            json.dumps(FIXTURE_FINDINGS), encoding="utf-8"
        )

        print(f"Starting jmo mcp-server against {summaries}")
        try:
            failures = asyncio.run(_probe(tmp / "results", tmp))
        except BaseException as exc:
            for line in _flatten(exc):
                _fail("startup", line)
            return 2

        for failure in failures:
            _fail("check", failure)
        if failures:
            print(f"\n{len(failures)} check(s) failed.", file=sys.stderr)
            return 1
        print("\nMCP server smoke: all checks passed.")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
