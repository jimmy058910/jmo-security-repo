#!/usr/bin/env python3
"""Read the error channel security tools already emit (#837).

Most scanners report, in band, the files they failed to analyse. None of it
reached JMo: counting references to a tool-reported error channel across the
adapters found **0 of 8**, and a file a tool could not parse was
indistinguishable in the report from a file that was scanned and found clean.

Measured reproduction. Two Python files with genuine syntax errors, scanned
with bandit, then reported:

===========================================  =====
bandit's own ``errors`` array                 2 entries, "syntax error while
                                              parsing AST from file"
findings reported                             17, all from the one file that
                                              *did* parse
mentions of either unanalysed file in
findings.json / SUMMARY.md / dashboard.html
/ findings.sarif / findings.csv                **0**
log records naming them, at any level          **0**
``jmo report`` exit code                       **0**
===========================================  =====

This is the coverage analogue of #836: there, findings were lost and nobody
said so; here, *coverage* is lost and nobody says so.

Design note -- why this is central and not per-adapter. The issue suggested
adapters return a diagnostic alongside their findings. That means changing
``AdapterPlugin.parse``'s return type and every one of the 29 adapters plus
their tests, to carry data that is sitting in the tool's own output file and
needs no adapter knowledge to read. Reading it centrally costs one extra
``json.loads`` for the **five** tools that actually have a channel, and nothing
at all for the other twenty-four.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scripts.core.adapters.common import normalize_finding_path

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ToolDiagnostic:
    """One thing a tool said it could not do.

    ``path`` is empty for a run-level problem the tool did not attribute to a
    file, which is why it is not the identity of the record.
    """

    tool: str
    reason: str
    path: str = ""

    def render(self) -> str:
        return f"{self.path or '(run-level)'}: {self.reason}"


def _as_text(value: Any) -> str:
    """Flatten whatever a tool put in a reason field into one line."""
    if isinstance(value, str):
        return " ".join(value.split())
    if isinstance(value, dict):
        for key in ("reason", "message", "long_msg", "short_msg", "error", "detail"):
            if key in value:
                return _as_text(value[key])
        return " ".join(f"{k}={v}" for k, v in sorted(value.items()))[:400]
    return str(value)[:400]


def _file_of(entry: Any) -> str:
    if not isinstance(entry, dict):
        return ""
    for key in ("filename", "file", "path", "location"):
        value = entry.get(key)
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            nested = value.get("path")
            if isinstance(nested, str):
                return nested
    return ""


def _from_errors_list(tool: str, data: Any) -> list[ToolDiagnostic]:
    """``{"errors": [...]}`` -- bandit, semgrep, semgrep-secrets.

    horusec uses the same key for a **string**, which is why the value's type
    is inspected rather than assumed. An adapter that assumed `list` here would
    iterate the characters of that string.
    """
    if not isinstance(data, dict):
        return []
    raw = data.get("errors")
    out: list[ToolDiagnostic] = []
    if isinstance(raw, str):
        if raw.strip():
            out.append(ToolDiagnostic(tool, _as_text(raw)))
    elif isinstance(raw, list):
        for entry in raw:
            out.append(ToolDiagnostic(tool, _as_text(entry), _file_of(entry)))
    return out


def _from_scancode(tool: str, data: Any) -> list[ToolDiagnostic]:
    """scancode carries a channel in two places, per-run and per-file."""
    if not isinstance(data, dict):
        return []
    out: list[ToolDiagnostic] = []
    headers = data.get("headers")
    if isinstance(headers, list) and headers and isinstance(headers[0], dict):
        for key in ("errors", "warnings"):
            for entry in headers[0].get(key) or []:
                out.append(ToolDiagnostic(tool, _as_text(entry)))
    for entry in data.get("files") or []:
        if not isinstance(entry, dict):
            continue
        for problem in entry.get("scan_errors") or []:
            out.append(ToolDiagnostic(tool, _as_text(problem), _file_of(entry)))
    return out


# Only tools with a channel appear here, so the other 24 adapters cost nothing.
# Keyed by adapter name, matching `PluginMetadata.name` (underscores).
DIAGNOSTIC_EXTRACTORS: dict[str, Callable[[str, Any], list[ToolDiagnostic]]] = {
    "bandit": _from_errors_list,
    "semgrep": _from_errors_list,
    "semgrep_secrets": _from_errors_list,
    "horusec": _from_errors_list,
    "scancode": _from_scancode,
}


def extract_tool_diagnostics(
    tool: str, output_path: Path, roots: Sequence[str] = ()
) -> list[ToolDiagnostic]:
    """Diagnostics a single tool output reports, or `[]`.

    Never raises: a tool output that cannot be read is already reported by
    `safe_load_json_file`, and a second warning about the same file would only
    teach the reader to skip both.
    """
    extractor = DIAGNOSTIC_EXTRACTORS.get(tool)
    if extractor is None:
        return []
    try:
        data = json.loads(output_path.read_text(encoding="utf-8-sig", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return []
    try:
        found = extractor(tool, data)
    except (TypeError, ValueError, KeyError, AttributeError) as exc:
        logger.debug("diagnostic extraction failed for %s: %s", output_path, exc)
        return []
    # Same spelling as `location.path`, so an unanalysed file and a finding on
    # its neighbour are comparable strings (#861).
    return [
        ToolDiagnostic(d.tool, d.reason, normalize_finding_path(d.path, roots))
        for d in found
    ]


def summarize(diagnostics: Sequence[ToolDiagnostic]) -> str:
    """A one-line summary, or `""` when there is nothing to say.

    Empty rather than "0 files could not be analysed" on purpose: a line that
    appears on every healthy run is the shape #784 removed, and it teaches
    readers to skip the class exactly when it finally has something to report.
    """
    if not diagnostics:
        return ""
    files = {d.path for d in diagnostics if d.path}
    tools = sorted({d.tool for d in diagnostics})
    what = f"{len(files)} file(s)" if files else f"{len(diagnostics)} problem(s)"
    return f"{what} could not be analysed, reported by {', '.join(tools)}"
