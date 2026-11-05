#!/usr/bin/env python3
"""
opengrep adapter - maps opengrep's multi-language SAST JSON to CommonFinding.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

opengrep (v2.0.0 Phase 5) replaced semgrep, and runs the rule bundle committed
under ``scripts/jmo_rules`` (docs/RULE_BUNDLE.md), so a scan needs no network
and no registry. Its ``--json`` document is semgrep's shape, and this adapter
is the semgrep adapter's, renamed: the tool name is hashed into every finding
id, so every SAST id changed once, on purpose (UPGRADE.md).

Tool Version: 1.32.0
Output Format: JSON with a ``results`` array, ``errors`` and ``paths.scanned``.
    ``errors`` (a file that timed out or did not parse) is read by
    ``tool_diagnostics``, not here, and ``paths.scanned`` by the descriptor
    row's examined-files reader: neither costs the other files' findings.
Exit Codes: 0 (the run worked, errors per file included), 7 (an invalid
    config; the output holds no results), 2 (a usage error; no output).

Rule ids are exactly the bundle YAML's (``--no-rewrite-rule-ids``), namespaced
by the rule's source path (``javascript.express.security.audit...``), so they
do not depend on the directory the scan ran from. Nor do the paths: the row runs
opengrep from inside its target, so ``path`` is relative to it.

Severity Mapping (opengrep -> CommonFinding), from ``extra.severity``:
- ERROR: HIGH
- WARNING: MEDIUM
- INFO: LOW

CWE, OWASP, confidence, likelihood and impact are read from ``extra.metadata``.

Autofix Support:
- When a rule has a fix, findings include it as remediation.fix with
  remediation.steps

Example:
    >>> adapter = OpengrepAdapter()
    >>> findings = adapter.parse(Path('opengrep.json'))
    >>> # Returns SAST findings with CWE/OWASP enrichment

See Also:
    - https://github.com/opengrep/opengrep
    - docs/RULE_BUNDLE.md
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from scripts.core.adapters.common import safe_load_json_file
from scripts.core.common_finding import (
    extract_code_snippet,
    fingerprint,
    map_tool_severity,
)
from scripts.core.plugin_api import (
    AdapterPlugin,
    Finding,
    PluginMetadata,
    adapter_plugin,
)
from scripts.core.scan_timings import SCAN_TIMINGS_FILENAME, read_scan_root
from scripts.core.secret_value_rules import (
    MESSAGE_SECRET_METAVARS,
    MESSAGE_TEMPLATES,
    SECRET_VALUE_RULES,
    is_secret_value_finding,
)

#: What a result that quotes a secret keeps of opengrep's `extra` (#1585). The
#: rest quotes the matched code: `lines`, `metavars`, `dataflow_trace`, a `fix`;
#: `fingerprint` hashes the match.
SECRET_SAFE_EXTRA = frozenset(
    {"engine_kind", "is_ignored", "message", "metadata", "severity", "validation_state"}
)
#: Stands for a secret in a message. One marker, unlike the secret scanners'
#: per-secret stand-ins: nothing pairs opengrep findings by their secret.
REDACTED = "[redacted]"
#: A snippet is the finding's line and this many on either side.
SNIPPET_CONTEXT_LINES = 2
_QUOTES = "\"'`"
_STRING_LITERAL = re.compile(r"([\"'`])((?:\\.|(?!\1).)*)\1")
_MIN_SECRET = 6


def _metavar_values(extra: dict[str, Any]) -> dict[str, str]:
    metavars = extra.get("metavars")
    if not isinstance(metavars, dict):
        return {}
    return {
        name: str(value.get("abstract_content") or "")
        for name, value in metavars.items()
        if isinstance(value, dict)
    }


def is_secret_result(result: dict[str, Any]) -> bool:
    """Whether an opengrep result's rule matches a secret's value: it is listed
    so, or carries a hard-coded-credential CWE (`secret_value_rules`)."""
    extra = result.get("extra") or {}
    metadata = extra.get("metadata") if isinstance(extra, dict) else None
    cwes = metadata.get("cwe") if isinstance(metadata, dict) else None
    return is_secret_value_finding(str(result.get("check_id") or ""), cwes or [])


def _own_secret_texts(result: dict[str, Any]) -> set[str]:
    """What one secret-class result may quote its secret as: the string
    literals on its lines, its quoted metavariable values, and the values of
    the metavariables named as holding one (every value, for a rule only its
    CWE marks). Unquoted identifiers (`session`, `crypto`) are not secrets, and
    scrubbing them would mangle opengrep's log."""
    extra = result.get("extra") or {}
    values = _metavar_values(extra)
    rule = str(result.get("check_id") or "")
    if SECRET_VALUE_RULES.get(rule):
        named = [
            values[n] for n in MESSAGE_SECRET_METAVARS.get(rule, ()) if n in values
        ]
    else:
        named = list(values.values())
    texts = {v.strip(_QUOTES) for v in named}
    texts.update(v.strip(_QUOTES) for v in values.values() if v[:1] in _QUOTES)
    lines = extra.get("lines")
    if isinstance(lines, str):
        texts.update(m.group(2) for m in _STRING_LITERAL.finditer(lines))
    return {t for t in texts if len(t) >= _MIN_SECRET}


def secret_texts(results: list[Any]) -> list[str]:
    """The secrets an output's secret-class results quote, longest first:
    what the report scrubs from opengrep's log and from the message of any
    other result over the same code."""
    texts: set[str] = set()
    for result in results:
        if isinstance(result, dict) and is_secret_result(result):
            texts |= _own_secret_texts(result)
    return sorted(texts, key=len, reverse=True)


def _span(result: dict[str, Any]) -> tuple[str, int, int] | None:
    path = result.get("path")
    start = (result.get("start") or {}).get("line")
    end = (result.get("end") or {}).get("line")
    if not isinstance(path, str) or not isinstance(start, int):
        return None
    return path, start, end if isinstance(end, int) and end >= start else start


def secret_spans(results: list[Any]) -> dict[str, list[tuple[int, int]]]:
    """By path, the lines each secret-class result matched. A redacted result
    keeps its location, so a later report finds the same spans."""
    spans: dict[str, list[tuple[int, int]]] = {}
    for result in results:
        if isinstance(result, dict) and is_secret_result(result):
            span = _span(result)
            if span:
                spans.setdefault(span[0], []).append(span[1:])
    return spans


def _reaches(
    spans: dict[str, list[tuple[int, int]]], path: str, lo: int, hi: int
) -> bool:
    return any(a <= hi and lo <= b for a, b in spans.get(path, ()))


def _scrub(text: str, texts: list[str]) -> str:
    for secret in texts:
        text = text.replace(secret, REDACTED)
    return text


def _redacted_message(result: dict[str, Any]) -> str:
    """A secret-class result's message without its secret. One that carried
    it is rebuilt from the rule's template: opengrep renders a value as the
    source spells it (`"x %s" % y`), which `abstract_content` does not
    (`"x %s"%y`), so replacing the value would miss. A rule only its CWE marks
    loses its own secret texts and metavariable values."""
    extra = result.get("extra") or {}
    message = str(extra.get("message") or "")
    rule = str(result.get("check_id") or "")
    template = MESSAGE_TEMPLATES.get(rule)
    if template is not None:
        for name in MESSAGE_SECRET_METAVARS[rule]:
            template = re.sub(re.escape(name) + r"(?![A-Z0-9_])", REDACTED, template)
        return template
    if SECRET_VALUE_RULES.get(rule):
        return message
    values = [v for v in _metavar_values(extra).values() if len(v) >= _MIN_SECRET]
    texts = _own_secret_texts(result) | set(values)
    return _scrub(message, sorted(texts, key=len, reverse=True))


def _without_code(result: dict[str, Any], message: str) -> dict[str, Any]:
    extra = result.get("extra") or {}
    kept = {k: v for k, v in extra.items() if k in SECRET_SAFE_EXTRA}
    kept["message"] = message
    return {**{k: v for k, v in result.items() if k != "extra"}, "extra": kept}


def redact_results(results: list[Any]) -> list[Any]:
    """An output's results with no secret a rule matched (#1585).

    A secret-class result keeps no code, and its message no secret. Any other
    result over the lines of one (opengrep reports several rules for one
    region) keeps no code either, and its message loses the secrets the
    secret-class results quote. Every decision past the secret-class results
    themselves is made from locations, so redacting a redacted output returns
    an equal one: a later report, reading the opengrep.json the report
    rewrote, makes the same decisions and computes the same ids.
    """
    spans = secret_spans(results)
    if not spans:
        return results
    texts = secret_texts(results)
    redacted: list[Any] = []
    for result in results:
        if not isinstance(result, dict):
            redacted.append(result)
        elif is_secret_result(result):
            redacted.append(_without_code(result, _redacted_message(result)))
        elif (span := _span(result)) and _reaches(spans, *span):
            message = str((result.get("extra") or {}).get("message") or "")
            redacted.append(_without_code(result, _scrub(message, texts)))
        else:
            redacted.append(result)
    return redacted


def _scan_root(output_path: Path) -> Path | None:
    """The target the scan ran in, from the ``scan-timings.json`` beside the output.

    The row runs opengrep from inside its target (R35), so a result's ``path``
    is relative to it and names no file the report phase could open from where
    it runs. The scan records the root beside every tree's outputs. None when
    there is no such file (a golden, a results directory from elsewhere) or it
    cannot be read (``read_scan_root`` names it), and a relative path is then
    not opened at all.
    """
    root = read_scan_root(output_path.parent / SCAN_TIMINGS_FILENAME)
    return Path(root) if root else None


@adapter_plugin(
    PluginMetadata(
        name="opengrep",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for the opengrep multi-language SAST scanner",
        tool_name="opengrep",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "ran", 2: "usage error", 7: "invalid config"},
    )
)
class OpengrepAdapter(AdapterPlugin):
    """opengrep SAST scanner adapter (plugin architecture)."""

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]  # Dynamically attached by @adapter_plugin decorator

    def parse(self, output_path: Path) -> list[Finding]:
        """Parse opengrep JSON output and return normalized findings.

        Args:
            output_path: Path to opengrep.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        data = safe_load_json_file(output_path, default=None)
        if data is None:
            return []

        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list):
            return []

        # No result quotes a secret a rule matched (#1585). Redacted before
        # any id is computed, as trufflehog's adapter drops `Raw`: redaction,
        # not enrichment.
        results = redact_results(results)
        spans = secret_spans(results)
        findings: list[Finding] = []
        root = _scan_root(output_path)
        tool_version = str(
            (data.get("version") if isinstance(data, dict) else None) or "unknown"
        )

        for r in results:
            if not isinstance(r, dict):
                continue
            secret_class = is_secret_result(r)

            # Extract rule ID
            check_id = str(
                r.get("check_id") or r.get("ruleId") or r.get("id") or "OPENGREP"
            )

            # Extract message
            msg = (
                (r.get("extra") or {}).get("message")
                or r.get("message")
                or "opengrep finding"
            )

            # Extract and normalize severity using centralized mapping
            sev_raw = (r.get("extra") or {}).get("severity") or r.get("severity")
            severity = map_tool_severity("opengrep", str(sev_raw) if sev_raw else "")

            # Extract path
            path_str = r.get("path") or (r.get("location") or {}).get("path") or ""

            # Extract line number (multiple fallbacks)
            start_line = 0
            if isinstance(r.get("start"), dict) and isinstance(
                r["start"].get("line"), int
            ):
                start_line = r["start"]["line"]
            else:
                line_val = (r.get("start") or {}).get("line")
                if isinstance(line_val, int):
                    start_line = line_val

            # Alternative location structure
            loc = r.get("location")
            if (
                isinstance(loc, dict)
                and isinstance(loc.get("start"), dict)
                and isinstance(loc["start"].get("line"), int)
            ):
                start_line = loc["start"]["line"]

            # Extract v1.1.0 fields
            extra = r.get("extra", {})

            # Remediation with autofix
            # v1.1.0: Return dict for autofix, string otherwise
            remediation: str | dict[str, Any] = (
                "Review and remediate per rule guidance."
            )
            autofix = extra.get("fix")
            if autofix:
                remediation_steps = [
                    "Apply the suggested fix above",
                    "Test the changes",
                    "Commit the fix",
                ]
                remediation = {
                    "fix": autofix,
                    "steps": remediation_steps,
                }

            # Risk metadata (CWE, OWASP, confidence)
            risk = {}
            metadata = extra.get("metadata", {})
            if metadata:
                # CWE
                cwe_list = metadata.get("cwe", [])
                if isinstance(cwe_list, list) and cwe_list:
                    risk["cwe"] = cwe_list
                elif isinstance(cwe_list, str):
                    risk["cwe"] = [cwe_list]

                # OWASP
                owasp = metadata.get("owasp", [])
                if isinstance(owasp, list) and owasp:
                    risk["owasp"] = owasp
                elif isinstance(owasp, str):
                    risk["owasp"] = [owasp]

                # Confidence
                confidence = metadata.get("confidence", "").upper()
                if confidence in ["HIGH", "MEDIUM", "LOW"]:
                    risk["confidence"] = confidence

                # Likelihood/Impact
                likelihood = metadata.get("likelihood", "").upper()
                if likelihood in ["HIGH", "MEDIUM", "LOW"]:
                    risk["likelihood"] = likelihood
                impact = metadata.get("impact", "").upper()
                if impact in ["HIGH", "MEDIUM", "LOW"]:
                    risk["impact"] = impact

            # Code context. ``path`` stays as opengrep wrote it: the report
            # phase strips a root from an absolute path and has nothing to strip
            # from a relative one, which is already the repository-relative form.
            # A relative path is opened only under the root the scan recorded:
            # against the working directory it would read whatever file of that
            # name the report happens to run beside, and attach another
            # repository's lines to the finding.
            # No snippet for a result that quotes a secret, nor for one whose
            # lines around would reach the lines a secret-class result matched.
            context = None
            near_secret = bool(path_str and start_line) and _reaches(
                spans,
                str(path_str),
                start_line - SNIPPET_CONTEXT_LINES,
                start_line + SNIPPET_CONTEXT_LINES,
            )
            if path_str and start_line and not secret_class and not near_secret:
                if Path(path_str).is_absolute():
                    readable: str | None = path_str
                elif root is not None:
                    readable = str(root / path_str)
                else:
                    readable = None
                if readable:
                    context = extract_code_snippet(
                        readable, start_line, context_lines=SNIPPET_CONTEXT_LINES
                    )

            # Create Finding object
            finding = Finding(
                schemaVersion="1.2.0",
                id="",  # Will be set by fingerprint
                ruleId=check_id,
                title=check_id,
                message=msg,
                description=msg,
                severity=severity,
                tool={"name": "opengrep", "version": tool_version},
                location={"path": path_str, "startLine": start_line},
                remediation=remediation,
                tags=["sast"],
                context=context,
                risk=risk or None,
                raw=r,
            )

            # Generate fingerprint
            finding.id = self.get_fingerprint(finding)
            # A message rebuilt without its value, from the rule's template or
            # by a CWE-only scrub, no longer tells two secrets on one line (a
            # flow-style map) apart, and dedup would drop one: the column keeps
            # them apart. Decided by the rule, so a later report decides the
            # same; a listed rule whose message never held the value keeps
            # its id.
            column = (r.get("start") or {}).get("col")
            message_rebuilt = check_id in MESSAGE_TEMPLATES or (
                check_id not in SECRET_VALUE_RULES
            )
            if secret_class and message_rebuilt and isinstance(column, int):
                finding.location["startColumn"] = column
                finding.id = fingerprint(
                    "opengrep",
                    check_id,
                    path_str,
                    start_line,
                    msg,
                    start_column=column,
                )

            findings.append(finding)

        return findings
