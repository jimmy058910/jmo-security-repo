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
    SECRET_VALUE_RULES,
    is_secret_value_finding,
)

#: What a result from a rule that matches a secret's value keeps of opengrep's
#: `extra` (#1585). The rest quotes the matched code, and so the secret:
#: `lines`, `metavars`, `dataflow_trace`, a `fix`; `fingerprint` hashes the match.
SECRET_SAFE_EXTRA = frozenset(
    {"engine_kind", "is_ignored", "message", "metadata", "severity", "validation_state"}
)
#: Stands for a secret in a message. One marker, unlike the secret scanners'
#: per-secret stand-ins: nothing pairs opengrep findings by their secret.
REDACTED = "[redacted]"
_QUOTES = "\"'`"
_STRING_LITERAL = re.compile(r"([\"'`])((?:\\.|(?!\1).)*)\1")


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


def secret_texts(result: dict[str, Any]) -> list[str]:
    """The texts a secret-class result may hold its secret in, longest first:
    each metavariable's value and each string literal on its lines, with and
    without quotes, 6 characters or more (shorter ones are common words in
    opengrep's log, which is what these are scrubbed from)."""
    extra = result.get("extra") or {}
    texts: set[str] = set()
    for value in _metavar_values(extra).values():
        texts.update((value, value.strip(_QUOTES)))
    lines = extra.get("lines")
    if isinstance(lines, str):
        texts.update(m.group(2) for m in _STRING_LITERAL.finditer(lines))
    return sorted((t for t in texts if len(t) >= 6), key=len, reverse=True)


def _redacted_message(result: dict[str, Any]) -> str:
    """The message with the secret it interpolated replaced. A listed rule
    names the metavariables that hold it; a rule only its CWE marks loses
    every metavariable value of 6 characters or more."""
    extra = result.get("extra") or {}
    message = str(extra.get("message") or "")
    rule = str(result.get("check_id") or "")
    values = _metavar_values(extra)
    if SECRET_VALUE_RULES.get(rule):
        held = [values[n] for n in MESSAGE_SECRET_METAVARS.get(rule, ()) if n in values]
    else:
        held = [v for v in values.values() if len(v) >= 6]
    for text in sorted(
        {t for v in held for t in (v, v.strip(_QUOTES)) if t}, key=len, reverse=True
    ):
        message = message.replace(text, REDACTED)
    return message


def redact_secret_result(result: dict[str, Any]) -> dict[str, Any]:
    """`result` itself when its rule does not match a secret's value; else a
    copy keeping only SECRET_SAFE_EXTRA of `extra`, its message with the secret
    replaced (#1585). Redacting a redacted result returns an equal one, so a
    later report, reading the rewritten opengrep.json, computes the same id."""
    if not is_secret_result(result):
        return result
    extra = result.get("extra") or {}
    kept = {k: v for k, v in extra.items() if k in SECRET_SAFE_EXTRA}
    kept["message"] = _redacted_message(result)
    return {**{k: v for k, v in result.items() if k != "extra"}, "extra": kept}


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

        findings: list[Finding] = []
        root = _scan_root(output_path)
        tool_version = str(
            (data.get("version") if isinstance(data, dict) else None) or "unknown"
        )

        for r in results:
            if not isinstance(r, dict):
                continue
            # A rule that matches a secret's value: its message, raw record and
            # snippet would quote the secret (#1585). Redacted before the id is
            # computed, as trufflehog's adapter drops `Raw`; not enrichment.
            secret_class = is_secret_result(r)
            r = redact_secret_result(r)

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
            context = None
            if path_str and start_line and not secret_class:
                if Path(path_str).is_absolute():
                    readable: str | None = path_str
                elif root is not None:
                    readable = str(root / path_str)
                else:
                    readable = None
                if readable:
                    context = extract_code_snippet(
                        readable, start_line, context_lines=2
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

            findings.append(finding)

        return findings
