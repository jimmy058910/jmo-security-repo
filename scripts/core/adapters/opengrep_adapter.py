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

import json
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
from scripts.core.scan_timings import SCAN_TIMINGS_FILENAME


def _scan_root(output_path: Path) -> Path | None:
    """The target the scan ran in, from the ``scan-timings.json`` beside the output.

    The row runs opengrep from inside its target (R35), so a result's ``path``
    is relative to it and names no file the report phase could open from where
    it runs. The scan records the root beside every tree's outputs. None when
    there is no such file (a golden, a results directory from elsewhere), and
    the path is then read as given.
    """
    try:
        root = json.loads(
            (output_path.parent / SCAN_TIMINGS_FILENAME).read_text(encoding="utf-8")
        ).get("root")
    except (OSError, ValueError, AttributeError):
        return None
    return Path(root) if isinstance(root, str) and root else None


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
            context = None
            if path_str and start_line:
                readable = (
                    str(root / path_str)
                    if root is not None and not Path(path_str).is_absolute()
                    else path_str
                )
                context = extract_code_snippet(readable, start_line, context_lines=2)

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
