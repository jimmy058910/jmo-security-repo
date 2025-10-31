#!/usr/bin/env python3
"""
TruffleHog adapter: normalize various TruffleHog outputs to CommonFinding
Inputs supported:
- JSON array of findings
- NDJSON (one JSON object per line)
- Single JSON object
- Nested arrays [[{...}]]

REFACTORED: v0.9.0 - Now uses plugin architecture
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Iterable, List

from scripts.core.common_finding import normalize_severity
from scripts.core.compliance_mapper import enrich_finding_with_compliance
from scripts.core.plugin_api import (
    AdapterPlugin,
    Finding,
    PluginMetadata,
    adapter_plugin,
)

logger = logging.getLogger(__name__)


def _flatten(obj: Any) -> Iterable[Dict[str, Any]]:
    if obj is None:
        return
    if isinstance(obj, dict):
        yield obj
    elif isinstance(obj, list):
        for item in obj:
            yield from _flatten(item)


def _iter_trufflehog(path: Path) -> Iterable[Dict[str, Any]]:
    raw = path.read_text(encoding="utf-8", errors="ignore")
    if not raw.strip():
        return
    # Try JSON parse of entire file first
    try:
        data = json.loads(raw)
        for item in _flatten(data):
            if isinstance(item, dict):
                yield item
        return
    except json.JSONDecodeError as e:
        logger.debug(
            f"Falling back to NDJSON parsing for {path}: {e.msg} at position {e.pos}"
        )
    # Fall back to NDJSON
    for line_num, line in enumerate(raw.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            logger.debug(
                f"Skipping malformed JSON at line {line_num} in {path}: {e.msg} at position {e.pos}"
            )
            continue
        if isinstance(obj, dict):
            yield obj
        elif isinstance(obj, list):
            for item in _flatten(obj):
                if isinstance(item, dict):
                    yield item


@adapter_plugin(
    PluginMetadata(
        name="trufflehog",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for TruffleHog secret scanner with verification",
        tool_name="trufflehog",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "clean", 1: "findings", 2: "error"},
    )
)
class TruffleHogAdapter(AdapterPlugin):
    """TruffleHog secret scanner adapter (plugin architecture)."""

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path) -> List[Finding]:
        """Parse TruffleHog JSON/NDJSON output and return normalized findings.

        Args:
            output_path: Path to trufflehog.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        if not output_path.exists():
            return []

        findings: List[Finding] = []

        for f in _iter_trufflehog(output_path):
            detector = str(f.get("DetectorName") or f.get("Detector") or "Unknown")
            verified = bool(f.get("Verified") or f.get("verified") or False)

            # Try to extract file path from SourceMetadata.Data.Filesystem.file or similar
            file_path = ""
            sm = f.get("SourceMetadata") or {}
            data = sm.get("Data") if isinstance(sm, dict) else {}
            if isinstance(data, dict):
                fs = data.get("Filesystem") or {}
                if isinstance(fs, dict):
                    file_path = fs.get("file") or fs.get("path") or ""
            # Some variants include Filename / Raw etc.
            file_path = file_path or f.get("Filename") or f.get("Path") or ""

            start_line = None
            if isinstance(f.get("StartLine"), int):
                start_line = f["StartLine"]
            elif isinstance(f.get("Line"), int):
                start_line = f["Line"]

            msg = f.get("Raw") or f.get("Redacted") or detector
            sev = "HIGH" if verified else "MEDIUM"
            severity = normalize_severity(sev)
            rule_id = detector

            # Create Finding object
            finding = Finding(
                schemaVersion="1.2.0",
                id="",  # Will be set by fingerprint
                ruleId=rule_id,
                title=f"{detector} secret",
                message=msg if isinstance(msg, str) else str(msg),
                description="Potential secret detected by TruffleHog",
                severity=severity,
                tool={
                    "name": "trufflehog",
                    "version": str(f.get("Version") or "unknown"),
                },
                location={"path": file_path, "startLine": start_line or 0},
                remediation="Rotate credentials and purge from history.",
                tags=["secrets", "verified" if verified else "unverified"],
                risk={
                    "cwe": ["CWE-798"],  # Use of Hard-coded Credentials
                    "confidence": "HIGH" if verified else "MEDIUM",
                    "likelihood": "HIGH",
                    "impact": "HIGH",
                },
                raw=f,
            )

            # Generate fingerprint
            finding.id = self.get_fingerprint(finding)

            # Enrich with compliance
            finding_dict = vars(finding)
            finding_dict = enrich_finding_with_compliance(finding_dict)
            finding.compliance = finding_dict.get("compliance")

            findings.append(finding)

        return findings
