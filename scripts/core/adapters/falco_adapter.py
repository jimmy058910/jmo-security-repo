#!/usr/bin/env python3
"""

REFACTORED: v0.9.0 - Now uses plugin architecture
Falco adapter: normalize Falco JSON outputs to CommonFinding
Supports:
- Falco alert JSON output (NDJSON format)
- Falco event logs from runtime monitoring
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from scripts.core.common_finding import fingerprint, normalize_severity
from scripts.core.compliance_mapper import enrich_finding_with_compliance
from scripts.core.plugin_api import (
    AdapterPlugin,
    Finding,
    PluginMetadata,
    adapter_plugin,
)

logger = logging.getLogger(__name__)


def _falco_priority_to_severity(priority: str) -> str:
    """Map Falco priority levels to CommonFinding severity."""
    priority_lower = str(priority).lower().strip()
    mapping = {
        "emergency": "CRITICAL",
        "alert": "CRITICAL",
        "critical": "CRITICAL",
        "error": "HIGH",
        "warning": "MEDIUM",
        "notice": "LOW",
        "informational": "INFO",
        "debug": "INFO",
    }
    return mapping.get(priority_lower, "MEDIUM")


@adapter_plugin(
    PluginMetadata(
        name="falco",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for Falco runtime security monitoring",
        tool_name="falco",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "clean"},
    )
)
class FalcoAdapter(AdapterPlugin):
    """Adapter for Falco runtime security monitoring (plugin architecture)."""

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]

    def parse(self, output_path: Path) -> List[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to falco.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_falco_internal(output_path)

        # Convert dicts to Finding objects
        findings = []
        for f_dict in findings_dicts:
            finding = Finding(
                schemaVersion=f_dict.get("schemaVersion", "1.2.0"),
                id=f_dict.get("id", ""),
                ruleId=f_dict.get("ruleId", ""),
                severity=f_dict.get("severity", "INFO"),
                tool=f_dict.get("tool", {}),
                location=f_dict.get("location", {}),
                message=f_dict.get("message", ""),
                title=f_dict.get("title"),
                description=f_dict.get("description"),
                remediation=f_dict.get("remediation"),
                references=f_dict.get("references", []),
                tags=f_dict.get("tags", []),
                cvss=f_dict.get("cvss"),
                risk=f_dict.get("risk"),
                compliance=f_dict.get("compliance"),
                context=f_dict.get("context"),
                raw=f_dict.get("raw"),
            )
            findings.append(finding)

        return findings


def _load_falco_internal(path: str | Path) -> List[Dict[str, Any]]:
    """Load and normalize Falco JSON output.

    Expected JSON structure (NDJSON - one JSON object per line):
    {
      "output": "Sensitive file opened for reading by non-trusted program",
      "priority": "Warning",
      "rule": "Read sensitive file untrusted",
      "time": "2024-01-01T12:00:00.000Z",
      "output_fields": {
        "container.id": "abc123",
        "container.name": "my-container",
        "fd.name": "/etc/shadow",
        "proc.name": "cat",
        "user.name": "root"
      },
      "source": "syscall",
      "tags": ["filesystem", "mitre_credential_access"],
      "hostname": "host1"
    }
    """
    p = Path(path)
    if not p.exists():
        return []

    findings: List[Dict[str, Any]] = []

    try:
        content = p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    if not content.strip():
        return []

    # Falco outputs NDJSON (one JSON object per line)
    for line_num, line in enumerate(content.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue

        try:
            event = json.loads(line)
        except json.JSONDecodeError as e:
            logger.debug(
                f"Skipping malformed JSON at line {line_num} in {path}: {e.msg} at position {e.pos}"
            )
            continue

        if not isinstance(event, dict):
            continue

        rule = str(event.get("rule") or "Unknown Rule")
        output = str(event.get("output") or "")
        priority = str(event.get("priority") or "Warning")
        timestamp = str(event.get("time") or "")
        source = str(event.get("source") or "syscall")
        hostname = str(event.get("hostname") or "")

        # Extract output fields for context
        output_fields = event.get("output_fields") or {}
        if not isinstance(output_fields, dict):
            output_fields = {}

        # Extract key information
        container_id = str(output_fields.get("container.id") or "")
        container_name = str(output_fields.get("container.name") or "")
        proc_name = str(
            output_fields.get("proc.name") or output_fields.get("proc.cmdline") or ""
        )
        fd_name = str(output_fields.get("fd.name") or "")
        user_name = str(output_fields.get("user.name") or "")

        # Extract tags
        tags_raw = event.get("tags") or []
        tags = ["runtime-security", "falco", source]
        if isinstance(tags_raw, list):
            tags.extend([str(t) for t in tags_raw if t])

        # Map priority to severity
        severity = _falco_priority_to_severity(priority)
        severity_normalized = normalize_severity(severity)

        # Build message
        message = output if output else rule

        # Create location from container/file information
        location_path = fd_name or container_name or hostname or "runtime"

        # Create unique fingerprint
        rule_id = f"FALCO-{rule.replace(' ', '-')}"
        fid = fingerprint("falco", rule_id, location_path, line_num, message)

        # Build description
        description_parts = [output] if output else [rule]
        if container_name:
            description_parts.append(f"Container: {container_name}")
        if proc_name:
            description_parts.append(f"Process: {proc_name}")
        description = " | ".join(description_parts)

        finding = {
            "schemaVersion": "1.0.0",
            "id": fid,
            "ruleId": rule_id,
            "title": rule,
            "message": message,
            "description": description,
            "severity": severity_normalized,
            "tool": {
                "name": "falco",
                "version": str(event.get("falco_version") or "unknown"),
            },
            "location": {
                "path": location_path,
                "startLine": line_num,
            },
            "remediation": "Review runtime behavior and apply security policies to prevent this activity.",
            "tags": tags,
            "context": {
                "timestamp": timestamp,
                "priority": priority,
                "source": source,
                "hostname": hostname,
                "container_id": container_id,
                "container_name": container_name,
                "process": proc_name,
                "file": fd_name,
                "user": user_name,
            },
            "raw": event,
        }

        # Enrich with compliance framework mappings
        finding = enrich_finding_with_compliance(finding)
        findings.append(finding)

    return findings
