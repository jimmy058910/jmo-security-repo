#!/usr/bin/env python3
"""
Trivy RBAC adapter - Maps Trivy Kubernetes RBAC assessment JSON to CommonFinding schema.

Plugin Architecture (v0.9.0):
- Uses @adapter_plugin decorator for auto-discovery
- Inherits from AdapterPlugin base class
- Returns Finding objects (not dicts)
- Auto-loaded by plugin registry

v1.0.0 Feature #1:
- Kubernetes workload and RBAC misconfiguration assessment
- Role and ClusterRole privilege analysis
- Overly permissive RBAC detection
- CIS Kubernetes Benchmark compliance

Tool Version: 0.74.0
Output Format: `trivy config` JSON -- ``Results[].Misconfigurations[]``
Exit Codes: 0 (clean), 1 (findings)

THE SCHEMA THIS PARSES, AND THE ONE IT USED TO
----------------------------------------------
Until #1215 this module read a top-level ``checks`` array of
``{"checkID", "success", ...}``. **No version of trivy has ever emitted that.**
``trivy config`` writes::

    {"SchemaVersion": 2,
     "Trivy": {"Version": "0.74.0"},
     "Results": [{"Target": "manifests/pod.yaml",
                  "Class": "config", "Type": "kubernetes",
                  "Misconfigurations": [{"ID": "KSV-0001", "Status": "FAIL", ...}]}]}

so ``data.get("checks", [])`` returned ``[]`` and the adapter produced **zero
findings from real output, always**. Every unit test passed because every unit
test hand-built the imagined shape -- a fixture encoding an assumption about the
caller rather than a measurement of it. The guard against a repeat is the golden
fixture under ``tests/fixtures/golden/trivy_rbac/``, which is real captured
output rather than a hand-written dict.

Two things the real schema gives that the invented one could not: ``Target`` is
a **path on disk**, so findings group by file and dedup has a real key, and
``CauseMetadata.StartLine`` is a **real line number**. The old code synthesised
``"Kind/name"`` and line 0.

``Status`` is ``FAIL`` for everything trivy puts in this array -- it does not
report passes here -- but it is filtered explicitly anyway, because
``--include-non-failures`` adds ``PASS`` entries and a user can reach that flag
through ``per_tool`` config.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from scripts.core.adapters.common import safe_load_json_file
from scripts.core.common_finding import fingerprint, normalize_severity
from scripts.core.plugin_api import (
    AdapterPlugin,
    Finding,
    PluginMetadata,
    adapter_plugin,
)

# Configure logging
logger = logging.getLogger(__name__)


@adapter_plugin(
    PluginMetadata(
        name="trivy_rbac",
        version="1.0.0",
        author="JMo Security",
        description="Adapter for Trivy Kubernetes RBAC security assessment",
        tool_name="trivy-rbac",
        schema_version="1.2.0",
        output_format="json",
        exit_codes={0: "clean", 1: "findings"},
    )
)
class TrivyRbacAdapter(AdapterPlugin):
    """Adapter for Trivy Kubernetes RBAC assessment (plugin architecture).

    v1.0.0 Features:
    - Kubernetes RBAC privilege analysis
    - Overly permissive role detection
    - CIS Kubernetes Benchmark checks
    - Cluster-admin and wildcard permission detection

    Findings are automatically tagged as 'rbac' and 'kubernetes'.
    """

    @property
    def metadata(self) -> PluginMetadata:
        """Return plugin metadata."""
        return self.__class__._plugin_metadata  # type: ignore[attr-defined,no-any-return]  # Dynamically attached by @adapter_plugin decorator

    def parse(self, output_path: Path) -> list[Finding]:
        """Parse tool output and return normalized findings.

        Args:
            output_path: Path to trivy-rbac.json output file

        Returns:
            List of Finding objects following CommonFinding schema v1.2.0
        """
        # Delegate to internal function that returns dicts
        findings_dicts = _load_trivy_rbac_internal(output_path)

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


def _load_trivy_rbac_internal(path: str | Path) -> list[dict[str, Any]]:
    """Internal function to parse `trivy config` JSON output.

    Args:
        path: Path to trivy-rbac.json output file

    Returns:
        List of dicts (converted to Finding objects by parse() method)
    """
    data = safe_load_json_file(path, default=None)

    out: list[dict[str, Any]] = []

    if not isinstance(data, dict):
        return []

    trivy_meta = data.get("Trivy")
    trivy_version = str(
        trivy_meta.get("Version", "unknown")
        if isinstance(trivy_meta, dict)
        else "unknown"
    )

    results = data.get("Results", [])
    if not isinstance(results, list):
        return []

    for result in results:
        if not isinstance(result, dict):
            continue

        # `Target` is the path trivy scanned, relative to the scan root.
        target = str(result.get("Target", ""))

        misconfigurations = result.get("Misconfigurations", [])
        if not isinstance(misconfigurations, list):
            continue

        for misconf in misconfigurations:
            if not isinstance(misconf, dict):
                continue

            # Only failures are findings -- see the module docstring for why
            # this is filtered rather than assumed.
            if str(misconf.get("Status", "FAIL")).upper() != "FAIL":
                continue

            check_id = str(misconf.get("ID", ""))
            # ONE value in both the fingerprint and the ruleId slot. The report
            # phase re-keys ids from the normalised path only when it can
            # recompute fingerprint(tool, ruleId, path, line, message) and get
            # the same answer; an adapter that hashes a different rule slot
            # than it reports falls through that check silently (#1135, syft).
            rule_id = check_id or "trivy-rbac-check"
            title = str(misconf.get("Title", check_id))
            description = str(misconf.get("Description", ""))
            severity = normalize_severity(str(misconf.get("Severity", "MEDIUM")))
            category = str(misconf.get("Type", "Kubernetes Security Check"))
            resolution = str(misconf.get("Resolution", ""))

            cause = misconf.get("CauseMetadata")
            if not isinstance(cause, dict):
                cause = {}
            # A file-level check carries no StartLine at all: measured, 1 of 56
            # on the golden sample (KSV-0109, "ConfigMap with secrets").
            raw_line = cause.get("StartLine", 0)
            start_line = raw_line if isinstance(raw_line, int) else 0

            # `Message` is the instance-specific sentence ("ConfigMap 'x' ...
            # stores secrets in key(s) ..."); `Description` is the generic rule
            # text. Prefer the specific one, and never emit an empty message.
            message = str(misconf.get("Message", "")) or description or title

            location_path = target or f"trivy-rbac-check:{check_id}"

            fid = fingerprint("trivy-rbac", rule_id, location_path, start_line, message)

            references: list[str] = []
            primary_url = str(misconf.get("PrimaryURL", ""))
            if primary_url:
                references.append(primary_url)
            extra_refs = misconf.get("References", [])
            if isinstance(extra_refs, list):
                references.extend(
                    str(ref) for ref in extra_refs if ref and str(ref) not in references
                )

            haystack = f"{title} {description}".lower()
            tags = ["rbac", "kubernetes", "k8s-security", "access-control"]
            if "cluster-admin" in haystack:
                tags.append("cluster-admin")
            if "wildcard" in haystack:
                tags.append("wildcard-permissions")
            if "secret" in haystack:
                tags.append("secret-access")

            finding = {
                "schemaVersion": "1.2.0",
                "id": fid,
                "ruleId": rule_id,
                "title": title,
                "message": message,
                "description": description,
                "severity": severity,
                "tool": {
                    "name": "trivy-rbac",
                    "version": trivy_version,
                },
                "location": {
                    "path": location_path,
                    "startLine": start_line,
                },
                "remediation": resolution
                or (
                    f"Review and restrict Kubernetes permissions for {location_path}. "
                    "Follow principle of least privilege."
                ),
                "references": references,
                "tags": tags,
                "context": {
                    "check_id": check_id or None,
                    "category": category,
                    "target": target or None,
                    "provider": str(cause.get("Provider", "")) or None,
                    "service": str(cause.get("Service", "")) or None,
                    "resource": str(cause.get("Resource", "")) or None,
                },
                "raw": misconf,
            }

            out.append(finding)

    return out
