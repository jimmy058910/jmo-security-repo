#!/usr/bin/env python3
"""
OWASP ZAP adapter: normalize ZAP JSON outputs to CommonFinding
Supports:
- ZAP Baseline Scan JSON output
- ZAP Full Scan JSON output
- ZAP API Scan JSON output
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from scripts.core.common_finding import fingerprint, normalize_severity
from scripts.core.compliance_mapper import enrich_finding_with_compliance


def _zap_risk_to_severity(risk: str) -> str:
    """Map ZAP risk levels to CommonFinding severity."""
    risk_lower = str(risk).lower().strip()
    mapping = {
        "informational": "INFO",
        "low": "LOW",
        "medium": "MEDIUM",
        "high": "HIGH",
        "critical": "CRITICAL",
    }
    return mapping.get(risk_lower, "MEDIUM")


def load_zap(path: str | Path) -> List[Dict[str, Any]]:
    """Load and normalize ZAP JSON output.

    Expected JSON structure:
    {
      "site": [
        {
          "alerts": [
            {
              "alert": "SQL Injection",
              "risk": "High",
              "confidence": "Medium",
              "desc": "...",
              "solution": "...",
              "reference": "...",
              "cweid": "89",
              "wascid": "19",
              "instances": [
                {
                  "uri": "http://example.com/page",
                  "method": "GET",
                  "param": "id",
                  "evidence": "..."
                }
              ]
            }
          ]
        }
      ]
    }
    """
    p = Path(path)
    if not p.exists():
        return []

    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
    except (json.JSONDecodeError, OSError):
        return []

    if not isinstance(data, dict):
        return []

    findings: List[Dict[str, Any]] = []

    # ZAP output structure: {"site": [{"alerts": [...]}]}
    sites = data.get("site", [])
    if not isinstance(sites, list):
        return []

    for site in sites:
        if not isinstance(site, dict):
            continue

        alerts = site.get("alerts", [])
        if not isinstance(alerts, list):
            continue

        for alert in alerts:
            if not isinstance(alert, dict):
                continue

            alert_name = str(alert.get("alert") or alert.get("name") or "Unknown")
            risk = str(alert.get("risk") or "Medium")
            confidence = str(alert.get("confidence") or "Medium")
            description = str(alert.get("desc") or "")
            solution = str(alert.get("solution") or "")
            reference = str(alert.get("reference") or "")
            cweid = str(alert.get("cweid") or "")
            wascid = str(alert.get("wascid") or "")

            severity = _zap_risk_to_severity(risk)
            severity_normalized = normalize_severity(severity)

            # Process instances (individual occurrences of the alert)
            instances = alert.get("instances", [])
            if not isinstance(instances, list) or len(instances) == 0:
                # If no instances, create a single finding for the alert
                instances = [{}]

            for idx, instance in enumerate(instances):
                if not isinstance(instance, dict):
                    continue

                uri = str(instance.get("uri") or instance.get("url") or "")
                method = str(instance.get("method") or "")
                param = str(instance.get("param") or instance.get("parameter") or "")
                evidence = str(instance.get("evidence") or "")

                # Extract path from URI for location
                file_path = uri.split("?")[0] if uri else ""

                # Build message
                msg_parts = [alert_name]
                if param:
                    msg_parts.append(f"(param: {param})")
                if method:
                    msg_parts.append(f"[{method}]")
                message = " ".join(msg_parts)

                # Create unique fingerprint per instance
                rule_id = f"ZAP-{cweid}" if cweid else f"ZAP-{alert_name}"
                location_key = f"{uri}:{method}:{param}:{idx}"
                fid = fingerprint("zap", rule_id, location_key, 0, message)

                # Build tags
                tags = ["dast", "web-security"]
                if cweid:
                    tags.append(f"CWE-{cweid}")
                if wascid:
                    tags.append(f"WASC-{wascid}")
                tags.append(f"confidence:{confidence.lower()}")

                # Build references
                refs = []
                if reference:
                    for ref_url in reference.split("\n"):
                        ref_url = ref_url.strip()
                        if ref_url:
                            refs.append(ref_url)

                finding = {
                    "schemaVersion": "1.0.0",
                    "id": fid,
                    "ruleId": rule_id,
                    "title": alert_name,
                    "message": message,
                    "description": description.strip() if description else alert_name,
                    "severity": severity_normalized,
                    "tool": {
                        "name": "zap",
                        "version": str(data.get("@version") or "unknown"),
                    },
                    "location": {
                        "path": file_path,
                        "startLine": 0,
                    },
                    "remediation": solution.strip() if solution else "",
                    "references": refs if refs else None,
                    "tags": tags,
                    "context": {
                        "uri": uri,
                        "method": method,
                        "param": param,
                        "evidence": (
                            evidence[:200] if evidence else ""
                        ),  # Truncate long evidence
                        "confidence": confidence,
                        "risk": risk,
                    },
                    "raw": {
                        "alert": alert_name,
                        "risk": risk,
                        "confidence": confidence,
                        "cweid": cweid,
                        "wascid": wascid,
                        "uri": uri,
                        "method": method,
                        "param": param,
                        "evidence": evidence,
                    },
                }

                # Enrich with compliance framework mappings
                finding = enrich_finding_with_compliance(finding)
                findings.append(finding)

    return findings
