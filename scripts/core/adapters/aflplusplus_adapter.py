#!/usr/bin/env python3
"""
AFL++ adapter: normalize AFL++ fuzzing outputs to CommonFinding
Supports:
- AFL++ crash reports and findings
- JSON exports from afl-collect or custom scripts
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from scripts.core.common_finding import fingerprint, normalize_severity
from scripts.core.compliance_mapper import enrich_finding_with_compliance


def _crash_type_to_severity(crash_type: str) -> str:
    """Map AFL++ crash types to CommonFinding severity."""
    crash_lower = str(crash_type).lower().strip()

    # Critical severity for exploitable crashes
    if any(
        keyword in crash_lower
        for keyword in [
            "segv",
            "segfault",
            "abort",
            "illegal",
            "sigill",
            "overflow",
            "heap",
            "stack",
            "uaf",
            "use-after-free",
        ]
    ):
        return "CRITICAL"

    # High severity for other crashes
    if any(keyword in crash_lower for keyword in ["crash", "fault", "error"]):
        return "HIGH"

    # Medium for hangs/timeouts
    if any(keyword in crash_lower for keyword in ["hang", "timeout", "slow"]):
        return "MEDIUM"

    return "MEDIUM"


def load_aflplusplus(path: str | Path) -> List[Dict[str, Any]]:
    """Load and normalize AFL++ JSON output.

    Expected JSON structure:
    {
      "fuzzer": "afl++",
      "version": "4.0",
      "crashes": [
        {
          "id": "crash-001",
          "type": "SEGV",
          "signal": "SIGSEGV",
          "target": "my_program",
          "input_file": "crashes/id:000000,sig:06,src:000000",
          "timestamp": "2024-01-01T12:00:00Z",
          "stack_trace": "...",
          "classification": "exploitable"
        }
      ],
      "stats": {
        "total_crashes": 5,
        "unique_crashes": 3,
        "hangs": 2
      }
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

    # Extract crashes
    crashes = data.get("crashes", [])
    if not isinstance(crashes, list):
        # Try alternative structure
        if "findings" in data and isinstance(data["findings"], list):
            crashes = data["findings"]
        else:
            crashes = []
    elif len(crashes) == 0:
        # Try alternative structure if crashes is empty
        if "findings" in data and isinstance(data["findings"], list):
            crashes = data["findings"]

    fuzzer_version = str(data.get("version") or "unknown")
    target_name = str(data.get("target") or "unknown")

    for crash in crashes:
        if not isinstance(crash, dict):
            continue

        crash_id = str(crash.get("id") or crash.get("crash_id") or "unknown")
        crash_type = str(crash.get("type") or crash.get("crash_type") or "UNKNOWN")
        signal = str(crash.get("signal") or "")
        target = str(crash.get("target") or target_name)
        input_file = str(crash.get("input_file") or crash.get("testcase") or "")
        timestamp = str(crash.get("timestamp") or "")
        stack_trace = str(crash.get("stack_trace") or crash.get("backtrace") or "")
        classification = str(crash.get("classification") or "unknown")

        # Map crash type to severity
        severity = _crash_type_to_severity(crash_type)
        severity_normalized = normalize_severity(severity)

        # Build message
        message_parts = [f"{crash_type} crash in {target}"]
        if signal:
            message_parts.append(f"(signal: {signal})")
        message = " ".join(message_parts)

        # Build title
        title = f"Fuzzing crash: {crash_type}"
        if classification and classification != "unknown":
            title += f" [{classification}]"

        # Create location from input file
        location_path = input_file if input_file else f"fuzzing/{target}"

        # Create unique fingerprint
        rule_id = f"AFL-{crash_type}"
        fid = fingerprint("afl++", rule_id, location_path, 0, message)

        # Build description
        desc_parts = [f"AFL++ fuzzing discovered a {crash_type} crash in {target}."]
        if classification and classification != "unknown":
            desc_parts.append(f"Classification: {classification}.")
        if stack_trace:
            # Include first 3 lines of stack trace
            trace_lines = stack_trace.strip().split("\n")[:3]
            if trace_lines:
                desc_parts.append("Stack trace preview:")
                desc_parts.append("\n".join(trace_lines))
        description = " ".join(desc_parts)

        # Build tags
        tags = ["fuzzing", "afl++", crash_type.lower()]
        if classification:
            tags.append(f"classification:{classification.lower()}")
        if "segv" in crash_type.lower() or "overflow" in crash_type.lower():
            tags.append("memory-safety")

        # Build remediation
        remediation = f"Fix the {crash_type} crash in {target}. "
        remediation += f"Reproduce with input: {input_file}. "
        if classification == "exploitable":
            remediation += "PRIORITY: This crash is potentially exploitable."

        finding = {
            "schemaVersion": "1.0.0",
            "id": fid,
            "ruleId": rule_id,
            "title": title,
            "message": message,
            "description": description,
            "severity": severity_normalized,
            "tool": {
                "name": "afl++",
                "version": fuzzer_version,
            },
            "location": {
                "path": location_path,
                "startLine": 0,
            },
            "remediation": remediation,
            "tags": tags,
            "context": {
                "crash_id": crash_id,
                "crash_type": crash_type,
                "signal": signal,
                "target": target,
                "input_file": input_file,
                "timestamp": timestamp,
                "classification": classification,
                "stack_trace": stack_trace[:500] if stack_trace else "",  # Truncate
            },
            "raw": crash,
        }

        # Enrich with compliance framework mappings
        finding = enrich_finding_with_compliance(finding)
        findings.append(finding)

    return findings
