#!/usr/bin/env python3
"""
Gitleaks adapter: normalize Gitleaks JSON to CommonFinding
Supports:
- Typical array of findings
- Object with 'findings' array (if present)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from scripts.core.common_finding import (
    extract_code_snippet,
    fingerprint,
    normalize_severity,
)
from scripts.core.compliance_mapper import enrich_finding_with_compliance


def _iter_findings(obj: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict):
                yield item
    elif isinstance(obj, dict):
        # Some formats may use 'findings' or 'leaks'
        for key in ("findings", "leaks", "results"):
            arr = obj.get(key)
            if isinstance(arr, list):
                for item in arr:
                    if isinstance(item, dict):
                        yield item
                break


def load_gitleaks(path: str | Path) -> List[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    raw = p.read_text(encoding="utf-8", errors="ignore").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Not JSON or malformed
        return []

    out: List[Dict[str, Any]] = []
    for f in _iter_findings(data):
        rule_id = str(
            f.get("RuleID")
            or f.get("ruleID")
            or f.get("rule_id")
            or f.get("Description")
            or "GITLEAKS"
        )
        file_path = (
            f.get("File")
            or f.get("FilePath")
            or (f.get("Location") or {}).get("file")
            or f.get("Path")
            or ""
        )
        start_line = None
        if isinstance(f.get("StartLine"), int):
            start_line = f["StartLine"]
        elif isinstance(f.get("Line"), int):
            start_line = f["Line"]
        msg = (
            f.get("Description")
            or f.get("Rule")
            or f.get("Match")
            or "Possible secret detected"
        )
        severity = normalize_severity(str(f.get("Severity") or "HIGH"))
        fid = fingerprint("gitleaks", rule_id, file_path, start_line, msg)

        # Extract secretContext for v1.1.0
        secret_context = {}
        secret = f.get("Secret") or f.get("Match")
        if secret:
            secret_context["type"] = rule_id
            secret_context["secret"] = secret

        # Entropy
        entropy = f.get("Entropy")
        if isinstance(entropy, (int, float)):
            secret_context["entropy"] = float(entropy)

        # Git metadata
        commit = f.get("Commit") or f.get("CommitSHA")
        if commit:
            secret_context["commit"] = commit

        author = f.get("Author") or f.get("CommitAuthor")
        if author:
            secret_context["author"] = author

        date = f.get("Date") or f.get("CommitDate")
        if date:
            secret_context["date"] = date

        # Git URL (if available)
        git_url = f.get("GitURL")
        if git_url:
            secret_context["gitUrl"] = git_url

        # Code context
        context = None
        if file_path and start_line:
            context = extract_code_snippet(file_path, start_line, context_lines=2)

        # Enhanced remediation with secret rotation steps
        remediation = {
            "summary": "Rotate credentials and remove secrets from history",
            "steps": [
                f"Rotate the exposed {rule_id}",
                "Remove the secret from Git history using git-filter-repo or BFG Repo-Cleaner",
                "Scan other repositories for the same secret",
                "Audit access logs for unauthorized usage",
                "Update secret scanning rules to prevent future leaks",
            ],
            "references": [
                "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository"
            ],
        }

        finding: Dict[str, Any] = {
            "schemaVersion": "1.1.0",
            "id": fid,
            "ruleId": rule_id,
            "title": f.get("Rule") or rule_id,
            "message": msg,
            "description": f.get("Description") or msg,
            "severity": severity,
            "tool": {
                "name": "gitleaks",
                "version": str(f.get("Version") or "unknown"),
            },
            "location": {"path": file_path, "startLine": start_line or 0},
            "remediation": remediation,
            "tags": ["secrets"],
            "risk": {"cwe": ["CWE-798"]},
            "raw": f,
        }

        # Add optional v1.1.0 fields if present
        if context:
            finding["context"] = context
        if secret_context:
            finding["secretContext"] = secret_context

        # Enrich with compliance framework mappings
        finding = enrich_finding_with_compliance(finding)
        out.append(finding)
    return out
