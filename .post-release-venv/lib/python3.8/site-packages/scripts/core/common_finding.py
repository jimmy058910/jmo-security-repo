#!/usr/bin/env python3
"""
CommonFinding helpers: severity mapping and fingerprinting.
"""
from __future__ import annotations

import hashlib

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def normalize_severity(value: str | None) -> str:
    if not value:
        return "INFO"
    v = str(value).strip().upper()
    if v in SEVERITY_ORDER:
        return v
    # Map common variants
    mapping = {
        "ERROR": "HIGH",
        "WARN": "MEDIUM",
        "WARNING": "MEDIUM",
        "INFO": "INFO",
        "LOW": "LOW",
        "MED": "MEDIUM",
        "HIGH": "HIGH",
        "CRIT": "CRITICAL",
        "CRITICAL": "CRITICAL",
    }
    return mapping.get(v, "INFO")


def fingerprint(
    tool: str,
    rule_id: str | None,
    path: str | None,
    start_line: int | None,
    message: str | None,
) -> str:
    base = f"{tool}|{rule_id or ''}|{path or ''}|{start_line or 0}|{(message or '').strip()[:120]}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:16]
