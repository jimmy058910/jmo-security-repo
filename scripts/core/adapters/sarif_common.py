#!/usr/bin/env python3
"""Generic SARIF 2.1.0 importer shared by the SARIF-emitting tool bindings.

Design: docs/superpowers/specs/2026-09-12-sarif-importer-design.md.

This module deliberately defines **no** ``AdapterPlugin`` subclass. The plugin
loader registers the first subclass it meets in ``sorted(dir(module))``, so a
registrable base class named ``SarifAdapter`` would win over ``ZizmorAdapter``
and lose to ``GitleaksAdapter`` -- one tool in three broken by the first letter
of its class name (spec section 2.6). Each binding is an ordinary adapter whose
``parse()`` calls :func:`parse_sarif` with its :class:`SarifToolSpec`.

Severity is resolved by a five-rank chain (section 3.2), because ``result.level``
alone reads every osv-scanner finding as MEDIUM and collapses zizmor's Low and
Informational into one bucket. ``file:`` URIs are decoded to plain paths
(section 3.3) so the report phase's root-stripping can see a path instead of a
URI -- the #861 failure class.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from scripts.core.adapters.common import safe_load_json_file
from scripts.core.common_finding import fingerprint, normalize_severity
from scripts.core.exceptions import AdapterParseException
from scripts.core.plugin_api import Finding
from scripts.core.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)

SARIF_VERSION = "2.1.0"

# CVSS v3.1 qualitative ranges; `> 0.0` is LOW, `0.0` is INFO (section 3.2).
_CVSS_BUCKETS: tuple[tuple[float, str], ...] = (
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
)


@dataclass(frozen=True)
class SarifToolSpec:
    """What one binding contributes: the tool name and its static tags."""

    tool: str  # Finding.tool["name"] AND the ToolRegistry key
    tags: tuple[str, ...] = ()


def parse_sarif(output_path: Path, spec: SarifToolSpec) -> list[Finding]:
    """Parse one SARIF 2.1.0 document into CommonFinding objects.

    Raises:
        AdapterParseException: the file is valid JSON but not a SARIF
            document (no ``runs`` list). Missing, empty and malformed files
            return ``[]`` through ``safe_load_json_file``'s shared warnings.
    """
    path = Path(output_path)
    data = safe_load_json_file(path, default=None)
    if data is None:
        return []
    if not isinstance(data, dict) or not isinstance(data.get("runs"), list):
        raise AdapterParseException(
            spec.tool,
            path,
            "not a SARIF document: expected an object with a `runs` list",
        )

    version = data.get("version")
    if version is not None and version != SARIF_VERSION:
        logger.warning(
            "%s: SARIF version %r is not %s; parsing anyway (SARIF is additive)",
            spec.tool,
            version,
            SARIF_VERSION,
        )

    runs = [run for run in data["runs"] if isinstance(run, dict)]
    tool_version = _tool_version(spec.tool, runs)
    findings: list[Finding] = []
    for run in runs:
        rules = _rules(run)
        results = run.get("results")
        if not isinstance(results, list):
            continue
        for result in results:
            if isinstance(result, dict):
                findings.append(_finding(result, rules, spec, tool_version))
    return findings


# --- tool version ------------------------------------------------------------


def _registry_version(tool: str) -> str | None:
    """versions.yaml first; the document's own version claim is a fallback
    (gitleaks 8.30.1 reports ``semanticVersion: v8.0.0``, section 2.4)."""
    try:
        info = ToolRegistry().get_tool(tool)
    except Exception:  # Acceptable: version detection fallback, registry may not load
        return None
    return info.version if info else None


def _tool_version(tool: str, runs: list[dict[str, Any]]) -> str:
    registry = _registry_version(tool)
    if registry:
        return str(registry)
    driver = _driver(runs[0]) if runs else {}
    for key in ("version", "semanticVersion"):
        value = driver.get(key)
        if isinstance(value, str) and value:
            return value
    return "unknown"


def _driver(run: dict[str, Any]) -> dict[str, Any]:
    tool = run.get("tool")
    driver = tool.get("driver") if isinstance(tool, dict) else None
    return driver if isinstance(driver, dict) else {}


def _rules(run: dict[str, Any]) -> list[Any]:
    rules = _driver(run).get("rules")
    return rules if isinstance(rules, list) else []


def _rule_for(result: dict[str, Any], rules: list[Any]) -> dict[str, Any]:
    """By ``ruleIndex`` when supplied and in range, else by ``rules[].id ==
    result.ruleId`` (section 2.3: osv-scanner sets the index, zizmor and
    gitleaks do not)."""
    index = result.get("ruleIndex")
    if (
        isinstance(index, int)
        and not isinstance(index, bool)
        and 0 <= index < len(rules)
    ):
        candidate = rules[index]
        if isinstance(candidate, dict):
            return candidate
    rule_id = result.get("ruleId")
    if rule_id is not None:
        for candidate in rules:
            if isinstance(candidate, dict) and candidate.get("id") == rule_id:
                return candidate
    return {}


# --- severity ----------------------------------------------------------------


def _props(holder: dict[str, Any]) -> dict[str, Any]:
    props = holder.get("properties")
    return props if isinstance(props, dict) else {}


def _security_severity(holders: tuple[dict[str, Any], ...]) -> float | None:
    """Rank 1: GitHub's ``security-severity`` (a CVSS base score as a string),
    on the result first, then on the rule. A non-numeric value is ignored."""
    for holder in holders:
        raw = _props(holder).get("security-severity")
        if raw is None or isinstance(raw, bool):
            continue
        try:
            return float(raw)
        except (TypeError, ValueError):
            logger.debug("ignoring non-numeric security-severity %r", raw)
    return None


def _severity_property(holders: tuple[dict[str, Any], ...]) -> str | None:
    """Rank 2: a property named ``severity`` or ending in ``/severity``
    (``zizmor/severity`` and any future ``<tool>/severity``)."""
    for holder in holders:
        for key, value in _props(holder).items():
            if (key == "severity" or key.endswith("/severity")) and isinstance(
                value, str
            ):
                return value
    return None


def _bucket(score: float) -> str:
    for floor, severity in _CVSS_BUCKETS:
        if score >= floor:
            return severity
    return "LOW" if score > 0.0 else "INFO"


def _resolve_severity(
    result: dict[str, Any], rule: dict[str, Any]
) -> tuple[str, dict[str, float] | None]:
    """Section 3.2, first hit wins. Returns ``(severity, cvss-or-None)``."""
    holders = (result, rule)
    score = _security_severity(holders)
    if score is not None:
        return _bucket(score), {"score": score}
    prop = _severity_property(holders)
    if prop is not None:
        return normalize_severity(prop), None
    level = result.get("level")
    if isinstance(level, str) and level:
        return normalize_severity(level), None
    default = rule.get("defaultConfiguration")
    default_level = default.get("level") if isinstance(default, dict) else None
    if isinstance(default_level, str) and default_level:
        return normalize_severity(default_level), None
    return normalize_severity("warning"), None  # SARIF's documented default


# --- location ----------------------------------------------------------------


def _decode_uri(uri: str) -> str:
    """``file:`` URIs become plain paths; anything else passes through unchanged."""
    if not uri.lower().startswith("file:"):
        return uri
    parts = urlsplit(uri)
    path = unquote(parts.path)
    if parts.netloc and parts.netloc.lower() != "localhost":
        return f"//{parts.netloc}{path}"
    if len(path) >= 3 and path[0] == "/" and path[1].isalpha() and path[2] == ":":
        path = path[1:]  # `/C:/x` -> `C:/x`
    return path


def _location(result: dict[str, Any]) -> dict[str, Any]:
    locations = result.get("locations")
    physical: dict[str, Any] = {}
    if isinstance(locations, list) and locations and isinstance(locations[0], dict):
        candidate = locations[0].get("physicalLocation")
        if isinstance(candidate, dict):
            physical = candidate
    artifact = physical.get("artifactLocation")
    uri = artifact.get("uri") if isinstance(artifact, dict) else None
    location: dict[str, Any] = {
        "path": _decode_uri(uri) if isinstance(uri, str) else ""
    }
    region = physical.get("region")
    if isinstance(region, dict):
        for key in ("startLine", "endLine", "startColumn", "endColumn"):
            value = region.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                location[key] = value
    return location


# --- fields ------------------------------------------------------------------


def _text(holder: dict[str, Any], key: str) -> str | None:
    value = holder.get(key)
    if isinstance(value, dict):
        text = value.get("text")
        return text if isinstance(text, str) and text else None
    return None


def _finding(
    result: dict[str, Any],
    rules: list[Any],
    spec: SarifToolSpec,
    tool_version: str,
) -> Finding:
    rule = _rule_for(result, rules)
    rule_id = str(result.get("ruleId") or rule.get("id") or "SARIF")
    message = _text(result, "message") or ""
    title = str(rule.get("name") or _text(rule, "shortDescription") or rule_id)
    description = (
        _text(rule, "fullDescription") or _text(rule, "shortDescription") or message
    )
    severity, cvss = _resolve_severity(result, rule)
    location = _location(result)

    tags = list(spec.tags)
    for tag in _props(rule).get("tags") or []:
        if isinstance(tag, str) and tag not in tags:
            tags.append(tag)
    help_uri = rule.get("helpUri")

    return Finding(
        schemaVersion="1.2.0",
        # The column is part of the key (#1242): two results on one line at
        # different columns are two findings, and gitleaks reports exactly that.
        id=fingerprint(
            spec.tool,
            rule_id,
            location["path"],
            location.get("startLine"),
            message,
            start_column=location.get("startColumn"),
        ),
        ruleId=rule_id,
        severity=severity,
        tool={"name": spec.tool, "version": tool_version},
        location=location,
        message=message,
        title=title,
        description=description,
        remediation=_text(rule, "help") or "See rule documentation",
        references=[help_uri] if isinstance(help_uri, str) and help_uri else [],
        tags=tags,
        cvss=cvss,
        raw=result,
    )
