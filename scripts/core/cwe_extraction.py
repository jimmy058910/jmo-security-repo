#!/usr/bin/env python3
"""Lift the CWE a tool already reported into `risk.cwe` (#845).

`compliance_mapper.enrich_finding_with_compliance` reads CWEs from
`finding["risk"]["cwe"]` and nowhere else, so everything CWE-driven hangs off
that one field: `cweTop25_2024`, the CWE half of `owaspTop10_2021`, and the
`cwes` input to `nistCsf2_0`, `pciDss4_0` and `mitreAttack`. Most adapters never
populate it, even when the tool reports a CWE in its own output.

Measured on a real `deep` scan, 152 findings after dedup:

=========  ========  ==========  ==================================
tool       findings  `risk.cwe`  CWE in the tool's own output
=========  ========  ==========  ==================================
bandit           17           0  17, structured `issue_cwe.id`
horusec          19           0  15, cited in the tool's `details`
checkov          64           0  **0** -- see below
trivy            46           0  0
hadolint          6           0  0
=========  ========  ==========  ==================================

and `cweTop25_2024` was populated on **0** findings corpus-wide.

**checkov reports no CWE at all, and that correction matters.** The issue put
checkov at 13. Measured, every one of those is the string ``CWE`` occurring
inside ``raw.code_block`` -- which is *the scanned file's own source text*. The
13 came from a fixture comment reading ``# Hardcoded credentials (CWE-798)``.
checkov's structured fields (`bc_category`, `benchmarks`, `description`,
`vulnerability_details`) are all `None`.

Extracting from a field like that would attribute a CWE to a finding because
the **scanned repository** happened to mention one, so any codebase with
``# CWE-89`` in a comment would acquire spurious compliance mappings. That is
why prose is read only from an explicit per-tool allowlist of *tool-authored*
fields, never from anything echoing the scanned file.
"""

from __future__ import annotations

import re
from typing import Any

# `CWE-798`, as tools write it in prose. Bounded to 1-5 digits so a long digit
# run in unrelated text cannot masquerade as an id.
_CWE_IN_TEXT = re.compile(r"\bCWE[-_ ]?(\d{1,5})\b", re.IGNORECASE)

# Structured keys, in the spellings tools actually use. `cweid` is zap's.
_STRUCTURED_KEYS = ("cwe", "CWE", "cweid", "cwe_id", "cweId", "cweID")

# Fields whose text the TOOL wrote, per adapter. Dotted paths, resolved against
# `raw`. Nothing here may be a field that echoes the scanned file's content --
# see the module docstring for why that distinction is the whole safety
# property of this module.
_PROSE_FIELDS: dict[str, tuple[str, ...]] = {
    "horusec": ("vulnerabilities.details",),
}


def _dig(raw: Any, dotted: str) -> Any:
    node: Any = raw
    for part in dotted.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def _ids_from_value(value: Any) -> list[str]:
    """Read CWE ids out of an int, a string, or a list of either."""
    out: list[str] = []
    # No `isinstance(value, bool)` guard here on purpose. `bool` is an `int`, so
    # `cwe: true` would reach the branch below and yield `"True"` -- which then
    # fails the `.isdigit()` canonicalization in `extract_cwes_from_raw` and is
    # dropped. A guard was written, and every mutation of it survived: it could
    # not change any result. Removed rather than kept, because an unfalsifiable
    # branch is a claim about behaviour that nothing checks. The property it was
    # meant to protect is still asserted, by the `{"cwe": True}` case.
    if isinstance(value, int):
        return [str(value)]
    if isinstance(value, str):
        found = _CWE_IN_TEXT.findall(value)
        if found:
            return found
        stripped = value.strip()
        return [stripped] if stripped.isdigit() else []
    if isinstance(value, list):
        for item in value:
            out.extend(_ids_from_value(item))
    return out


def extract_cwes_from_raw(raw: Any, tool: str = "") -> list[str]:
    """CWE ids the tool reported, as canonical ``CWE-<n>``, in first-seen order.

    Returns `[]` for anything it cannot read confidently. Silence is correct
    here: a wrong CWE produces a wrong compliance mapping, which is worse than
    no mapping at all.
    """
    if not isinstance(raw, dict):
        return []

    ids: list[str] = []

    # 1. Structured, top level.
    for key in _STRUCTURED_KEYS:
        if key in raw:
            ids.extend(_ids_from_value(raw[key]))

    # 2. bandit's `{"issue_cwe": {"id": 502, "link": ...}}`.
    issue_cwe = raw.get("issue_cwe")
    if isinstance(issue_cwe, dict):
        ids.extend(_ids_from_value(issue_cwe.get("id")))
    elif issue_cwe is not None:
        ids.extend(_ids_from_value(issue_cwe))

    # 3. Prose the tool itself wrote, for tools that cite a CWE only in words.
    for dotted in _PROSE_FIELDS.get(tool, ()):
        value = _dig(raw, dotted)
        if isinstance(value, str):
            ids.extend(_CWE_IN_TEXT.findall(value))

    seen: set[str] = set()
    ordered: list[str] = []
    for raw_id in ids:
        canonical = f"CWE-{int(raw_id)}" if raw_id.isdigit() else ""
        if canonical and canonical not in seen:
            seen.add(canonical)
            ordered.append(canonical)
    return ordered


def backfill_risk_cwe(findings: list[dict[str, Any]]) -> int:
    """Populate `risk.cwe` from each finding's raw output. Returns the count.

    Runs before `enrich_findings_with_compliance`, which is the only consumer.
    An adapter that already populated `risk.cwe` is left alone: it had the
    tool's structured metadata in hand and this works from a copy.
    """
    filled = 0
    for finding in findings:
        risk = finding.get("risk")
        if isinstance(risk, dict) and risk.get("cwe"):
            continue
        tool = (finding.get("tool") or {}).get("name", "")
        cwes = extract_cwes_from_raw(finding.get("raw"), tool)
        if not cwes:
            continue
        if not isinstance(risk, dict):
            risk = {}
            finding["risk"] = risk
        # An ARRAY of strings, per docs/schemas/common_finding.v1.json. A bare
        # string here was the only schema violation in a 242-finding scan.
        risk["cwe"] = cwes
        filled += 1
    return filled
