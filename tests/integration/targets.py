"""Shared scan helpers for the baseline test and scripts/dev/generate_baseline.py.

Both scan a vulnerable application with ``jmo scan``, read what the product
wrote, and compare or record per-CWE and per-tool counts. They share one
implementation so the number the generator records is the number the test
asserts: two copies of the CWE or tool counting would drift apart, and a
baseline derived by one would then fail the other.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]

JUICE_SHOP_URL = "https://github.com/juice-shop/juice-shop.git"
WEBGOAT_URL = "https://github.com/WebGoat/WebGoat.git"

# One full scan of a vulnerable application: measured 118 s (juice-shop) and
# 62 s (WebGoat) on a workstation; a slow CI runner gets a wide margin.
SCAN_TIMEOUT = 1800

_CWE_ID = re.compile(r"^\s*(?:CWE[-_ ]?)?(\d+)\b", re.IGNORECASE)


def run_scan(target_path: Path, results_dir: Path) -> subprocess.CompletedProcess[str]:
    """Run ``jmo scan`` on a directory and return the finished process.

    Real scanners, so HOME stays as the caller set it: they, JMo's ~/.jmo/bin
    and isolated venvs, and yara's ~/.jmo/yara-rules all resolve through it. The
    scan's two writes outside its results are contained instead: history goes to
    a database beside ``results_dir``, and the counter ``_show_kofi_reminder``
    bumps in ~/.jmo/config.yml (it has no injection point) is put back
    afterwards.
    """
    cmd = [
        sys.executable,
        "-m",
        "scripts.cli.jmo",
        "scan",
        "--repo",
        str(target_path),
        "--results-dir",
        str(results_dir),
        "--history-db",
        str(results_dir.parent / "history.db"),
    ]

    config = Path.home() / ".jmo" / "config.yml"
    before = config.read_bytes() if config.exists() else None
    try:
        return subprocess.run(
            cmd,
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=SCAN_TIMEOUT,
        )
    finally:
        if before is None:
            config.unlink(missing_ok=True)
        else:
            config.write_bytes(before)


def load_findings(results_dir: Path) -> list[dict[str, Any]]:
    """Return the findings ``jmo scan`` wrote to ``summaries/findings.json``.

    Raises when the file is absent or is not ``{"findings": [...]}``: a scan that
    wrote nothing must not read as a scan that found nothing.
    """
    findings_file = results_dir / "summaries" / "findings.json"
    if not findings_file.exists():
        raise FileNotFoundError(
            f"jmo scan wrote no summaries/findings.json under {results_dir}"
        )

    data = json.loads(findings_file.read_bytes())
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise ValueError(
            f"{findings_file} is not a JSON object with a 'findings' list "
            f"(got {type(data).__name__})"
        )
    return data["findings"]  # type: ignore[no-any-return]


def bare_cwe(value: object) -> str | None:
    """Reduce ``"CWE-89: Improper ..."``, ``"CWE-89"`` or ``"89"`` to ``"CWE-89"``.

    ``risk.cwe`` carries two spellings: bare (gitleaks and others) and with the
    weakness title appended (opengrep's rule bundle). Returns None for anything
    that does not start with a CWE number.
    """
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    match = _CWE_ID.match(str(value))
    return f"CWE-{int(match.group(1))}" if match else None


def finding_cwes(finding: dict[str, Any]) -> list[str]:
    """Return the distinct bare CWE ids of one finding, in the order listed.

    Reads ``risk.cwe`` (CommonFinding v1.2.0) and falls back to ``metadata.cwe``
    (legacy tools) only when the first names none. Roughly half of a real scan's
    findings carry ``risk.cwe = None``.
    """
    risk = finding.get("risk")
    raw: list[object] = []
    if isinstance(risk, dict) and isinstance(risk.get("cwe"), list):
        raw = risk["cwe"]

    ids = _distinct(bare_cwe(item) for item in raw)
    if ids:
        return ids

    metadata = finding.get("metadata")
    if isinstance(metadata, dict):
        legacy = metadata.get("cwe", metadata.get("CWE"))
        return _distinct(
            bare_cwe(item)
            for item in (legacy if isinstance(legacy, list) else [legacy])
        )
    return []


def finding_tools(finding: dict[str, Any]) -> set[str]:
    """Return every tool that reported a finding.

    A clustered finding keeps one ``tool`` but lists every member in
    ``detected_by``; juice-shop's trufflehog findings were all merged into
    gitleaks', so ``tool.name`` alone would count trufflehog as silent.
    """
    names: set[str] = set()
    tool = finding.get("tool")
    if isinstance(tool, dict) and tool.get("name"):
        names.add(tool["name"])
    for member in finding.get("detected_by") or []:
        if isinstance(member, dict) and member.get("name"):
            names.add(member["name"])
    return names


def count_by_tool(findings: list[dict[str, Any]]) -> Counter[str]:
    """Count findings per reporting tool, once per finding per tool."""
    counts: Counter[str] = Counter()
    for finding in findings:
        counts.update(finding_tools(finding))
    return counts


def _distinct(values: Any) -> list[str]:
    """Drop None and repeats, keeping first-seen order."""
    return list(dict.fromkeys(v for v in values if v))
