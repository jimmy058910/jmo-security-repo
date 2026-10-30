"""Pinned scan targets and the scan helpers the baseline test and generator share.

The baseline test and scripts/dev/generate_baseline.py both scan a vulnerable
application with ``jmo scan``, read what the product wrote, and compare or
record per-CWE and per-tool counts. They share one implementation so the number
the generator records is the number the test asserts: two copies of the CWE or
tool counting would drift apart, and a baseline derived by one would then fail
the other.

Why every target is a commit sha, never a tag or a branch. juice-shop's pin is
one commit after its v20.2.0 tag, so no tag names it, and a moving branch turns
upstream drift into a red nightly run with no change of ours behind it: the
baseline counts findings in specific files at a specific revision. A sha is the
only spelling that names the same tree tomorrow. Bumping a pin means
re-deriving its baseline (``python scripts/dev/generate_baseline.py --target
<name>``) in the same commit; ``test_baselines_pin_the_commit_the_test_scans``
fails until both agree.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]

JUICE_SHOP_URL = "https://github.com/juice-shop/juice-shop.git"
# One commit after the v20.2.0 tag.
JUICE_SHOP_COMMIT = "1618a611b173b4bf114028e6e02549950606e29d"

WEBGOAT_URL = "https://github.com/WebGoat/WebGoat.git"
# Release v2026.5, 2026-10-12.
WEBGOAT_COMMIT = "7e198f39189f33e1912f7cbb60e24e42635ca06a"


@dataclass(frozen=True)
class PinnedTarget:
    """A vulnerable application at the one commit its baseline describes."""

    slug: str  # the baseline's metadata.target
    url: str
    commit: str
    note: str  # the baseline's metadata.notes


# Keyed by the baseline's file stem: tests/integration/baselines/<key>.baseline.json
PINNED_TARGETS = {
    "juice-shop": PinnedTarget(
        "juice-shop/juice-shop",
        JUICE_SHOP_URL,
        JUICE_SHOP_COMMIT,
        "OWASP Juice Shop at the commit one after the v20.2.0 tag",
    ),
    "webgoat": PinnedTarget(
        "WebGoat/WebGoat",
        WEBGOAT_URL,
        WEBGOAT_COMMIT,
        "OWASP WebGoat at release v2026.5",
    ),
}

# One full scan of a vulnerable application: measured 118 s (juice-shop) and
# 62 s (WebGoat) on a workstation; a slow CI runner gets a wide margin.
SCAN_TIMEOUT = 1800
# One git call of a depth-1 clone; each of the four gets this long.
CLONE_TIMEOUT = 300

_CWE_ID = re.compile(r"^\s*(?:CWE[-_ ]?)?(\d+)\b", re.IGNORECASE)


def clone_at_commit(
    url: str, commit: str, dest: Path, timeout: float = CLONE_TIMEOUT
) -> None:
    """Fetch exactly ``commit`` from ``url`` into ``dest`` and check it out.

    ``git init`` plus a depth-1 fetch of the sha, because ``git clone --branch``
    cannot name a commit that is not a tag or a branch tip. Raises on a failed
    or timed-out git call, and when ``dest`` does not end up at ``commit``: the
    caller scans a tree it can name, or does not scan.
    """
    dest.mkdir(parents=True, exist_ok=True)

    def git(*args: str) -> str:
        try:
            done = subprocess.run(
                ["git", *args],
                cwd=dest,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                f"git {' '.join(args)} failed ({exc.returncode}): {exc.stderr.strip()}"
            ) from exc
        return done.stdout

    longpaths = ["-c", "core.longpaths=true"]  # deep node_modules on Windows
    git("init", "--quiet")
    git(*longpaths, "fetch", "--quiet", "--depth", "1", url, commit)
    git(
        *longpaths,
        "-c",
        "advice.detachedHead=false",
        "checkout",
        "--quiet",
        "FETCH_HEAD",
    )

    head = git("rev-parse", "HEAD").strip()
    if head != commit:
        raise RuntimeError(f"fetched {url} at {commit} but HEAD is {head}")


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
