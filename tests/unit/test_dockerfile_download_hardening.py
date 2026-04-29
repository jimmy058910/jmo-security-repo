#!/usr/bin/env python3
"""Drift guard: every binary download in `Dockerfile.*` builder stages must use curl.

PR #350 hardened all curl invocations with `-f --retry --retry-all-errors --max-time`,
but missed 9 wget invocations across nuclei / ZAP / dependency-check in all 4
Dockerfiles. The post-v1.0.5 nightly Docker Smoke Tests then failed when nuclei's
release URL returned a transient HTTP error and `wget --tries=3` didn't retry on
HTTP errors (wget retries connection failures only by default).

Standardizing on the curl pattern documented in `.claude/rules/docker.rules.md`
gives uniform retry-on-any-error behavior. This test enforces that.

Allowed:
  - `wget` in the apt-get install lines (we keep it available as a builder tool
    even though no download currently uses it — removing it is a separate concern).
  - `wget` in comments.
  - `wget` in test fixtures (`tests/e2e/fixtures/iac/Dockerfile.bad`,
    `tests/fixtures/samples/dockerfile-issues/Dockerfile`) which are intentional
    bad-Dockerfile examples.

Forbidden:
  - `wget` actually invoking a URL — `wget URL`, `wget -q URL`, etc.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Match a wget download invocation: `wget` followed by flags then a URL or
# variable-quoted URL. Matches at start-of-line or after `&&`/`;`/whitespace.
# Excludes the apt-get continuation line (which is just `    wget \`).
WGET_DOWNLOAD_PATTERN = re.compile(
    r"""
    (?:^|\s|&&|;)         # boundary
    wget                  # the command
    \s+                   # at least one space
    (?:-\S+\s+)*          # zero or more short/long flags
    ["']?https?://        # URL (quoted or bare)
    """,
    re.VERBOSE | re.MULTILINE,
)


def _production_dockerfiles() -> list[Path]:
    """Dockerfile.* files in repo root that ship in releases."""
    return sorted(p for p in REPO_ROOT.glob("Dockerfile.*") if p.is_file())


def test_no_wget_downloads_in_production_dockerfiles() -> None:
    """No `wget URL` invocation may appear in any production Dockerfile.

    All binary downloads must use the hardened curl pattern in
    `.claude/rules/docker.rules.md`. wget retries connection failures only
    and silently fails on transient HTTP 4xx/5xx; curl with
    `--retry-all-errors` recovers.
    """
    violations: list[str] = []
    for path in _production_dockerfiles():
        text = path.read_text(encoding="utf-8")
        for match in WGET_DOWNLOAD_PATTERN.finditer(text):
            line_num = text[: match.start()].count("\n") + 1
            line = text.splitlines()[line_num - 1].strip()
            violations.append(f"{path.name}:{line_num} - {line}")

    assert not violations, (
        "Found wget invocations downloading from a URL. Use the hardened curl "
        "pattern instead:\n"
        "  curl -fsSL --retry 3 --retry-delay 5 --retry-all-errors "
        '--connect-timeout 30 --max-time 600 "$URL" -o /path\n'
        "Reason: wget --tries=N retries connection failures only, not HTTP "
        "4xx/5xx errors. See .claude/rules/docker.rules.md 'Download Hardening "
        "Convention'.\n"
        "Violations:\n  " + "\n  ".join(violations)
    )


def test_drift_guard_finds_a_real_wget_download_when_planted() -> None:
    """Sanity check: the regex actually matches a known-bad pattern.

    Without this, a regex bug could silently pass the main test forever.
    """
    sample = (
        'RUN NUCLEI_VERSION="3.7.0" && \\\n'
        "    wget -q --tries=3 --waitretry=5 --timeout=600 "
        '"https://github.com/projectdiscovery/nuclei/releases/download/'
        'v${NUCLEI_VERSION}/nuclei.zip" -O /tmp/nuclei.zip\n'
    )
    assert WGET_DOWNLOAD_PATTERN.search(sample) is not None, (
        "Drift-guard regex failed to match a known-bad wget download line. "
        "The main test would silently pass even with violations present."
    )


def test_drift_guard_ignores_apt_install_wget() -> None:
    """The apt-get install continuation line `    wget \\` must NOT match.

    Otherwise we'd flag every Dockerfile's build-deps install as a violation.
    """
    sample = (
        "RUN apt-get update && apt-get install -y --no-install-recommends \\\n"
        "    curl \\\n"
        "    wget \\\n"
        "    unzip \\\n"
        "    && rm -rf /var/lib/apt/lists/*\n"
    )
    assert WGET_DOWNLOAD_PATTERN.search(sample) is None, (
        "Drift-guard regex incorrectly matches the apt-install continuation "
        "line. It must only match wget invocations followed by a URL."
    )
