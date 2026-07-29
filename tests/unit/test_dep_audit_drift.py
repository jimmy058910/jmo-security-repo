#!/usr/bin/env python3
"""Drift guards for the dependency-audit path and the pinned-uv convention.

Two invariants that have each been broken before and are invisible until CI
goes red for an unrelated-looking reason:

1. The two pip-audit `--ignore-vuln` advisories must survive refactors. Both
   were adopted because no remediation existed: PYSEC-2025-183 is a disputed
   pyjwt advisory with no fix version, and GHSA-qp9x-wp8f-qgjj could not be
   resolved while sigstore capped tuf<7 (tracked in #539). Dropping an ignore
   whose advisory is still live turns every CI run red with nothing to do
   about it.

2. Exactly one uv version is pinned across every site (the PR #488 convention).
   The uv.lock migration multiplied the number of pinned sites from ~4 to ~16;
   a single stale pin means one job resolves differently from the rest, which
   is precisely the class of bug this migration removed.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

AUDIT_SCRIPT = REPO_ROOT / "scripts" / "dev" / "audit_deps.sh"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
PRE_COMMIT = REPO_ROOT / ".pre-commit-config.yaml"

REQUIRED_IGNORES = ("PYSEC-2025-183", "GHSA-qp9x-wp8f-qgjj")

# The single pinned uv version. Bump here and at every site in one commit.
PINNED_UV_VERSION = "0.11.15"

# Every file that pins a uv version. All must agree.
UV_PIN_SITES = (
    ".github/workflows/ci.yml",
    ".github/workflows/scheduled.yml",
    ".github/workflows/maintenance.yml",
    ".github/workflows/release.yml",
    ".github/actions/setup-python-jmo/action.yml",
    ".pre-commit-config.yaml",
    "Makefile",
    ".devcontainer/devcontainer.json",
)


def test_audit_script_exists_and_is_bash() -> None:
    assert AUDIT_SCRIPT.exists(), (
        "scripts/dev/audit_deps.sh is missing. It is the single implementation "
        "of the pip-audit invocation shared by CI and pre-commit."
    )
    assert AUDIT_SCRIPT.read_text(encoding="utf-8").startswith("#!/usr/bin/env bash")


def test_audit_script_preserves_both_ignores() -> None:
    text = AUDIT_SCRIPT.read_text(encoding="utf-8")
    for advisory in REQUIRED_IGNORES:
        assert advisory in text, (
            f"{advisory} is no longer ignored in audit_deps.sh. Confirm the "
            "advisory is genuinely resolved in the current lock before "
            "removing the ignore -- see the script's header comment and #539."
        )


def test_both_call_sites_use_the_shared_script() -> None:
    """CI and pre-commit must call the script, not re-inline pip-audit.

    Two inlined copies is what let their explanatory comments drift apart in
    the first place.
    """
    for path in (CI_WORKFLOW, PRE_COMMIT):
        text = path.read_text(encoding="utf-8")
        assert "scripts/dev/audit_deps.sh" in text, (
            f"{path.name} does not call scripts/dev/audit_deps.sh. Do not "
            "re-inline the pip-audit invocation -- the ignores drift."
        )
        assert (
            "requirements-dev.txt" not in text
        ), f"{path.name} still references the deleted requirements-dev.txt."


def test_single_pinned_uv_version_across_all_sites() -> None:
    """Every uv pin in the repo agrees on one version (PR #488 convention)."""
    mismatches: list[str] = []

    for rel in UV_PIN_SITES:
        path = REPO_ROOT / rel
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        uses_setup_uv = "astral-sh/setup-uv" in text

        for lineno, line in enumerate(text.splitlines(), start=1):
            # Form 1: `uv==0.11.15` (pip install)
            for found in re.findall(r"uv==(\d+\.\d+\.\d+)", line):
                if found != PINNED_UV_VERSION:
                    mismatches.append(f"{rel}:{lineno} pins uv=={found}")

            # Form 2: setup-uv's `version: "0.11.15"` input. Only meaningful in
            # a file that actually uses setup-uv; other `version:` keys (e.g.
            # tool versions in env blocks) are unrelated.
            m = re.match(r'\s*version:\s*"(\d+\.\d+\.\d+)"\s*(?:#.*)?$', line)
            if uses_setup_uv and m and m.group(1) != PINNED_UV_VERSION:
                mismatches.append(f"{rel}:{lineno} setup-uv version {m.group(1)}")

    assert not mismatches, (
        "uv version pins disagree across sites:\n  "
        + "\n  ".join(mismatches)
        + f"\nAll sites must pin {PINNED_UV_VERSION} (PR #488 convention). "
        "Bump every site in one commit, including this test's PINNED_UV_VERSION."
    )


def test_pinned_uv_version_is_actually_used_somewhere() -> None:
    """Guard against the pin-check passing vacuously.

    If every site stopped pinning uv, `test_single_pinned_uv_version_across_all_sites`
    would find zero mismatches and pass while the convention was entirely gone.
    """
    sites_with_pin = [
        rel
        for rel in UV_PIN_SITES
        if (REPO_ROOT / rel).exists()
        and PINNED_UV_VERSION in (REPO_ROOT / rel).read_text(encoding="utf-8")
    ]
    assert len(sites_with_pin) >= 4, (
        f"Only {len(sites_with_pin)} site(s) pin uv {PINNED_UV_VERSION}: "
        f"{sites_with_pin}. The pinned-uv convention (PR #488) appears to have "
        "been dropped rather than bumped."
    )
