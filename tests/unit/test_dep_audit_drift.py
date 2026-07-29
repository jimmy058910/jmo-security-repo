#!/usr/bin/env python3
"""Drift guards for the dependency-audit path and the pinned-uv convention.

Invariants that have each been broken before and are invisible until CI goes
red for an unrelated-looking reason:

1. A pip-audit `--ignore-vuln` is only justified while there is nothing to
   adopt. PYSEC-2025-183 is a disputed pyjwt advisory with no fix version, so
   the ignore is the only available lever and must survive refactors.

2. The converse also needs guarding: an ignore whose fix has become reachable
   must NOT come back. GHSA-qp9x-wp8f-qgjj (tuf) was dropped in #539 once
   sigstore 4.5.0 lifted the `tuf<7` cap and the lock moved to the fixed
   7.0.0. Re-adding it would silently mask a regression rather than paper over
   an unfixable finding -- verified: forcing `tuf<7` back into the lock makes
   pip-audit report it with fix version 7.0.0 available.

3. Exactly one uv version is pinned across every site (the PR #488 convention).
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

# Advisories with no reachable fix -- the ignore is the only lever, keep it.
REQUIRED_IGNORES = ("PYSEC-2025-183",)

# Advisories whose fix IS reachable -- an ignore here masks a regression.
# Maps advisory -> the fix that made it retired, for the failure message.
RETIRED_IGNORES = {
    "GHSA-qp9x-wp8f-qgjj": "tuf 7.0.0 (sigstore 4.5.0 lifted the tuf<7 cap) -- issue #539",
}

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


def test_audit_script_preserves_unfixable_ignores() -> None:
    """Ignores with no reachable fix must survive refactors."""
    text = AUDIT_SCRIPT.read_text(encoding="utf-8")
    for advisory in REQUIRED_IGNORES:
        assert advisory in text, (
            f"{advisory} is no longer ignored in audit_deps.sh. It has no fix "
            "version, so the ignore is the only available lever -- removing it "
            "turns CI red with nothing to upgrade to. See the script header."
        )


def test_audit_script_does_not_readd_retired_ignores() -> None:
    """An ignore whose fix is reachable must not come back -- it masks regressions."""
    # Only the executable invocation matters; the header comment documents the
    # removal by name and must stay readable.
    invocation = [
        ln
        for ln in AUDIT_SCRIPT.read_text(encoding="utf-8").splitlines()
        if "--ignore-vuln" in ln and not ln.lstrip().startswith("#")
    ]
    joined = "\n".join(invocation)
    for advisory, fix in RETIRED_IGNORES.items():
        assert advisory not in joined, (
            f"{advisory} was re-added to audit_deps.sh, but its fix is "
            f"reachable: {fix}. Suppressing it now hides a regression instead "
            "of papering over an unfixable finding. Upgrade the dependency "
            "rather than restoring the ignore."
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
