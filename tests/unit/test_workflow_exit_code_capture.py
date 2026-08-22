#!/usr/bin/env python3
"""Guard: workflows must not capture ``$?`` after a negated command.

Bash's ``!`` replaces ``$?`` with the *negated* status, so::

    if ! some_command; then
      rc=$?              # ALWAYS 0, never the real exit code
      exit "$rc"         # therefore always `exit 0` -- the step passes
    fi

reports success for every failure it was written to catch. This is not a
theoretical footgun. Two sites in ``scheduled.yml`` shipped it:

* ``validate-variants`` -- run 31925247675 (2026-08-16) logged
  ``tools check --profile deep exited with rc=0`` and reported SUCCESS, while
  balanced/slim/fast each printed a real ``Installed tools: N`` line. The deep
  image's tool-count assertion had never executed.
* the ``trufflehog`` secret scan -- a crashed scanner would ``exit 0`` and skip
  the verified-secrets check entirely.

Both were found in chunk 21 of the v1.1.0 audit campaign. The correct idiom is
``set +e`` / run / capture / ``set -e``, which keeps the real status.

This guard is deliberately about the *pattern*, not those two sites: it fails on
the next occurrence anywhere in ``.github/workflows/``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"

# A negated command opening an `if`. Matches `if ! cmd`, including the
# line-continuation form where the command spans several lines.
_IF_BANG = re.compile(r"^\s*if\s+!\s")
# Any shell variable taking the previous command's status.
_RC_CAPTURE = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*=\$\?\s*$")
# How far past the `if !` to look. The capture is the first statement of the
# `then` block in every instance of this bug; 12 lines covers a multi-line
# command plus the `then`.
_LOOKAHEAD = 12


def find_negated_status_captures(text: str) -> list[tuple[int, str]]:
    """Return ``(line_number, offending_line)`` for each bad capture.

    Line numbers are 1-indexed to match editor and CI annotations.
    """
    lines = text.splitlines()
    hits: list[tuple[int, str]] = []
    for i, line in enumerate(lines):
        if not _IF_BANG.search(line):
            continue
        for j in range(i + 1, min(i + 1 + _LOOKAHEAD, len(lines))):
            # A new `if`/`fi` ends the region we care about.
            if _IF_BANG.search(lines[j]) or re.match(r"^\s*fi\s*$", lines[j]):
                break
            if _RC_CAPTURE.match(lines[j]):
                hits.append((j + 1, lines[j].strip()))
                break
    return hits


def _workflow_files() -> list[Path]:
    return sorted(WORKFLOW_DIR.glob("*.yml")) + sorted(WORKFLOW_DIR.glob("*.yaml"))


def test_workflow_dir_is_present_and_non_empty() -> None:
    """Fail loudly rather than vacuously passing on an empty glob.

    A guard that scans zero files passes forever. This is the check that keeps
    the parametrised test below honest if the directory is ever moved.
    """
    files = _workflow_files()
    assert files, f"no workflow files found under {WORKFLOW_DIR}"


@pytest.mark.parametrize("workflow", _workflow_files(), ids=lambda p: p.name)
def test_no_status_capture_after_negated_command(workflow: Path) -> None:
    """No workflow may read ``$?`` inside an ``if !`` block."""
    hits = find_negated_status_captures(workflow.read_text(encoding="utf-8"))
    assert not hits, (
        f"{workflow.relative_to(REPO_ROOT)} captures $? after a negated command, "
        f"which yields 0 for every failure:\n"
        + "\n".join(f"  line {ln}: {src}" for ln, src in hits)
        + "\n\nUse `set +e` / run / capture / `set -e` instead, so the real "
        "exit code survives."
    )


def test_detector_flags_the_known_bad_shape() -> None:
    """Positive control: the detector must fire on the shape it exists to catch.

    Without this, a detector that silently stopped matching would look exactly
    like a clean repo. The literal below is the code that shipped.
    """
    bad = (
        "          if ! docker run --rm image tools check --json \\\n"
        "              > out.json 2>err.log; then\n"
        "            rc=$?\n"
        '            echo "failed"\n'
        '            exit "$rc"\n'
        "          fi\n"
    )
    hits = find_negated_status_captures(bad)
    assert hits == [(3, "rc=$?")], f"detector missed the known bad shape: {hits}"


def test_detector_accepts_the_correct_idiom() -> None:
    """Negative control: the fix must not be flagged.

    A detector that fired on the repaired code too would force the next author
    back to the broken form.
    """
    good = (
        "          set +e\n"
        "          docker run --rm image tools check --json > out.json\n"
        "          rc=$?\n"
        "          set -e\n"
        '          if [ "$rc" -ne 0 ]; then exit "$rc"; fi\n'
    )
    assert find_negated_status_captures(good) == []
