"""Drift guards keeping console-encoding handling correct and in one place.

How this bug class was created
------------------------------
Four modules each grew a private copy of the same helper::

    scripts/cli/diff_commands.py       _can_encode_unicode + safe_print
    scripts/cli/history_commands.py    _can_encode_unicode + safe_write
    scripts/cli/trend_commands.py      _can_encode_unicode + safe_write
    scripts/cli/wizard_flows/ui_helpers.py                   safe_print

Every copy decided whether output was safe from the encoding's *name*
("is it cp1252/ascii/latin-1?"). cp437 and cp850 -- the OEM codepages a real
Windows console actually uses -- are not on that list, and they *do* contain the
box-drawing character the probe tested with. So all four copies answered "safe"
and then crashed on the first emoji.

One implementation means one place to fix and one place to test. These guards
keep it that way.
"""

from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"
CANONICAL = SCRIPTS / "core" / "unicode_utils.py"

# Names that must exist in exactly one module.
GUARDED_NAMES = frozenset(
    {
        "safe_print",
        "safe_write",
        "_can_encode_unicode",
        "harden_console_streams",
    }
)


def test_console_encoding_helpers_are_not_reimplemented() -> None:
    """No module may define its own copy of the encoding helpers.

    Importing or re-exporting them is fine -- only `def` is flagged, because a
    definition is what forks the behaviour.
    """
    offenders: list[str] = []

    for path in sorted(SCRIPTS.rglob("*.py")):
        if path == CANONICAL:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
                and node.name in GUARDED_NAMES
            ):
                rel = path.relative_to(REPO_ROOT).as_posix()
                offenders.append(f"{rel}:{node.lineno} defines {node.name}()")

    assert not offenders, (
        "Console-encoding helpers must live only in "
        "scripts/core/unicode_utils.py. Found local definitions:\n  "
        + "\n  ".join(offenders)
        + "\n\nImport them instead. Four divergent copies are what produced the "
        "cp437/cp850 crash this guard exists to prevent."
    )


def test_main_hardens_streams_before_parsing_args() -> None:
    """Hardening must happen before ANY output can be produced.

    argparse writes --help and usage errors straight to the console, so
    hardening after parse_args() would leave the most-run paths of all
    unprotected.
    """
    import scripts.cli.jmo as jmo

    recorder = MagicMock()
    # A bare object() has no `cmd` attribute, so main() returns immediately
    # after parsing -- a MagicMock would satisfy hasattr() and dispatch.
    recorder.parse_args.return_value = object()

    with (
        patch.object(jmo, "harden_console_streams", recorder.harden),
        patch.object(jmo, "parse_args", recorder.parse_args),
    ):
        assert jmo.main() == 0

    called = [name for name, _, _ in recorder.mock_calls]
    assert called == [
        "harden",
        "parse_args",
    ], f"Expected harden_console_streams() before parse_args(), got: {called}"
