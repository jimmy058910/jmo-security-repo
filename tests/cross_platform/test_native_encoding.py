"""Guards `jmo` against UnicodeEncodeError on a console that is not UTF-8.

Why this file exists
--------------------
`jmo` prints emoji ("\U0001f3c6 Security Posture Score") and box-drawing
characters. Windows consoles cannot encode them:

    piped stdout   -> ANSI codepage, cp1252 on a US box
    real console   -> OEM codepage,  cp437 / cp850

An unguarded ``sys.stdout.write()`` of that text raises UnicodeEncodeError and
the command exits 1. `jmo trends explain score` did exactly that.

Why these tests pin PYTHONIOENCODING
------------------------------------
CI's main shards set ``PYTHONUTF8=1`` (`.github/workflows/ci.yml`), which forces
UTF-8 for stdio and file I/O -- an environment no ordinary user has, and one in
which this bug class is invisible. Measured: ``PYTHONIOENCODING`` takes priority
over UTF-8 Mode for stdio (``utf8_mode=1`` still yields
``sys.stdout.encoding == 'cp1252'``). Pinning it in the child therefore
reproduces a legacy console on *every* platform and inside *every* shard,
rather than only on a Windows box that happens to have PYTHONUTF8 unset.

cp437/cp850 are covered as well as cp1252 on purpose: they contain the
box-drawing characters but not the emoji, so a guard that only recognises
"cp1252" by name passes them through and still crashes.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.native_encoding

REPO_ROOT = Path(__file__).resolve().parents[2]

# Codecs a real Windows user's stdout actually gets. None can encode an emoji.
LEGACY_CODECS = ["cp1252", "cp437", "cp850"]


def _run(*args: str, codec: str) -> subprocess.CompletedProcess[str]:
    """Invoke the real CLI with stdio pinned to a legacy codec."""
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = codec
    return subprocess.run(
        [sys.executable, "-m", "scripts.cli.jmo", *args],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(REPO_ROOT),
        env=env,
        check=False,
    )


@pytest.mark.parametrize("codec", LEGACY_CODECS)
def test_trends_explain_survives_legacy_console(codec: str) -> None:
    """`jmo trends explain all` must not die encoding its own output.

    Regression: the explanation blocks embed emoji and were written straight to
    sys.stdout, so the command exited 1 with
    ``UnicodeEncodeError: 'charmap' codec can't encode character '\\U0001f3c6'``.

    `explain` is the strongest reproduction available because it needs no
    history database -- a bare `jmo trends explain score` crashed.
    """
    result = _run("trends", "explain", "all", codec=codec)

    assert "UnicodeEncodeError" not in result.stderr, (
        f"jmo trends explain crashed encoding its own output on {codec}:\n"
        f"{result.stderr[-2000:]}"
    )
    # Asserted separately from the traceback check: if argparse ever stops
    # accepting these arguments the command would "not crash" while testing
    # nothing at all.
    assert result.returncode == 0, (
        f"jmo trends explain exited {result.returncode} on {codec}:\n"
        f"{result.stderr[-2000:]}"
    )


@pytest.mark.parametrize("codec", LEGACY_CODECS)
def test_help_survives_legacy_console(codec: str) -> None:
    """--help is the most-run path of all; it must survive a legacy console."""
    result = _run("--help", codec=codec)

    assert (
        "UnicodeEncodeError" not in result.stderr
    ), f"jmo --help crashed on {codec}:\n{result.stderr[-2000:]}"
    assert result.returncode == 0, f"jmo --help exited {result.returncode} on {codec}"


def test_legacy_codec_choice_is_not_vacuous() -> None:
    """Fails if the codecs above ever gain emoji support.

    Without this, a change in the codec table would silently turn every test in
    this file into a no-op that passes forever.
    """
    for codec in LEGACY_CODECS:
        with pytest.raises(UnicodeEncodeError):
            "\U0001f3c6".encode(codec)
