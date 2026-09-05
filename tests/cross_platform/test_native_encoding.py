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
    """Invoke the real CLI with stdio pinned to a legacy codec.

    The parent must decode with the SAME codec it pinned on the child. Plain
    `text=True` decodes with the parent's locale codec instead, which breaks two
    ways: on Linux it is UTF-8, and cp850's 0x9E ("x" in the score formula) is
    not valid UTF-8, so the test itself dies with UnicodeDecodeError; on Windows
    subprocess decodes in a reader thread, where the same error is swallowed and
    the captured output silently goes missing.

    errors="replace" keeps this test measuring the product rather than its own
    plumbing -- any traceback we assert on is ASCII, so it survives regardless.
    """
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = codec
    return subprocess.run(
        [sys.executable, "-m", "scripts.cli.jmo", *args],
        capture_output=True,
        timeout=60,
        cwd=str(REPO_ROOT),
        env=env,
        check=False,
        encoding=codec,
        errors="replace",
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


@pytest.mark.parametrize("codec", LEGACY_CODECS)
def test_generate_release_notes_survives_legacy_console(codec: str) -> None:
    """The release-notes generator must not truncate on a legacy console.

    Its own template carries eight non-ASCII characters (an em dash, an arrow
    and six emoji), and every caller redirects stdout -- `release.yml` runs
    `... > /tmp/raw-notes.txt`. On Windows that makes stdout cp1252, so the
    first emoji raised UnicodeEncodeError and the script exited 1 having
    written a PARTIAL file.

    Truncation is the reason this is asserted rather than left to the crash:
    release.yml pipes the output through `sed -n '/^# Release/,$p'`, and sed
    exits 0 on a truncated file. A failure here would therefore surface as a
    published GitHub Release with an EMPTY body, not as an error -- so the
    assertion is on the extracted body being non-empty, not merely on rc == 0.
    """
    result = subprocess.run(
        [sys.executable, "scripts/dev/generate_release_notes.py", "v1.1.0"],
        capture_output=True,
        timeout=60,
        cwd=str(REPO_ROOT),
        env={**os.environ, "PYTHONIOENCODING": codec},
        check=False,
        encoding=codec,
        errors="replace",
    )

    assert (
        "UnicodeEncodeError" not in result.stderr
    ), f"generate_release_notes crashed on {codec}:\n{result.stderr[-2000:]}"
    assert result.returncode == 0, (
        f"generate_release_notes exited {result.returncode} on {codec}:\n"
        f"{result.stderr[-2000:]}"
    )

    # The half release.yml actually consumes. Asserting on the marker AND on
    # trailing content catches a stream that died partway through the document,
    # which a returncode check alone cannot see.
    assert "# Release v1.1.0" in result.stdout, (
        f"release-notes header missing on {codec} -- "
        f"sed would extract an empty body:\n{result.stdout[-500:]}"
    )
    body = result.stdout.split("# Release v1.1.0", 1)[1]
    assert "[Full Changelog]" in body, (
        f"document truncated before its footer on {codec}; " f"tail was:\n{body[-500:]}"
    )
