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


# Modules whose subprocess output carries bytes we do not control: scanner
# output over arbitrary repositories, git metadata from third-party clones, and
# OPA's UTF-8 JSON. Decoding these with the host locale under strict errors
# loses the capture entirely on Windows -- the exception is raised inside
# `subprocess._readerthread`, where it cannot reach the caller.
#
# Measured on a 5-repo public scan (cp1252 host): five UnicodeDecodeErrors,
# `trufflehog.json` written as 0 bytes in all 5 repos, trufflehog reported
# successful, and the `zero-secrets` policy PASSED. A missed finding is a gap;
# a policy that certifies "no secrets" because the scanner's output was
# destroyed is a false assurance.
#
# This guard is deliberately scoped to the data path rather than all ~73
# `text=True` sites in `scripts/`. PR #696 fixed all 153 lint-visible encoding
# sites and repaired zero actual failures; scope comes from failures, not from
# an enumerable pattern. Add a module here when it starts handling foreign bytes.
DATA_PATH_MODULES = (
    "core/tool_runner.py",  # scanner stdout over arbitrary repo content
    "core/policy_engine.py",  # OPA JSON; decides PASS/FAIL
    "core/developer_attribution.py",  # git blame: author names
    "core/history_db.py",  # git refs, tags, porcelain paths
    "cli/clone_from_tsv.py",  # git clone of arbitrary public repos
)


def _capturing_subprocess_calls(tree: ast.AST):
    """Yield (lineno, kwargs) for subprocess calls that capture output."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = ast.unparse(node.func)
        if func not in {
            "subprocess.run",
            "subprocess.Popen",
            "subprocess.check_output",
        }:
            continue
        kwargs = {kw.arg for kw in node.keywords if kw.arg}
        if kwargs & {"capture_output", "stdout", "stderr"}:
            yield node.lineno, kwargs


def test_data_path_subprocesses_decode_explicitly() -> None:
    """Scan-path subprocess output must not be decoded with the host locale.

    `text=True` / `universal_newlines=True` select
    `locale.getpreferredencoding()` under `errors="strict"`. Both halves are
    wrong for foreign bytes: the codec is the host's rather than the tool's, and
    strict turns one unmappable byte into total data loss.
    """
    offenders: list[str] = []

    for rel in DATA_PATH_MODULES:
        path = SCRIPTS / rel
        assert path.exists(), f"guard references a module that moved: {rel}"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

        for lineno, kwargs in _capturing_subprocess_calls(tree):
            if kwargs & {"text", "universal_newlines"}:
                offenders.append(f"{rel}:{lineno} uses text=True (locale decoding)")
            elif "encoding" not in kwargs:
                offenders.append(f"{rel}:{lineno} has no explicit encoding=")
            elif "errors" not in kwargs:
                offenders.append(
                    f"{rel}:{lineno} has encoding= but no errors= "
                    "(strict discards the whole capture on one bad byte)"
                )

    assert (
        not offenders
    ), "Locale-decoded subprocess output on the scan data path:\n" + "\n".join(
        f"  {o}" for o in offenders
    )


# Codec names that appear in the "is this stream safe?" denylists this guard
# exists to eliminate. Deliberately not exhaustive -- it does not need to be,
# because the point is that NO such list can be.
_CODEC_NAME_LITERALS = frozenset(
    {
        "cp1252",
        "cp437",
        "cp850",
        "ascii",
        "latin-1",
        "latin1",
        "iso-8859-1",
    }
)


def test_no_module_branches_on_the_encodings_name() -> None:
    """Nothing may decide encodability by comparing a codec's NAME.

    The definition guard above only sees `def safe_print(...)`. Two copies of
    the broken logic survived it anyway, each through a different hole:

        scripts/cli/policy_commands.py  defined `_safe_print` -- underscored,
                                        so not in GUARDED_NAMES
        scripts/cli/jmo.py             inlined the branch inside `_log`, so it
                                        defined no guarded helper at all

    A definition-scanner tests for the shape the bug had last time. This tests
    for the behaviour it is actually forbidden to have, wherever it appears and
    whatever the enclosing function is called.

    Measured on cp437, the codec a real Windows console uses: the name-based
    branch never fired, so 'Scan complete <check>' rendered '?' where the
    canonical helper renders '[v]'. It is not a crash -- harden_console_streams
    guarantees that -- it is the fallback table being silently skipped in
    exactly the environment it was written for.

    The fix is always the same: call safe_print/safe_write, which probe the real
    payload against the stream's real codec.
    """
    offenders: list[str] = []

    for path in sorted(SCRIPTS.rglob("*.py")):
        if path == CANONICAL:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            # `enc == "cp1252"` / `enc != "ascii"` / `enc in (...)`
            operands = list(node.comparators)
            literals: set[str] = set()
            for operand in operands:
                if isinstance(operand, ast.Constant) and isinstance(operand.value, str):
                    literals.add(operand.value.lower())
                elif isinstance(operand, ast.Tuple | ast.List | ast.Set):
                    for element in operand.elts:
                        if isinstance(element, ast.Constant) and isinstance(
                            element.value, str
                        ):
                            literals.add(element.value.lower())

            if literals & _CODEC_NAME_LITERALS:
                rel = path.relative_to(REPO_ROOT).as_posix()
                offenders.append(
                    f"{rel}:{node.lineno} branches on codec name(s) "
                    f"{sorted(literals & _CODEC_NAME_LITERALS)}"
                )

    assert not offenders, (
        "Encodability must be probed, never inferred from the codec's name -- "
        "no list can enumerate the codecs you did not think of, and cp437/cp850 "
        "are the ones a real Windows console uses. Found:\n  "
        + "\n  ".join(offenders)
        + "\n\nCall safe_print()/safe_write() from scripts/core/unicode_utils.py "
        "instead; they encode the actual payload against the stream's actual "
        "codec."
    )


class _LegacyConsole:
    """A write target that reports a legacy Windows console codec.

    Not `io.StringIO`: `safe_write` reads `stream.encoding` to decide what the
    payload has to survive, and StringIO advertises none.
    """

    def __init__(self, encoding: str) -> None:
        self.encoding = encoding
        self._chunks: list[str] = []

    def write(self, text: str) -> int:
        """Encode on write, the way a real console does.

        Storing `text` verbatim would make this fake useless: `print()` and
        `safe_write()` would produce identical output and a caller that
        bypassed the fallback table would look correct. Mutation-tested --
        without this encode step, replacing `safe_write` with `print` in
        `_write_progress_line` left the guard below green.
        """
        rendered = text.encode(self.encoding, "replace").decode(
            self.encoding, "replace"
        )
        self._chunks.append(rendered)
        return len(text)

    def flush(self) -> None:
        """A real stderr has one; the progress writer flushes after every line."""

    def getvalue(self) -> str:
        return "".join(self._chunks)


def _render(text: str, codec: str) -> str:
    """What a legacy console would actually show for `text`."""
    from scripts.core.unicode_utils import safe_write

    stream = _LegacyConsole(codec)
    safe_write(text, stream)
    return stream.getvalue()


def test_scan_progress_spinner_survives_a_legacy_console() -> None:
    """The scan spinner must remain readable AND animated on a real console.

    `ProgressTracker._SPINNER_FRAMES` is Braille (U+280B..U+280F). Measured
    before this guard existed: **all ten frames are unrenderable in cp1252,
    cp437 and cp850** -- every codec a real Windows console uses -- and none had
    a `UNICODE_FALLBACKS` entry. The three call sites wrote them with
    `print(..., file=sys.stderr)`, which reaches only the stream hardening's
    `errors="replace"`, so the spinner was a motionless `?` for the length of
    every scan on Windows.

    Two properties, not one. Checking only "is it renderable" would pass if all
    ten frames collapsed to the same character -- readable, but no longer an
    animation, which is the entire purpose of a spinner. Asserted as properties
    of whatever frames the tracker declares, so changing the frame set cannot
    walk around this the way a hardcoded list would.
    """
    from scripts.cli.jmo import ProgressTracker

    frames = list(ProgressTracker._SPINNER_FRAMES)
    assert frames, "the tracker must declare spinner frames for this to mean anything"

    for codec in ("cp1252", "cp437", "cp850"):
        rendered = [_render(f, codec) for f in frames]

        unreadable = [f for f, r in zip(frames, rendered) if not r or "?" in r]
        assert not unreadable, (
            f"{len(unreadable)} of {len(frames)} spinner frames render as '?' on "
            f"{codec}. Add a UNICODE_FALLBACKS entry for each, and make sure the "
            f"call site uses safe_write() rather than print(file=sys.stderr) -- "
            f"stream hardening alone only guarantees no crash, not legibility."
        )

        assert len(set(rendered)) > 1, (
            f"every spinner frame renders identically on {codec}, so the spinner "
            f"no longer animates. Map the frames onto a rotating substitute."
        )


def test_progress_line_writer_goes_through_the_fallback_table() -> None:
    """`ProgressTracker` must write progress lines with safe_write, not print.

    This is the behavioural half of the test above: the fallback table can be
    complete and still never consulted, because `print(..., file=sys.stderr)`
    bypasses it entirely. Asserting the rendered output rather than the source
    keeps this true however the writer is spelled.
    """
    from scripts.cli.jmo import ProgressTracker

    spinner = ProgressTracker._SPINNER_FRAMES[0]
    line = f"\r[0/1] {spinner} trufflehog (0s) [0%]"

    console = _LegacyConsole("cp437")
    with patch("scripts.cli.jmo.sys.stderr", console):
        ProgressTracker._write_progress_line(line)

    written = console.getvalue()
    assert "trufflehog" in written, "the progress line never reached the stream"
    assert "?" not in written, (
        "the progress line was written without the fallback table -- the spinner "
        "degraded to '?'. Use safe_write() from scripts/core/unicode_utils.py."
    )
