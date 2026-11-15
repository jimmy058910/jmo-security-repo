"""scripts/dev/platform_check.py: a branch's changed tests under a CRLF
checkout, a non-UTF-8 locale and forced directory-listing order.

The guard plants one defect per condition in a scratch repository and runs the
real command on it: each must be caught under its own condition and no other,
and a clean test under none. The two defects it was built for (#1633's first
`rglob` match, #1639's backslash-newline on `read_bytes()`) were found only
after a push, so a check that stopped catching them would fail silently.
"""

from __future__ import annotations

import glob
import json
import os
import subprocess
import sys
import types
from pathlib import Path

import pytest

from scripts.dev import platform_check as pc

REPO_ROOT = Path(__file__).resolve().parents[2]

PLANTED = r'''
import os
from pathlib import Path

HERE = Path(__file__).parent
_raw_listdir = __import__("nt" if os.name == "nt" else "posix").listdir


def test_reads_a_continuation_from_bytes():
    """#1639's shape: a backslash-newline matched on read_bytes()."""
    text = (HERE / "data" / "cont.sh").read_bytes().decode("utf-8")
    assert text.count("\\\n") == 1


def test_reads_text_in_the_locale_codec():
    """A default-encoding read of UTF-8 text. U+2192 is in neither ascii nor
    cp1252, so it fails under both."""
    assert (HERE / "data" / "arrow.txt").read_text() == "→\n"


def test_takes_the_listing_order_as_given(tmp_path):
    """#1633's shape: code that trusts the order a directory lists in. It
    passes in any natural order, and a forced order differs from the natural
    one in at least one direction."""
    for name in ("a", "b", "c"):
        (tmp_path / name).write_text(name, encoding="utf-8")
    assert [p.name for p in tmp_path.iterdir()] == _raw_listdir(tmp_path)


def test_clean(tmp_path):
    (tmp_path / "f.txt").write_text("→", encoding="utf-8")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["f.txt"]
    assert (tmp_path / "f.txt").read_text(encoding="utf-8") == "→"
'''


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        timeout=60,
    )
    return proc.stdout.decode("utf-8", errors="replace").strip()


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A repository with one base commit, stored byte-for-byte."""
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    # A machine whose global autocrlf is true (Git for Windows) would
    # otherwise normalise on `git add`.
    _git(root, "config", "core.autocrlf", "false")
    # The scratch runs' rootdir, so no pytest config above it applies.
    (root / "pytest.ini").write_bytes(b"[pytest]\n")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "base")
    monkeypatch.chdir(root)
    return root


def _commit(repo: Path, files: dict[str, bytes], message: str = "change") -> None:
    for name, data in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="the check emulates Windows from Linux and macOS, and windows-2022's "
    "test step runs within a minute of its limit (#1637)",
)
@pytest.mark.timeout(300)
def test_each_planted_defect_is_caught_under_its_own_condition_only(
    repo: Path, tmp_path: Path
) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    _commit(
        repo,
        {
            "tests/test_planted.py": PLANTED.encode("utf-8"),
            "tests/data/cont.sh": b"run \\\nnow\n",
            "tests/data/arrow.txt": "→\n".encode(),
        },
    )
    out = tmp_path / "result.json"

    rc = pc.main(
        ["--base", base, "--workdir", str(tmp_path / "work"), "--json", str(out)]
    )

    result = json.loads(out.read_text(encoding="utf-8"))
    assert result["broken"] == [], result
    caught: dict[str, set[str]] = {}
    for f in result["findings"]:
        caught.setdefault(f["test"].split("::")[-1], set()).add(f["condition"])
    assert caught.pop("test_reads_a_continuation_from_bytes") == {"crlf"}
    assert caught.pop("test_reads_text_in_the_locale_codec") == {"locale"}
    order = caught.pop("test_takes_the_listing_order_as_given")
    assert order and order <= {"order-asc", "order-desc"}, order
    assert caught == {}, "the clean test was flagged, or something else was"
    assert rc == 1


def test_no_changed_test_file_is_a_pass(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    base = _git(repo, "rev-parse", "HEAD")
    _commit(repo, {"docs/notes.md": b"text\n", "tests/helper.py": b"X = 1\n"})

    assert pc.main(["--base", base]) == 0
    assert "no changed test files" in capsys.readouterr().out


def test_the_selection_is_the_test_files_the_branch_adds_changes_or_renames(
    repo: Path,
) -> None:
    body = b"def test_x():\n    assert True\n" * 20  # enough for rename detection
    _commit(
        repo,
        {
            "tests/test_old.py": body,
            "tests/test_gone.py": body + b"# gone\n",
            "tests/test_ren.py": body + b"# ren\n",
            "tests/helper.py": b"X = 1\n",
        },
    )
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "tests" / "test_gone.py").unlink()
    (repo / "tests" / "unit").mkdir()
    _git(repo, "mv", "tests/test_ren.py", "tests/unit/test_moved.py")
    _commit(
        repo,
        {
            "tests/test_old.py": body + b"# changed\n",
            "tests/unit/test_new.py": body,
            "tests/helper.py": b"X = 2\n",
            "docs/test_not_a_test.py": body,
        },
    )

    assert pc.changed_test_files(repo, base, "HEAD") == [
        "tests/test_old.py",
        "tests/unit/test_moved.py",
        "tests/unit/test_new.py",
    ]


@pytest.mark.parametrize("reverse", [False, True], ids=["ascending", "descending"])
def test_every_listing_api_returns_the_forced_order_with_parents_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reverse: bool
) -> None:
    for name in ("b.txt", "a.txt", "c.txt", "d/y.txt", "d/x.txt"):
        (tmp_path / name).parent.mkdir(exist_ok=True)
        (tmp_path / name).write_bytes(b"")
    pc.install_listing_order(reverse, monkeypatch.setattr)

    def order(names: list[str]) -> list[str]:
        return sorted(names, reverse=reverse)

    top = order(["a.txt", "b.txt", "c.txt", "d"])
    assert os.listdir(tmp_path) == top
    with os.scandir(tmp_path) as it:
        assert [e.name for e in it] == top
    assert [p.name for p in tmp_path.iterdir()] == top
    assert [p.name for p in tmp_path.glob("*")] == top
    assert [Path(p).name for p in glob.glob(str(tmp_path / "*"))] == top
    assert [Path(p).name for p in glob.iglob(str(tmp_path / "*"))] == top
    # A real traversal yields a directory before what it holds; only siblings
    # are reordered.
    expected = (
        ["a.txt", "b.txt", "c.txt", "d", "d/x.txt", "d/y.txt"]
        if not reverse
        else ["d", "d/y.txt", "d/x.txt", "c.txt", "b.txt", "a.txt"]
    )
    assert [p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*")] == expected
    walks = [
        [(Path(t).name, d, f) for t, d, f in os.walk(tmp_path)],
        [(t.name, d, f) for t, d, f in tmp_path.walk()],
    ]
    for walk in walks:
        assert walk == [
            (tmp_path.name, ["d"], order(["a.txt", "b.txt", "c.txt"])),
            ("d", [], order(["x.txt", "y.txt"])),
        ]


def _results(**runs: dict[str, str]) -> dict[str, dict]:
    return {
        name: {
            "meta": {},
            "tests": {
                t: {"outcome": o, "message": f"{name} {t}"} for t, o in r.items()
            },
        }
        for name, r in runs.items()
    }


def test_a_finding_is_a_test_that_passes_normally_and_not_under_a_condition() -> None:
    shell = "tests/unit/test_verify_badges.py::test_a"
    results = _results(
        normal={
            "t.py::a": "passed",
            "t.py::b": "passed",
            "t.py::c": "failed",
            "t.py::d": "skipped",
            "t.py::e": "passed",
            shell: "passed",
        },
        crlf={
            "t.py::a": "failed",
            "t.py::b": "passed",
            "t.py::c": "failed",
            "t.py::d": "failed",
            shell: "failed",
        },
        locale={"t.py::b": "skipped", "u.py": "collection-error", shell: "failed"},
        **{"order-asc": {"t.py::e": "error"}},
    )

    broken, found, excused = pc.findings(results)

    assert [(b["condition"], b["test"]) for b in broken] == [("normal", "t.py::c")]
    assert [(f["condition"], f["test"], f["outcome"]) for f in found] == [
        ("crlf", "t.py::a", "failed"),
        ("locale", "t.py::b", "skipped"),
        ("locale", shell, "failed"),  # exempt under crlf only
        ("locale", "u.py", "collection-error"),
        ("order-asc", "t.py::e", "error"),
    ]
    assert [(e["condition"], e["test"]) for e in excused] == [("crlf", shell)]


def test_a_collection_error_already_there_normally_is_not_a_finding() -> None:
    results = _results(
        normal={"u.py": "collection-error"}, crlf={"u.py": "collection-error"}
    )

    broken, found, _ = pc.findings(results)

    assert [b["test"] for b in broken] == ["u.py"]
    assert found == []


def _meta(**overrides: object) -> dict:
    return {
        "meta": {
            "encoding": "utf-8",
            "utf8_mode": 1,
            "order": None,
            "wrong_tree": [],
            **overrides,
        },
        "tests": {},
    }


def test_a_condition_that_did_not_take_effect_stops_the_check() -> None:
    good = {
        "normal": _meta(),
        "crlf": _meta(),
        "locale": _meta(encoding="ascii", utf8_mode=0),
        "order-asc": _meta(order="asc"),
        "order-desc": _meta(order="desc"),
    }
    assert pc.condition_errors(good) == []

    # `LC_ALL=C` alone: Python turns UTF-8 mode on and the run tests nothing.
    bad = {
        **good,
        "locale": _meta(encoding="utf-8", utf8_mode=1),
        "order-desc": _meta(order=None),
        "crlf": _meta(wrong_tree=["/src/scripts/__init__.py"]),
    }
    errors = pc.condition_errors(bad)
    assert len(errors) == 3, errors
    assert any(e.startswith("locale: the run still decoded as utf-8") for e in errors)
    assert any(
        e.startswith("order-desc: the listing order was not forced") for e in errors
    )
    assert any(e.startswith("crlf: imported from the source checkout") for e in errors)


def test_a_module_imported_from_the_source_checkout_is_the_wrong_tree(
    tmp_path: Path,
) -> None:
    source, tree, prefix = tmp_path / "src", tmp_path / "clone", tmp_path / "src/.venv"

    def module(path: Path) -> types.ModuleType:
        m = types.ModuleType("m")
        m.__file__ = str(path)
        return m

    modules = [
        module(source / "scripts" / "core.py"),
        module(tree / "scripts" / "core.py"),
        module(prefix / "lib" / "site.py"),
        module(tmp_path / "elsewhere.py"),
        types.ModuleType("no_file"),
    ]

    assert pc.wrong_tree_modules(modules, source, tree, prefix) == [
        str((source / "scripts" / "core.py").resolve())
    ]


def test_every_exemption_names_a_test_that_exists() -> None:
    """Each entry is a place the check is blind; one whose test moved would
    hide a new test of the same name, or nothing, without saying so."""
    for condition, entries in pc.EXEMPT.items():
        assert condition in pc.CONDITIONS
        for prefix in entries:
            path, *names = prefix.split("::")
            text = (REPO_ROOT / path).read_text(encoding="utf-8")
            for name in names:
                assert f"def {name}(" in text or f"class {name}" in text, (
                    f"{prefix}: {name} is not in {path}"
                )
