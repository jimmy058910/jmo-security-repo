#!/usr/bin/env python3
"""Run a branch's changed tests under the platform conditions CI meets late.

Three conditions reach a branch only through CI: windows-2022's CRLF checkout, a
locale that is not UTF-8, and a filesystem that lists a directory in another
order. On 2026-11-14 two defects of that kind were found only after a push: a
test matched a backslash-newline on `read_bytes()`, so windows-2022's CRLF
checkout crashed its collection and the shard ran no test under a green tick
(#1639); and the installer took the first `rglob` match, which on CI's runner was
the checksum file saved beside the download (#1633). Both reproduce on Linux
under the right condition, in about two seconds.

This script takes the test files a commit adds or changes against a base
(`tests/**/test_*.py`), clones the commit twice into a scratch directory, and runs
those files five times:

    normal      LF clone, UTF-8 mode          the reference
    crlf        CRLF clone (core.autocrlf=true, as windows-2022 checks out)
    locale      LF clone, LC_ALL=C and PYTHONUTF8=0 (open() and stdio are ascii)
    order-asc   LF clone, directory listings forced into ascending order
    order-desc  LF clone, directory listings forced into descending order

A test that passes in the normal run and fails, errors or skips under a
condition is a finding, and so is a file that collects normally and not under
one. Each run's environment is set, not inherited, so a check of this script's
own tests is not changed by the condition it runs under.

The script refuses (exit 2) when a condition did not take effect: the locale
run still decoded as UTF-8, the CRLF clone holds no CRLF test file, the order
was not forced, or the tests imported the project from the source checkout
instead of the clone. A check that silently tests nothing is the failure this
exists to prevent: `LC_ALL=C` alone turns Python's UTF-8 mode on, and
`Path.rglob` binds `os.scandir` at import, so patching `os.scandir` does not
reorder it.

Usage:
    platform_check.py                        # HEAD's changed tests against origin/dev
    platform_check.py --base origin/main     # another base
    platform_check.py --rev <sha> --base X   # a commit other than HEAD
    platform_check.py tests/unit/test_x.py   # these files instead of the diff

Limits: the listing order is forced inside the pytest process, not in a `jmo`
subprocess a test starts. ascii is stricter than Windows' cp1252, so a test can
fail here on a character cp1252 has; the rules ask for an explicit
`encoding="utf-8"` anyway. The C locale also makes Linux's file-system encoding
ascii, which Windows' never is, so a test that creates a non-ASCII file name
fails or skips here for a reason Windows does not have; `EXEMPT` lists those,
and a CRLF clone's shell scripts, with why. The commit is checked, not the
working tree.

Exit code 0 = no finding, 1 = a finding or a test that fails normally,
2 = the check could not run or a condition did not take effect.
"""

from __future__ import annotations

import argparse
import codecs
import functools
import glob
import json
import locale
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterable
from pathlib import Path, PurePath, PurePosixPath
from typing import Any

ORDER_ENV = "JMO_PLATFORM_CHECK_ORDER"
REPORT_ENV = "JMO_PLATFORM_CHECK_REPORT"
SOURCE_ENV = "JMO_PLATFORM_CHECK_SOURCE"
PLUGIN_MODULE = "jmo_platform_check_plugin"

# ci.yml's marker filters: windows-2022 and windows-native-encoding drop `slow`,
# the Ubuntu shards and macOS keep it.
WINDOWS_MARKERS = "not smoke and not requires_tools and not docker and not slow"
POSIX_MARKERS = "not smoke and not requires_tools and not docker"

# name -> (tree, marker filter, environment)
CONDITIONS: dict[str, tuple[str, str, dict[str, str]]] = {
    "normal": ("lf", POSIX_MARKERS, {"PYTHONUTF8": "1"}),
    "crlf": ("crlf", WINDOWS_MARKERS, {"PYTHONUTF8": "1"}),
    "locale": ("lf", WINDOWS_MARKERS, {"LC_ALL": "C", "LANG": "C", "PYTHONUTF8": "0"}),
    "order-asc": ("lf", POSIX_MARKERS, {"PYTHONUTF8": "1", ORDER_ENV: "asc"}),
    "order-desc": ("lf", POSIX_MARKERS, {"PYTHONUTF8": "1", ORDER_ENV: "desc"}),
}

# Never inherited by a run: each condition sets what it needs.
DROPPED_ENV = (
    "PYTHONIOENCODING",
    "PYTHONUTF8",
    "PYTHONPATH",
    "PYTEST_ADDOPTS",
    "PYTEST_PLUGINS",
    ORDER_ENV,
    REPORT_ENV,
    SOURCE_ENV,
)

# Tests a condition cannot fairly judge, by node id or a prefix of one, with
# the reason. Measured over the whole suite at 97baa6ac, these were every
# finding that was the emulation's and not the platform's. Keep it short:
# every entry is a place the check is blind.
_SH_ON_LINUX = (
    "runs a checked-out .sh under bash, only on Linux, where a checkout is LF"
)
_NON_ASCII_NAME = (
    "creates a non-ASCII file name: the C locale also makes Linux's file-system "
    "encoding ascii, and Windows' is always UTF-8"
)
EXEMPT: dict[str, dict[str, str]] = {
    "crlf": {
        "tests/unit/test_install_tools_script.py": _SH_ON_LINUX,
        "tests/unit/test_verify_badges.py": _SH_ON_LINUX,
    },
    "locale": {
        "tests/cli/test_wizard_edge_cases.py::TestUnicodePaths": _NON_ASCII_NAME,
        "tests/core/test_platform_validator.py::TestPathChecks::test_paths_with_unicode": _NON_ASCII_NAME,
        "tests/unit/test_gitleaks_wiring.py::TestConfig::test_a_character_outside_the_bmp_survives_as_toml": _NON_ASCII_NAME,
    },
}


def exempt_reason(condition: str, test: str) -> str | None:
    """Why `condition` does not judge `test`, or None."""
    for prefix, reason in EXEMPT.get(condition, {}).items():
        if test == prefix or test.startswith(prefix + "::"):
            return reason
    return None


GIT_TIMEOUT_S = 300
# A run of a whole changed-test set; a single test's limit is pytest-timeout's.
RUN_TIMEOUT_S = 3600


class CheckError(Exception):
    """The check could not run, or a condition did not take effect (exit 2)."""


# --------------------------------------------------------------------------
# The pytest plugin: loaded into every run as PLUGIN_MODULE (a copy of this
# file), so it works on a commit that does not have this file.
# --------------------------------------------------------------------------

_outcomes: dict[str, dict[str, str]] = {}
_order_installed: str | None = None
_rootpath: Path | None = None


def install_listing_order(
    reverse: bool, set_attr: Callable[[Any, str, Any], None] = setattr
) -> None:
    """Make every common directory-listing API return a sorted order.

    Siblings come out ascending, or descending when `reverse`; a parent still
    comes before its children, as every real traversal yields them. The public
    APIs are wrapped, not `os.scandir` alone: `Path.glob` and `Path.rglob` bind
    `os.scandir` at import in Python 3.13.
    """

    def component(name: str) -> Any:
        # The tuple form reverses string order exactly, and the trailing 1
        # sorts a name after every longer name it prefixes.
        return tuple(-ord(c) for c in name) + (1,) if reverse else name

    def path_key(p: Any) -> tuple[Any, ...]:
        return tuple(component(part) for part in PurePath(os.fsdecode(p)).parts)

    def sorted_iter(real: Callable[..., Iterable[Any]]) -> Callable[..., Any]:
        return lambda *a, **k: iter(sorted(real(*a, **k), key=path_key))

    def sorted_walk(real: Callable[..., Iterable[Any]]) -> Callable[..., Any]:
        def walk(*a: Any, **k: Any) -> Any:
            for top, dirs, files in real(*a, **k):
                # In place: a top-down caller prunes `dirs`, and the walk
                # descends in the order the list holds.
                dirs.sort(key=lambda n: component(os.fsdecode(n)))
                files.sort(key=lambda n: component(os.fsdecode(n)))
                yield top, dirs, files

        return walk

    class _SortedScandir:
        def __init__(self, it: Any) -> None:
            self._it = it
            self._entries = iter(sorted(it, key=lambda e: component(e.name)))

        def __iter__(self) -> _SortedScandir:
            return self

        def __next__(self) -> Any:
            return next(self._entries)

        def __enter__(self) -> _SortedScandir:
            return self

        def __exit__(self, *_: object) -> None:
            self.close()

        def close(self) -> None:
            self._it.close()

    real_listdir, real_scandir = os.listdir, os.scandir
    real_glob = glob.glob
    set_attr(
        os,
        "listdir",
        lambda *a, **k: sorted(
            real_listdir(*a, **k), key=lambda n: component(os.fsdecode(n))
        ),
    )
    set_attr(os, "scandir", lambda *a, **k: _SortedScandir(real_scandir(*a, **k)))
    set_attr(os, "walk", sorted_walk(os.walk))
    set_attr(glob, "glob", lambda *a, **k: sorted(real_glob(*a, **k), key=path_key))
    set_attr(glob, "iglob", sorted_iter(glob.iglob))
    for name in ("glob", "rglob", "iterdir"):
        set_attr(Path, name, sorted_iter(getattr(Path, name)))
    set_attr(Path, "walk", sorted_walk(Path.walk))


def wrong_tree_modules(
    modules: Iterable[Any], source: Path, tree: Path, prefix: Path
) -> list[str]:
    """Modules imported from the source checkout instead of the clone.

    An editable install or a stale PYTHONPATH can import the project from the
    checkout the clone was made from, and then the clone's CRLF files or its
    commit are never what ran. The venv may live inside the source checkout,
    so anything under `prefix` is not counted.
    """
    found = set()
    for module in modules:
        file = getattr(module, "__file__", None)
        if not file:
            continue
        path = Path(file).resolve()
        if (
            path.is_relative_to(source)
            and not path.is_relative_to(tree)
            and not path.is_relative_to(prefix)
        ):
            found.add(str(path))
    return sorted(found)


def _crash_line(report: Any) -> str:
    if isinstance(report.longrepr, tuple):  # a skip: (path, line, reason)
        return str(report.longrepr[2])[:300]
    crash = getattr(report.longrepr, "reprcrash", None)
    text: str
    if crash is not None and crash.message:
        text = str(crash.message)
    else:
        text = str(report.longrepr or "")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return ""
    line = lines[0] if crash is not None else lines[-1]
    return line.removeprefix("E ").strip()[:300]


def pytest_configure(config: Any) -> None:
    global _order_installed, _rootpath
    _rootpath = Path(config.rootpath).resolve()
    order = os.environ.get(ORDER_ENV)
    if order in ("asc", "desc"):
        install_listing_order(reverse=order == "desc")
        _order_installed = order


def pytest_collectreport(report: Any) -> None:
    if report.failed:
        _outcomes[report.nodeid] = {
            "outcome": "collection-error",
            "message": _crash_line(report),
        }


def pytest_runtest_logreport(report: Any) -> None:
    if report.when == "call" or not report.passed:
        if hasattr(report, "wasxfail"):
            outcome = "xfailed" if report.skipped else "xpassed"
        elif report.failed and report.when != "call":
            outcome = "error"
        else:
            # A rerun attempt reads "rerun" and the next attempt overwrites it;
            # a teardown error comes after the call and overwrites its pass.
            outcome = report.outcome
        _outcomes[report.nodeid] = {
            "outcome": outcome,
            "message": _crash_line(report) if not report.passed else "",
        }


def pytest_sessionfinish(session: Any) -> None:
    path = os.environ.get(REPORT_ENV)
    if not path or hasattr(session.config, "workerinput"):
        return
    source = os.environ.get(SOURCE_ENV)
    meta = {
        "encoding": codecs.lookup(locale.getpreferredencoding(False)).name,
        "utf8_mode": sys.flags.utf8_mode,
        "order": _order_installed,
        "wrong_tree": (
            wrong_tree_modules(
                list(sys.modules.values()),
                Path(source).resolve(),
                _rootpath or Path.cwd(),
                Path(sys.prefix).resolve(),
            )
            if source
            else []
        ),
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"meta": meta, "tests": _outcomes}, fh)


# --------------------------------------------------------------------------
# The runner.
# --------------------------------------------------------------------------


@functools.cache
def _git_env() -> dict[str, str]:
    """os.environ without git's local variables. A hook exports GIT_DIR, and
    with it set every git command here would act on another repository."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    proc = subprocess.run(
        ["git", "rev-parse", "--local-env-vars"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=GIT_TIMEOUT_S,
        env=env,
        check=False,
    )
    drop = set(proc.stdout.split())
    return {k: v for k, v in os.environ.items() if k not in drop}


def git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=GIT_TIMEOUT_S,
        env=_git_env(),
        check=False,
    )
    if proc.returncode != 0:
        raise CheckError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def is_test_file(path: str) -> bool:
    p = PurePosixPath(path)
    return (
        p.parts[:1] == ("tests",) and p.name.startswith("test_") and p.suffix == ".py"
    )


def changed_test_files(repo: Path, base: str, rev: str) -> list[str]:
    """Test files `rev` adds, modifies or renames since its merge-base with
    `base`. A deleted file has nothing to run."""
    merge_base = git(repo, "merge-base", base, rev).strip()
    out = git(repo, "diff", "--name-only", "-z", "--diff-filter=AMR", merge_base, rev)
    return sorted(p for p in out.split("\0") if p and is_test_file(p))


def make_clone(repo: Path, rev: str, dest: Path, autocrlf: str) -> None:
    # --shared borrows the source's objects, so any commit it holds checks out.
    # The setting is written into the clone: a clone does not inherit the
    # source's local core.autocrlf, and Git for Windows defaults it to true.
    git(
        repo,
        "clone",
        "--quiet",
        "--shared",
        "--no-checkout",
        "--config",
        f"core.autocrlf={autocrlf}",
        str(repo),
        str(dest),
    )
    git(dest, "checkout", "--quiet", "--detach", rev)


def run_condition(
    name: str,
    trees: dict[str, Path],
    workdir: Path,
    plugin_dir: Path,
    source: Path,
    targets: list[str],
) -> dict[str, Any]:
    tree_name, markers, extra = CONDITIONS[name]
    tree = trees[tree_name]
    report = workdir / f"{name}.json"
    env = {k: v for k, v in _git_env().items() if k not in DROPPED_ENV}
    env.update(extra)
    env["PYTHONPATH"] = os.pathsep.join([str(tree), str(plugin_dir)])
    env[REPORT_ENV] = str(report)
    env[SOURCE_ENV] = str(source)
    cmd = [
        sys.executable, "-m", "pytest", "-q", "-rfE",
        "-p", PLUGIN_MODULE, "-p", "no:cacheprovider",
        "--continue-on-collection-errors", "--disable-warnings",
        "-m", markers, "--basetemp", str(workdir / f"bt-{name}"),
    ]  # fmt: skip
    if _has_module("pytest_rerunfailures"):
        cmd += ["--reruns", "2"]  # as the Ubuntu and macOS shards run
    proc = subprocess.run(
        [*cmd, *targets],
        cwd=tree,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=RUN_TIMEOUT_S,
        check=False,
    )
    if proc.returncode not in (0, 1, 5) or not report.is_file():
        tail = "\n".join((proc.stdout + proc.stderr).splitlines()[-15:])
        raise CheckError(f"the {name} run ended with exit {proc.returncode}:\n{tail}")
    result: dict[str, Any] = json.loads(report.read_text(encoding="utf-8"))
    return result


def _has_module(name: str) -> bool:
    import importlib.util

    return importlib.util.find_spec(name) is not None


def condition_errors(results: dict[str, dict[str, Any]]) -> list[str]:
    """Conditions that did not take effect, and runs that imported the wrong
    tree. Any one makes the comparison meaningless."""
    errors = []
    for name, result in results.items():
        meta = result["meta"]
        if meta["wrong_tree"]:
            errors.append(
                f"{name}: imported from the source checkout, not the clone: "
                + ", ".join(meta["wrong_tree"][:3])
            )
    locale_meta = results.get("locale", {}).get("meta")
    if locale_meta and (locale_meta["utf8_mode"] or locale_meta["encoding"] == "utf-8"):
        errors.append(
            f"locale: the run still decoded as {locale_meta['encoding']} "
            f"(utf8_mode={locale_meta['utf8_mode']})"
        )
    for name in ("order-asc", "order-desc"):
        meta = results.get(name, {}).get("meta")
        if meta and meta["order"] != CONDITIONS[name][2][ORDER_ENV]:
            errors.append(f"{name}: the listing order was not forced")
    return errors


def findings(
    results: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, str]]]:
    """(tests that fail normally, tests that pass normally and not under a
    condition, those of the second kind that EXEMPT excuses). A collection
    error under a condition is a finding when the same file collected
    normally."""
    normal = results["normal"]["tests"]
    broken = [
        {"condition": "normal", "test": t, **o}
        for t, o in sorted(normal.items())
        if o["outcome"] in ("failed", "error", "collection-error")
    ]
    found, excused = [], []
    for name, result in results.items():
        if name == "normal":
            continue
        for test, o in sorted(result["tests"].items()):
            if o["outcome"] == "collection-error":
                regressed = normal.get(test, {}).get("outcome") != "collection-error"
            else:
                regressed = normal.get(test, {}).get("outcome") == "passed" and o[
                    "outcome"
                ] in ("failed", "error", "skipped")
            if not regressed:
                continue
            reason = exempt_reason(name, test)
            entry = {"condition": name, "test": test, **o}
            if reason:
                excused.append({**entry, "reason": reason})
            else:
                found.append(entry)
    return broken, found, excused


def _counts(tests: dict[str, dict[str, str]]) -> str:
    tally: dict[str, int] = {}
    for o in tests.values():
        tally[o["outcome"]] = tally.get(o["outcome"], 0) + 1
    return ", ".join(f"{n} {k}" for k, n in sorted(tally.items())) or "nothing ran"


def check(
    repo: Path, rev: str, targets: list[str], workdir: Path
) -> dict[str, dict[str, Any]]:
    trees = {"lf": workdir / "lf", "crlf": workdir / "crlf"}
    make_clone(repo, rev, trees["lf"], "false")
    make_clone(repo, rev, trees["crlf"], "true")
    files = [t.split("::")[0] for t in targets]
    if not any(
        b"\r\n" in (trees["crlf"] / f).read_bytes()
        for f in files
        if (trees["crlf"] / f).is_file()
    ):
        raise CheckError("crlf: the CRLF clone holds no selected file with CRLF")
    plugin_dir = workdir / "plugin"
    plugin_dir.mkdir()
    shutil.copyfile(__file__, plugin_dir / f"{PLUGIN_MODULE}.py")
    return {
        name: run_condition(name, trees, workdir, plugin_dir, repo, targets)
        for name in CONDITIONS
    }


def main(argv: list[str] | None = None) -> int:
    # A finding's message can hold any character, and this may run under the
    # very ascii locale it tests.
    sys.stdout.reconfigure(errors="backslashreplace")  # type: ignore[union-attr]
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0] if __doc__ else None
    )
    parser.add_argument("paths", nargs="*", help="test files or node ids to run")
    parser.add_argument("--base", default="origin/dev", help="default: origin/dev")
    parser.add_argument("--rev", default="HEAD", help="commit to check (HEAD)")
    # The system temp directory: the clones borrow the source's objects
    # (`--shared`), so each holds only a working tree, and every run removes its
    # own unless --keep. The basetemps the five runs write go there too.
    parser.add_argument(
        "--workdir",
        type=Path,
        default=Path(tempfile.gettempdir()) / "jmo-platform-check",
        help="scratch root (default <system temp dir>/jmo-platform-check)",
    )
    parser.add_argument("--keep", action="store_true", help="keep the clones")
    parser.add_argument("--json", type=Path, help="also write the result here")
    args = parser.parse_args(argv)

    try:
        repo = Path(git(Path.cwd(), "rev-parse", "--show-toplevel").strip())
        rev = git(repo, "rev-parse", "--verify", f"{args.rev}^{{commit}}").strip()
        targets = args.paths or changed_test_files(repo, args.base, rev)
        if not targets:
            print(f"platform check: no changed test files at {rev[:12]}")
            return 0
        head = git(repo, "rev-parse", "HEAD").strip()
        dirty = git(
            repo, "status", "--porcelain", "--", *{t.split("::")[0] for t in targets}
        )
        print(f"platform check: {len(targets)} target(s) at {rev[:12]}")
        if rev == head and dirty.strip():
            print("  uncommitted changes are not checked (commit them first):")
            print("    " + "\n    ".join(dirty.strip().splitlines()))
        args.workdir.mkdir(parents=True, exist_ok=True)
        tmp = tempfile.mkdtemp(prefix=f"{rev[:12]}-", dir=args.workdir)
        try:
            results = check(repo, rev, targets, Path(tmp))
        finally:
            if args.keep:
                print(f"  kept: {tmp}")
            else:
                shutil.rmtree(tmp, ignore_errors=True)
        errors = condition_errors(results)
        if errors:
            raise CheckError("\n".join(errors))
    except CheckError as exc:
        print(f"platform check: could not run\n{exc}")
        return 2

    broken, found, excused = findings(results)
    for name, result in results.items():
        print(f"  {name:<11} {_counts(result['tests'])}")
    for f in excused:
        print(f"  not judged under {f['condition']}: {f['test']} ({f['reason']})")
    if broken:
        print(f"\n{len(broken)} test(s) fail with no condition applied:")
        for f in broken:
            print(f"  {f['test']}  {f['outcome']}: {f['message']}")
    if found:
        print(f"\n{len(found)} test(s) pass normally and not under a condition:")
        for f in found:
            print(f"  {f['condition']:<11} {f['test']}  {f['outcome']}: {f['message']}")
    if args.json:
        args.json.write_text(
            json.dumps(
                {"broken": broken, "findings": found, "excused": excused}, indent=2
            ),
            encoding="utf-8",
        )
    if broken or found:
        return 1
    print("platform check: no finding")
    return 0


if __name__ == "__main__":
    sys.exit(main())
