"""No value JMo builds reaches the command line of a `.bat`/`.cmd` launcher (#1403).

On Windows `CreateProcess` cannot run a batch file itself: it hands the whole
command line to `cmd.exe /c`, which re-reads `& | ^ < > %` in every argument,
quoted or not. Measured through `jmo scan` on Windows before the fix, each with
the benign `echo.<MARKER>` as the injected command:

- zap (`zap.bat`), a `--results-dir` holding `&echo.X`: the plan's path on its
  command line was cut there, `echo.X` ran, rc 0, 0 requests, no report.
- checkov (`checkov.cmd`), a repository named `tf&echo.X`: `echo.X` ran with
  the rest of the command line as its output, which became checkov.json; the
  row read `ran`, 0 of its 10 findings. An IaC file's directory, the same.

So every descriptor's command lines are rendered here with a target, a results
directory and the files under the target holding each of the six characters,
and none may reach an argument after a batch launcher. A launcher is a batch
file by its suffix, as Windows decides; the tools JMo resolves to one are
rendered with one (`BATCH_TOOLS`).
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path, PureWindowsPath

import pytest

from scripts.cli.scan_jobs import tool_loop
from scripts.cli.scan_utils import batch_argv_refusal, tool_exclusion_flags
from scripts.core import tool_utils
from scripts.core.install_config import BINARY_URLS
from scripts.core.tool_descriptors import (
    DESCRIPTORS,
    ZAP_PLAN,
    ExclusionStyle,
    Fallback,
    Invocation,
    ScanContext,
)
from scripts.core.tool_registry import BUILTIN_TOOLS
from scripts.core.tool_runner import ToolResult

CMD_METACHARACTERS = "&|^<>%"
BATCH_SUFFIXES = (".bat", ".cmd")

# Which launcher JMo resolves each tool to on Windows (`find_tool`):
# - a downloaded binary (`BINARY_URLS`): `BinaryInstaller` names it `<tool>.exe`;
# - jmo-native, and yara (libyara bindings): the interpreter, `python.exe`;
# - semgrep, in its own venv: pip's `semgrep.exe` shim (its package declares a
#   console script; measured);
# - checkov, in its own venv: `checkov.cmd` (its package declares none);
# - zap: `zap.bat`, picked beside `zap.sh` (`_platform_launcher`).
# A tool not shown here to resolve to an `.exe` is rendered with a batch
# launcher, so a new tool is held to this until it is.
RESOLVES_TO_EXE = (frozenset(BINARY_URLS) | BUILTIN_TOOLS | {"yara", "semgrep"}) & set(
    DESCRIPTORS
)
BATCH_TOOLS = sorted(set(DESCRIPTORS) - RESOLVES_TO_EXE)


def _launcher(tmp_path: Path, tool: str, suffix: str) -> Path:
    """The tool's launcher as installed: an `.exe`, or a batch file beside
    what an install puts there (zap's jar)."""
    d = DESCRIPTORS[tool]
    stem = Path(d.binary or tool).stem
    where = tmp_path / "installed" / tool
    where.mkdir(parents=True, exist_ok=True)
    if tool not in BATCH_TOOLS:
        return where / f"{stem}.exe"
    launcher = where / f"{stem}{suffix}"
    launcher.write_bytes(b"@echo off\r\n")
    if tool == "zap":
        (where / "zap-2.17.0.jar").write_bytes(b"")
        (where / "zap.sh").write_bytes(b"")
    return launcher


def _target(root: Path, key: str, char: str):
    """A target holding `char`, under `root`. An IaC file holds it in its
    directory: a file is handed to its tool by name, and a name holding one is
    refused by the scan loop instead (`batch_argv_refusal`)."""
    return {
        "repo": root / f"repo{char}x",
        "iac": root / f"iac{char}x" / "main.tf",
        "url": f"http://127.0.0.1:1/a{char}b/?q=1{char}echo.X",
        "image": f"registry.test/img{char}x:latest",
        "k8s": {"context": f"ctx{char}x", "namespace": f"ns{char}x"},
    }[key]


def _exclusions(tool: str, out_dir: Path, results_name: str) -> tuple[str, ...]:
    """What the scan loop hands a repository builder (`tool_loop._exclusions`):
    flags rendered from the results directory's name, or a file it writes
    there."""
    d = DESCRIPTORS[tool]
    if d.exclusion_style in (ExclusionStyle.PATTERN_FILE, ExclusionStyle.CONFIG_FILE):
        return (str(d.exclusion_flag), str(out_dir / f".{tool}-exclusions"))
    return tuple(tool_exclusion_flags(tool, results_dir_name=results_name))


def _render(
    tmp_path: Path,
    tool: str,
    key: str,
    char: str,
    suffix: str,
    root: Path | None = None,
):
    d = DESCRIPTORS[tool]
    results_name = f"res{char}ults"
    out_dir = tmp_path / results_name / "target"
    target = _target(root or tmp_path, key, char)
    repo = key == "repo"
    excl = _exclusions(tool, out_dir, results_name) if repo else ()
    files = (
        (str(target / f"sub{char}y" / f"f{char}z.sh"),)
        if repo and d.file_patterns
        else ()
    )
    ctx = ScanContext(
        tool=tool,
        target_type=key,
        target=target,
        out_dir=out_dir,
        binary=str(_launcher(tmp_path, tool, suffix)),
        exclusion_args=excl,
        history_exclusion_args=excl,
        history=d.reads_history,
        files=files,
        plan=out_dir / ZAP_PLAN if d.automation_plan else None,
    )
    return d.invocations[key](ctx)


def _command_lines(invocations: list[Invocation]) -> list[tuple[str, ...]]:
    """Each command line a run can execute: a fallback's too."""
    lines: list[tuple[str, ...]] = []
    for inv in invocations:
        lines.append(inv.command)
        if inv.fallback is not None:
            lines.extend(each.command for each in inv.fallback.invocations)
    return lines


def _leaks(invocations: list[Invocation]) -> list[tuple[str, str]]:
    """(launcher, argument) for each argument of a batch launcher that cmd.exe
    would re-read."""
    return [
        (Path(line[0]).name, arg)
        for line in _command_lines(invocations)
        if Path(line[0]).suffix.lower() in BATCH_SUFFIXES
        for arg in line[1:]
        if set(arg) & set(CMD_METACHARACTERS)
    ]


@pytest.fixture
def java(tmp_path, monkeypatch):
    """java as `find_tool` resolves it, for zap's launch on Windows."""
    path = str(tmp_path / "jre" / "bin" / "java.exe")
    real = tool_utils.find_tool
    monkeypatch.setattr(
        tool_utils, "find_tool", lambda name: path if name == "java" else real(name)
    )
    return path


CASES = [
    pytest.param(tool, key, char, suffix, id=f"{tool}-{key}-{char}{suffix}")
    for tool, d in DESCRIPTORS.items()
    for key in sorted(d.invocations)
    for char in CMD_METACHARACTERS
    for suffix in (BATCH_SUFFIXES if tool in BATCH_TOOLS else (".exe",))
]


@pytest.mark.parametrize(("tool", "key", "char", "suffix"), CASES)
def test_no_value_reaches_a_batch_launchers_command_line(
    tmp_path, java, tool, key, char, suffix
) -> None:
    invocations = _render(tmp_path, tool, key, char, suffix)

    assert invocations, f"{tool} rendered no command line for {key}"
    assert _leaks(invocations) == [], _command_lines(invocations)


# A share no test reaches: nothing here may touch it.
UNC_ROOT = Path(r"\\server.invalid\share")


def _is_unc(path: Path | None) -> bool:
    return path is not None and PureWindowsPath(str(path)).drive.startswith("\\\\")


def _unc_cwds(invocations: list[Invocation]) -> list[tuple[str, str]]:
    """(launcher, cwd) for each batch launcher told to start in a UNC
    directory: cmd.exe will not, and starts in `C:\\Windows` instead."""
    every = [
        each
        for inv in invocations
        for each in (inv, *(inv.fallback.invocations if inv.fallback else ()))
    ]
    return [
        (Path(each.command[0]).name, str(each.cwd))
        for each in every
        if Path(each.command[0]).suffix.lower() in BATCH_SUFFIXES and _is_unc(each.cwd)
    ]


UNC_CASES = [
    pytest.param(tool, key, suffix, id=f"{tool}-{key}{suffix}")
    for tool in BATCH_TOOLS
    for key in sorted(DESCRIPTORS[tool].invocations)
    for suffix in BATCH_SUFFIXES
]


@pytest.mark.parametrize(("tool", "key", "suffix"), UNC_CASES)
def test_no_batch_launcher_starts_in_a_unc_directory(
    tmp_path, java, tool, key, suffix
) -> None:
    """A target on a share (`\\\\wsl.localhost\\...`, a mapped server): run
    from there, checkov scanned `C:\\Windows`, row `ran`, 0 of 10 findings
    (measured through `jmo scan`)."""
    invocations = _render(tmp_path, tool, key, "-", suffix, root=UNC_ROOT)

    assert _unc_cwds(invocations) == [], [i.cwd for i in invocations]


class TestTheClassTestIsNotVacuous:
    def test_the_tools_known_to_resolve_to_a_batch_file_are_rendered_as_one(self):
        assert {"checkov", "zap"} <= set(BATCH_TOOLS)

    def test_every_tool_named_an_exe_by_hand_is_in_the_matrix(self):
        assert {"yara", "semgrep"} <= set(DESCRIPTORS)

    def test_checkov_is_still_run_through_its_batch_launcher(self, tmp_path, java):
        """So its two command lines are really checked: they keep
        `checkov.cmd` and only the values are kept off them."""
        for key in ("repo", "iac"):
            (line,) = _command_lines(_render(tmp_path, "checkov", key, "&", ".cmd"))
            assert Path(line[0]).name == "checkov.cmd", line

    def test_the_rendered_values_hold_the_character(self, tmp_path, java):
        """A rendering that lost the character would pass for every tool."""
        (inv,) = _render(tmp_path, "trivy", "repo", "&", ".exe")
        assert any("repo&x" in arg for arg in inv.command), inv.command
        assert "res&ults" in str(inv.output_file)

    @pytest.mark.parametrize(
        ("launcher", "expected"),
        [
            ("C:/x/t.cmd", [("t.cmd", "a&b")]),
            ("C:/x/T.BAT", [("T.BAT", "a&b")]),
            ("C:/x/t.exe", []),
            ("/usr/bin/t", []),
        ],
        ids=["cmd", "bat-upper", "exe", "posix"],
    )
    def test_the_oracle_finds_a_leak_on_a_batch_launcher_only(self, launcher, expected):
        inv = Invocation(
            command=(launcher, "-d", "a&b"),
            output_file=Path("o.json"),
            capture_stdout=True,
            ok_return_codes=(0,),
        )
        assert _leaks([inv]) == expected

    def test_the_oracle_reads_a_fallbacks_command_lines(self):
        inner = Invocation(
            command=("C:/x/t.cmd", "a|b"),
            output_file=Path("p.json"),
            capture_stdout=True,
            ok_return_codes=(0,),
        )
        outer = Invocation(
            command=("C:/x/t.cmd", "clean"),
            output_file=Path("o.json"),
            capture_stdout=True,
            ok_return_codes=(0,),
            fallback=Fallback(
                returncodes=(1,), stderr_marker="x", invocations=(inner,)
            ),
        )
        assert _leaks([outer]) == [("t.cmd", "a|b")]

    @pytest.mark.parametrize(
        ("launcher", "cwd", "flagged"),
        [
            ("C:/x/t.cmd", r"\\server\share\repo", True),
            ("C:/x/t.BAT", r"\\wsl.localhost\Ubuntu\home\u\repo", True),
            ("C:/x/t.exe", r"\\server\share\repo", False),
            ("C:/x/t.cmd", "C:/repo", False),
            ("C:/x/t.cmd", None, False),
        ],
        ids=["cmd-unc", "bat-wsl", "exe-unc", "cmd-local", "cmd-none"],
    )
    def test_the_unc_oracle_flags_a_batch_launcher_only(self, launcher, cwd, flagged):
        inv = Invocation(
            command=(launcher, "-d", "."),
            output_file=Path("o.json"),
            capture_stdout=True,
            ok_return_codes=(0,),
            cwd=None if cwd is None else Path(cwd),
        )
        assert bool(_unc_cwds([inv])) is flagged


# --- what the fix is made of --------------------------------------------------


class TestCheckovRunsFromItsTarget:
    """`-d .` from the repository, `-f <name>` from the file's directory: the
    target's path is never an argument. Measured through `jmo scan` (checkov
    3.3.16): `-d .` found the same 10 ids at the same paths, and the same 30
    under JMo's `--skip-path` exclusions, as the absolute path."""

    @staticmethod
    def _invocation(
        tmp_path: Path,
        key: str,
        target: Path,
        binary: str = "C:/venv/Scripts/checkov.cmd",
    ) -> Invocation:
        ctx = ScanContext(
            tool="checkov",
            target_type=key,
            target=target,
            out_dir=tmp_path / "out",
            binary=binary,
        )
        (inv,) = DESCRIPTORS["checkov"].invocations[key](ctx)
        return inv

    @pytest.mark.parametrize(
        ("key", "flag", "target"),
        [
            ("repo", "-d", UNC_ROOT / "repo"),
            ("iac", "-f", UNC_ROOT / "iac" / "pod.yaml"),
            ("repo", "-d", Path(r"\\wsl.localhost\Ubuntu-24.04\home\u\repo")),
        ],
        ids=["repo", "iac", "wsl"],
    )
    def test_a_unc_target_is_the_argument_with_no_cwd(
        self, tmp_path, key, flag, target
    ):
        """cmd.exe will not start in a UNC directory ("UNC paths are not
        supported. Defaulting to Windows directory."): from there checkov
        scanned `C:\\Windows`, 0 of 10 findings (measured through `jmo scan`).
        The scan loop fails this row first (`_checkov_unc`); built anyway,
        the path is the argument, as before #1403, and checkov fails loudly."""
        inv = self._invocation(tmp_path, key, target)

        assert inv.command[1:3] == (flag, str(target))
        assert inv.cwd is None

    def test_a_unc_target_through_an_exe_is_still_run_from(self, tmp_path):
        """The control: only cmd.exe refuses a UNC working directory."""
        target = UNC_ROOT / "repo"
        inv = self._invocation(tmp_path, "repo", target, "C:/venv/Scripts/checkov.exe")

        assert inv.command[1:3] == ("-d", ".")
        assert inv.cwd == target

    def test_a_repository_is_scanned_as_dot_from_inside_it(self, tmp_path):
        repo = tmp_path / "repo"
        inv = self._invocation(tmp_path, "repo", repo)

        assert inv.command[1:3] == ("-d", ".")
        assert inv.cwd == repo
        assert not any(str(repo) in arg for arg in inv.command)

    def test_a_file_is_scanned_by_name_from_its_directory(self, tmp_path):
        manifest = tmp_path / "iac" / "pod.yaml"
        inv = self._invocation(tmp_path, "iac", manifest)

        assert inv.command[1:3] == ("-f", "pod.yaml")
        assert inv.cwd == manifest.parent
        assert not any(str(manifest.parent) in arg for arg in inv.command)


class TestBatchArgvRefusal:
    """The scan loop's last check: what a builder cannot keep off a batch
    launcher's command line is refused, never run."""

    @pytest.mark.parametrize(
        "char", [*CMD_METACHARACTERS, "\n", "\r"], ids=[*CMD_METACHARACTERS, "lf", "cr"]
    )
    def test_a_batch_launcher_with_a_metacharacter_is_refused(self, char):
        why = batch_argv_refusal(("C:/v/Scripts/checkov.cmd", "-f", f"pod{char}x.yaml"))

        assert why is not None
        assert "checkov.cmd" in why and "cmd.exe" in why, why
        assert "\n" not in why and "\r" not in why, why

    @pytest.mark.parametrize(
        "command",
        [
            ("C:/v/Scripts/checkov.cmd", "-d", ".", "--skip-path", "[\\\\/]res.ults$"),
            ("C:/bin/trivy.exe", "fs", "C:/repo&x"),
            ("/usr/local/bin/checkov", "-d", "/repo&x"),
            ("C:/jre/bin/java.exe", "-jar", "C:/zap/zap.jar", "-autorun", "C:/r&x/p"),
            (),
        ],
        ids=["clean-batch", "exe", "posix", "java", "empty"],
    )
    def test_anything_else_runs(self, command):
        """The control: without it, "refuse everything" passes the test above."""
        assert batch_argv_refusal(command) is None

    def test_the_launcher_itself_is_not_an_argument(self):
        """Where the tool is installed is not a value JMo builds."""
        assert batch_argv_refusal(("C:/Users/a&b/zap.bat", "-cmd")) is None


class _Recording:
    definitions: list = []

    def __init__(self, tools, progress_callback=None):
        type(self).definitions = list(tools)

    def run_all_parallel(self):
        return [
            ToolResult(tool=d.name, status="success", returncode=0)
            for d in self.definitions
        ]


def _run(tmp_path, monkeypatch, tool, target_type, target, find):
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "home"))
    _Recording.definitions = []
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    rows = tool_loop.run_tools(
        tools=[tool],
        target_type=target_type,
        target=target,
        target_label="t",
        out_dir=out,
        timeout=900,
        retries=0,
        per_tool_config={},
        allow_missing_tools=False,
        runner_cls=_Recording,
        find_tool_func=find,
        write_stub_func=lambda tool, path: None,
    )
    return rows[tool], _Recording.definitions


class TestTheScanLoopRefusesALeakingLauncher:
    def test_an_iac_file_named_with_one_fails_and_never_runs(
        self, tmp_path, monkeypatch, caplog
    ):
        manifest = tmp_path / "iac" / "pod&echo.X.yaml"
        with caplog.at_level("ERROR"):
            row, ran = _run(
                tmp_path,
                monkeypatch,
                "checkov",
                "iac",
                manifest,
                lambda name: "C:/venv/Scripts/checkov.cmd",
            )

        assert ran == []
        assert row.label == "failed:could not be run"
        assert "`pod&echo.X.yaml`" in row.detail, row.detail
        assert "did NOT run" in caplog.text

    def test_the_same_file_through_an_exe_runs(self, tmp_path, monkeypatch):
        """The control: the refusal is the launcher's, not the name's."""
        manifest = tmp_path / "iac" / "pod&echo.X.yaml"
        row, ran = _run(
            tmp_path,
            monkeypatch,
            "checkov",
            "iac",
            manifest,
            lambda name: "C:/venv/Scripts/checkov.exe",
        )

        assert [d.command[1:3] for d in ran] == [["-f", "pod&echo.X.yaml"]]
        assert row.label == "ran"

    @pytest.mark.parametrize(
        "manifest",
        [UNC_ROOT / "iac" / "pod.yaml", UNC_ROOT / "iac&echo.X" / "pod.yaml"],
        ids=["plain", "metacharacter"],
    )
    def test_a_unc_target_fails_checkovs_row_saying_why(
        self, tmp_path, monkeypatch, manifest
    ):
        """checkov.cmd cannot scan a UNC path from anywhere: from the target
        cmd.exe started in `C:\\Windows` and checkov scanned that (row `ran`,
        0 of 10 findings), and from another drive checkov failed on the path,
        rc 2 (both measured through `jmo scan`)."""
        row, ran = _run(
            tmp_path,
            monkeypatch,
            "checkov",
            "iac",
            manifest,
            lambda name: "C:/venv/Scripts/checkov.cmd",
        )

        assert ran == []
        assert row.label == "failed:could not be run"
        assert str(manifest) in row.detail and "UNC" in row.detail, row.detail
        assert "drive letter" in row.detail, row.detail

    def test_a_unc_target_through_an_exe_runs(self, tmp_path, monkeypatch):
        """The control: the refusal is cmd.exe's, not the share's."""
        row, ran = _run(
            tmp_path,
            monkeypatch,
            "checkov",
            "iac",
            UNC_ROOT / "iac" / "pod.yaml",
            lambda name: "C:/venv/Scripts/checkov.exe",
        )

        assert [d.command[1:3] for d in ran] == [["-f", "pod.yaml"]]
        assert row.label == "ran"

    def test_a_unc_repository_is_refused_by_the_same_precheck(self, tmp_path):
        """The repository row reaches the precheck once its trigger has found
        IaC files in the tree: the precheck alone decides."""
        ctx = ScanContext(
            tool="checkov",
            target_type="repo",
            target=UNC_ROOT / "repo",
            out_dir=tmp_path,
            binary="C:/venv/Scripts/checkov.cmd",
        )
        shortfall = DESCRIPTORS["checkov"].precheck(ctx)

        assert shortfall is not None and shortfall.files == ()
        assert str(UNC_ROOT / "repo") in shortfall.detail
        local = replace(ctx, target=tmp_path / "repo")
        assert DESCRIPTORS["checkov"].precheck(local) is None

    def test_a_fallbacks_command_line_is_checked_too(self, tmp_path, monkeypatch):
        """A fallback runs in a second round, which no builder sees again."""

        def leaking_fallback(ctx: ScanContext) -> list[Invocation]:
            part = Invocation(
                command=("C:/x/t.cmd", "a&echo.X"),
                output_file=ctx.part_output(1),
                capture_stdout=True,
                ok_return_codes=(0,),
            )
            whole = Invocation(
                command=("C:/x/t.cmd", "clean"),
                output_file=ctx.output,
                capture_stdout=True,
                ok_return_codes=(0,),
                fallback=Fallback((127,), "x", (part,)),
            )
            return [whole]

        monkeypatch.setitem(DESCRIPTORS["trivy"].invocations, "image", leaking_fallback)
        row, ran = _run(
            tmp_path, monkeypatch, "trivy", "image", "nginx:1", lambda n: "C:/x/t.cmd"
        )

        assert ran == []
        assert row.label == "failed:could not be run"
        assert "`a&echo.X`" in row.detail, row.detail


class TestZapIsNotRunThroughZapBat:
    """On Windows zap runs as `java -Xmx512m -jar zap-<version>.jar`, from its
    directory, with the arguments zap.bat would have passed on. zap.bat's rc
    was the injected command's (0), so only JMo's no-output check saw the
    measured run fail."""

    @staticmethod
    def _zap(
        tmp_path, monkeypatch, java="C:/jre/bin/java.exe", jars=("zap-2.17.0.jar",)
    ):
        where = tmp_path / "jmo-bin" / "zap"
        where.mkdir(parents=True)
        for name in ("zap.bat", "zap.sh", *jars):
            (where / name).write_bytes(b"")
        real = tool_utils.find_tool
        monkeypatch.setattr(
            tool_utils, "find_tool", lambda n: java if n == "java" else real(n)
        )
        row, ran = _run(
            tmp_path,
            monkeypatch,
            "zap",
            "url",
            "http://127.0.0.1:1/?a=1&b=2",
            lambda name: str(where / "zap.bat"),
        )
        return row, ran, where

    def test_the_scan_runs_java_on_the_jar_from_zaps_directory(
        self, tmp_path, monkeypatch
    ):
        row, ran, where = self._zap(tmp_path, monkeypatch)

        (definition,) = ran
        assert definition.command[:6] == [
            "C:/jre/bin/java.exe",
            "-Xmx512m",
            "-jar",
            str(where / "zap-2.17.0.jar"),
            "-cmd",
            "-silent",
        ]
        assert definition.cwd == where
        assert row.label == "ran"

    @pytest.mark.parametrize(
        ("jars", "found"),
        [
            ((), "found: none"),
            (("zap-2.16.0.jar", "zap-2.17.0.jar"), "zap-2.16.0.jar, zap-2.17.0.jar"),
        ],
        ids=["none", "two"],
    )
    def test_anything_but_one_jar_fails_the_row_naming_what_is_there(
        self, tmp_path, monkeypatch, jars, found
    ):
        row, ran, where = self._zap(tmp_path, monkeypatch, jars=jars)

        assert ran == []
        assert row.label == "failed:could not be run"
        assert found in row.detail and str(where) in row.detail, row.detail

    def test_no_java_fails_the_row(self, tmp_path, monkeypatch):
        row, ran, _ = self._zap(tmp_path, monkeypatch, java=None)

        assert ran == []
        assert row.label == "failed:could not be run"
        assert "java" in row.detail, row.detail
