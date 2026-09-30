#!/usr/bin/env python3
"""The secret scanners' two runs: the row, the flags, the history switch.

G1 (v2.0.0 Phase 3, PR C) gave trufflehog and gitleaks a second invocation
when a repository has history, reading it. Three things still assumed one.

**The row (#1324)** was built as though there were one invocation:

- A failed invocation was named only when the runner's result carried the
  output file it was meant to write, and only a success and the two
  ``no_output`` results did. A non-accepted exit code, a timeout, an OSError
  and an exception all came back without one, so the row said which run failed
  only in the test that built its fake result by hand.
- When both failed, only the first was named.
- The row's ``exit_code`` and ``scanned_count`` came from ``results[-1]`` and
  ``results[0]``: whichever run the runner happened to finish last or first.
- The reconciler checked ``<tool>.json`` alone, so a ``ran`` row whose
  ``<tool>.git.json`` was missing or did not parse passed.

**The flags JMo must own (#1325, #1335)**: gitleaks spells its report flags
its own way, so ``per_tool.gitleaks.flags`` could reformat or redirect its
output (measured: ``--report-format json`` lost every finding with the row
``ran``), and trufflehog's parser refuses a flag JMo already passes when it
is given again.

**One flag list for two modes (#1327)**: each mode rejects flags the other
needs (measured: trufflehog filesystem refuses ``--since-commit``, gitleaks git
refuses ``--follow-symlinks``), and history could not be turned off.

These run ``jmo scan`` on a repository with history. Only the process the
runner would start is fake: the real ``ToolRunner`` builds every result.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import tomllib
import types
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from scripts.cli import jmo
from scripts.core.exceptions import ToolExecutionException
from scripts.core.tool_descriptors import DESCRIPTORS
from scripts.core.tool_runner import ToolRunner
from scripts.dev.reconcile_scan_accounting import reconcile

# The tree invocation's name for each tool that reads history.
TREE = {"trufflehog": "filesystem", "gitleaks": "dir"}

# One trufflehog record: an accepted exit code 1 with nothing on stdout is
# graded a crash, so a run that reports findings has to print one.
_TRUFFLEHOG_HIT = json.dumps(
    {
        "DetectorName": "Generic",
        "Raw": "not-a-secret",
        "Verified": False,
        "SourceMetadata": {"Data": {"Filesystem": {"file": "README.md", "line": 1}}},
    }
)


def _process(outcomes: dict[str, object], seen: list[list[str]] | None = None):
    """A `_run_bounded` for the scanners: each mode's exit code, or the
    exception it raises. A run that succeeds writes what the tool would.
    `seen` collects every scanner command line."""
    real = sys.modules["scripts.core.tool_runner"]._run_bounded

    def run(command, **kwargs):
        if Path(command[0]).name not in TREE:
            return real(command, **kwargs)
        if seen is not None:
            seen.append(list(command))
        outcome = outcomes[command[1]]
        if isinstance(outcome, BaseException):
            raise outcome
        if outcome == 0 and "--report-path" in command:
            report = Path(command[command.index("--report-path") + 1])
            report.write_bytes(b'{"runs": []}')
        stdout = _TRUFFLEHOG_HIT + "\n" if outcome == 1 else ""
        stderr = f"{command[1]} exited {outcome}" if outcome not in (0, 1) else ""
        return subprocess.CompletedProcess(command, outcome, stdout, stderr)

    return run


@pytest.fixture
def scan(tmp_path: Path, monkeypatch):
    """`jmo scan` in `tmp_path` on `proj`, a repository with one commit, so
    both secret scanners read its history too."""
    project = tmp_path / "proj"
    project.mkdir()
    (project / "README.md").write_bytes(b"# proj\n")
    git = ["git", "-C", str(project)]
    identity = ["-c", "user.name=t", "-c", "user.email=t@example.com"]
    for cmd in (
        [*git, "init", "-q"],
        [*git, "add", "-A"],
        [*git, *identity, "commit", "-q", "-m", "init"],
    ):
        subprocess.run(cmd, check=True, capture_output=True, timeout=60)
    cfg = tmp_path / "jmo.yml"

    def configure(per_tool: dict | None = None) -> None:
        document: dict = {"outputs": ["json"]}
        if per_tool:
            document["per_tool"] = per_tool
        cfg.write_bytes(yaml.safe_dump(document).encode())

    configure()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(jmo, "_check_scan_tools", lambda args, tools: (tools, []))
    monkeypatch.setattr(
        "scripts.cli.tool_manager.ToolManager._find_binary", lambda *a, **k: None
    )
    monkeypatch.setenv("CI", "true")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(
        "scripts.cli.scan_jobs.tool_loop.find_tool", lambda name, *a, **k: name
    )
    results = tmp_path / "results"

    def run(*argv: str) -> int:
        full = [
            "jmo",
            "scan",
            "--repo",
            "proj",
            *argv,
            "--results-dir",
            str(results),
            "--config",
            str(cfg),
            "--history-db",
            str(tmp_path / "history.db"),
        ]
        with patch.object(sys, "argv", full):
            args = jmo.parse_args()
        return jmo.cmd_scan(args)

    def row(tool: str) -> dict:
        meta = json.loads((results / ".scan_metadata.json").read_bytes())
        (found,) = [r for r in meta["tool_runs"] if r["tool"] == tool]
        return found

    return types.SimpleNamespace(
        run=run,
        row=row,
        configure=configure,
        project=project,
        results=results,
        out=results / "individual-repos" / "proj",
    )


def _raising_run_tool(monkeypatch, error: Exception) -> None:
    """`run_tool` itself raises for the history run: the two paths
    `run_all_parallel` turns into a result of its own."""
    real = ToolRunner.run_tool

    def run_tool(self, tool):
        if tool.command[1] == "git":
            raise error
        return real(self, tool)

    monkeypatch.setattr(ToolRunner, "run_tool", run_tool)


# What `_run_bounded` does on the history run: each reaches a different
# return in `run_tool`.
FAILURES = {
    "exit code": 2,
    "timeout": subprocess.TimeoutExpired(["x"], 1),
    "os error": OSError("permission denied"),
    "not found": FileNotFoundError("gone"),
}
# What `run_tool` raises instead: `run_all_parallel`'s two handlers.
RAISED = {
    "raised": ToolExecutionException("t", ["t", "git"], 3, "raised"),
    "runner crashed": RuntimeError("runner crashed"),
}


class TestAFailedRunIsNamed:
    @pytest.mark.parametrize("tool", sorted(TREE))
    @pytest.mark.parametrize("failure", [*FAILURES, *RAISED])
    def test_a_failed_history_run_is_named_on_the_row(
        self, scan, monkeypatch, tool, failure
    ):
        if failure in RAISED:
            _raising_run_tool(monkeypatch, RAISED[failure])
            outcomes = {TREE[tool]: 0, "git": 0}
        else:
            outcomes = {TREE[tool]: 0, "git": FAILURES[failure]}
        monkeypatch.setattr("scripts.core.tool_runner._run_bounded", _process(outcomes))

        scan.run("--tools", tool)

        row = scan.row(tool)
        assert (row["state"], row["invocations"]) == ("failed", 2), row
        assert row["detail"].startswith("git: "), row["detail"]
        # The run that worked still wrote its output.
        assert (scan.out / f"{tool}.json").is_file()

    def test_when_both_fail_both_are_named(self, scan, monkeypatch):
        """In the order the builder made them, not the order they finished:
        the runner here returns history's first."""
        monkeypatch.setattr(
            "scripts.core.tool_runner._run_bounded",
            _process({"filesystem": 2, "git": OSError("permission denied")}),
        )
        monkeypatch.setattr(
            "scripts.cli.scan_jobs.repository_scanner.ToolRunner", _in_order(True)
        )

        scan.run("--tools", "trufflehog")

        detail = scan.row("trufflehog")["detail"]
        assert detail.startswith("filesystem: "), detail
        assert "; git: " in detail, detail


def _in_order(git_first: bool):
    """A real runner that returns its results in the order given, since the
    one it would return depends on which run finishes first."""

    class Ordered(ToolRunner):
        def run_all_parallel(self):
            results = [self.run_tool(t) for t in self.tools]
            return sorted(
                results,
                key=lambda r: (r.output_file.name.endswith(".git.json")) != git_first,
            )

    return Ordered


class TestTheTreeRunSpeaksForTheRow:
    @pytest.mark.parametrize(
        "git_first", [True, False], ids=["git-first", "tree-first"]
    )
    def test_the_exit_code_is_the_tree_runs(self, scan, monkeypatch, git_first):
        """Findings in the tree (trufflehog's 1), none in history (0)."""
        monkeypatch.setattr(
            "scripts.core.tool_runner._run_bounded",
            _process({"filesystem": 1, "git": 0}),
        )
        monkeypatch.setattr(
            "scripts.cli.scan_jobs.repository_scanner.ToolRunner", _in_order(git_first)
        )

        scan.run("--tools", "trufflehog")

        row = scan.row("trufflehog")
        assert (row["state"], row["exit_code"]) == ("ran", 1), row

    @pytest.mark.parametrize(
        "git_first", [True, False], ids=["git-first", "tree-first"]
    )
    def test_the_files_examined_are_the_tree_runs(self, scan, monkeypatch, git_first):
        """No two-invocation tool counts the files it examined today; one that
        did would have read history's output half the time."""
        counted: list[str] = []

        def examined(path: Path) -> int:
            counted.append(path.name)
            return 0 if path.name.endswith(".git.json") else 3

        monkeypatch.setitem(
            DESCRIPTORS,
            "trufflehog",
            replace(DESCRIPTORS["trufflehog"], scanned_count=examined),
        )
        monkeypatch.setattr(
            "scripts.core.tool_runner._run_bounded",
            _process({"filesystem": 0, "git": 0}),
        )
        monkeypatch.setattr(
            "scripts.cli.scan_jobs.repository_scanner.ToolRunner", _in_order(git_first)
        )

        scan.run("--tools", "trufflehog")

        assert counted == ["trufflehog.json"]
        assert scan.row("trufflehog")["state"] == "ran"


class TestTheReconcilerReadsEveryOutput:
    @pytest.mark.parametrize("damage", ["deleted", "unparseable"])
    def test_a_ran_row_needs_its_history_output_too(self, scan, monkeypatch, damage):
        monkeypatch.setattr(
            "scripts.core.tool_runner._run_bounded",
            _process({"filesystem": 0, "git": 0}),
        )
        assert scan.run("--tools", "trufflehog") == 0
        assert scan.row("trufflehog")["invocations"] == 2
        assert reconcile(scan.results).ok  # the control: both outputs intact

        history = scan.out / "trufflehog.git.json"
        if damage == "deleted":
            history.unlink()
        else:
            history.write_bytes(b"{not json")

        result = reconcile(scan.results)
        assert not result.ok
        assert result.no_output == [
            "individual-repos/proj: trufflehog (trufflehog.git.json)"
        ]


def _by_mode(seen: list[list[str]]) -> dict[str, list[str]]:
    by_mode = {command[1]: command for command in seen}
    assert len(by_mode) == len(seen), "a mode ran twice"
    return by_mode


class TestGitleaksOutputFlagsAreJmos:
    """#1325: a tool's reserved flags keep a user's flags from choosing where
    it writes and in what format (#822), and gitleaks spells those flags its
    own way. Measured through `jmo scan`: `--report-format json` gave 0
    findings with the row `ran`, `--report-path` and `-r` left both runs
    writing one stray file, and `--exit-code 1` failed the row while its
    findings still reached the report. `--redact` makes every secret's
    snippet `REDACTED`, which the pairing digests (#1323); `--config` would
    replace the config that carries JMo's exclusions. #1335: its parser
    chains short flags, so `-vfjson` is `-v -f json` and `-vrREPORT.sarif`
    wrote the unredacted report into the scanned repository (measured)."""

    # How many times JMo passes each itself; the rest it never passes.
    OWN = {"--report-format": 1, "--report-path": 1, "--exit-code": 1, "--config": 1}

    @pytest.mark.parametrize("key", ["flags", "history_flags"])
    @pytest.mark.parametrize(
        "flags",
        [
            ["--report-format", "json"],
            ["--report-path", "elsewhere.json"],
            ["-r", "elsewhere.json"],
            ["--report-template", "mine.tmpl"],
            ["--exit-code", "1"],
            ["--config", "mine.toml"],
            ["-c", "mine.toml"],
            ["--redact"],
            ["--redact=50"],
            # gitleaks' flag parser reads a short flag's value attached.
            ["-cmine.toml"],
            ["-relsewhere.json"],
            ["-fjson"],
            # ...and after its no-value `-v` (#1335).
            ["-vfjson"],
            ["-vf", "json"],
            ["-vrREPORT.sarif"],
            ["-vcmine.toml"],
        ],
        ids=lambda flags: flags[0],
    )
    def test_a_flag_that_decides_the_output_is_dropped(
        self, scan, monkeypatch, flags, key
    ):
        seen: list[list[str]] = []
        monkeypatch.setattr(
            "scripts.core.tool_runner._run_bounded",
            _process({"dir": 0, "git": 0}, seen),
        )
        scan.configure({"gitleaks": {key: [*flags, "--max-target-megabytes", "5"]}})

        assert scan.run("--tools", "gitleaks") == 0

        command = _by_mode(seen)["dir" if key == "flags" else "git"]
        name = flags[0].split("=", 1)[0]
        assert sum(t.split("=", 1)[0] == name for t in command) == self.OWN.get(
            name, 0
        ), command
        if len(flags) == 2:
            assert flags[1] not in command, command
        # A flag JMo does not own still reaches the run it was given for.
        assert "--max-target-megabytes" in command, command
        assert scan.row("gitleaks")["state"] == "ran"


class TestTrufflehogFlagsJmoPassesAreJmos:
    """#1335: trufflehog's parser (kingpin) refuses any flag given twice, and
    JMo passes `--json`, `--no-update` and `--no-verification` to both runs.
    Measured through `jmo scan` on a fixture: `--no-verification` in its
    flags made it exit 1 with "flag 'no-verification' cannot be repeated"
    and no output. `--no-json` is `--json` given again."""

    # How many times JMo passes each itself, in each run.
    OWN = {"--json": 1, "--no-update": 1, "--no-verification": 1}

    @pytest.mark.parametrize("key", ["flags", "history_flags"])
    @pytest.mark.parametrize(
        "flag", ["--no-verification", "--no-update", "--json", "-j", "--no-json"]
    )
    def test_a_flag_it_would_refuse_twice_is_dropped(
        self, scan, monkeypatch, flag, key
    ):
        seen: list[list[str]] = []
        monkeypatch.setattr(
            "scripts.core.tool_runner._run_bounded",
            _process({"filesystem": 0, "git": 0}, seen),
        )
        scan.configure({"trufflehog": {key: [flag, "--concurrency=2"]}})

        assert scan.run("--tools", "trufflehog") == 0

        command = _by_mode(seen)["filesystem" if key == "flags" else "git"]
        assert command.count(flag) == self.OWN.get(flag, 0), command
        for own, times in self.OWN.items():
            assert command.count(own) == times, command
        # A flag JMo does not own still reaches the run it was given for.
        assert "--concurrency=2" in command, command
        assert scan.row("trufflehog")["state"] == "ran"


class TestEachModeHasItsOwnFlags:
    """#1327 item 1: `per_tool.<tool>.flags` reached both runs, and each mode
    rejects flags the other needs (measured: trufflehog filesystem exits 1 on
    `--since-commit`, gitleaks git exits 126 on `--follow-symlinks`). `flags`
    now reach the tree's run and `history_flags` history's."""

    @pytest.mark.parametrize("tool", sorted(TREE))
    def test_flags_reach_the_tree_and_history_flags_history(
        self, scan, monkeypatch, tool
    ):
        seen: list[list[str]] = []
        monkeypatch.setattr(
            "scripts.core.tool_runner._run_bounded",
            _process({TREE[tool]: 0, "git": 0}, seen),
        )
        scan.configure(
            {tool: {"flags": ["--tree-flag"], "history_flags": ["--history-flag"]}}
        )

        assert scan.run("--tools", tool) == 0

        by_mode = _by_mode(seen)
        assert "--tree-flag" in by_mode[TREE[tool]]
        assert "--history-flag" not in by_mode[TREE[tool]]
        assert "--history-flag" in by_mode["git"]
        assert "--tree-flag" not in by_mode["git"]

    def test_each_trufflehog_run_verifies_as_its_own_flags_ask(self, scan, monkeypatch):
        """Verification follows each run's flags: asking for verified results
        in history's flags verifies history, and not the tree."""
        seen: list[list[str]] = []
        monkeypatch.setattr(
            "scripts.core.tool_runner._run_bounded",
            _process({"filesystem": 0, "git": 0}, seen),
        )
        scan.configure({"trufflehog": {"history_flags": ["--only-verified"]}})

        assert scan.run("--tools", "trufflehog") == 0

        by_mode = _by_mode(seen)
        assert "--no-verification" in by_mode["filesystem"]
        assert "--no-verification" not in by_mode["git"]


class TestHistoryCanBeTurnedOff:
    """#1327 item 2: a repository whose history is too large or too noisy had
    no setting that kept the tree's scan and skipped history."""

    @pytest.mark.parametrize("tool", sorted(TREE))
    def test_history_false_runs_the_tree_only_and_says_so(
        self, scan, monkeypatch, tool
    ):
        seen: list[list[str]] = []
        monkeypatch.setattr(
            "scripts.core.tool_runner._run_bounded",
            _process({TREE[tool]: 0, "git": 0}, seen),
        )
        scan.configure({tool: {"history": False}})

        assert scan.run("--tools", tool) == 0

        assert [command[1] for command in seen] == [TREE[tool]]
        row = scan.row(tool)
        assert (row["state"], row["invocations"]) == ("ran", 1), row
        assert row["detail"] == f"history not read: per_tool.{tool}.history is false"
        assert not (scan.out / f"{tool}.git.json").exists()

    def test_history_off_for_one_tool_leaves_the_other_reading_it(
        self, scan, monkeypatch
    ):
        """The switch is per tool: git is asked for the tool that still reads
        history, and the one turned off runs its tree alone."""
        seen: list[list[str]] = []
        monkeypatch.setattr(
            "scripts.core.tool_runner._run_bounded",
            _process({"filesystem": 0, "dir": 0, "git": 0}, seen),
        )
        scan.configure({"gitleaks": {"history": False}})

        assert scan.run("--tools", "trufflehog,gitleaks") == 0

        runs = sorted((Path(command[0]).name, command[1]) for command in seen)
        assert runs == [
            ("gitleaks", "dir"),
            ("trufflehog", "filesystem"),
            ("trufflehog", "git"),
        ]
        assert scan.row("gitleaks")["invocations"] == 1
        assert scan.row("trufflehog")["invocations"] == 2

    def test_git_is_not_asked_when_no_tool_will_read_history(self, scan, monkeypatch):
        """The probe exists for the tools that read history; with history off
        for each, a shallow clone's WARNING would be about nothing."""
        probed: list[Path] = []

        def probe(root: Path) -> tuple[bool, str]:
            probed.append(root)
            return True, ""

        monkeypatch.setattr("scripts.cli.scan_jobs.tool_loop.read_history", probe)
        monkeypatch.setattr(
            "scripts.core.tool_runner._run_bounded",
            _process({"filesystem": 0, "dir": 0, "git": 0}),
        )
        scan.configure(
            {"trufflehog": {"history": False}, "gitleaks": {"history": False}}
        )

        assert scan.run("--tools", "trufflehog,gitleaks") == 0

        assert probed == []


class TestTheRepositorysGitleaksConfig:
    """#1327 item 3: JMo passes `--config <its own>` to carry its exclusions,
    and gitleaks then never read the repository's `.gitleaks.toml` (measured:
    a repository-allowlisted key 0 alone and 1 under JMo; a custom rule 1 and
    0). gitleaks refuses a config that sets both `useDefault` and `path`
    (measured, rc 1), so JMo's extends the repository's instead of the
    defaults when there is one."""

    @staticmethod
    def _generated(scan) -> dict:
        return tomllib.loads((scan.out / ".gitleaks.toml").read_text("utf-8"))

    @pytest.fixture(autouse=True)
    def _scanners_run(self, monkeypatch):
        monkeypatch.setattr(
            "scripts.core.tool_runner._run_bounded",
            _process({"filesystem": 0, "dir": 0, "git": 0}),
        )

    def test_without_one_the_defaults_are_extended(self, scan):
        assert scan.run("--tools", "gitleaks") == 0

        config = self._generated(scan)
        assert config["extend"] == {"useDefault": True}
        assert config["allowlists"][0]["paths"], config

    def test_with_one_it_is_extended_instead(self, scan, caplog):
        own = scan.project / ".gitleaks.toml"
        own.write_bytes(b"[extend]\nuseDefault = true\n")
        caplog.set_level(logging.INFO)

        assert scan.run("--tools", "gitleaks") == 0

        config = self._generated(scan)
        assert config["extend"] == {"path": str(own.resolve())}
        # JMo's exclusions still ride along.
        assert config["allowlists"][0]["paths"], config
        # The scanned repository shapes its own audit, so the run says so.
        said = [r.getMessage() for r in caplog.records if r.levelname == "INFO"]
        assert any("extends its .gitleaks.toml" in m for m in said), said

    def test_one_that_extends_a_further_config_is_warned_about(self, scan, caplog):
        """gitleaks follows extensions only so deep, and JMo's config adds a
        level: the defaults a repository config's own base asks for were
        dropped silently, rc 0 (measured, 8.30.1)."""
        (scan.project / ".gitleaks.toml").write_bytes(b'[extend]\npath = "base.toml"\n')
        (scan.project / "base.toml").write_bytes(b"[extend]\nuseDefault = true\n")

        assert scan.run("--tools", "gitleaks") == 0

        warnings = [
            r.getMessage()
            for r in caplog.records
            if r.levelname == "WARNING" and "base.toml" in r.getMessage()
        ]
        assert len(warnings) == 1, [r.getMessage() for r in caplog.records]
        # Lost to the depth limit, which gitleaks alone does not hit: not the
        # "never asked for" warning a base without `useDefault` gets.
        assert "its default rules are NOT loaded" in warnings[0], warnings[0]
        assert "past the depth" in warnings[0], warnings[0]

    @pytest.mark.parametrize(
        ("own", "base"),
        [
            pytest.param(b'extend = "base.toml"\n', None, id="extend-not-a-table"),
            pytest.param(
                b'[extend]\npath = "base.toml"\n',
                b"extend = [1]\n",
                id="base-not-a-table",
            ),
            pytest.param(b'[extend]\npath = "a\\u0000b"\n', None, id="nul-in-path"),
            pytest.param(b"[extend\n", None, id="not-toml"),
        ],
    )
    def test_a_config_it_cannot_walk_does_not_stop_the_scan(self, scan, own, base):
        """The scanned repository's config is untrusted input, read before
        any tool runs. One the warning's probe could not walk raised there,
        and every tool on the target failed (review of #1327). gitleaks says
        itself what it cannot load."""
        (scan.project / ".gitleaks.toml").write_bytes(own)
        if base is not None:
            (scan.project / "base.toml").write_bytes(base)

        assert scan.run("--tools", "trufflehog,gitleaks") == 0

        assert scan.row("trufflehog")["state"] == "ran"
        assert scan.row("gitleaks")["state"] == "ran"

    @pytest.mark.parametrize(
        ("own", "base"),
        [
            pytest.param(b'title = "mine"\n', None, id="no-extend"),
            pytest.param(
                b'[extend]\npath = "base.toml"\n',
                b'title = "base"\n',
                id="base-no-extend",
            ),
        ],
    )
    def test_one_that_does_not_ask_for_the_defaults_is_warned_about(
        self, scan, caplog, own, base
    ):
        """Such a config runs only its own rules, under JMo as alone: the
        scanned repository decides that gitleaks' defaults do not run, and
        nothing said so (review of #1327)."""
        (scan.project / ".gitleaks.toml").write_bytes(own)
        if base is not None:
            (scan.project / "base.toml").write_bytes(base)

        assert scan.run("--tools", "gitleaks") == 0

        warnings = [
            r.getMessage()
            for r in caplog.records
            if r.levelname == "WARNING" and ".gitleaks.toml" in r.getMessage()
        ]
        assert len(warnings) == 1, [r.getMessage() for r in caplog.records]
        assert "default rules" in warnings[0]
        assert "only the rules" in warnings[0]

    def test_one_that_extends_only_the_defaults_is_not_warned_about(self, scan, caplog):
        (scan.project / ".gitleaks.toml").write_bytes(b"[extend]\nuseDefault = true\n")

        assert scan.run("--tools", "gitleaks") == 0

        assert not [
            r
            for r in caplog.records
            if ".gitleaks.toml" in r.getMessage() and r.levelname == "WARNING"
        ]
