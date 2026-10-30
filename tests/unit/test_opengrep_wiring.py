"""opengrep installs as a static binary (v2.0.0 Phase 5, PR B, task B1).

Measured before any of this was written:

- The release names its assets `opengrep_<flavour>_<arch>` with no version in
  the name and no archive around them, and spells the architecture three ways:
  `x86` for Intel, `aarch64` on Linux, `arm64` on macOS. The installer's
  `{arch}` is `arm64` for both ARM spellings, so the URL takes its own
  placeholder, `{arch_x86}`, read from the platform's own machine name.
- It ships no Windows arm64 build: the x86 `.exe` is fetched there, as it is
  for hadolint, shellcheck and zizmor.
- Its checksum is a cosign `.sig` and `.cert` beside each asset, not a file of
  sums; the download is made without one, as zizmor's is.
- The first run unpacks 255,465,660 bytes (104 files) into
  `$XDG_CACHE_HOME/opengrep/v1.32.0/` and takes 1.1 s, the same as the second
  (v1.32.0, x86_64, fresh `HOME`, 2026-10-29), so the Dockerfile has no
  warm-up step.

The descriptor row (task B3), measured on v1.32.0 the same day:

- A run whose files carry errors exits 0 with every other file's results in
  the output: a syntax error, a `Timeout` and a `Stack overflow` each gave rc 0
  and an entry in `errors`. An invalid `--config` exits 7 and still writes the
  output, with no results and the cause in `errors`. A usage error (`-j` given
  twice) exits 2 and writes nothing. rc 1 comes only from `--error` and rc 3
  only from `--strict`, which a user may not set.
- It has no `--metrics` flag, so nothing in the command turns telemetry off.

Its debug log (task B5), measured on v1.32.0 the same day under a scratch
`HOME`:

- Every run truncates and rewrites `$HOME/.opengrep/semgrep.log`, and the log
  holds each match's source text: a line `KEY = "<a PEM header and its body>"`
  matched by a rule appears whole, in a `semgrep.rule_match` line.
- `SEMGREP_LOG_FILE` moves it. It names the file itself, opengrep creates the
  missing parent directories, and with it set nothing at all is written under
  `HOME`. `OPENGREP_LOG_FILE`, `SEMGREP_USER_DATA_FOLDER` and
  `OPENGREP_USER_DATA_FOLDER` change nothing: the log stayed in `~/.opengrep`.
- A relative value is opened from the working directory, which is the target
  (R35): `SEMGREP_LOG_FILE=rel.log` left `rel.log` in the scanned repository.
  An empty value is rc 1 and no output.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from scripts.cli.scan_jobs import tool_loop
from scripts.cli.tool_installer import ToolInstaller
from scripts.cli.tool_manager import ToolManager
from scripts.core.rule_bundle import BUNDLE_DIR
from scripts.core.scan_timings import SKIP_REASONS, Reason, State
from scripts.core.tool_descriptors import (
    DESCRIPTORS,
    VENDORED_DIRS,
    ExclusionStyle,
    FlagGrammar,
    Reserved,
)
from scripts.core.tool_diagnostics import extract_tool_diagnostics
from scripts.core.tool_registry import ToolInfo

# opengrep v1.32.0's release assets, listed with `gh release view v1.32.0 -R
# opengrep/opengrep --json assets --jq '.assets[].name'` on 2026-10-29. A URL
# the installer builds must be one of these, or it downloads a 404 page.
RELEASE_ASSETS_1_32_0 = frozenset(
    {
        "opengrep-core_linux_aarch64.tar.gz",
        "opengrep-core_linux_x86.tar.gz",
        "opengrep-core_osx_aarch64.tar.gz",
        "opengrep-core_osx_x86.tar.gz",
        "opengrep-core_windows_x86.zip",
        "opengrep_manylinux_aarch64",
        "opengrep_manylinux_aarch64.cert",
        "opengrep_manylinux_aarch64.sig",
        "opengrep_manylinux_x86",
        "opengrep_manylinux_x86.cert",
        "opengrep_manylinux_x86.sig",
        "opengrep_musllinux_aarch64",
        "opengrep_musllinux_aarch64.cert",
        "opengrep_musllinux_aarch64.sig",
        "opengrep_musllinux_x86",
        "opengrep_musllinux_x86.cert",
        "opengrep_musllinux_x86.sig",
        "opengrep_osx_arm64",
        "opengrep_osx_arm64.cert",
        "opengrep_osx_arm64.sig",
        "opengrep_osx_x86",
        "opengrep_osx_x86.cert",
        "opengrep_osx_x86.sig",
        "opengrep_windows_x86.exe",
        "opengrep_windows_x86.exe.cert",
        "opengrep_windows_x86.exe.sig",
    }
)


class TestInstallUrl:
    """Through `ToolInstaller._install_binary`, the path `jmo tools install`
    takes, stopped at the download so nothing is fetched."""

    @pytest.mark.parametrize(
        ("platform_key", "machine", "asset"),
        [
            ("linux", "x86_64", "opengrep_manylinux_x86"),
            ("linux", "aarch64", "opengrep_manylinux_aarch64"),
            ("macos", "x86_64", "opengrep_osx_x86"),
            ("macos", "arm64", "opengrep_osx_arm64"),
            ("windows", "AMD64", "opengrep_windows_x86.exe"),
            # No Windows arm64 build exists: the x86 one is fetched there.
            ("windows", "ARM64", "opengrep_windows_x86.exe"),
        ],
    )
    def test_the_url_names_a_real_asset(
        self, tmp_path, platform_key, machine, asset
    ) -> None:
        installer = ToolInstaller(install_dir=tmp_path)
        installer.platform = platform_key
        urls: list[str] = []

        def capture(url: str, dest: Path) -> None:
            urls.append(url)
            return None  # "no download tool": _install_binary stops here

        info = ToolInfo(
            name="opengrep", version="1.32.0", description="", category="binary_tools"
        )
        with (
            patch("platform.machine", return_value=machine),
            patch.object(installer, "_get_download_command", side_effect=capture),
        ):
            installer._install_binary("opengrep", info, time.time())

        assert urls == [
            "https://github.com/opengrep/opengrep/releases/download/v1.32.0/" + asset
        ]
        assert asset in RELEASE_ASSETS_1_32_0


def test_jmo_tools_check_says_there_is_no_windows_arm64_build() -> None:
    """The hint `jmo tools check` prints for a missing opengrep."""
    manager = ToolManager()
    with patch.object(manager, "_find_binary", return_value=None):
        status = manager.check_tool("opengrep")

    assert status.installed is False
    # versions.yaml's pin, read rather than restated: the weekly update moves it.
    pin = yaml.safe_load(Path("versions.yaml").read_text(encoding="utf-8"))
    assert status.expected_version == pin["binary_tools"]["opengrep"]["version"]
    assert status.install_hint.startswith("jmo tools install opengrep")
    assert "no Windows arm64 build" in status.install_hint


# --- the descriptor row (task B3) ------------------------------------------------


class TestDescriptor:
    def test_it_sits_in_the_slot_semgrep_had(self) -> None:
        names = list(DESCRIPTORS)
        assert "semgrep" not in names
        assert names[names.index("gitleaks") + 1] == "opengrep"

    def test_it_takes_the_exclusion_flag_it_always_had(self) -> None:
        d = DESCRIPTORS["opengrep"]
        assert d.exclusion_style is ExclusionStyle.INLINE
        assert d.exclusion_flag == "--exclude"
        assert d.excluded_vendored == VENDORED_DIRS
        assert d.target_types == frozenset({"repo", "gitlab"})
        assert d.flag_grammar is FlagGrammar.CMDLINER

    def test_the_probe_reads_what_opengrep_version_prints(self) -> None:
        """`opengrep --version` prints the bare version (measured, 1.32.0)."""
        probe = DESCRIPTORS["opengrep"].version_probe
        assert probe.pattern.search("1.32.0\n").group(1) == "1.32.0"
        assert probe.command is None

    def test_no_rule_languages_is_a_skip_reason(self) -> None:
        d = DESCRIPTORS["opengrep"]
        assert d.trigger is not None
        assert d.file_patterns == ()
        assert Reason.NO_RULE_LANGUAGES in SKIP_REASONS
        assert (
            Reason.NO_RULE_LANGUAGES.value
            == "no files in a language the rule bundle reads"
        )

    def test_its_empty_result_has_no_results(self) -> None:
        assert DESCRIPTORS["opengrep"].stub == {"results": []}

    def test_examined_files_are_read_from_paths_scanned(self, tmp_path) -> None:
        reader = DESCRIPTORS["opengrep"].scanned_count
        assert reader is not None
        out = tmp_path / "opengrep.json"
        out.write_text(json.dumps({"paths": {"scanned": ["a.py", "b.py"]}}))
        assert reader(out) == 2
        out.write_text(json.dumps({"paths": {"scanned": []}}))
        assert reader(out) == 0
        out.write_text(json.dumps({"results": []}))
        assert reader(out) is None
        assert reader(tmp_path / "missing.json") is None

    def test_it_reserves_what_it_owns(self) -> None:
        reserved = DESCRIPTORS["opengrep"].reserved_flags
        for flag in ("-o", "--output", "--json", "--sarif", "--text"):
            assert reserved[flag] is Reserved.OUTPUT
        for flag in ("--error", "--strict"):
            assert reserved[flag] is Reserved.EXIT_CODE
        for flag in (
            *("-j", "--jobs", "--rewrite-rule-ids", "--no-rewrite-rule-ids"),
            *("--enable-version-check", "--disable-version-check"),
        ):
            assert reserved[flag] is Reserved.PASSED
        # A rule file is a list option: a user's own pack adds to JMo's.
        assert "--config" not in reserved
        assert "-c" not in reserved


# --- the command line, through the scan loop -------------------------------------

PYTHON = b"import os\nos.system(input())\n"


def _plant(repo: Path, paths) -> None:
    for rel in paths:
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(PYTHON)


def _recorded(repo: Path, out: Path, per_tool_config=None, results_tree=None):
    captured: list = []

    class Recorder:
        def __init__(self, tools, progress_callback=None):
            captured.extend(tools)

        def run_all_parallel(self):
            return []

    rows = tool_loop.run_tools(
        tools=["opengrep"],
        target_type="repo",
        target=repo,
        target_label="t",
        out_dir=out,
        timeout=60,
        retries=0,
        per_tool_config=per_tool_config or {},
        allow_missing_tools=False,
        runner_cls=Recorder,
        find_tool_func=lambda name: "/bin/opengrep" if name == "opengrep" else None,
        repo_root=repo,
        results_name="results" if results_tree else None,
        results_tree=results_tree,
    )
    return rows, captured


def _bundle(*stems: str) -> list[str]:
    return [arg for s in stems for arg in ("--config", str(BUNDLE_DIR / f"{s}.yaml"))]


def test_the_command_line(tmp_path) -> None:
    """A TypeScript repository: opengrep runs JavaScript rules on `.ts`, so
    both files and `generic.yaml` (every scan gets it) are named."""
    repo = tmp_path / "repo"
    _plant(repo, ["src/app.ts", "README.md"])
    out = repo / "results" / "individual-repos" / "repo"
    out.mkdir(parents=True)

    _, (definition,) = _recorded(repo, out, results_tree=(repo / "results").resolve())

    assert definition.command == [
        "/bin/opengrep",
        "scan",
        *_bundle("generic", "javascript", "typescript"),
        # The id is the YAML's, whatever the working directory (B7): without
        # this opengrep prefixes it with the path it was run from.
        "--no-rewrite-rule-ids",
        "--json",
        "--output",
        str((out / "opengrep.json").resolve()),
        "--disable-version-check",
        "-j",
        "4",
        *(f"--exclude={d}" for d in (*VENDORED_DIRS, "results")),
        # Run from inside the target, which is named `.`: see
        # `test_a_target_under_a_directory_the_default_ignore_list_names_is_scanned`.
        ".",
    ]
    assert definition.cwd == repo.resolve()
    assert definition.output_file == out / "opengrep.json"
    assert definition.capture_stdout is False
    assert definition.ok_return_codes == (0,)
    assert definition.timeout == 900


def test_user_configs_replace_the_bundle(tmp_path) -> None:
    """`per_tool.opengrep.configs` is the user's own packs, offline: it takes
    the bundle's place, and the languages present no longer pick the files."""
    repo = tmp_path / "repo"
    _plant(repo, ["app.py"])
    out = tmp_path / "out"
    out.mkdir()
    mine = ["/rules/mine.yaml", "/rules/more.yaml"]

    _, (definition,) = _recorded(repo, out, {"opengrep": {"configs": mine}})

    command = definition.command
    assert command[:6] == [
        "/bin/opengrep",
        "scan",
        *("--config", "/rules/mine.yaml"),
        *("--config", "/rules/more.yaml"),
    ]
    assert command[6] == "--no-rewrite-rule-ids"
    assert str(BUNDLE_DIR) not in " ".join(command)


def test_a_bare_string_or_a_tuple_of_configs_is_accepted(tmp_path) -> None:
    repo = tmp_path / "repo"
    _plant(repo, ["app.py"])
    out = tmp_path / "out"
    out.mkdir()

    for own in ("/rules/mine.yaml", ("/rules/mine.yaml",), ["/rules/mine.yaml"]):
        _, (definition,) = _recorded(repo, out, {"opengrep": {"configs": own}})
        assert definition.command[2:4] == ["--config", "/rules/mine.yaml"], own


@pytest.mark.parametrize(
    ("configs", "said"),
    [
        (5, "int"),
        (0, "int"),
        (True, "bool"),
        (False, "bool"),
        ({"a": 1}, "dict"),
        ({}, "dict"),
        (1.5, "float"),
        ([5], "int"),
        (["ok.yaml", None], "NoneType"),
        ([["nested.yaml"]], "list"),
    ],
)
def test_a_malformed_configs_fails_only_the_opengrep_row_and_names_its_key(
    tmp_path, caplog, configs, said
) -> None:
    """`configs: 5` raised "'int' object is not iterable" out of the command
    builder, which failed the whole target: every tool on it, with a message
    that names no key (measured: "Scan failed for repo t7"). The row alone
    fails, `could not be run`, naming `per_tool.opengrep.configs` and the type
    it got; the tool beside it still runs."""
    repo = tmp_path / "repo"
    _plant(repo, ["app.py"])
    out = tmp_path / "out"
    out.mkdir()
    captured: list = []
    scanner = _scanning(["app.py"])

    class Recorder(scanner):
        def __init__(self, tools, progress_callback=None):
            super().__init__(tools, progress_callback)
            captured.extend(tools)

    caplog.set_level(logging.ERROR)
    rows = tool_loop.run_tools(
        tools=["opengrep", "syft"],
        target_type="repo",
        target=repo,
        target_label="t",
        out_dir=out,
        timeout=60,
        retries=0,
        per_tool_config={"opengrep": {"configs": configs}},
        allow_missing_tools=False,
        runner_cls=Recorder,
        find_tool_func=lambda name: f"/bin/{name}",
        repo_root=repo,
    )

    row = rows["opengrep"]
    assert row.state is State.FAILED
    assert row.reason is Reason.COULD_NOT_RUN
    assert "per_tool.opengrep.configs" in (row.detail or "")
    assert said in (row.detail or "")
    assert "per_tool.opengrep.configs" in caplog.text
    # The other tool on the same target was planned and ran.
    assert [d.name for d in captured] == ["syft"]
    assert rows["syft"].state is State.RAN


def test_a_malformed_configs_is_reported_even_where_the_trigger_would_skip(
    tmp_path,
) -> None:
    """`configs: 0` is falsy, and a repository with no bundle language is
    skipped before the command is built: the user's mistake must still be
    named, not read as `no files in a language the rule bundle reads`."""
    repo = tmp_path / "repo"
    _plant(repo, ["README.md"])
    out = tmp_path / "out"
    out.mkdir()

    rows, definitions = _recorded(repo, out, {"opengrep": {"configs": 0}})

    assert definitions == []
    assert rows["opengrep"].reason is Reason.COULD_NOT_RUN
    assert "per_tool.opengrep.configs" in (rows["opengrep"].detail or "")


def test_it_runs_from_inside_the_target_with_every_other_path_absolute(
    tmp_path, monkeypatch
) -> None:
    """The target is `.` and the working directory is the target (R35), so the
    command must not hold a path that means something only from where JMo is
    run: a relative repository and a relative results directory, as `jmo scan
    --repo app --results-dir out` gives, are made absolute before the
    directory changes."""
    monkeypatch.chdir(tmp_path)
    _plant(Path("repo"), ["app.py"])
    Path("out").mkdir()

    _, (definition,) = _recorded(Path("repo"), Path("out"))

    command = definition.command
    assert definition.cwd == (tmp_path / "repo").resolve()
    assert command[-1] == "."
    assert command[command.index("--output") + 1] == str(
        (tmp_path / "out" / "opengrep.json").resolve()
    )
    configs = [command[i + 1] for i, tok in enumerate(command) if tok == "--config"]
    assert configs and all(Path(c).is_absolute() for c in configs), configs
    # Nothing else names where the scan was started.
    assert str(Path("repo")) not in command


LOG = ".opengrep/semgrep.log"


def test_its_debug_log_is_written_into_the_scans_scratch(tmp_path) -> None:
    """opengrep logs each match's source text to `$HOME/.opengrep/semgrep.log`
    (measured), so a scan of code that holds a key left the key in the user's
    home. `SEMGREP_LOG_FILE` is the one variable that moves it, and the log goes
    where the scan keeps its other scratch: a dot-prefixed name beside the
    outputs, which the report does not read as a tool's."""
    repo = tmp_path / "repo"
    _plant(repo, ["app.py"])
    out = tmp_path / "out"
    out.mkdir()

    _, (definition,) = _recorded(repo, out)

    assert definition.env == {"SEMGREP_LOG_FILE": str((out / LOG).resolve())}
    # The scratch directory is dot-prefixed, as every tool's is.
    assert Path(definition.env["SEMGREP_LOG_FILE"]).parent.name == ".opengrep"


def test_the_log_path_is_absolute_because_the_scan_runs_in_the_target(
    tmp_path, monkeypatch
) -> None:
    """opengrep starts in the target, and opens a relative `SEMGREP_LOG_FILE`
    from there: the log, with its matched code, would be written into the
    repository being scanned (measured). A relative results directory, as
    `jmo scan --results-dir out` gives, must be made absolute first."""
    monkeypatch.chdir(tmp_path)
    _plant(Path("repo"), ["app.py"])
    Path("out").mkdir()

    _, (definition,) = _recorded(Path("repo"), Path("out"))

    log = Path(definition.env["SEMGREP_LOG_FILE"])
    assert log == (tmp_path / "out" / LOG).resolve()
    assert log.is_absolute()
    assert (tmp_path / "repo").resolve() not in log.parents


def test_a_relative_user_config_is_made_absolute_before_the_directory_changes(
    tmp_path, monkeypatch
) -> None:
    """A user's `configs: [rules.yaml]` is relative to where JMo runs, and
    opengrep now starts in the target. A file that exists is made absolute; a
    name that is no file here (a registry pack, a URL) is the user's to
    spell."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "rules.yaml").write_text("rules: []\n", encoding="utf-8")
    _plant(Path("repo"), ["app.py"])
    Path("out").mkdir()
    mine = ["rules.yaml", "p/python", "https://example.invalid/r.yaml"]

    _, (definition,) = _recorded(
        Path("repo"), Path("out"), {"opengrep": {"configs": mine}}
    )

    assert definition.command[2:8] == [
        *("--config", str((tmp_path / "rules.yaml").resolve())),
        *("--config", "p/python"),
        *("--config", "https://example.invalid/r.yaml"),
    ]


def test_a_single_user_config_is_one_config_not_its_characters(tmp_path) -> None:
    """`configs: rules.yaml` in YAML is a string, which iterated as a list is
    one `--config` per letter."""
    repo = tmp_path / "repo"
    _plant(repo, ["app.py"])
    out = tmp_path / "out"
    out.mkdir()

    _, (definition,) = _recorded(repo, out, {"opengrep": {"configs": "rules.yaml"}})

    assert definition.command[2:4] == ["--config", "rules.yaml"]
    assert definition.command[4] == "--no-rewrite-rule-ids"


def test_user_configs_run_on_a_tree_with_no_bundle_language(tmp_path) -> None:
    """The skip is the bundle's: a user's pack may read what the bundle does
    not (Lua, say), so it decides for itself."""
    repo = tmp_path / "repo"
    (repo / "lib").mkdir(parents=True)
    (repo / "lib" / "init.lua").write_bytes(b"print(1)\n")
    out = tmp_path / "out"
    out.mkdir()

    _, definitions = _recorded(repo, out, {"opengrep": {"configs": ["m.yaml"]}})

    assert len(definitions) == 1


@pytest.mark.parametrize(
    "files",
    [
        {"README.md": b"# t\n", "LICENSE": b"MIT\n"},
        # Vendored trees are not the repository's: pruned by the walk.
        {"README.md": b"# t\n", "node_modules/x/index.js": b"x\n"},
        {"README.md": b"# t\n", "vendor/lib.go": b"package x\n"},
        {"README.md": b"# t\n", "a/venv/m.py": b"x = 1\n"},
    ],
)
def test_a_repo_with_no_bundle_language_is_skipped_and_says_why(
    tmp_path, files
) -> None:
    """Review Focus 2: with no file in a language the rule bundle reads,
    opengrep would load `generic.yaml`, scan nothing, and the row would read
    `ran` with 0 findings."""
    repo = tmp_path / "repo"
    for rel, data in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_bytes(data)
    out = tmp_path / "out"
    out.mkdir()

    rows, definitions = _recorded(repo, out)

    assert definitions == []
    assert rows["opengrep"].state is State.SKIPPED
    assert rows["opengrep"].reason is Reason.NO_RULE_LANGUAGES
    assert rows["opengrep"].label == (
        "skipped:no files in a language the rule bundle reads"
    )
    # The row's output is the empty result, so the report reads it.
    assert json.loads((out / "opengrep.json").read_bytes()) == {"results": []}


def test_the_results_directory_is_not_a_language_file(tmp_path) -> None:
    """JMo's own earlier output, inside the tree, is not the repository's."""
    repo = tmp_path / "repo"
    (repo / "README.md").parent.mkdir(parents=True)
    (repo / "README.md").write_bytes(b"# t\n")
    _plant(repo, ["results/individual-repos/old/x.py"])
    out = repo / "results" / "individual-repos" / "repo"
    out.mkdir(parents=True)

    rows, definitions = _recorded(repo, out, results_tree=(repo / "results").resolve())

    assert definitions == []
    assert rows["opengrep"].reason is Reason.NO_RULE_LANGUAGES


def test_the_languages_are_chosen_from_the_whole_walk(tmp_path, caplog) -> None:
    """`ctx.files` is a tuple capped at 300 sorted paths (a command-line
    length limit, true of the file-fed tools), so a language whose only file
    sorts after 300 of another would lose its rules without a word. The
    languages are read from the pruned walk, which is not capped, and the cap's
    "NOT scanned" warning, false here since opengrep is handed the directory,
    is never logged."""
    repo = tmp_path / "repo"
    _plant(repo, [f"a/f{i:03d}.py" for i in range(tool_loop.MAX_FILE_ARGS + 1)])
    (repo / "z").mkdir()
    (repo / "z" / "main.go").write_bytes(b"package main\n")
    out = tmp_path / "out"
    out.mkdir()

    with caplog.at_level(logging.WARNING, logger=tool_loop.logger.name):
        _, (definition,) = _recorded(repo, out)

    assert definition.command[2:8] == _bundle("generic", "go", "python")
    assert "NOT scanned" not in caplog.text


def test_a_user_jobs_flag_is_refused_with_its_reason(tmp_path, caplog) -> None:
    """opengrep refuses a second `-j` (rc 2, "option '-j' cannot be repeated",
    no output: measured) and JMo sets it to 4 (the program plan's decision:
    only `-j 1` fits 800 MB, and Phase 7 owns tuning it)."""
    repo = tmp_path / "repo"
    _plant(repo, ["app.py"])
    out = tmp_path / "out"
    out.mkdir()
    flags = ["-j", "2", "--jobs=3", "-j8", "--timeout", "9"]

    with caplog.at_level(logging.WARNING):
        _, (definition,) = _recorded(repo, out, {"opengrep": {"flags": flags}})

    command = definition.command
    assert command.count("-j") == 1 and command[command.index("-j") + 1] == "4"
    assert not any(tok.startswith(("--jobs", "-j8")) for tok in command)
    # What is not JMo's is the user's, spliced in before the target.
    assert command[-3:-1] == ["--timeout", "9"]
    assert command[-1] == "."  # the target, from inside it
    for refused in ("-j 2", "--jobs=3", "-j8"):
        assert f"Ignoring `{refused}` in per_tool.opengrep.flags" in caplog.text
    assert Reserved.PASSED.value in caplog.text


@pytest.mark.parametrize(
    "flag", ["--rewrite-rule-ids", "--no-rewrite-rule-ids", "--enable-version-check"]
)
def test_the_other_flags_jmo_passes_are_refused(tmp_path, flag) -> None:
    repo = tmp_path / "repo"
    _plant(repo, ["app.py"])
    out = tmp_path / "out"
    out.mkdir()

    _, (definition,) = _recorded(repo, out, {"opengrep": {"flags": [flag]}})

    assert definition.command.count(flag) == (
        1 if flag == "--no-rewrite-rule-ids" else 0
    )


# --- what a run with errors still gives ------------------------------------------

# Copied from runs of 1.32.0 (2026-10-29): a `Timeout` names the rule and the
# file, a `Syntax error` the file, and both are `"level": "warn"`.
TIMEOUT = {
    "code": 2,
    "level": "warn",
    "type": "Timeout",
    "rule_id": "raptor-use-after-free",
    "message": "Timeout when running raptor-use-after-free on src/big.c:\n ",
    "path": "src/big.c",
}


def _result(path: str, line: int) -> dict:
    return {
        "check_id": "python.lang.security.audit.dangerous-system-call.dangerous-system-call",
        "path": path,
        "start": {"line": line, "col": 1, "offset": 0},
        "end": {"line": line, "col": 20, "offset": 19},
        "extra": {
            "message": "Detected a system call.",
            "metadata": {
                "cwe": ["CWE-78: OS Command Injection"],
                "owasp": ["A03:2021 - Injection"],
                "confidence": "HIGH",
                "category": "security",
            },
            "severity": "ERROR",
            "lines": "os.system(input())",
        },
    }


def test_errors_keep_the_other_files_findings(tmp_path) -> None:
    """Review Focus 3: a file opengrep times out on leaves the others' findings
    in the report, and is named. Both come from the one output file."""
    from scripts.core.adapters.opengrep_adapter import OpengrepAdapter

    out = tmp_path / "opengrep.json"
    out.write_text(
        json.dumps(
            {
                "version": "1.32.0",
                "results": [_result("src/a.py", 2), _result("src/b.py", 7)],
                "errors": [TIMEOUT],
                "paths": {"scanned": ["src/a.py", "src/b.py", "src/big.c"]},
            }
        ),
        encoding="utf-8",
    )

    findings = OpengrepAdapter().parse(out)
    diagnostics = extract_tool_diagnostics("opengrep", out)

    assert [(f.location["path"], f.location["startLine"]) for f in findings] == [
        ("src/a.py", 2),
        ("src/b.py", 7),
    ]
    assert [f.severity for f in findings] == ["HIGH", "HIGH"]
    assert [(d.tool, d.path) for d in diagnostics] == [("opengrep", "src/big.c")]
    assert "Timeout" in diagnostics[0].reason


# --- the real binary --------------------------------------------------------------


def _opengrep() -> str:
    found = shutil.which("opengrep")
    if found is None:
        pytest.skip("opengrep is not on PATH")
    return found


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [_opengrep(), "scan", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )


@pytest.mark.requires_tools
def test_a_run_with_errors_is_rc_0_and_keeps_the_other_files(tmp_path) -> None:
    """Why `ok_return_codes` is `(0,)` and a file that does not parse costs
    only itself: a syntax error is rc 0 with the error in the output."""
    (tmp_path / "good.py").write_bytes(PYTHON)
    (tmp_path / "bad.py").write_bytes(b"def broken(:\n  x = (\n")

    done = _run(
        [
            *("--config", str(BUNDLE_DIR / "python.yaml")),
            *("--no-rewrite-rule-ids", "--json", "--output", "o.json"),
            *("--disable-version-check", "-j", "4", "."),
        ],
        tmp_path,
    )

    data = json.loads((tmp_path / "o.json").read_bytes())
    assert done.returncode == 0, done.stderr
    assert [r["path"] for r in data["results"]] == ["good.py"]
    assert [e["path"] for e in data["errors"]] == ["bad.py"]
    assert "bad.py" in data["paths"]["scanned"]


@pytest.mark.requires_tools
def test_an_invalid_config_is_rc_7_with_no_results(tmp_path) -> None:
    """Rc 7, not 0, and the output is written with the cause in `errors`: the
    row fails as `unaccepted exit code` instead of reading `examined 0 files`."""
    (tmp_path / "good.py").write_bytes(PYTHON)

    done = _run(
        [
            *("--config", str(BUNDLE_DIR / "python.yaml")),
            *("--config", str(tmp_path / "no-such-rules.yaml")),
            *("--no-rewrite-rule-ids", "--json", "--output", "o.json"),
            *("--disable-version-check", "-j", "4", "."),
        ],
        tmp_path,
    )

    data = json.loads((tmp_path / "o.json").read_bytes())
    assert done.returncode == 7
    assert data["results"] == []
    assert any("invalid configuration" in e["message"] for e in data["errors"])


@pytest.mark.requires_tools
def test_a_second_jobs_flag_is_rc_2_and_writes_nothing(tmp_path) -> None:
    """Why `-j` is JMo's (measured: "option '-j' cannot be repeated")."""
    (tmp_path / "good.py").write_bytes(PYTHON)

    done = _run(
        [
            *("--config", str(BUNDLE_DIR / "python.yaml")),
            *("--json", "--output", "o.json", "-j", "4", "-j", "2", "."),
        ],
        tmp_path,
    )

    assert done.returncode == 2
    assert "cannot be repeated" in done.stderr
    assert not (tmp_path / "o.json").exists()


# --- the real binary, through the scan loop (R35) --------------------------------

# opengrep matches its default ignore list against the path it is given, so a
# target with an ancestor so named scanned 0 files (rc 0, measured on 1.32.0):
# the row read `failed:examined 0 files`, for a repository merely cloned under
# `~/build/` or `~/work/tests/`. JMo's own `--exclude=vendor` and the like hid
# an ancestor of that name the same way. Measured at the commit before R35,
# through this row: each of these hid its target, and `work`, `results` and
# `target` did not.
HIDING_ANCESTORS = [
    "tests",
    "test",
    "build",
    "dist",
    "vendor",
    "node_modules",
    "venv",
    ".venv",
]

TWO_FINDINGS = b"import os\nos.system(input())\neval(input())\n"


def _real_scan(repo: Path, out: Path):
    """The row, run for real through `run_tools`, as `jmo scan` runs it."""
    from scripts.core.tool_runner import ToolRunner

    if shutil.which("opengrep") is None:
        pytest.skip("opengrep is not on PATH")
    out.mkdir(parents=True, exist_ok=True)
    return tool_loop.run_tools(
        tools=["opengrep"],
        target_type="repo",
        target=repo,
        target_label="app",
        out_dir=out,
        timeout=300,
        retries=0,
        per_tool_config={},
        allow_missing_tools=False,
        runner_cls=ToolRunner,
        repo_root=repo,
    )["opengrep"]


def _hits(out: Path) -> list[tuple[str, str, int]]:
    document = json.loads((out / "opengrep.json").read_bytes())
    return sorted(
        (r["check_id"].rsplit(".", 1)[-1], r["path"], r["start"]["line"])
        for r in document["results"]
    )


@pytest.mark.requires_tools
@pytest.mark.parametrize("ancestor", HIDING_ANCESTORS)
def test_a_target_under_a_directory_the_default_ignore_list_names_is_scanned(
    tmp_path, ancestor
) -> None:
    """The row runs from inside the target, so what lies above it is not matched
    against anything. The files are named relative to the target."""
    repo = tmp_path / ancestor / "app"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "a.py").write_bytes(TWO_FINDINGS)
    out = tmp_path / "out"

    row = _real_scan(repo, out)

    assert row.state is State.RAN, row
    document = json.loads((out / "opengrep.json").read_bytes())
    assert document["paths"]["scanned"] == ["src/a.py"]
    assert {path for _, path, _ in _hits(out)} == {"src/a.py"}
    assert len(_hits(out)) >= 2


@pytest.mark.requires_tools
def test_the_same_scan_from_another_working_directory_gives_the_same_ids(
    tmp_path, monkeypatch
) -> None:
    """A relative target used to be named in every path (`app/src/a.py`,
    `../../app/src/a.py`), and the path is hashed into the finding's id, so one
    repository had an id for each directory it was scanned from. Run from
    inside the target, the paths are the target's own."""
    from scripts.core.adapters.opengrep_adapter import OpengrepAdapter

    work = tmp_path / "work"
    (work / "app" / "src").mkdir(parents=True)
    (work / "app" / "src" / "a.py").write_bytes(TWO_FINDINGS)

    def ids_from(cwd: Path, repo: Path, out: Path) -> tuple[list, list[str]]:
        monkeypatch.chdir(cwd)
        assert _real_scan(repo, out).state is State.RAN
        found = OpengrepAdapter().parse(out / "opengrep.json")
        return _hits(out), sorted(f.id for f in found)

    absolute = ids_from(Path("/"), work / "app", tmp_path / "out-a")
    relative = ids_from(work, Path("app"), Path("out-b"))
    nested = ids_from(work / "app" / "src", Path("../../app"), tmp_path / "out-c")

    assert absolute[0], "no findings to compare"
    assert absolute == relative == nested


@pytest.mark.requires_tools
def test_the_report_keeps_repo_relative_paths_and_the_code_context(
    tmp_path, monkeypatch
) -> None:
    """Through the report phase, as `jmo scan` runs it. Before R35 the raw path
    was absolute (an absolute target) and the report stripped the scan root; now
    the raw path is relative and there is nothing to strip, and the finding must
    still read as `src/a.py`, id and all, and still carry its code context:
    the adapter finds the file under the root the scan recorded."""
    from scripts.core.normalize_and_report import gather_results

    repo = tmp_path / "tests" / "app"  # hidden before R35
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "a.py").write_bytes(TWO_FINDINGS)
    results = tmp_path / "results"
    out = results / "individual-repos" / "app"
    (results / ".scan_metadata.json").parent.mkdir(parents=True)
    (results / ".scan_metadata.json").write_text(
        json.dumps({"repo_paths": [str(repo.resolve())]}), encoding="utf-8"
    )
    # Not the target's own directory, so reading the file by its relative path
    # from here would find nothing.
    monkeypatch.chdir(tmp_path)

    assert _real_scan(repo, out).state is State.RAN
    findings = gather_results(results)

    assert findings
    assert {f["location"]["path"] for f in findings} == {"src/a.py"}
    assert all(f["context"] for f in findings), "the code context was lost"
    assert "os.system" in findings[0]["context"]["snippet"]


@pytest.mark.requires_tools
def test_the_exclusions_and_the_examined_count_hold_from_inside_the_target(
    tmp_path,
) -> None:
    """`--exclude=NAME` is a name, so it needs no path to be right: vendored
    trees and JMo's own in-tree results directory are still left out, and
    `paths.scanned` (what the examined-files reader counts) lists only what was
    read, relative to the target."""
    from scripts.core.tool_runner import ToolRunner

    repo = tmp_path / "build" / "app"  # an ancestor the default list would hide
    for rel in (
        "src/a.py",
        "node_modules/dep/n.py",
        "vendor/v.py",
        ".venv/lib/v.py",
        "results/individual-repos/old/r.py",
    ):
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_bytes(TWO_FINDINGS)
    out = repo / "results" / "individual-repos" / "app"
    out.mkdir(parents=True, exist_ok=True)
    if shutil.which("opengrep") is None:
        pytest.skip("opengrep is not on PATH")

    row = tool_loop.run_tools(
        tools=["opengrep"],
        target_type="repo",
        target=repo,
        target_label="app",
        out_dir=out,
        timeout=300,
        retries=0,
        per_tool_config={},
        allow_missing_tools=False,
        runner_cls=ToolRunner,
        repo_root=repo,
        results_name="results",
        results_tree=(repo / "results").resolve(),
    )["opengrep"]

    assert row.state is State.RAN, row
    document = json.loads((out / "opengrep.json").read_bytes())
    assert document["paths"]["scanned"] == ["src/a.py"]
    assert DESCRIPTORS["opengrep"].scanned_count(out / "opengrep.json") == 1


# --- a baseline scan that has nothing to read (F1) ---------------------------------

BASELINE_FLAGS = [
    ["--baseline-commit", "HEAD~1"],
    ["--baseline-commit=HEAD~1"],
]


def _scanning(scanned: list[str]):
    """A runner whose opengrep exits 0 and writes `paths.scanned`, as measured on
    1.32.0 for every scan, `scanned` being what the run read."""
    from scripts.core.tool_runner import ToolResult

    class Scanner:
        def __init__(self, tools, progress_callback=None):
            self.tools = tools

        def run_all_parallel(self):
            results = []
            for definition in self.tools:
                definition.output_file.write_text(
                    json.dumps({"results": [], "paths": {"scanned": scanned}}),
                    encoding="utf-8",
                )
                results.append(
                    ToolResult(
                        tool=definition.name,
                        status="success",
                        returncode=0,
                        duration=1.0,
                        output_file=definition.output_file,
                    )
                )
            return results

    return Scanner


def _row_of(repo: Path, out: Path, scanned: list[str], flags: list[str]):
    out.mkdir(exist_ok=True)
    return tool_loop.run_tools(
        tools=["opengrep"],
        target_type="repo",
        target=repo,
        target_label="t",
        out_dir=out,
        timeout=60,
        retries=0,
        per_tool_config={"opengrep": {"flags": flags}} if flags else {},
        allow_missing_tools=False,
        runner_cls=_scanning(scanned),
        find_tool_func=lambda name: "/bin/opengrep",
        repo_root=repo,
    )["opengrep"]


@pytest.mark.parametrize("flags", BASELINE_FLAGS)
def test_a_baseline_scan_that_examined_nothing_is_a_skip(tmp_path, flags) -> None:
    """`--baseline-commit HEAD~1` scans only the files that changed since the
    commit. A commit that deletes files, or touches only paths opengrep's default
    ignore list skips (`tests/`, `*_test.go`, `*.min.js`, `build/`), leaves it
    nothing to read, and `paths.scanned` is `[]` (measured, 1.32.0): the ordinary
    outcome of a test-only commit, and not a scan that did not work. The docs'
    incremental recipe would otherwise exit 1 on it."""
    repo = tmp_path / "repo"
    _plant(repo, ["src/app.py"])

    row = _row_of(repo, tmp_path / "out", [], flags)

    assert row.state is State.SKIPPED
    assert row.reason is Reason.NO_CHANGED_FILES
    # The label names baseline mode; the commit is in the detail.
    assert row.label == (
        "skipped:no changed file opengrep reads since the baseline commit"
    )
    assert "HEAD~1" in (row.detail or "")
    assert row.exit_code == 0
    # The run's own output stays: the report reads it as an empty result.
    assert (
        json.loads((tmp_path / "out" / "opengrep.json").read_bytes())["results"] == []
    )


@pytest.mark.parametrize("flags", BASELINE_FLAGS)
def test_a_baseline_scan_that_read_a_file_is_ran(tmp_path, flags) -> None:
    repo = tmp_path / "repo"
    _plant(repo, ["src/app.py"])

    row = _row_of(repo, tmp_path / "out", ["src/app.py"], flags)

    assert row.state is State.RAN
    assert row.reason is None


def test_zero_files_without_a_baseline_flag_is_still_a_failure(tmp_path) -> None:
    """The skip is for baseline mode only: a target whose walk found nothing
    (a gitignored tree, an ancestor the ignore list names) is the bug the row
    exists to report, and reads `failed:examined 0 files` as before."""
    repo = tmp_path / "repo"
    _plant(repo, ["src/app.py"])

    row = _row_of(repo, tmp_path / "out", [], [])

    assert row.state is State.FAILED
    assert row.reason is Reason.EXAMINED_ZERO


def test_other_flags_do_not_make_zero_files_a_skip(tmp_path) -> None:
    repo = tmp_path / "repo"
    _plant(repo, ["src/app.py"])

    row = _row_of(repo, tmp_path / "out", [], ["--verbose", "--max-memory", "4000"])

    assert row.state is State.FAILED
    assert row.reason is Reason.EXAMINED_ZERO


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=repo,
        check=True,
        capture_output=True,
    )


def _commit(repo: Path, files: dict[str, bytes | None], message: str) -> None:
    """Write (or, for None, delete) `files` and commit them."""
    for rel, data in files.items():
        path = repo / rel
        if data is None:
            path.unlink()
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)


def _history(tmp_path: Path) -> Path:
    if shutil.which("git") is None:
        pytest.skip("git is not on PATH")
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _commit(
        repo,
        {
            "src/a.py": b"x = 1\n",
            "tests/test_a.py": b"x = 1\n",
            "gone.py": b"y = 1\n",
            "README.md": b"# t\n",
        },
        "base",
    )
    return repo


@pytest.mark.requires_tools
@pytest.mark.parametrize(
    ("commit", "scanned"),
    [
        # Each is the last commit of a repository scanned with
        # `--baseline-commit HEAD~1`, as docs/SCAN_OPTIMIZATION.md runs it.
        pytest.param({"tests/test_a.py": TWO_FINDINGS}, None, id="test-only"),
        pytest.param({"gone.py": None}, None, id="deletion-only"),
        pytest.param({"app.min.js": b"var a=1;\n"}, None, id="min-js-only"),
        pytest.param({"src/a.py": TWO_FINDINGS}, ["src/a.py"], id="source"),
        # `generic.yaml` is loaded for every scan, and one of its rules reads any
        # file, so a changed README is read.
        pytest.param({"README.md": b"# changed\n"}, ["README.md"], id="readme-only"),
    ],
)
def test_the_incremental_recipe_through_the_real_binary(
    tmp_path, commit, scanned
) -> None:
    """The recipe in docs/SCAN_OPTIMIZATION.md, run for real on a repository
    whose last commit is each kind. Measured before the skip: a test-only
    commit read `failed:examined 0 files` and a deletion-only one the same, so
    a CI job that scanned every push exited 1 on them; a commit with source
    still reads `ran`, having read only what the commit changed."""
    repo = _history(tmp_path)
    _commit(repo, commit, "last")
    out = tmp_path / "out"
    out.mkdir()
    from scripts.core.tool_runner import ToolRunner

    row = tool_loop.run_tools(
        tools=["opengrep"],
        target_type="repo",
        target=repo,
        target_label="app",
        out_dir=out,
        timeout=300,
        retries=0,
        per_tool_config={"opengrep": {"flags": ["--baseline-commit", "HEAD~1"]}},
        allow_missing_tools=False,
        runner_cls=ToolRunner,
        repo_root=repo,
    )["opengrep"]

    if scanned is None:
        assert row.state is State.SKIPPED, row
        assert row.reason is Reason.NO_CHANGED_FILES
    else:
        assert row.state is State.RAN, row
        document = json.loads((out / "opengrep.json").read_bytes())
        assert document["paths"]["scanned"] == scanned


def _stat_of(path: Path) -> tuple[int, int] | None:
    """(mtime in ns, size) of a file, or None when it is not there."""
    try:
        stat = path.stat()
    except FileNotFoundError:
        return None
    return stat.st_mtime_ns, stat.st_size


@pytest.mark.requires_tools
def test_a_scan_leaves_no_log_in_the_home_directory(tmp_path) -> None:
    """opengrep's debug log holds the source text of every match, and its
    default home is the user's `~/.opengrep` (measured, v1.32.0): the log of a
    scan of a repository holding a key sat there after the scan, outside the
    scan, outliving it. It is the scan's scratch now, under the results
    directory. The cache that holds its 255 MB extraction stays in the home."""
    repo = tmp_path / "app"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "a.py").write_bytes(TWO_FINDINGS)
    out = tmp_path / "out"
    home_log = Path.home() / ".opengrep" / "semgrep.log"
    before = _stat_of(home_log)

    row = _real_scan(repo, out)

    assert row.state is State.RAN, row
    assert _hits(out), "the scan found nothing, so there was nothing to log"
    assert _stat_of(home_log) == before, f"{home_log} was written by the scan"
    log = out / ".opengrep" / "semgrep.log"
    assert log.is_file(), sorted(p.name for p in out.rglob("*"))
    # The log of THIS scan: its debug lines name the file it matched.
    assert "src/a.py" in log.read_text(encoding="utf-8", errors="replace")
    # Nothing was left in the repository either.
    assert sorted(p.name for p in repo.iterdir()) == ["src"]
