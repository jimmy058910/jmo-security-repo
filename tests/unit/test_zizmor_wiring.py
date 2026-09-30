"""zizmor wired as a descriptor row (v2.0.0 Phase 4, PR Z, task Z1).

Measured before any of this was written (the Phase 4 plan, "Measured: zizmor"):

- Given a directory, zizmor collects vendored trees as well: a planted
  `node_modules/evil/.github/workflows/ci.yml` and `vendor/act/action.yml` gave
  7 of 10 findings, and zizmor has no exclude flag. So JMo walks the tree,
  pruning what it prunes for every walk-fed tool, and hands zizmor the files.
- Given absolute paths, every URI in its SARIF is absolute, so a finding's id
  would depend on where the checkout lives. Repository-relative paths, run
  from the root, give the golden's URIs.
- `.github/dependabot.yml` has audits of its own: a walk that did not name it
  lost the 6 `dependabot-cooldown` findings at 3098c766.
- `--offline`, not `--no-online-audits`: zizmor reads `GH_TOKEN`, and with a
  token set `--no-online-audits` still looked up commits on GitHub (measured
  2026-09-27, 1.30.1: "failed to look up commit for actions/checkout@v4").
- The release names its assets by target triple, with no version in the name,
  and ships no Windows arm64 build and no checksum file.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.cli.scan_jobs import tool_loop
from scripts.cli.tool_installer import ToolInstaller
from scripts.cli.tool_manager import ToolManager
from scripts.core.scan_timings import SKIP_REASONS, Reason, State
from scripts.core.tool_descriptors import DESCRIPTORS, VENDORED_DIRS, ExclusionStyle
from scripts.core.tool_registry import ToolInfo
from scripts.core.tool_runner import ToolResult

# zizmor v1.30.1's release assets, listed with `gh api
# repos/zizmorcore/zizmor/releases/tags/v1.30.1 --jq '.assets[].name'` on
# 2026-09-27. A URL the installer builds must be one of these, or it downloads
# a 404 page.
RELEASE_ASSETS_1_30_1 = frozenset(
    {
        "zizmor-aarch64-apple-darwin.tar.gz",
        "zizmor-aarch64-unknown-linux-gnu.tar.gz",
        "zizmor-x86_64-apple-darwin.tar.gz",
        "zizmor-x86_64-pc-windows-msvc.zip",
        "zizmor-x86_64-unknown-linux-gnu.tar.gz",
    }
)

PATTERNS = (
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    "**/action.yml",
    "**/action.yaml",
    ".github/dependabot.yml",
    ".github/dependabot.yaml",
)

WORKFLOW = (
    b"name: ci\n"
    b"on: push\n"
    b"jobs:\n"
    b"  build:\n"
    b"    runs-on: ubuntu-latest\n"
    b"    steps:\n"
    b"      - uses: actions/checkout@v4\n"
)
ACTION = (
    b"name: act\n"
    b"description: x\n"
    b"runs:\n"
    b"  using: composite\n"
    b"  steps:\n"
    b"    - uses: actions/checkout@v4\n"
)
DEPENDABOT = (
    b"version: 2\n"
    b"updates:\n"
    b"  - package-ecosystem: pip\n"
    b"    directory: /\n"
    b"    schedule:\n"
    b"      interval: weekly\n"
)


def _content(name: str) -> bytes:
    if name.startswith("action."):
        return ACTION
    if name.startswith("dependabot."):
        return DEPENDABOT
    return WORKFLOW


class TestInstallUrl:
    """Through `ToolInstaller._install_binary`, the path `jmo tools install`
    takes, stopped at the download so nothing is fetched."""

    @pytest.mark.parametrize(
        ("platform_key", "machine", "asset"),
        [
            ("linux", "x86_64", "zizmor-x86_64-unknown-linux-gnu.tar.gz"),
            ("linux", "aarch64", "zizmor-aarch64-unknown-linux-gnu.tar.gz"),
            ("macos", "x86_64", "zizmor-x86_64-apple-darwin.tar.gz"),
            ("macos", "arm64", "zizmor-aarch64-apple-darwin.tar.gz"),
            ("windows", "AMD64", "zizmor-x86_64-pc-windows-msvc.zip"),
            # No Windows arm64 build exists: the x86_64 one is fetched there,
            # as it is for hadolint and shellcheck.
            ("windows", "ARM64", "zizmor-x86_64-pc-windows-msvc.zip"),
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
            name="zizmor", version="1.30.1", description="", category="binary_tools"
        )
        with (
            patch("platform.machine", return_value=machine),
            patch.object(installer, "_get_download_command", side_effect=capture),
        ):
            installer._install_binary("zizmor", info, time.time())

        assert urls == [
            "https://github.com/zizmorcore/zizmor/releases/download/v1.30.1/" + asset
        ]
        assert asset in RELEASE_ASSETS_1_30_1


def test_jmo_tools_check_says_there_is_no_windows_arm64_build() -> None:
    """The hint `jmo tools check` prints for a missing zizmor."""
    manager = ToolManager()
    with patch.object(manager, "_find_binary", return_value=None):
        status = manager.check_tool("zizmor")

    assert status.installed is False
    assert status.expected_version == "1.30.1"
    assert status.install_hint.startswith("jmo tools install zizmor")
    assert "no Windows arm64 build" in status.install_hint


class TestDescriptor:
    def test_it_is_walk_fed_with_the_six_patterns(self) -> None:
        d = DESCRIPTORS["zizmor"]
        assert d.exclusion_style is ExclusionStyle.WALK
        assert d.exclusion_flag is None
        assert d.file_patterns == PATTERNS
        assert d.excluded_vendored == VENDORED_DIRS
        assert d.target_types == frozenset({"repo", "gitlab"})

    def test_no_workflows_is_a_skip_reason(self) -> None:
        assert DESCRIPTORS["zizmor"].no_files_reason is Reason.NO_WORKFLOWS
        assert Reason.NO_WORKFLOWS.value == "no GitHub Actions workflows"
        assert Reason.NO_WORKFLOWS in SKIP_REASONS

    def test_its_empty_result_is_an_empty_sarif_document(self) -> None:
        assert DESCRIPTORS["zizmor"].stub == {"version": "2.1.0", "runs": []}

    def test_the_probe_reads_what_zizmor_version_prints(self) -> None:
        """`zizmor --version` prints `zizmor 1.30.1` (measured)."""
        pattern = DESCRIPTORS["zizmor"].version_probe.pattern
        assert pattern.search("zizmor 1.30.1\n").group(1) == "1.30.1"
        assert DESCRIPTORS["zizmor"].version_probe.command is None

    def test_it_sits_with_the_other_walk_fed_linters(self) -> None:
        names = list(DESCRIPTORS)
        assert names[names.index("shellcheck") + 1] == "zizmor"


# --- the command line, through the scan loop ----------------------------------

# Relative path -> whether zizmor must be handed it.
PLANTED = {
    ".github/workflows/ci.yml": True,
    ".github/workflows/release.yaml": True,
    ".github/dependabot.yml": True,
    "action.yml": True,  # a repository that is itself an action
    "actions/setup/action.yaml": True,
    # Vendored trees: pruned by the walk, as for hadolint and shellcheck.
    "node_modules/evil/.github/workflows/ci.yml": False,
    "vendor/act/action.yml": False,
    ".venv/lib/action.yml": False,
    "a/b/venv/action.yml": False,
    # JMo's own results directory inside the tree (#1156, Review Focus 2).
    "results/individual-repos/old/action.yml": False,
    # Not workflows GitHub runs: only the root's `.github/workflows`, flat.
    "sub/.github/workflows/ci.yml": False,
    ".github/workflows/nested/ci.yml": False,
    "workflows/ci.yml": False,
    ".github/workflows/ci.json": False,
}


def _plant(repo: Path, paths) -> None:
    for rel in paths:
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_content(path.name))


def _recorded(repo: Path, out: Path, results_tree: Path | None = None):
    captured: list = []

    class Recorder:
        def __init__(self, tools, progress_callback=None):
            captured.extend(tools)

        def run_all_parallel(self):
            return []

    rows = tool_loop.run_tools(
        tools=["zizmor"],
        target_type="repo",
        target=repo,
        target_label="t",
        out_dir=out,
        timeout=60,
        retries=0,
        per_tool_config={},
        allow_missing_tools=False,
        runner_cls=Recorder,
        find_tool_func=lambda name: "/bin/zizmor" if name == "zizmor" else None,
        repo_root=repo,
        results_name="results" if results_tree else None,
        results_tree=results_tree,
    )
    return rows, captured


def test_it_hands_zizmor_the_repositorys_own_files_relative_to_its_root(
    tmp_path, monkeypatch
) -> None:
    """A relative repository and out_dir, so every path the command carries
    must survive zizmor running from the repository."""
    monkeypatch.chdir(tmp_path)
    repo = Path("repo")
    _plant(repo, PLANTED)
    out = Path("repo") / "results" / "individual-repos" / "repo"
    out.mkdir(parents=True)

    _, (definition,) = _recorded(
        repo, out, results_tree=(tmp_path / "repo" / "results").resolve()
    )

    fixed, inputs = definition.command[:5], definition.command[5:]
    # At 1.30.1 `--format sarif` exits 0 with findings anyway, so
    # `--no-exit-codes` guards a future release; pinned here so it stays.
    assert fixed == ["/bin/zizmor", "--format", "sarif", "--offline", "--no-exit-codes"]
    assert sorted(inputs) == sorted(rel for rel, kept in PLANTED.items() if kept)
    # Repository-relative and `/`-separated: the URIs zizmor writes are these
    # strings, and an absolute one puts the checkout's location in every id.
    assert all(not Path(i).is_absolute() and "\\" not in i for i in inputs)
    assert definition.cwd == (tmp_path / "repo").resolve()
    assert definition.output_file == out / "zizmor.json"
    assert definition.capture_stdout is True
    # A run with findings is rc 0, so anything else is a run that failed.
    # `--format sarif` already exits 0 with findings (measured, 1.30.1: the
    # plain and json formats exit 14); `--no-exit-codes` keeps it so if a
    # release changes that.
    assert definition.ok_return_codes == (0,)


def _link_directory(link: Path, target: Path) -> None:
    """A directory link made without privilege: a junction on Windows, where
    `os.symlink` needs admin or developer mode (WinError 1314, measured)."""
    if sys.platform == "win32":
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    else:
        os.symlink(target, link, target_is_directory=True)


def test_a_link_out_of_the_repository_is_handed_over_by_its_own_path(
    tmp_path,
) -> None:
    """A workflow reached through a link that leaves the repository, as a
    monorepo package's `.github` linked to a shared one. Resolved before it
    was made relative, its path left the root: ValueError, and the scan loop
    failed every tool on the target (measured on a junction, `jmo scan --tools
    zizmor semgrep`: rc 1, "every tool failed (semgrep, zizmor)"). The path as
    the walk found it is repository-relative and reaches the file from the
    root."""
    shared = tmp_path / "shared" / ".github"
    (shared / "workflows").mkdir(parents=True)
    (shared / "workflows" / "ci.yml").write_bytes(WORKFLOW)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "lib.py").write_bytes(b"x = 1\n")
    _link_directory(repo / ".github", shared)
    out = tmp_path / "out"
    out.mkdir()

    _, (definition,) = _recorded(repo, out)

    assert definition.command[5:] == [".github/workflows/ci.yml"]
    assert definition.cwd == repo.resolve()
    assert (definition.cwd / definition.command[5]).is_file()


def test_the_results_directory_is_not_read_even_when_it_is_all_there_is(
    tmp_path,
) -> None:
    """Review Focus 2: a repository cloned without `node_modules` but holding
    an earlier scan's `results/`, scanned with `--results-dir <repo>/results`.
    Its workflow-shaped file is JMo's own output, not the repository's."""
    repo = tmp_path / "repo"
    _plant(repo, ["results/individual-repos/old/action.yml"])
    (repo / "lib.py").write_bytes(b"x = 1\n")
    out = repo / "results" / "individual-repos" / "repo"
    out.mkdir(parents=True)

    rows, definitions = _recorded(repo, out, results_tree=(repo / "results").resolve())

    assert definitions == []
    assert rows["zizmor"].label == "skipped:no GitHub Actions workflows"


@pytest.mark.parametrize(
    "files",
    [
        {"lib.py": b"x = 1\n"},
        # Workflows that are not the repository's own are not content.
        {"lib.py": b"x = 1\n", "node_modules/x/action.yml": ACTION},
        {"lib.py": b"x = 1\n", "vendor/x/.github/workflows/ci.yml": WORKFLOW},
    ],
)
def test_a_repository_without_workflows_is_skipped_and_says_why(
    tmp_path, files
) -> None:
    repo = tmp_path / "repo"
    for rel, data in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_bytes(data)
    out = tmp_path / "out"
    out.mkdir()

    rows, definitions = _recorded(repo, out)

    assert definitions == []
    assert rows["zizmor"].state is State.SKIPPED
    assert rows["zizmor"].label == "skipped:no GitHub Actions workflows"
    # The row's output is the empty SARIF document, so the report reads it.
    assert json.loads((out / "zizmor.json").read_bytes()) == {
        "version": "2.1.0",
        "runs": [],
    }


# --- the real binary ------------------------------------------------------------


def _sarif_uris(path: Path) -> list[str]:
    results = json.loads(path.read_bytes())["runs"][0]["results"]
    return sorted(
        {
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in results
        }
    )


@pytest.mark.requires_tools
def test_real_zizmor_audits_only_the_repositorys_own_workflows(
    tmp_path, monkeypatch
) -> None:
    """Against the binary, not the command text: a vendored workflow handed
    over by mistake reads exactly like one that is not, until its findings
    are in the report. The repository sits under a `vendor` directory of its
    own, the root-anchoring trap trufflehog fell into (B5). A bogus token is
    set: without `--offline` zizmor's online audits fail on it (rc 1, measured),
    and with `--no-online-audits` it still calls GitHub."""
    from scripts.core.tool_runner import ToolRunner

    if shutil.which("zizmor") is None:
        pytest.skip("zizmor is not on PATH")
    monkeypatch.setenv("GH_TOKEN", "bogus-token-for-a-test")
    repo = tmp_path / "vendor" / "app"
    _plant(repo, PLANTED)
    out = repo / "results" / "individual-repos" / "app"
    out.mkdir(parents=True)

    rows = tool_loop.run_tools(
        tools=["zizmor"],
        target_type="repo",
        target=repo,
        target_label="app",
        out_dir=out,
        timeout=120,
        retries=0,
        per_tool_config={},
        allow_missing_tools=False,
        runner_cls=ToolRunner,
        repo_root=repo,
        results_name="results",
        results_tree=(repo / "results").resolve(),
    )

    assert rows["zizmor"].state is State.RAN, rows["zizmor"]
    # Every file handed over has a finding (the dependabot file's is
    # `dependabot-cooldown`), so each one is seen to be read.
    assert _sarif_uris(out / "zizmor.json") == sorted(
        rel for rel, kept in PLANTED.items() if kept
    )


@pytest.mark.requires_tools
def test_real_zizmor_exits_nonzero_when_it_cannot_audit(tmp_path) -> None:
    """Why `ok_return_codes` is `(0,)`: findings are rc 0, and a run that
    audited nothing is not (measured before relying on it: rc 3, "no inputs
    collected")."""
    import subprocess

    if shutil.which("zizmor") is None:
        pytest.skip("zizmor is not on PATH")
    (tmp_path / "action.yml").write_bytes(b"runs: [\n")
    result = subprocess.run(
        ["zizmor", "--format", "sarif", "--offline", "--no-exit-codes", "action.yml"],
        cwd=tmp_path,
        capture_output=True,
        timeout=60,
        env={**os.environ},
    )
    assert result.returncode != 0


# --- what zizmor says about the inputs it was handed ---------------------------

# 1.30.1's own stderr, copied from runs through JMo's command line. A YAML file
# that does not parse is not named in its warning; one that parses but is not
# the kind of file its name says (`action.yml` of another framework) is. Each
# input that was audited gets a `completed` line.
PARSE_WARNING = (
    " WARN collect_inputs: zizmor::registry::input: failed to parse input: "
    "did not find expected ',' or ']' at line 2 column 3, while parsing a "
    "flow sequence at line 1 column 7\n"
)
ACTION_WARNING = (
    " WARN collect_inputs: zizmor::registry::input: failed to validate "
    "file://sub/action.yml as action: input does not match expected "
    "validation schema\n"
)
NO_INPUTS = (
    "fatal: no audit was performed\nerror: no inputs collected\n  |\n"
    "  = help: collection yielded no auditable inputs\n"
)
EMPTY_SARIF = json.dumps({"version": "2.1.0", "runs": []})


def _completed(*files: str) -> str:
    return "".join(f" INFO audit: zizmor: \U0001f308 completed {f}\n" for f in files)


def _run_with(repo: Path, out: Path, result):
    """The scan loop over `repo`, with `result(definition)` as zizmor's run."""

    class Runner:
        def __init__(self, tools, progress_callback=None):
            self.tools = tools

        def run_all_parallel(self):
            return [result(t) for t in self.tools]

    return tool_loop.run_tools(
        tools=["zizmor"],
        target_type="repo",
        target=repo,
        target_label="t",
        out_dir=out,
        timeout=60,
        retries=0,
        per_tool_config={},
        allow_missing_tools=False,
        runner_cls=Runner,
        find_tool_func=lambda name: "/bin/zizmor" if name == "zizmor" else None,
        repo_root=repo,
    )


def _repo_and_out(tmp_path: Path, files: dict[str, bytes]):
    repo = tmp_path / "repo"
    for rel, data in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_bytes(data)
    out = tmp_path / "out"
    out.mkdir()
    return repo, out


def _success(stderr: str):
    def result(definition):
        return ToolResult(
            tool="zizmor",
            status="success",
            returncode=0,
            stdout=EMPTY_SARIF,
            stderr=stderr,
            output_file=definition.output_file,
            capture_stdout=True,
        )

    return result


def _crash(stderr: str):
    def result(definition):
        return ToolResult(
            tool="zizmor",
            status="error",
            returncode=3,
            stderr=stderr,
            output_file=definition.output_file,
            capture_stdout=True,
            failure="crash",
            error_message="Return code 3 not in (0,)",
        )

    return result


def test_every_input_invalid_is_a_skip_naming_the_files_not_a_failure(
    tmp_path, caplog
) -> None:
    """rc 3, "no inputs collected" (measured, 1.30.1): the only `action.yml`
    of a repository is another framework's file of that name. It read
    `failed:unaccepted exit code` on every scan, and the only remedy was
    `--skip-tools zizmor`. Nothing failed: there was nothing to audit."""
    repo, out = _repo_and_out(tmp_path, {"sub/action.yml": b"name: x\nfoo: bar\n"})

    with caplog.at_level(logging.INFO):
        rows = _run_with(repo, out, _crash(ACTION_WARNING + NO_INPUTS))

    row = rows["zizmor"]
    assert row.state is State.SKIPPED, row
    assert row.reason is Reason.NO_READABLE_WORKFLOWS
    assert row.reason in SKIP_REASONS
    assert row.label == "skipped:no workflow zizmor could read"
    # The reason is a closed-set label; the files are in the detail and the log.
    assert "sub/action.yml" in (row.detail or "")
    warned = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert any("sub/action.yml" in m for m in warned), warned
    assert not [r for r in caplog.records if r.levelname == "ERROR"]
    # The row's output is the empty SARIF document, so the report reads it.
    assert json.loads((out / "zizmor.json").read_bytes())["runs"] == []


def test_an_rc_3_that_is_not_no_inputs_is_still_a_failure(tmp_path) -> None:
    """The skip is for zizmor's own words, not for the return code alone."""
    repo, out = _repo_and_out(tmp_path, {".github/workflows/ci.yml": WORKFLOW})

    rows = _run_with(repo, out, _crash("error: something else\n"))

    assert rows["zizmor"].state is State.FAILED
    assert rows["zizmor"].reason is Reason.EXIT_CODE


def test_an_invalid_file_among_valid_ones_is_named_and_the_row_still_ran(
    tmp_path, caplog
) -> None:
    """One invalid input beside valid ones: zizmor exits 0 with the others'
    findings and writes only a WARN, which does not name a file that did not
    parse. The row implied `bad.yml` was audited; it was not."""
    repo, out = _repo_and_out(
        tmp_path,
        {
            ".github/workflows/good.yml": WORKFLOW,
            ".github/workflows/bad.yml": b"name: [unclosed\n  : :\n",
        },
    )
    stderr = PARSE_WARNING + _completed(".github\\workflows\\good.yml")

    with caplog.at_level(logging.INFO):
        rows = _run_with(repo, out, _success(stderr))

    assert rows["zizmor"].state is State.RAN, rows["zizmor"]
    warned = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert len(warned) == 1, warned
    assert ".github/workflows/bad.yml" in warned[0]
    assert "good.yml" not in warned[0]
    assert "did not find expected" in warned[0]
    assert ".github/workflows/bad.yml" in (rows["zizmor"].detail or "")


def test_a_named_warning_names_its_own_file(tmp_path, caplog) -> None:
    repo, out = _repo_and_out(
        tmp_path,
        {
            ".github/workflows/good.yml": WORKFLOW,
            "sub/action.yml": b"name: x\nfoo: bar\n",
        },
    )
    stderr = ACTION_WARNING + _completed(".github\\workflows\\good.yml")

    with caplog.at_level(logging.WARNING):
        _run_with(repo, out, _success(stderr))

    warned = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert len(warned) == 1 and "sub/action.yml" in warned[0], warned
    assert "does not match expected validation schema" in warned[0]


def test_a_clean_run_says_nothing_about_inputs(tmp_path, caplog) -> None:
    repo, out = _repo_and_out(tmp_path, {".github/workflows/ci.yml": WORKFLOW})

    with caplog.at_level(logging.INFO):
        rows = _run_with(repo, out, _success(_completed(".github\\workflows\\ci.yml")))

    assert rows["zizmor"].state is State.RAN
    assert rows["zizmor"].detail is None
    assert not [r for r in caplog.records if r.levelname in ("WARNING", "ERROR")]


@pytest.mark.parametrize(
    "config", ["zizmor.yml", "zizmor.yaml", ".github/zizmor.yml", ".github/zizmor.yaml"]
)
def test_a_repository_config_zizmor_reads_is_announced_naming_it(
    tmp_path, caplog, config
) -> None:
    """zizmor obeys the scanned repository's own config, and a `.github/zizmor.yml`
    disabling `artipacked` and `unpinned-uses` took a sample from 3 rule ids to 1
    with nothing said (measured, 1.30.1, which reads the `.yaml` spellings too).
    As for gitleaks' `.gitleaks.toml`: honoured, and said."""
    repo, out = _repo_and_out(
        tmp_path,
        {".github/workflows/ci.yml": WORKFLOW, config: b"rules:\n  artipacked:\n"},
    )

    with caplog.at_level(logging.INFO):
        _run_with(repo, out, _success(_completed(".github\\workflows\\ci.yml")))

    said = [r.getMessage() for r in caplog.records if r.levelname == "INFO"]
    assert any(config in m and "zizmor" in m for m in said), said


def test_a_repository_without_a_zizmor_config_announces_nothing(
    tmp_path, caplog
) -> None:
    repo, out = _repo_and_out(tmp_path, {".github/workflows/ci.yml": WORKFLOW})

    with caplog.at_level(logging.INFO):
        _run_with(repo, out, _success(_completed(".github\\workflows\\ci.yml")))

    assert not [r for r in caplog.records if "zizmor.y" in r.getMessage()]


def test_a_config_is_not_announced_for_a_scan_that_skips(tmp_path, caplog) -> None:
    """No workflow to read: zizmor does not run, so the config shapes nothing."""
    repo, out = _repo_and_out(
        tmp_path, {"lib.py": b"x = 1\n", ".github/zizmor.yml": b"rules: {}\n"}
    )

    with caplog.at_level(logging.INFO):
        rows = _run_with(repo, out, lambda d: None)

    assert rows["zizmor"].state is State.SKIPPED
    assert not [r for r in caplog.records if "zizmor.yml" in r.getMessage()]


@pytest.mark.requires_tools
def test_real_zizmor_edges_through_the_scan_loop(tmp_path, caplog) -> None:
    """Against the binary, through the scan loop: the two edges measured on
    1.30.1 (#1362), and the config announcement (#1363)."""
    from scripts.core.tool_runner import ToolRunner

    if shutil.which("zizmor") is None:
        pytest.skip("zizmor is not on PATH")

    def scan(files: dict[str, bytes], name: str):
        repo = tmp_path / name
        for rel, data in files.items():
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_bytes(data)
        out = tmp_path / f"out-{name}"
        out.mkdir()
        rows = tool_loop.run_tools(
            tools=["zizmor"],
            target_type="repo",
            target=repo,
            target_label=name,
            out_dir=out,
            timeout=120,
            retries=0,
            per_tool_config={},
            allow_missing_tools=False,
            runner_cls=ToolRunner,
            repo_root=repo,
        )
        return rows["zizmor"], out

    with caplog.at_level(logging.INFO):
        # (a) every matched file invalid: a skip, where it was a failure.
        row, out = scan({"sub/action.yml": b"name: x\nfoo: bar\n"}, "a")
        assert row.state is State.SKIPPED, row
        assert row.reason is Reason.NO_READABLE_WORKFLOWS
        assert "sub/action.yml" in (row.detail or "")
        assert json.loads((out / "zizmor.json").read_bytes())["runs"] == []

        # (b) one invalid file beside a valid one: ran, and the invalid one named.
        caplog.clear()
        row, out = scan(
            {
                ".github/workflows/good.yml": WORKFLOW,
                ".github/workflows/bad.yml": b"name: [unclosed\n  : :\n",
            },
            "b",
        )
        assert row.state is State.RAN, row
        warned = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        assert any(".github/workflows/bad.yml" in m for m in warned), warned
        assert not any("good.yml" in m for m in warned), warned

        # (c) the repository's own config: honoured, and said.
        caplog.clear()
        row, out = scan(
            {
                ".github/workflows/ci.yml": WORKFLOW,
                ".github/zizmor.yml": b"rules:\n  unpinned-uses:\n    disable: true\n",
            },
            "c",
        )
        assert row.state is State.RAN, row
        results = json.loads((out / "zizmor.json").read_bytes())["runs"][0]["results"]
        assert "zizmor/unpinned-uses" not in {r["ruleId"] for r in results}
        said = [r.getMessage() for r in caplog.records if r.levelname == "INFO"]
        assert any(".github/zizmor.yml" in m for m in said), said
