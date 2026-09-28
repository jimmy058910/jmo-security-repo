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
import os
import shutil
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
