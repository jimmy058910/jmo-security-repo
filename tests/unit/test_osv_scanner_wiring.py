"""osv-scanner wired as a descriptor row (v2.0.0 Phase 4, PR O, task O1).

Measured before any of this was written (the Phase 4 plan, and O1's own):

- Given a directory on Windows, osv-scanner walks nothing (rc 128, "No package
  sources found", 2.5.1 and 2.6.0). So JMo walks the tree, pruning what it
  prunes for every walk-fed tool, and hands over each lockfile with `-L`.
- One name osv-scanner rejects in the `-L` list (`go.sum`) aborts the whole
  run: rc 127, no output, every other lockfile's findings lost. The walk's
  patterns are therefore exactly the names it accepts.
- One lockfile it cannot extract (a truncated `package-lock.json` in a
  subdirectory) does the same: rc 127, "extraction failed on specified
  lockfile", no output. So a run that fails that way is split into one run
  per lockfile, which costs the database load each time (npm ~11 s).
- A lockfile whose ecosystem has no offline database, beside one that has:
  rc **1** and NodeGoat's 304 results became **40**, deterministically (three
  runs). osv-scanner's own exit code cannot be trusted there, so the check
  is JMo's and runs before osv-scanner does.
- `--offline-vulnerabilities` alone still resolves `pom.xml` and
  `requirements.txt` transitively over the network (deps.dev; under an
  unroutable proxy: "failed resolution ... dial tcp 127.0.0.1:9"); with
  `--no-resolve` nothing is dialled and NodeGoat's 304 are unchanged.

The real-binary tests read `tests/fixtures/osv-db`: two synthetic advisories
(`JMO-TEST-2026-0001`, npm `left-pad` < 1.3.0; `JMO-TEST-2026-0002`, PyPI
`urllib3` < 1.26.5), so they run offline and download nothing.
"""

from __future__ import annotations

import json
import shutil
import time
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.cli.scan_jobs import tool_loop
from scripts.cli.tool_installer import ToolInstaller
from scripts.core import osv_database
from scripts.core.normalize_and_report import tool_of_output
from scripts.core.osv_database import LOCKFILE_ECOSYSTEMS, database_path
from scripts.core.scan_timings import FAIL_REASONS, SKIP_REASONS, Reason, State
from scripts.core.tool_descriptors import DESCRIPTORS, VENDORED_DIRS, ExclusionStyle
from scripts.core.tool_registry import ToolInfo
from scripts.core.tool_runner import ToolResult

ROOT = Path(__file__).resolve().parents[2]
FROZEN_DB = ROOT / "tests" / "fixtures" / "osv-db"

# osv-scanner v2.6.0's release assets, listed with `gh api
# repos/google/osv-scanner/releases/tags/v2.6.0 --jq '.assets[].name'` on
# 2026-09-28. A URL the installer builds must be one of these.
RELEASE_ASSETS_2_6_0 = frozenset(
    {
        "osv-scanner_darwin_amd64",
        "osv-scanner_darwin_arm64",
        "osv-scanner_linux_amd64",
        "osv-scanner_linux_arm64",
        "osv-scanner_windows_amd64.exe",
        "osv-scanner_windows_arm64.exe",
    }
)

CACHE_ENV = "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"
MARKER = "extraction failed on specified lockfile"

NPM_LOCK = json.dumps(
    {
        "name": "app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/left-pad": {"version": "1.0.0"},
        },
    }
).encode()


class TestInstallUrl:
    """Through `ToolInstaller._install_binary`, the path `jmo tools install`
    takes, stopped at the download so nothing is fetched. The release ships
    raw binaries, so there is nothing to extract."""

    @pytest.mark.parametrize(
        ("platform_key", "machine", "asset"),
        [
            ("linux", "x86_64", "osv-scanner_linux_amd64"),
            ("linux", "aarch64", "osv-scanner_linux_arm64"),
            ("macos", "x86_64", "osv-scanner_darwin_amd64"),
            ("macos", "arm64", "osv-scanner_darwin_arm64"),
            ("windows", "AMD64", "osv-scanner_windows_amd64.exe"),
            ("windows", "ARM64", "osv-scanner_windows_arm64.exe"),
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
            name="osv-scanner",
            version="2.6.0",
            description="",
            category="binary_tools",
        )
        with (
            patch("platform.machine", return_value=machine),
            patch.object(installer, "_get_download_command", side_effect=capture),
        ):
            installer._install_binary("osv-scanner", info, time.time())

        assert urls == [
            "https://github.com/google/osv-scanner/releases/download/v2.6.0/" + asset
        ]
        assert asset in RELEASE_ASSETS_2_6_0


class TestDescriptor:
    def test_it_is_walk_fed_with_exactly_the_names_osv_scanner_accepts(self) -> None:
        """Derived from the lockfile map, so a pattern cannot name a file the
        map has no ecosystem for, or the reverse."""
        d = DESCRIPTORS["osv-scanner"]
        assert d.exclusion_style is ExclusionStyle.WALK
        assert d.exclusion_flag is None
        assert d.file_patterns == tuple(f"**/{name}" for name in LOCKFILE_ECOSYSTEMS)
        assert d.excluded_vendored == VENDORED_DIRS
        assert d.target_types == frozenset({"repo", "gitlab"})

    def test_no_lockfile_is_a_skip_and_a_missing_database_a_failure(self) -> None:
        """G8: a repository with no lockfile is not clean, it was not read."""
        assert DESCRIPTORS["osv-scanner"].no_files_reason is Reason.NO_LOCKFILE
        assert Reason.NO_LOCKFILE.value == "no lockfile"
        assert Reason.NO_LOCKFILE in SKIP_REASONS
        assert Reason.NO_OFFLINE_DB.value == "offline database missing"
        assert Reason.NO_OFFLINE_DB in FAIL_REASONS
        assert Reason.NO_OFFLINE_DB not in SKIP_REASONS

    def test_its_empty_result_is_an_empty_sarif_document(self) -> None:
        assert DESCRIPTORS["osv-scanner"].stub == {"version": "2.1.0", "runs": []}

    def test_the_probe_reads_osv_scanners_own_version(self) -> None:
        """`osv-scanner --version` prints its library's version on the next
        line; the probe must not take that one."""
        pattern = DESCRIPTORS["osv-scanner"].version_probe.pattern
        printed = (
            "osv-scanner version: 2.6.0\nosv-scalibr version: 0.5.2\n"
            "commit: e840a6e8\nbuilt at: 2026-09-14T01:44:58Z\n"
        )
        assert pattern.search(printed).group(1) == "2.6.0"
        assert DESCRIPTORS["osv-scanner"].version_probe.command is None

    def test_it_sits_with_the_other_dependency_scanner(self) -> None:
        names = list(DESCRIPTORS)
        assert names[names.index("grype") + 1] == "osv-scanner"


# --- through the scan loop ------------------------------------------------------


def _cache(tmp_path: Path, monkeypatch, *ecosystems: str) -> Path:
    """A cache holding a (placeholder) database for each of `ecosystems`."""
    cache = tmp_path / "osv-db"
    cache.mkdir()
    for ecosystem in ecosystems:
        path = database_path(ecosystem, cache)
        path.parent.mkdir(parents=True)
        path.write_bytes(b"PK")
    monkeypatch.setattr(osv_database, "cache_dir", lambda: cache)
    return cache


def _plant(repo: Path, files) -> None:
    for rel in files:
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(NPM_LOCK if rel.endswith(".json") else b"x==1.0\n")


class Scripted:
    """A runner whose results a test scripts, round by round."""

    def __init__(self, respond=None):
        self.rounds: list[list] = []
        self.respond = respond or (lambda definition, round_no: _ok(definition))

    def __call__(self, tools, progress_callback=None):
        self.rounds.append(list(tools))
        round_no = len(self.rounds)
        respond = self.respond

        class Runner:
            def run_all_parallel(self_inner):
                return [respond(d, round_no) for d in tools]

        return Runner()


def _ok(definition, seconds: float = 1.0) -> ToolResult:
    return ToolResult(
        tool=definition.name,
        status="success",
        returncode=1,
        duration=seconds,
        output_file=definition.output_file,
    )


def _failed(definition, stderr: str, seconds: float = 1.0) -> ToolResult:
    return ToolResult(
        tool=definition.name,
        status="error",
        returncode=127,
        stderr=stderr,
        duration=seconds,
        output_file=definition.output_file,
        error_message="Return code 127 not in (0, 1)",
        failure="crash",
    )


def _lockfiles(definition) -> list[str]:
    command = definition.command
    return [command[i + 1] for i, tok in enumerate(command) if tok == "-L"]


def _run(repo: Path, out: Path, runner, results_tree=None, per_tool_config=None):
    return tool_loop.run_tools(
        tools=["osv-scanner"],
        target_type="repo",
        target=repo,
        target_label="t",
        out_dir=out,
        timeout=60,
        retries=0,
        per_tool_config=per_tool_config or {},
        allow_missing_tools=False,
        runner_cls=runner,
        find_tool_func=lambda name: (
            "/bin/osv-scanner" if name == "osv-scanner" else None
        ),
        repo_root=repo,
        results_name="results" if results_tree else None,
        results_tree=results_tree,
    )


# Relative path -> whether osv-scanner must be handed it.
PLANTED = {
    "package-lock.json": True,
    "services/api/requirements.txt": True,
    "services/api/requirements-dev.txt": True,
    "tools/go.mod": True,
    # Vendored trees: pruned by the walk, as for every walk-fed tool.
    "node_modules/left-pad/package-lock.json": False,
    "vendor/lib/requirements.txt": False,
    ".venv/lib/requirements.txt": False,
    # JMo's own results directory inside the tree (#1156, Review Focus 2).
    "results/individual-repos/old/package-lock.json": False,
    # Names osv-scanner rejects: one of them aborts the whole run.
    "package.json": False,
    "tools/go.sum": False,
    "pyproject.toml": False,
    "services/api/requirements.in": False,
}


def test_one_run_reads_every_lockfile_relative_to_the_root(
    tmp_path, monkeypatch
) -> None:
    """A relative repository and out_dir, so every path the command carries
    must survive osv-scanner running from the repository."""
    cache = _cache(tmp_path, monkeypatch, "npm", "PyPI", "Go")
    monkeypatch.chdir(tmp_path)
    repo = Path("repo")
    _plant(repo, PLANTED)
    out = Path("repo") / "results" / "individual-repos" / "repo"
    out.mkdir(parents=True)
    runner = Scripted()

    rows = _run(repo, out, runner, results_tree=(tmp_path / "repo/results").resolve())

    ((definition,),) = runner.rounds
    assert definition.command[:10] == [
        "/bin/osv-scanner",
        "scan",
        "source",
        "--format",
        "sarif",
        "--output-file",
        # Absolute: the tool runs from the repository, not from here.
        str((tmp_path / out / "osv-scanner.json").absolute()),
        # Scans never download (decision 6), and never resolve over the
        # network: `pom.xml` and `requirements.txt` dial deps.dev without it.
        "--offline-vulnerabilities",
        "--no-resolve",
        # A lockfile with no packages is rc 128 and no report without it
        # (measured); JMo has already found the lockfile, so it is clean.
        "--allow-no-lockfiles",
    ]
    lockfiles = _lockfiles(definition)
    assert definition.command[10:] == [a for f in lockfiles for a in ("-L", f)]
    assert sorted(lockfiles) == sorted(rel for rel, kept in PLANTED.items() if kept)
    assert all(not Path(f).is_absolute() and "\\" not in f for f in lockfiles)
    assert definition.cwd == (tmp_path / "repo").resolve()
    assert definition.env == {CACHE_ENV: str(cache)}
    assert definition.output_file == out / "osv-scanner.json"
    assert definition.capture_stdout is False
    # 1 is findings; 127 is an error and 128 "no package sources found".
    assert definition.ok_return_codes == (0, 1)
    assert rows["osv-scanner"].state is State.RAN


def test_the_users_flags_come_before_the_lockfiles(tmp_path, monkeypatch) -> None:
    _cache(tmp_path, monkeypatch, "npm")
    repo = tmp_path / "repo"
    _plant(repo, ["package-lock.json"])
    runner = Scripted()

    _run(
        repo,
        tmp_path,
        runner,
        per_tool_config={"osv-scanner": {"flags": ["--verbosity", "error"]}},
    )

    command = runner.rounds[0][0].command
    assert command.index("--verbosity") < command.index("-L")


def test_a_user_flag_cannot_move_its_report_or_download_mid_scan() -> None:
    from scripts.cli.scan_utils import tool_flags

    flags = [
        "--output-file",
        "elsewhere.sarif",
        "--download-offline-databases",
        "--verbosity",
        "error",
    ]

    assert tool_flags({"osv-scanner": {"flags": flags}}, "osv-scanner") == [
        "--verbosity",
        "error",
    ]


@pytest.mark.parametrize(
    "files",
    [
        # juice-shop at 1618a611: package.json and `package-lock=false`.
        {"package.json": b"{}", ".npmrc": b"package-lock=false\n"},
        {"lib.py": b"x = 1\n"},
        # Only names osv-scanner rejects.
        {"pyproject.toml": b"[project]\n", "go.sum": b"", "Pipfile": b""},
        # Lockfiles that are not the repository's own.
        {"lib.py": b"x = 1\n", "node_modules/x/package-lock.json": NPM_LOCK},
    ],
)
def test_a_repository_without_a_lockfile_is_skipped_and_says_why(
    tmp_path, monkeypatch, files
) -> None:
    """G8: `skipped:no lockfile`, honest, not a clean run."""
    _cache(tmp_path, monkeypatch, "npm")
    repo = tmp_path / "repo"
    for rel, data in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_bytes(data)
    out = tmp_path / "out"
    out.mkdir()
    runner = Scripted()

    rows = _run(repo, out, runner)

    assert runner.rounds == [[]]
    assert rows["osv-scanner"].label == "skipped:no lockfile"
    assert json.loads((out / "osv-scanner.json").read_bytes()) == {
        "version": "2.1.0",
        "runs": [],
    }


def test_a_lockfile_in_the_results_directory_is_not_read(tmp_path, monkeypatch) -> None:
    """Review Focus 2: an earlier scan's `results/` inside the repository,
    scanned with `--results-dir <repo>/results`. Its lockfile-shaped file is
    JMo's own output, not the repository's."""
    _cache(tmp_path, monkeypatch, "npm")
    repo = tmp_path / "repo"
    _plant(repo, ["results/individual-repos/old/package-lock.json"])
    (repo / "lib.py").write_bytes(b"x = 1\n")
    out = repo / "results" / "individual-repos" / "repo"
    out.mkdir(parents=True)
    runner = Scripted()

    rows = _run(repo, out, runner, results_tree=(repo / "results").resolve())

    assert runner.rounds == [[]]
    assert rows["osv-scanner"].label == "skipped:no lockfile"


# --- the offline database, checked before the run (Ruling 32) ------------------


def test_with_no_database_osv_scanner_does_not_run(tmp_path, monkeypatch) -> None:
    _cache(tmp_path, monkeypatch)
    repo = tmp_path / "repo"
    _plant(repo, ["package-lock.json", "api/requirements.txt"])
    out = tmp_path / "out"
    out.mkdir()
    runner = Scripted()

    row = _run(repo, out, runner)["osv-scanner"]

    assert runner.rounds == [[]]
    assert row.label == "failed:offline database missing"
    assert "npm (package-lock.json)" in row.detail
    assert "PyPI (api/requirements.txt)" in row.detail
    assert "jmo tools update" in row.detail
    # Nothing that reads like a clean run: no empty result was written.
    assert not (out / "osv-scanner.json").exists()


def test_with_a_partial_database_the_lockfiles_it_covers_still_run(
    tmp_path, monkeypatch
) -> None:
    """Handed to osv-scanner together, a Cargo.lock with no crates.io database
    cost 264 of NodeGoat's 304 npm results with rc 1 (measured). So it is kept
    out of the run, and the row says what was not read."""
    _cache(tmp_path, monkeypatch, "npm")
    repo = tmp_path / "repo"
    _plant(repo, ["package-lock.json", "native/Cargo.lock"])
    runner = Scripted(lambda d, n: _ok(d, seconds=4.0))

    row = _run(repo, tmp_path, runner)["osv-scanner"]

    ((definition,),) = runner.rounds
    assert _lockfiles(definition) == ["package-lock.json"]
    assert row.label == "failed:offline database missing"
    assert "crates.io (native/Cargo.lock)" in row.detail
    assert "jmo tools update" in row.detail
    assert "npm" not in row.detail
    assert (row.seconds, row.invocations) == (4.0, 1)


def test_a_partial_database_and_a_failed_run_are_both_named(
    tmp_path, monkeypatch
) -> None:
    _cache(tmp_path, monkeypatch, "npm")
    repo = tmp_path / "repo"
    _plant(repo, ["package-lock.json", "Cargo.lock"])
    runner = Scripted(lambda d, n: _failed(d, "something else went wrong"))

    row = _run(repo, tmp_path, runner)["osv-scanner"]

    assert row.label == "failed:offline database missing"
    assert "crates.io (Cargo.lock)" in row.detail
    assert "Return code 127" in row.detail


# --- one broken lockfile (Review Focus 1) ---------------------------------------


EXTRACTION_ERROR = (
    "Error during extraction: (extracting as javascript/packagelockjson) "
    "C:/r/sub/package-lock.json: could not extract: unexpected end of JSON "
    "input\n" + MARKER + "\n"
)


def test_one_broken_lockfile_costs_only_its_own_findings(tmp_path, monkeypatch) -> None:
    _cache(tmp_path, monkeypatch, "npm")
    repo = tmp_path / "repo"
    _plant(repo, ["package-lock.json", "sub/package-lock.json"])
    out = tmp_path / "out"
    out.mkdir()

    def respond(d, round_no):
        if round_no == 1:
            return _failed(d, EXTRACTION_ERROR, seconds=10.0)
        if _lockfiles(d) == ["sub/package-lock.json"]:
            return _failed(d, EXTRACTION_ERROR)
        return _ok(d)

    runner = Scripted(respond)

    row = _run(repo, out, runner)["osv-scanner"]

    combined, each = runner.rounds
    assert sorted(_lockfiles(combined[0])) == [
        "package-lock.json",
        "sub/package-lock.json",
    ]
    assert sorted(_lockfiles(d)[0] for d in each) == [
        "package-lock.json",
        "sub/package-lock.json",
    ]
    assert all(len(_lockfiles(d)) == 1 for d in each)
    outputs = [d.output_file for d in each]
    assert len(set(outputs)) == 2
    assert out / "osv-scanner.json" not in outputs
    # The report reads each one with osv-scanner's adapter.
    assert all(p.parent == out and tool_of_output(p) == "osv-scanner" for p in outputs)
    assert all(d.env == combined[0].env and d.cwd == combined[0].cwd for d in each)
    assert all(d.command[:6] == combined[0].command[:6] for d in each)
    # Failed, naming only the lockfile that could not be read.
    assert row.state is State.FAILED
    assert row.reason is Reason.EXIT_CODE
    assert row.detail == "sub/package-lock.json: Return code 127 not in (0, 1)"
    # The combined run's time is part of what the row cost.
    assert (row.invocations, row.seconds) == (3, 12.0)


def test_a_split_leaves_no_output_of_an_earlier_scan_behind(
    tmp_path, monkeypatch
) -> None:
    """The report reads every `osv-scanner.*.json` in the directory. The
    combined run failed, so an `osv-scanner.json` there is an earlier scan's;
    a numbered output this scan did not write is too."""
    _cache(tmp_path, monkeypatch, "npm")
    repo = tmp_path / "repo"
    _plant(repo, ["package-lock.json", "sub/package-lock.json"])
    out = tmp_path / "out"
    out.mkdir()
    (out / "osv-scanner.json").write_bytes(b"earlier")
    (out / "osv-scanner.part9.json").write_bytes(b"earlier")
    (out / "trivy.json").write_bytes(b"another tool's")

    runner = Scripted(lambda d, n: _failed(d, EXTRACTION_ERROR) if n == 1 else _ok(d))
    _run(repo, out, runner)

    assert sorted(p.name for p in out.glob("*.json")) == [
        "scan-timings.json",
        "trivy.json",
    ]


def test_an_earlier_splits_outputs_go_when_one_run_reads_everything(
    tmp_path, monkeypatch
) -> None:
    """A later scan whose one run succeeds, or which has a single lockfile, must
    not also report what an earlier scan's split runs wrote."""
    _cache(tmp_path, monkeypatch, "npm")
    repo = tmp_path / "repo"
    _plant(repo, ["package-lock.json"])
    out = tmp_path / "out"
    out.mkdir()
    (out / "osv-scanner.part1.json").write_bytes(b"earlier")
    (out / "osv-scanner.part2.json").write_bytes(b"earlier")

    _run(repo, out, Scripted())

    assert not list(out.glob("osv-scanner.part*.json"))


@pytest.mark.parametrize(
    ("returncode", "stderr"),
    [
        (127, "could not load db for npm ecosystem"),
        # The marker under another exit code is not the failure it marks.
        (2, EXTRACTION_ERROR),
    ],
)
def test_a_failure_that_is_not_a_broken_lockfile_is_not_split(
    tmp_path, monkeypatch, returncode, stderr
) -> None:
    """osv-scanner exits 127 for any error; a split costs a database load per
    lockfile, so only the failure a split can recover from is split."""
    _cache(tmp_path, monkeypatch, "npm")
    repo = tmp_path / "repo"
    _plant(repo, ["package-lock.json", "sub/package-lock.json"])

    def respond(d, round_no):
        result = _failed(d, stderr)
        result.returncode = returncode
        return result

    runner = Scripted(respond)

    row = _run(repo, tmp_path, runner)["osv-scanner"]

    assert len(runner.rounds) == 1
    assert row.label == "failed:unaccepted exit code"
    assert row.invocations == 1


def test_a_single_broken_lockfile_has_nothing_to_split_and_is_named(
    tmp_path, monkeypatch
) -> None:
    _cache(tmp_path, monkeypatch, "npm")
    repo = tmp_path / "repo"
    _plant(repo, ["app/package-lock.json"])
    runner = Scripted(lambda d, n: _failed(d, EXTRACTION_ERROR))

    row = _run(repo, tmp_path, runner)["osv-scanner"]

    assert len(runner.rounds) == 1
    assert row.state is State.FAILED
    assert row.detail == "app/package-lock.json: Return code 127 not in (0, 1)"


# --- the frozen database and the real binary ----------------------------------


def test_the_frozen_database_is_two_synthetic_advisories() -> None:
    """What the real-binary and contract tests read. Synthetic, so it is no
    advisory's copy and matches nothing in a real lockfile by accident."""
    held = {}
    for ecosystem in ("npm", "PyPI"):
        with zipfile.ZipFile(database_path(ecosystem, FROZEN_DB)) as z:
            (name,) = z.namelist()
            record = json.loads(z.read(name))
        (affected,) = record["affected"]
        held[ecosystem] = (record["id"], affected["package"]["name"])
        assert affected["package"]["ecosystem"] == ecosystem
        assert record["summary"].startswith("Synthetic advisory")
    assert held == {
        "npm": ("JMO-TEST-2026-0001", "left-pad"),
        "PyPI": ("JMO-TEST-2026-0002", "urllib3"),
    }


def _real_scan(tmp_path, monkeypatch, files: dict[str, bytes]):
    """The real binary through the scan loop, against the frozen database,
    with every proxy pointed at a closed port: a network call is an error."""
    from scripts.core.tool_runner import ToolRunner

    if shutil.which("osv-scanner") is None:
        pytest.skip("osv-scanner is not on PATH")
    monkeypatch.setattr(osv_database, "cache_dir", lambda: FROZEN_DB)
    for var in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
        monkeypatch.setenv(var, "http://127.0.0.1:9")
    monkeypatch.setenv("NO_PROXY", "")
    results: list[ToolResult] = []

    class Keeping(ToolRunner):
        def run_all_parallel(self):
            got = super().run_all_parallel()
            results.extend(got)
            return got

    repo = tmp_path / "vendor" / "app"  # under a `vendor` of its own (B5)
    for rel, data in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_bytes(data)
    out = repo / "results" / "individual-repos" / "app"
    out.mkdir(parents=True)
    rows = tool_loop.run_tools(
        tools=["osv-scanner"],
        target_type="repo",
        target=repo,
        target_label="app",
        out_dir=out,
        timeout=120,
        retries=0,
        per_tool_config={},
        allow_missing_tools=False,
        runner_cls=Keeping,
        repo_root=repo,
        results_name="results",
        results_tree=(repo / "results").resolve(),
    )
    return rows["osv-scanner"], out, results


def _rule_ids(path: Path) -> list[str]:
    return sorted(
        r["ruleId"] for r in json.loads(path.read_bytes())["runs"][0]["results"]
    )


@pytest.mark.requires_tools
def test_real_osv_scanner_reads_every_lockfile_offline(tmp_path, monkeypatch) -> None:
    row, out, results = _real_scan(
        tmp_path,
        monkeypatch,
        {
            "package-lock.json": NPM_LOCK,
            "api/requirements.txt": b"urllib3==1.25.0\n",
            "node_modules/x/package-lock.json": NPM_LOCK,
        },
    )

    assert row.state is State.RAN, row
    assert _rule_ids(out / "osv-scanner.json") == [
        "JMO-TEST-2026-0001",
        "JMO-TEST-2026-0002",
    ]
    # `--no-resolve`: without it, `requirements.txt` dials deps.dev (measured
    # "failed resolution ... dial tcp 127.0.0.1:9" under this proxy).
    (result,) = results
    assert "failed resolution" not in result.stderr, result.stderr


@pytest.mark.requires_tools
def test_real_osv_scanner_keeps_the_readable_lockfile_when_one_is_truncated(
    tmp_path, monkeypatch
) -> None:
    row, out, _ = _real_scan(
        tmp_path,
        monkeypatch,
        {
            "package-lock.json": NPM_LOCK,
            "examples/old/package-lock.json": NPM_LOCK[: len(NPM_LOCK) // 2],
        },
    )

    assert row.state is State.FAILED
    assert row.detail.startswith("examples/old/package-lock.json: "), row.detail
    assert not (out / "osv-scanner.json").exists()
    kept = list(out.glob("osv-scanner.part*.json"))
    assert [_rule_ids(p) for p in kept] == [["JMO-TEST-2026-0001"]]


@pytest.mark.requires_tools
def test_real_osv_scanner_reads_a_lockfile_with_no_packages_as_clean(
    tmp_path, monkeypatch
) -> None:
    """A lockfile whose project has no dependencies is a clean read, not a
    failure (measured: rc 128, "No package sources found", no report without
    `--allow-no-lockfiles`)."""
    empty = {
        "name": "app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {"": {"name": "app", "version": "1.0.0"}},
    }
    row, out, _ = _real_scan(
        tmp_path, monkeypatch, {"package-lock.json": json.dumps(empty).encode()}
    )

    assert row.state is State.RAN, row
    assert _rule_ids(out / "osv-scanner.json") == []


@pytest.mark.requires_tools
def test_real_osv_scanner_reads_what_has_a_database_and_names_the_rest(
    tmp_path, monkeypatch
) -> None:
    row, out, _ = _real_scan(
        tmp_path,
        monkeypatch,
        {"package-lock.json": NPM_LOCK, "native/Cargo.lock": b"version = 3\n"},
    )

    assert row.label == "failed:offline database missing"
    assert "crates.io (native/Cargo.lock)" in row.detail
    assert _rule_ids(out / "osv-scanner.json") == ["JMO-TEST-2026-0001"]
