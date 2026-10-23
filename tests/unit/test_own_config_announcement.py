"""A scanned repository's own tool configuration is announced (#1414, #1363's class).

osv-scanner reads an `osv-scanner.toml` from the directory of every lockfile it
is handed, and nowhere else (measured, 2.6.0: not the parent, not a child, and
no flag stops it). A toml ignoring a lockfile's advisories took a scan from 4
findings to 0, row `ran`, with nothing said. checkov, run from its target,
reads a `.checkov.yaml` / `.checkov.yml` there (3.3.16: the `-d` target's root,
or the directory of the single file given with `-f`; not a subdirectory, not a
parent). JMo does not override either: honouring the repository's own settings
is each tool's documented behaviour and the choice is the user's, but the scan
says which file decided part of its audit.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from scripts.cli.scan_jobs import tool_loop
from scripts.core import osv_database
from scripts.core.scan_timings import State
from scripts.core.tool_descriptors import DESCRIPTORS, ScanContext
from scripts.core.tool_utils import find_tool

ROOT = Path(__file__).resolve().parents[2]
FROZEN_DB = ROOT / "tests" / "fixtures" / "osv-db"

NPM_LOCK = json.dumps(
    {
        "name": "app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {"name": "app", "version": "1.0.0"},
            # `resolved`, as npm writes it for a registry package: from 2.7.0
            # osv-scanner skips an entry without one as a local package and
            # finds nothing (osv-scalibr#2414, measured).
            "node_modules/left-pad": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz",
            },
        },
    }
).encode()

TOML_TWO_AND_ONE = (
    b'[[IgnoredVulns]]\nid = "JMO-TEST-2026-0001"\nreason = "fixture"\n\n'
    b'[[IgnoredVulns]]\nid = "JMO-TEST-2026-0002"\nreason = "fixture"\n\n'
    b'[[PackageOverrides]]\nname = "left-pad"\necosystem = "npm"\nignore = true\n'
)
TOML_IGNORES_THE_TEST_ADVISORY = (
    b'[[IgnoredVulns]]\nid = "JMO-TEST-2026-0001"\nreason = "fixture"\n'
)
TF = b'resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'
# Checks the bucket above fails; skipping them all empties the report.
CHECKOV_SKIPS = b"skip-check:\n" + b"".join(
    f"  - {c}\n".encode()
    for c in (
        "CKV_AWS_18",
        "CKV_AWS_21",
        "CKV_AWS_144",
        "CKV_AWS_145",
        "CKV2_AWS_6",
        "CKV2_AWS_61",
        "CKV2_AWS_62",
        "CKV2_AWS_67",
    )
)


def _plant(root: Path, files: dict[str, bytes]) -> None:
    for rel, data in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def _announced(caplog, tool: str) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.levelname == "WARNING" and f"{tool} reads its" in r.getMessage()
    ]


def _osv(tmp_path: Path, files: dict[str, bytes], handed: list[str], caplog):
    """The announcement osv-scanner's row makes for `handed` lockfiles."""
    repo = tmp_path / "repo"
    _plant(repo, files)
    ctx = ScanContext(
        tool="osv-scanner",
        target_type="repo",
        target=repo,
        out_dir=tmp_path,
        files=tuple(str(repo / f) for f in handed),
    )
    with caplog.at_level(logging.INFO):
        tool_loop._announce_own_config(DESCRIPTORS["osv-scanner"], ctx)
    return _announced(caplog, "osv-scanner")


class TestOsvScannerDiscovery:
    def test_a_toml_beside_a_lockfile_is_named_with_its_counts(
        self, tmp_path, caplog
    ) -> None:
        said = _osv(
            tmp_path,
            {"package-lock.json": NPM_LOCK, "osv-scanner.toml": TOML_TWO_AND_ONE},
            ["package-lock.json"],
            caplog,
        )

        (line,) = said
        assert "osv-scanner.toml" in line
        assert (
            "2 ignored vulnerabilities and 1 ignored package suppress findings" in line
        )

    def test_the_counts_are_the_files_not_a_constant(self, tmp_path, caplog) -> None:
        said = _osv(
            tmp_path,
            {
                "package-lock.json": NPM_LOCK,
                "osv-scanner.toml": TOML_IGNORES_THE_TEST_ADVISORY,
            },
            ["package-lock.json"],
            caplog,
        )

        (line,) = said
        assert (
            "1 ignored vulnerability and 0 ignored packages suppress findings" in line
        )

    @pytest.mark.parametrize(
        ("override", "counted"),
        [
            # Measured with osv-scanner 2.6.0 on the frozen database: these two
            # dropped left-pad's advisory...
            (b"ignore = true\n", 1),
            (b"vulnerability.ignore = true\n", 1),
            # ...and these did not: the finding came back.
            (b"ignore = false\n", 0),
            (b'license.override = ["MIT"]\n', 0),
        ],
    )
    def test_only_an_override_that_ignores_is_counted(
        self, tmp_path, caplog, override, counted
    ) -> None:
        """Every `[[PackageOverrides]]` entry was counted as suppressing:
        `ignore = false` was announced as "1 package override suppress
        findings" while the finding came back."""
        toml = (
            b'[[PackageOverrides]]\nname = "left-pad"\necosystem = "npm"\n' + override
        )
        said = _osv(
            tmp_path,
            {"package-lock.json": NPM_LOCK, "osv-scanner.toml": toml},
            ["package-lock.json"],
            caplog,
        )

        (line,) = said
        if counted:
            assert "0 ignored vulnerabilities and 1 ignored package suppress" in line
        else:
            assert "suppress" not in line
            assert "it ignores no vulnerability and no package" in line

    def test_a_file_that_ignores_nothing_is_named_but_suppresses_nothing(
        self, tmp_path, caplog
    ) -> None:
        """An empty file read "0 ignored vulnerabilities and 0 package
        overrides suppress findings". osv-scanner still reads it, so it is
        named."""
        said = _osv(
            tmp_path,
            {"package-lock.json": NPM_LOCK, "osv-scanner.toml": b""},
            ["package-lock.json"],
            caplog,
        )

        (line,) = said
        assert line.endswith(
            "osv-scanner reads its osv-scanner.toml "
            "(it ignores no vulnerability and no package)"
        )

    def test_a_toml_beside_a_lockfile_in_a_subdirectory_is_named_by_its_path(
        self, tmp_path, caplog
    ) -> None:
        said = _osv(
            tmp_path,
            {
                "api/package-lock.json": NPM_LOCK,
                "api/osv-scanner.toml": TOML_TWO_AND_ONE,
            },
            ["api/package-lock.json"],
            caplog,
        )

        (line,) = said
        assert "api/osv-scanner.toml" in line

    @pytest.mark.parametrize(
        ("files", "handed"),
        [
            # osv-scanner looks in a lockfile's own directory only (measured):
            # the parent's toml is not read for a lockfile below it...
            (
                {
                    "api/package-lock.json": NPM_LOCK,
                    "osv-scanner.toml": TOML_TWO_AND_ONE,
                },
                ["api/package-lock.json"],
            ),
            # ...nor a child's for a lockfile above it.
            (
                {
                    "package-lock.json": NPM_LOCK,
                    "api/osv-scanner.toml": TOML_TWO_AND_ONE,
                },
                ["package-lock.json"],
            ),
            # No toml at all.
            ({"package-lock.json": NPM_LOCK}, ["package-lock.json"]),
            # A toml beside a lockfile JMo did not hand over (left out because
            # its ecosystem has no offline database): osv-scanner never sees it.
            (
                {
                    "package-lock.json": NPM_LOCK,
                    "native/Cargo.lock": b"version = 3\n",
                    "native/osv-scanner.toml": TOML_TWO_AND_ONE,
                },
                ["package-lock.json"],
            ),
        ],
    )
    def test_a_toml_osv_scanner_does_not_read_is_not_announced(
        self, tmp_path, caplog, files, handed
    ) -> None:
        assert _osv(tmp_path, files, handed, caplog) == []

    def test_each_directory_is_announced_once_however_many_lockfiles_it_holds(
        self, tmp_path, caplog
    ) -> None:
        said = _osv(
            tmp_path,
            {
                "package-lock.json": NPM_LOCK,
                "requirements.txt": b"urllib3==1.25.0\n",
                "osv-scanner.toml": TOML_TWO_AND_ONE,
                "api/package-lock.json": NPM_LOCK,
                "api/osv-scanner.toml": TOML_IGNORES_THE_TEST_ADVISORY,
            },
            ["package-lock.json", "requirements.txt", "api/package-lock.json"],
            caplog,
        )

        assert len(said) == 2
        assert sum("api/osv-scanner.toml" in m for m in said) == 1

    def test_a_toml_that_does_not_parse_is_announced_as_unreadable(
        self, tmp_path, caplog
    ) -> None:
        said = _osv(
            tmp_path,
            {
                "package-lock.json": NPM_LOCK,
                "osv-scanner.toml": b"[[IgnoredVulns\nid =",
            },
            ["package-lock.json"],
            caplog,
        )

        (line,) = said
        assert "osv-scanner.toml" in line
        assert "could not be parsed" in line


def _checkov(
    tmp_path: Path, target_type: str, files: dict[str, bytes], target: str, caplog
):
    root = tmp_path / "t"
    _plant(root, files)
    ctx = ScanContext(
        tool="checkov",
        target_type=target_type,
        target=root / target if target else root,
        out_dir=tmp_path,
    )
    with caplog.at_level(logging.INFO):
        tool_loop._announce_own_config(DESCRIPTORS["checkov"], ctx)
    return _announced(caplog, "checkov")


class TestCheckovDiscovery:
    @pytest.mark.parametrize("name", [".checkov.yaml", ".checkov.yml"])
    def test_a_repository_config_at_the_target_root_is_named(
        self, tmp_path, caplog, name
    ) -> None:
        said = _checkov(
            tmp_path, "repo", {"main.tf": TF, name: CHECKOV_SKIPS}, "", caplog
        )

        (line,) = said
        assert name in line

    def test_a_config_in_a_subdirectory_is_not_read_so_not_announced(
        self, tmp_path, caplog
    ) -> None:
        said = _checkov(
            tmp_path,
            "repo",
            {"main.tf": TF, "sub/.checkov.yaml": CHECKOV_SKIPS},
            "",
            caplog,
        )

        assert said == []

    @pytest.mark.parametrize("name", [".checkov.yaml", ".checkov.yml"])
    def test_a_single_iac_file_reads_the_config_in_its_own_directory(
        self, tmp_path, caplog, name
    ) -> None:
        said = _checkov(
            tmp_path,
            "iac",
            {"sub/main.tf": TF, f"sub/{name}": CHECKOV_SKIPS},
            "sub/main.tf",
            caplog,
        )

        (line,) = said
        assert name in line

    def test_a_single_iac_file_does_not_read_its_parents_config(
        self, tmp_path, caplog
    ) -> None:
        said = _checkov(
            tmp_path,
            "iac",
            {"sub/main.tf": TF, ".checkov.yaml": CHECKOV_SKIPS},
            "sub/main.tf",
            caplog,
        )

        assert said == []


# --- the real binaries, through the scan loop ---------------------------------


def _scan(tmp_path: Path, tool: str, files: dict[str, bytes], name: str):
    from scripts.core.tool_runner import ToolRunner

    repo = tmp_path / name
    _plant(repo, files)
    out = tmp_path / f"out-{name}"
    out.mkdir()
    rows = tool_loop.run_tools(
        tools=[tool],
        target_type="repo",
        target=repo,
        target_label=name,
        out_dir=out,
        timeout=300,
        retries=0,
        per_tool_config={},
        allow_missing_tools=False,
        runner_cls=ToolRunner,
        repo_root=repo,
    )
    return rows[tool], out


def _osv_ids(out: Path) -> list[str]:
    runs = json.loads((out / "osv-scanner.json").read_bytes())["runs"]
    return sorted(r["ruleId"] for run in runs for r in run["results"])


@pytest.mark.requires_tools
def test_real_osv_scanner_obeys_the_repositorys_toml_and_the_scan_says_so(
    tmp_path, caplog, monkeypatch
) -> None:
    """The probe of #1414 against the binary: findings 1 -> 0, row `ran`, and now
    the toml and its count are named."""
    if find_tool("osv-scanner") is None:
        pytest.skip("osv-scanner is not installed")
    monkeypatch.setattr(osv_database, "cache_dir", lambda: FROZEN_DB)
    with caplog.at_level(logging.INFO):
        row, out = _scan(tmp_path, "osv-scanner", {"package-lock.json": NPM_LOCK}, "a")
        assert row.state is State.RAN, row
        assert _osv_ids(out) == ["JMO-TEST-2026-0001"]
        assert _announced(caplog, "osv-scanner") == []

        caplog.clear()
        row, out = _scan(
            tmp_path,
            "osv-scanner",
            {
                "package-lock.json": NPM_LOCK,
                "osv-scanner.toml": TOML_IGNORES_THE_TEST_ADVISORY,
            },
            "b",
        )

    assert row.state is State.RAN, row
    assert _osv_ids(out) == []
    (line,) = _announced(caplog, "osv-scanner")
    assert "osv-scanner.toml" in line
    assert "1 ignored vulnerability" in line


@pytest.mark.requires_tools
def test_real_checkov_obeys_the_repositorys_config_and_the_scan_says_so(
    tmp_path, caplog
) -> None:
    """Run from its target (`-d .`), checkov reads `.checkov.yaml` there: its
    failed checks went from 14 to 0 with nothing said (measured, 3.3.16)."""
    if find_tool("checkov") is None:
        pytest.skip("checkov is not installed")

    def failed(out: Path) -> int:
        data = json.loads((out / "checkov.json").read_bytes())
        data = data[0] if isinstance(data, list) else data
        return len(data["results"]["failed_checks"])

    with caplog.at_level(logging.INFO):
        row, out = _scan(tmp_path, "checkov", {"main.tf": TF}, "a")
        assert row.state is State.RAN, row
        before = failed(out)
        assert before > 0
        assert _announced(caplog, "checkov") == []

        caplog.clear()
        row, out = _scan(
            tmp_path, "checkov", {"main.tf": TF, ".checkov.yaml": CHECKOV_SKIPS}, "b"
        )

    assert row.state is State.RAN, row
    assert failed(out) < before
    (line,) = _announced(caplog, "checkov")
    assert ".checkov.yaml" in line


def test_the_announcement_reaches_a_scan_at_its_default_log_level(
    tmp_path, capsys
) -> None:
    """`jmo scan` configures the `scripts` logger at WARNING unless told
    otherwise, so an INFO announcement was invisible by default: a repository
    could still switch findings off with nothing said. A repository's own
    configuration shaping a security scan's results is a warning."""
    import argparse

    from scripts.cli import jmo

    repo = tmp_path / "repo"
    _plant(repo, {"package-lock.json": NPM_LOCK, "osv-scanner.toml": TOML_TWO_AND_ONE})
    ctx = ScanContext(
        tool="osv-scanner",
        target_type="repo",
        target=repo,
        out_dir=tmp_path,
        files=(str(repo / "package-lock.json"),),
    )
    jmo.configure_scan_logging(argparse.Namespace(log_level=None, human_logs=False))
    try:
        tool_loop._announce_own_config(DESCRIPTORS["osv-scanner"], ctx)
    finally:
        jmo.reset_scan_logging()

    assert "osv-scanner reads its osv-scanner.toml" in capsys.readouterr().err
