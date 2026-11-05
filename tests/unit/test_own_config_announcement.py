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
from scripts.core.scan_timings import OwnConfig, State
from scripts.core.tool_descriptors import DESCRIPTORS, Invocation, ScanContext
from scripts.core.tool_runner import ToolResult
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

    @pytest.mark.parametrize(
        ("toml", "expected"),
        [
            # Measured with osv-scanner 2.7.0 on the frozen database: a past
            # date kept left-pad's advisory, a future one dropped it.
            (
                b'[[IgnoredVulns]]\nid = "JMO-TEST-2026-0001"\n'
                b"ignoreUntil = 2020-01-01\n",
                None,
            ),
            (
                b'[[IgnoredVulns]]\nid = "JMO-TEST-2026-0001"\n'
                b"ignoreUntil = 2020-01-01T00:00:00Z\n",
                None,
            ),
            (
                b'[[IgnoredVulns]]\nid = "JMO-TEST-2026-0001"\n'
                b"ignoreUntil = 2999-01-01\n",
                "1 ignored vulnerability and 0 ignored packages suppress findings",
            ),
            (
                b'[[PackageOverrides]]\nname = "left-pad"\necosystem = "npm"\n'
                b"ignore = true\neffectiveUntil = 2020-01-01\n",
                None,
            ),
            (
                b'[[PackageOverrides]]\nname = "left-pad"\necosystem = "npm"\n'
                b"ignore = true\neffectiveUntil = 2999-01-01\n",
                "0 ignored vulnerabilities and 1 ignored package suppress findings",
            ),
        ],
        ids=[
            "ignore-expired",
            "ignore-expired-datetime",
            "ignore-active",
            "override-expired",
            "override-active",
        ],
    )
    def test_an_entry_counts_only_until_its_date(
        self, tmp_path, caplog, toml, expected
    ) -> None:
        """An expired `ignoreUntil` or `effectiveUntil` was counted as
        suppressing while osv-scanner kept the finding (#1433)."""
        said = _osv(
            tmp_path,
            {"package-lock.json": NPM_LOCK, "osv-scanner.toml": toml},
            ["package-lock.json"],
            caplog,
        )

        (line,) = said
        if expected is None:
            assert "suppress" not in line, line
            assert "it ignores no vulnerability and no package" in line
        else:
            assert line.endswith(f"({expected})"), line

    @pytest.mark.parametrize(
        ("selectors", "scope"),
        [
            (b'ecosystem = "npm"\n', "an override that ignores every npm package"),
            (b"", "an override that ignores every package"),
            (
                b'ecosystem = "Maven"\ngroup = "org.example"\n',
                "an override that ignores every Maven package matching its "
                "version or group",
            ),
        ],
        ids=["ecosystem", "everything", "group"],
    )
    def test_an_override_without_a_name_says_what_it_ignores(
        self, tmp_path, caplog, selectors, scope
    ) -> None:
        """Without `name` an override selects every package its other fields
        do: osv-scanner 2.7.0 dropped left-pad's advisory for `ecosystem =
        "npm"` and for no selector at all. It was announced as "1 ignored
        package" (#1433)."""
        toml = b"[[PackageOverrides]]\n" + selectors + b"ignore = true\n"
        said = _osv(
            tmp_path,
            {"package-lock.json": NPM_LOCK, "osv-scanner.toml": toml},
            ["package-lock.json"],
            caplog,
        )

        (line,) = said
        assert line.endswith(
            f"(0 ignored vulnerabilities, 0 ignored packages and {scope} "
            "suppress findings)"
        ), line

    def test_nameless_overrides_with_one_scope_are_counted_together(
        self, tmp_path, caplog
    ) -> None:
        override = b'[[PackageOverrides]]\necosystem = "npm"\nignore = true\n'
        said = _osv(
            tmp_path,
            {
                "package-lock.json": NPM_LOCK,
                "osv-scanner.toml": override + b"\n" + override,
            },
            ["package-lock.json"],
            caplog,
        )

        (line,) = said
        assert "and 2 overrides that ignore every npm package suppress" in line

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


# --- what is announced is recorded on the row (#1430) -------------------------


SCRIPT = b"#!/bin/bash\necho $1\n"
DOCKERFILE = b"FROM ubuntu:latest\nRUN apt-get update && apt-get install -y curl\n"


def _walked(tmp_path: Path, tool: str, files: dict[str, bytes], handed: list[str]):
    """The announcement a walk-fed tool's row makes for `handed` files."""
    repo = tmp_path / "repo"
    _plant(repo, files)
    ctx = ScanContext(
        tool=tool,
        target_type="repo",
        target=repo,
        out_dir=tmp_path,
        files=tuple(str(repo / f) for f in handed),
    )
    return tool_loop._announce_own_config(DESCRIPTORS[tool], ctx)


class TestShellcheckDiscovery:
    """shellcheck reads `.shellcheckrc` or `shellcheckrc` from each script's
    directory and its parents (measured, 0.11.0: a root `disable=SC2086`
    silenced a script in a subdirectory). Unannounced, a repository could
    switch checks off (#1574)."""

    @pytest.mark.parametrize("name", [".shellcheckrc", "shellcheckrc"])
    def test_an_rc_at_the_root_is_named_for_a_script_below_it(self, tmp_path, name):
        found = _walked(
            tmp_path,
            "shellcheck",
            {"tools/s.sh": SCRIPT, name: b"disable=SC2086\n"},
            ["tools/s.sh"],
        )

        assert found == (OwnConfig(name, "its audit settings apply"),)

    def test_an_rc_beside_a_script_is_named_by_its_path(self, tmp_path):
        found = _walked(
            tmp_path,
            "shellcheck",
            {"tools/s.sh": SCRIPT, "tools/.shellcheckrc": b"disable=SC2086\n"},
            ["tools/s.sh"],
        )

        assert found == (OwnConfig("tools/.shellcheckrc", "its audit settings apply"),)

    def test_an_rc_no_script_reaches_is_not_named(self, tmp_path):
        """shellcheck looks up from a script, never down or sideways."""
        found = _walked(
            tmp_path,
            "shellcheck",
            {"s.sh": SCRIPT, "docs/.shellcheckrc": b"disable=SC2086\n"},
            ["s.sh"],
        )

        assert found is None


class TestHadolintAndTrivyReadTheirTarget:
    """hadolint reads `.hadolint.yaml` / `.hadolint.yml`, and trivy `trivy.yaml`
    and `.trivyignore`, from the directory they run in, and from nowhere else
    (measured: hadolint 2.15.1; trivy 0.74.0, which ignored `.trivyignore.yaml`,
    `trivy.yml` and a subdirectory's `.trivyignore`). They ran in jmo's own
    directory: launched from the repository the findings dropped unannounced,
    launched elsewhere a stray file there applied to every target (#1574).
    Now they run from the target, whose files are announced, or from JMo's
    output folder, which holds none."""

    @pytest.mark.parametrize(
        ("tool", "name", "handed"),
        [
            ("hadolint", ".hadolint.yaml", ["Dockerfile"]),
            ("hadolint", ".hadolint.yml", ["Dockerfile"]),
            ("trivy", "trivy.yaml", []),
            ("trivy", ".trivyignore", []),
        ],
    )
    def test_a_config_at_the_root_is_named(self, tmp_path, tool, name, handed):
        found = _walked(
            tmp_path, tool, {"Dockerfile": DOCKERFILE, name: b"x: 1\n"}, handed
        )

        assert found == (OwnConfig(name, "its audit settings apply"),)

    @staticmethod
    def _invocation(tmp_path: Path, tool: str, key: str, target, **kw) -> Invocation:
        ctx = ScanContext(
            tool=tool,
            target_type=key,
            target=target,
            out_dir=Path("relative-out"),
            binary=f"/opt/{tool}",
            **kw,
        )
        (inv,) = DESCRIPTORS[tool].invocations[key](ctx)
        return inv

    def test_trivy_scans_a_repository_from_inside_it(self, tmp_path, monkeypatch):
        """Given as `--repo .` it stays relative, so every path JMo passes is
        absolute: the target is `.` from its root, the output JMo's own."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "repo").mkdir()
        inv = self._invocation(tmp_path, "trivy", "repo", Path("repo"))

        assert inv.cwd == (tmp_path / "repo").resolve()
        assert inv.command[-3:] == (
            ".",
            "-o",
            str((tmp_path / "relative-out" / "trivy.json").absolute()),
        )

    @pytest.mark.parametrize(
        ("key", "target"),
        [
            ("image", "nginx:1.27"),
            ("iac", Path("iac/main.tf")),
            ("k8s", {"context": "kind", "namespace": "default"}),
        ],
    )
    def test_trivy_runs_anything_else_from_jmos_own_folder(
        self, tmp_path, monkeypatch, key, target
    ):
        monkeypatch.chdir(tmp_path)
        inv = self._invocation(tmp_path, "trivy", key, target)

        assert inv.cwd == (tmp_path / "relative-out").absolute()
        assert str((tmp_path / "relative-out" / "trivy.json").absolute()) in (
            inv.command
        )
        if key == "iac":
            assert str((tmp_path / "iac" / "main.tf").absolute()) in inv.command

    def test_hadolint_runs_from_its_target_with_absolute_files(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "repo").mkdir()
        inv = self._invocation(
            tmp_path, "hadolint", "repo", Path("repo"), files=("repo/Dockerfile",)
        )

        assert inv.cwd == (tmp_path / "repo").resolve()
        assert inv.command[-1] == str((tmp_path / "repo" / "Dockerfile").absolute())


class TestTheRowRecordsIt:
    """The announcement was a console line only, so `findings.json`, history
    and a teammate reading the artifacts saw fewer findings with no hint that
    the repository had switched some off (#1430)."""

    def test_what_is_announced_is_returned_for_the_row(self, tmp_path) -> None:
        repo = tmp_path / "repo"
        _plant(
            repo,
            {
                "package-lock.json": NPM_LOCK,
                "osv-scanner.toml": TOML_TWO_AND_ONE,
                "api/package-lock.json": NPM_LOCK,
                "api/osv-scanner.toml": b"",
            },
        )
        ctx = ScanContext(
            tool="osv-scanner",
            target_type="repo",
            target=repo,
            out_dir=tmp_path,
            files=(
                str(repo / "package-lock.json"),
                str(repo / "api/package-lock.json"),
            ),
        )

        found = tool_loop._announce_own_config(DESCRIPTORS["osv-scanner"], ctx)

        assert found == (
            OwnConfig(
                "osv-scanner.toml",
                "2 ignored vulnerabilities and 1 ignored package suppress findings",
            ),
            OwnConfig(
                "api/osv-scanner.toml", "it ignores no vulnerability and no package"
            ),
        )

    def test_nothing_read_is_none(self, tmp_path) -> None:
        repo = tmp_path / "repo"
        _plant(repo, {"package-lock.json": NPM_LOCK})
        ctx = ScanContext(
            tool="osv-scanner",
            target_type="repo",
            target=repo,
            out_dir=tmp_path,
            files=(str(repo / "package-lock.json"),),
        )

        assert tool_loop._announce_own_config(DESCRIPTORS["osv-scanner"], ctx) is None

    def test_a_config_that_resolves_outside_the_target_is_named_by_its_name(
        self, tmp_path, caplog
    ) -> None:
        """The row reaches `findings.json`, history and the artifacts people
        share, which keep no host path (#1007); the log line may. A symlink
        to a shared config resolves outside the target."""
        shared = tmp_path / "shared" / "zizmor.yml"
        _plant(tmp_path / "shared", {"zizmor.yml": b"rules: {}\n"})
        repo = tmp_path / "repo"
        repo.mkdir()
        try:
            (repo / "zizmor.yml").symlink_to(shared)
        except OSError:
            pytest.skip("this platform cannot create a symlink here")
        ctx = ScanContext(
            tool="zizmor", target_type="repo", target=repo, out_dir=tmp_path
        )

        with caplog.at_level(logging.INFO):
            found = tool_loop._announce_own_config(DESCRIPTORS["zizmor"], ctx)

        assert found == (OwnConfig("zizmor.yml", "its audit settings apply"),)

    @pytest.mark.parametrize(
        ("tool", "files", "expected"),
        [
            (
                "zizmor",
                {
                    ".github/workflows/ci.yml": b"on: push\njobs: {}\n",
                    ".github/zizmor.yml": b"rules: {}\n",
                },
                [{"file": ".github/zizmor.yml", "detail": "its audit settings apply"}],
            ),
            (
                "checkov",
                {"main.tf": TF, ".checkov.yaml": CHECKOV_SKIPS},
                [{"file": ".checkov.yaml", "detail": "its audit settings apply"}],
            ),
            (
                "gitleaks",
                {
                    "app.py": b"x = 1\n",
                    ".gitleaks.toml": b"[extend]\nuseDefault = true\n",
                },
                [
                    {
                        "file": ".gitleaks.toml",
                        "detail": "its rules and allowlists apply",
                    }
                ],
            ),
            ("zizmor", {".github/workflows/ci.yml": b"on: push\njobs: {}\n"}, None),
            ("gitleaks", {"app.py": b"x = 1\n"}, None),
        ],
    )
    def test_the_row_and_scan_timings_carry_it(
        self, tmp_path, caplog, tool, files, expected
    ) -> None:
        """Through the loop, not the helper: the row is what every artifact
        is written from, so a value the helper returns and the loop drops
        reaches none of them."""
        repo = tmp_path / "repo"
        _plant(repo, files)
        out = tmp_path / "out"
        out.mkdir()
        d = DESCRIPTORS[tool]

        class Runner:
            def __init__(self, tools, progress_callback=None):
                self.tools = tools

            def run_all_parallel(self):
                results = []
                for definition in self.tools:
                    Path(definition.output_file).write_bytes(
                        json.dumps(d.stub).encode()
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

        with caplog.at_level(logging.INFO):
            rows = tool_loop.run_tools(
                tools=[tool],
                target_type="repo",
                target=repo,
                target_label="repo",
                out_dir=out,
                timeout=60,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
                runner_cls=Runner,
                find_tool_func=lambda name: f"/bin/{name}",
                repo_root=repo,
            )

        row = rows[tool]
        doc = json.loads((out / "scan-timings.json").read_bytes())
        (written,) = doc["tools"]
        assert written["own_config"] == expected, (row, written)
        assert (
            None if row.own_config is None else [c._asdict() for c in row.own_config]
        ) == expected
        if expected:
            # Said on the console too, at WARNING, as for the other tools:
            # gitleaks' line was INFO, which a default scan hides.
            (line,) = _announced(caplog, tool)
            assert expected[0]["file"] in line


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
        assert row.own_config is None

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
    assert row.own_config == (
        OwnConfig(
            "osv-scanner.toml",
            "1 ignored vulnerability and 0 ignored packages suppress findings",
        ),
    )


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
    assert row.own_config == (OwnConfig(".checkov.yaml", "its audit settings apply"),)


@pytest.mark.requires_tools
@pytest.mark.parametrize(
    ("tool", "files", "config", "code"),
    [
        (
            "hadolint",
            {"Dockerfile": DOCKERFILE},
            (".hadolint.yaml", b"ignored:\n  - DL3007\n"),
            "DL3007",
        ),
        ("shellcheck", {"s.sh": SCRIPT}, (".shellcheckrc", b"disable=SC2086\n"), 2086),
    ],
    ids=["hadolint", "shellcheck"],
)
def test_real_tools_read_the_targets_config_not_the_launch_directorys(
    tmp_path, caplog, monkeypatch, tool, files, config, code
) -> None:
    """hadolint read `.hadolint.yaml` from wherever jmo was launched, so a
    stray one there applied to every target, and from the repository's root
    only when launched there; shellcheck read the repository's rc unannounced
    (#1574). Launched from a directory holding the config, nothing changes;
    the target's own config applies and is named."""
    if find_tool(tool) is None:
        pytest.skip(f"{tool} is not installed")

    def codes(out: Path) -> set:
        return {d["code"] for d in json.loads((out / f"{tool}.json").read_bytes())}

    name, body = config
    launch = tmp_path / "launch"
    _plant(launch, {name: body})
    monkeypatch.chdir(launch)

    with caplog.at_level(logging.INFO):
        row, out = _scan(tmp_path, tool, files, "a")
        assert row.state is State.RAN, row
        assert code in codes(out)
        assert row.own_config is None

        row, out = _scan(tmp_path, tool, {**files, name: body}, "b")

    assert row.state is State.RAN, row
    assert code not in codes(out)
    assert row.own_config == (OwnConfig(name, "its audit settings apply"),)


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
