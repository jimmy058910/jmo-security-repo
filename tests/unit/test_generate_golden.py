"""`scripts/dev/generate_golden.py` captures a golden fixture through `jmo scan`
(v2.0.0 Phase 6, Task F1).

A fixture written from a hand-kept command line is a mirror of the descriptor,
and #1349 measured the drift (trivy's still read `vuln,secret,misconfig`). So
the generator runs `jmo scan --tools <tool>` on a sample and keeps what the
scan wrote. These tests drive it against a fake `jmo` that writes a results
tree the way a scan does, so they run everywhere; one `requires_tools` test
captures shellcheck for real.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts.core.tool_registry import TOOL_MATRIX
from scripts.dev import generate_golden as gg

ROOT = Path(__file__).resolve().parents[2]


def _hadolint_raw(work: Path) -> list[dict]:
    dockerfile = str(work / "target" / "Dockerfile")
    return [
        {
            "code": "DL3006",
            "column": 1,
            "file": dockerfile,
            "level": "warning",
            "line": 9,
            "message": "Always tag the version of an image explicitly",
        },
        {
            "code": "DL3015",
            "column": 1,
            "file": dockerfile,
            "level": "info",
            "line": 12,
            "message": "Avoid additional packages",
        },
    ]


class FakeJmo:
    """Stands in for `jmo scan` and `jmo tools check --json`: writes the one
    target directory a repo scan writes, its row and the tool's output."""

    def __init__(self, raw=None, state: str = "ran", reason: str | None = None):
        self.raw = raw
        self.state = state
        self.reason = reason
        self.calls: list[list[str]] = []

    def __call__(self, args, *, env, cwd, timeout):
        self.calls.append(list(args))
        if args[:2] == ["tools", "check"]:
            tool = args[2]
            binary = Path(cwd) / "fake-binary"
            binary.write_bytes(b"#!/bin/sh\n")
            out = {
                "tools": {
                    tool: {"installed_version": "9.9.9", "binary_path": str(binary)}
                }
            }
            return subprocess.CompletedProcess(args, 0, json.dumps(out), "")
        assert args[0] == "scan"
        tool = args[args.index("--tools") + 1]
        results = Path(args[args.index("--results-dir") + 1])
        target = Path(args[args.index("--repo") + 1])
        out_dir = results / "individual-repos" / target.name
        out_dir.mkdir(parents=True)
        row = {"tool": tool, "state": self.state, "reason": self.reason}
        (out_dir / "scan-timings.json").write_bytes(
            json.dumps({"schema_version": 5, "tools": [row]}).encode()
        )
        if self.state == "ran":
            raw = self.raw(Path(cwd)) if callable(self.raw) else self.raw
            data = (
                raw
                if isinstance(raw, bytes)
                else json.dumps(raw, indent=2).encode()  # as a tool writes it
            )
            (out_dir / f"{tool}.json").write_bytes(data)
        return subprocess.CompletedProcess(args, 0, "", "")


@pytest.fixture
def golden(tmp_path) -> Path:
    path = tmp_path / "golden"
    path.mkdir()
    return path


def _capture(tmp_path, monkeypatch, fake, tool="hadolint"):
    monkeypatch.setattr(gg, "run_jmo", fake)
    work = (tmp_path / "work").resolve()
    return gg.capture(tool, home=tmp_path / "home", work=work), work


# --- the table --------------------------------------------------------------------


def test_every_matrix_tool_has_a_capture_and_nothing_else_does() -> None:
    # A tool joining TOOL_MATRIX with no way to capture its golden is the gap
    # #1097 measured (6 registered tools generated no test at all).
    assert set(gg.CAPTURES) == set(TOOL_MATRIX)


def test_every_sample_a_capture_names_is_tracked() -> None:
    named = {s for c in gg.CAPTURES.values() for s in c.samples}
    assert named, "no capture names a sample"
    for sample in named:
        assert (gg.SAMPLES_DIR / sample).is_dir(), sample


def test_a_url_capture_names_no_sample_and_a_repo_capture_has_a_target() -> None:
    for tool, c in gg.CAPTURES.items():
        if c.url:
            assert not c.samples, tool
        else:
            assert c.samples or c.prepare, tool


def test_the_fixture_directory_is_the_adapter_name_the_report_looks_up() -> None:
    # One name mapping: the report finds an output's adapter by
    # `tool.replace("-", "_")` (`count_findings`), so the directory is that.
    assert gg.fixture_dir_name("osv-scanner") == "osv_scanner"
    assert gg.fixture_dir_name("jmo-native") == "jmo_native"
    assert gg.fixture_dir_name("trivy") == "trivy"


# --- one capture ------------------------------------------------------------------


def test_a_capture_keeps_the_scans_output_with_the_work_directory_rewritten(
    tmp_path, monkeypatch
) -> None:
    captured, work = _capture(tmp_path, monkeypatch, FakeJmo(_hadolint_raw))

    raw = captured.raw.decode()
    assert str(work) not in raw
    assert json.dumps(str(work))[1:-1] not in raw
    assert f'"{gg.PLACEHOLDER}' in raw
    assert captured.version == "9.9.9"
    assert len(captured.findings) == 2
    assert {f["ruleId"] for f in captured.findings} == {"DL3006", "DL3015"}
    # The adapter read the rewritten bytes, not the scan's own.
    assert all(
        f["location"]["path"].startswith(gg.PLACEHOLDER) for f in captured.findings
    )


def test_the_json_escaped_spelling_of_the_work_directory_is_rewritten_too(
    tmp_path, monkeypatch
) -> None:
    def raw(work: Path) -> bytes:
        # A Windows-style escaped path, as a JSON writer spells one: the rule
        # is the work directory's own JSON spelling, whatever the platform.
        escaped = json.dumps(str(work))[1:-1]
        return (
            b'[{"code": "DL3006", "column": 1, "file": "%s/target/Dockerfile", "level": "warning", "line": 9, "message": "m"}]'
            % escaped.encode()
        )

    captured, work = _capture(tmp_path, monkeypatch, FakeJmo(raw))
    assert json.dumps(str(work))[1:-1] not in captured.raw.decode()


def test_the_raw_output_is_what_the_whitespace_hooks_would_commit(
    tmp_path, monkeypatch
) -> None:
    # trailing-whitespace and end-of-file-fixer rewrote zap's report and three
    # outputs with no final newline (measured): a fixture the hooks change no
    # longer matches its recorded hash. Whitespace at a line's end is never
    # inside a JSON string, so removing it changes no value.
    def raw(work: Path) -> bytes:
        return (
            json.dumps(_hadolint_raw(work), indent=2).replace(",\n", ",   \n").encode()
        )

    captured, _ = _capture(tmp_path, monkeypatch, FakeJmo(raw))

    assert captured.raw.endswith(b"\n")
    assert not any(line != line.rstrip() for line in captured.raw.decode().splitlines())
    assert len(captured.findings) == 2


def test_the_capture_home_reads_as_the_placeholder_home(tmp_path, monkeypatch) -> None:
    # syft records its Go and Maven caches under HOME (measured, 1.55.0), and a
    # HOME given with --home is not under the work directory.
    home = tmp_path / "prepared-home"

    def raw(work: Path) -> list[dict]:
        found = _hadolint_raw(work)
        found[0]["message"] = f"cache {home / 'go' / 'pkg' / 'mod'}"
        return found

    monkeypatch.setattr(gg, "run_jmo", FakeJmo(raw))
    captured = gg.capture("hadolint", home=home, work=(tmp_path / "work").resolve())

    assert str(home) not in captured.raw.decode()
    assert f"{gg.PLACEHOLDER}/home" in captured.raw.decode()


def test_a_capture_naming_the_developers_own_home_is_refused(
    tmp_path, monkeypatch
) -> None:
    developer = tmp_path / "developer"
    monkeypatch.setattr(Path, "home", staticmethod(lambda: developer))

    def raw(work: Path) -> list[dict]:
        found = _hadolint_raw(work)
        found[0]["message"] = f"cache {developer / '.cache' / 'trivy'}"
        return found

    with pytest.raises(gg.CaptureError, match="home"):
        _capture(tmp_path, monkeypatch, FakeJmo(raw))


def test_a_row_that_did_not_run_is_refused_naming_its_state(
    tmp_path, monkeypatch
) -> None:
    fake = FakeJmo(state="skipped", reason="no Dockerfiles")
    with pytest.raises(gg.CaptureError, match="skipped.*no Dockerfiles"):
        _capture(tmp_path, monkeypatch, fake)


def test_a_capture_with_no_findings_is_refused(tmp_path, monkeypatch) -> None:
    # A fixture of 0 findings guards nothing: semgrep's empty one passed
    # `0 == 0` until Phase 5 removed it (#1097).
    with pytest.raises(gg.CaptureError, match="0 findings"):
        _capture(tmp_path, monkeypatch, FakeJmo([]))


def test_the_scan_is_told_its_tool_config_and_results_and_history_stay_in_work(
    tmp_path, monkeypatch
) -> None:
    fake = FakeJmo(_hadolint_raw)
    _, work = _capture(tmp_path, monkeypatch, fake)

    (scan,) = [c for c in fake.calls if c[0] == "scan"]
    for flag in ("--results-dir", "--history-db", "--config"):
        assert Path(scan[scan.index(flag) + 1]).is_relative_to(work), flag
    assert "--no-store-history" in scan
    assert scan[scan.index("--tools") + 1] == "hadolint"


def test_a_repo_capture_merges_its_samples_at_the_target_root(
    tmp_path, monkeypatch
) -> None:
    # zizmor reads `.github/workflows` at the root only: a sample nested one
    # level down was skipped, "no GitHub Actions workflows" (measured).
    _, work = _capture(tmp_path, monkeypatch, FakeJmo(_hadolint_raw))
    assert (work / "target" / "Dockerfile").is_file()
    assert not (work / "target" / "dockerfile-issues").exists()


def test_trufflehogs_fixture_holds_no_secret_and_the_same_findings(
    tmp_path, monkeypatch
) -> None:
    # Assembled, so this file holds no key-shaped text (detect-private-key).
    header = "-----BEGIN " + "RSA PRIVATE KEY-----"
    pem = f"{header}\nMIIEnotakey\n-----END " + "RSA PRIVATE KEY-----\n"

    def raw(work: Path) -> bytes:
        record = {
            "SourceMetadata": {
                "Data": {
                    "Filesystem": {"file": str(work / "target/deploy.pem"), "line": 1}
                }
            },
            "DetectorName": "PrivateKey",
            "Verified": False,
            "Raw": pem,
            "RawV2": "",
            "Redacted": pem[:40],
            "SecretParts": {"token": pem},
            "ExtraData": {},
            "StructuredData": None,
        }
        return (json.dumps(record) + "\n").encode()

    # The key is generated in the target: no sample of ours is one trufflehog
    # reports (every credential in credential-patterns is a refused shape).
    monkeypatch.setattr(gg, "_generated_key", lambda: pem.encode())
    captured, work = _capture(tmp_path, monkeypatch, FakeJmo(raw), tool="trufflehog")

    assert header.encode() not in captured.raw
    assert b"MIIEnotakey" not in captured.raw
    (finding,) = captured.findings
    assert finding["ruleId"] == "PrivateKey"
    assert finding["location"]["path"].startswith(gg.PLACEHOLDER)
    assert finding["location"]["path"].endswith("deploy.pem")
    assert captured.metadata_extra["stripped"]


def test_scrubbing_that_changed_a_finding_fails_the_capture(
    tmp_path, monkeypatch
) -> None:
    # The guard behind stripping a secret: what the adapter reads from the
    # committed bytes is what it read from the scan's.
    monkeypatch.setattr(gg, "_generated_key", lambda: b"k")
    monkeypatch.setattr(gg, "_scrub", lambda tool, raw: b"")
    record = {
        "SourceMetadata": {"Data": {"Filesystem": {"file": "a.pem", "line": 1}}},
        "DetectorName": "PrivateKey",
        "Raw": "k",
    }
    fake = FakeJmo((json.dumps(record) + "\n").encode())
    with pytest.raises(gg.CaptureError, match="stripping"):
        _capture(tmp_path, monkeypatch, fake, tool="trufflehog")


# --- the fixture on disk ----------------------------------------------------------


def test_a_written_fixture_is_the_three_files_the_golden_test_reads(
    tmp_path, monkeypatch, golden
) -> None:
    captured, _ = _capture(tmp_path, monkeypatch, FakeJmo(_hadolint_raw))
    out = gg.write_fixture("hadolint", captured, golden_dir=golden)

    assert out == golden / "hadolint" / "v9.9.9"
    assert sorted(p.name for p in out.iterdir()) == [
        "expected-findings.json",
        "metadata.json",
        "raw-output.json",
    ]
    meta = json.loads((out / "metadata.json").read_bytes())
    expected = json.loads((out / "expected-findings.json").read_bytes())
    assert meta["finding_count"] == len(expected) == 2
    for key in (
        "tool",
        "version",
        "generated_at",
        "target",
        "command",
        "binary_sha256",
    ):
        assert meta[key], key
    assert meta["recipe"] == gg.CAPTURES["hadolint"].recipe()
    assert (out / "raw-output.json").read_bytes() == captured.raw
    assert b"\r\n" not in (out / "metadata.json").read_bytes()


def test_an_existing_fixture_is_kept_unless_update_is_given(
    tmp_path, monkeypatch, golden
) -> None:
    captured, _ = _capture(tmp_path, monkeypatch, FakeJmo(_hadolint_raw))
    out = gg.write_fixture("hadolint", captured, golden_dir=golden)
    (out / "raw-output.json").write_bytes(b"kept")

    with pytest.raises(gg.CaptureError, match="--update"):
        gg.write_fixture("hadolint", captured, golden_dir=golden)
    assert (out / "raw-output.json").read_bytes() == b"kept"

    gg.write_fixture("hadolint", captured, golden_dir=golden, update=True)
    assert (out / "raw-output.json").read_bytes() == captured.raw


# --- --check ----------------------------------------------------------------------


def _committed(golden: Path, tool: str, version: str, count: int, recipe) -> None:
    out = golden / gg.fixture_dir_name(tool) / f"v{version}"
    out.mkdir(parents=True)
    meta = {"tool": tool, "version": version, "finding_count": count, "recipe": recipe}
    (out / "metadata.json").write_bytes(json.dumps(meta).encode())


def test_check_reports_a_count_change_and_passes(
    tmp_path, monkeypatch, golden, capsys
) -> None:
    monkeypatch.setattr(gg, "run_jmo", FakeJmo(_hadolint_raw))
    _committed(golden, "hadolint", "9.9.9", 5, gg.CAPTURES["hadolint"].recipe())

    rc = gg.check(
        ["hadolint"], home=tmp_path / "home", golden_dir=golden, scratch=tmp_path
    )

    assert rc == 0
    out = capsys.readouterr().out
    assert "hadolint" in out and "5 -> 2" in out


def test_check_fails_when_a_tool_cannot_be_captured(
    tmp_path, monkeypatch, golden, capsys
) -> None:
    # Each tool's real output parses: the purpose of the smoke job this replaces
    # (J6). A tool that did not run is a failure, never a skip.
    monkeypatch.setattr(gg, "run_jmo", FakeJmo(state="failed", reason="exit 2"))

    rc = gg.check(
        ["hadolint"], home=tmp_path / "home", golden_dir=golden, scratch=tmp_path
    )

    assert rc == 1
    assert "FAIL" in capsys.readouterr().out


def test_check_names_a_fixture_another_recipe_made_without_comparing(
    tmp_path, monkeypatch, golden, capsys
) -> None:
    # The four kept fixtures (gitleaks, osv-scanner, zizmor, opengrep) were
    # captured from pinned external targets by bare binaries: their count is
    # not this capture's, and comparing would report a change every night.
    monkeypatch.setattr(gg, "run_jmo", FakeJmo(_hadolint_raw))
    _committed(golden, "hadolint", "1.0.0", 300, None)

    rc = gg.check(
        ["hadolint"], home=tmp_path / "home", golden_dir=golden, scratch=tmp_path
    )

    assert rc == 0
    out = capsys.readouterr().out
    assert "300 -> 2" not in out
    assert "another recipe" in out


def test_run_adapter_never_writes_the_transient_digest(tmp_path) -> None:
    raw = tmp_path / "trufflehog.json"
    raw.write_bytes(
        (
            json.dumps(
                {
                    "SourceMetadata": {
                        "Data": {"Filesystem": {"file": "keys/live.pem", "line": 1}}
                    },
                    "DetectorName": "PrivateKey",
                    "Raw": "not-a-secret-7f3a9c",
                }
            )
            + "\n"
        ).encode()
    )
    (found,) = gg.run_adapter("trufflehog", raw)
    assert "secretDigest" not in found


# --- for real ---------------------------------------------------------------------


@pytest.mark.requires_tools
def test_a_real_shellcheck_capture_parses_to_findings(tmp_path) -> None:
    if (
        shutil.which("shellcheck") is None
        and not (Path.home() / ".jmo" / "bin" / "shellcheck").exists()
    ):
        pytest.skip("shellcheck is not installed")
    work = (tmp_path / "work").resolve()
    home = gg.isolated_home(tmp_path / "home")
    captured = gg.capture("shellcheck", home=home, work=work)

    assert len(captured.findings) > 0
    assert str(work) not in captured.raw.decode()
    assert all(f["tool"]["name"] == "shellcheck" for f in captured.findings)
