import os
from pathlib import Path

import pytest

from scripts.cli.jmo import cmd_ci, cmd_scan


def test_scan_skips_missing_tools_and_runs_available(tmp_path: Path, monkeypatch):
    """Test that scan succeeds with allow_missing_tools=True.

    v1.0.0 Architecture: Missing tools are skipped entirely (no stubs).
    Only available/installed tools produce output files.
    """
    # Read the REAL CI flag before the monkeypatch below sets it for the scan.
    in_ci = os.environ.get("CI") == "true" or os.environ.get("GITHUB_ACTIONS") == "true"

    # Set CI=true to skip interactive prompts
    monkeypatch.setenv("CI", "true")
    # `cmd_scan` unconditionally calls `_show_kofi_reminder()` (#933), which
    # resolves `Path.home()` with no injection point.
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

    # Create two dummy repos
    rbase = tmp_path / "repos"
    r1 = rbase / "repo1"
    r2 = rbase / "repo2"
    r1.mkdir(parents=True)
    r2.mkdir(parents=True)

    class Args:
        repo = None
        repos_dir = str(rbase)
        targets = None
        results_dir = str(tmp_path / "results")
        config = str(tmp_path / "no.yml")
        # Request multiple tools - some may be missing
        tools = [
            "trufflehog",
            "semgrep",
            "syft",
            "trivy",
            "checkov",
            "bandit",
        ]
        timeout = 30  # semgrep takes ~5-10s on empty dirs
        threads = 2
        allow_missing_tools = True

    rc = cmd_scan(Args())
    assert rc == 0, "Scan should succeed even with missing tools"

    # The contract that holds on every machine: a per-repo output directory is
    # created for each discovered repo whether or not any tool ran.
    outputs = {}
    for repo in (r1, r2):
        outdir = Path(Args.results_dir) / "individual-repos" / repo.name
        assert outdir.exists(), f"Expected results directory {outdir}"
        outputs[repo.name] = list(outdir.glob("*.json"))

    # Output files require a requested tool that both RESOLVES and SUCCEEDS, so
    # this half is environment-dependent.
    #
    # On CI, `.venv/Scripts` is on PATH and supplies bandit (a dev dependency),
    # so output is always produced -- never skip there, or the coverage rots
    # silently the way #683/#693 did.
    #
    # On a developer box the set can legitimately come up empty. Measured case:
    # semgrep resolves from a user-site install but, on a non-UTF-8 console,
    # crashes inside its own config_resolver (it writes the downloaded ruleset
    # with the locale codec and the ruleset contains U+202A). It exits 2, which
    # jmo accepts as an OK return code, and writes no file.
    if not any(outputs.values()):
        if in_ci:
            pytest.fail(
                "No tool produced output on CI. `.venv/Scripts` should supply "
                f"bandit; check the PATH step. Requested: {Args.tools}"
            )
        pytest.skip(
            "None of the requested tools both resolved and succeeded on this "
            f"machine (requested: {Args.tools}); nothing to assert about output."
        )

    # Some tool worked, so it must have worked for EVERY repo -- this catches a
    # scan that silently processes only the first target.
    for name, json_files in outputs.items():
        assert json_files, f"Repo {name!r} got no output while others did"


def test_ci_composes_scan_and_report(tmp_path: Path, monkeypatch):
    # One dummy repo
    repo = tmp_path / "repo"
    repo.mkdir()

    class Args:
        def __init__(self):
            self.repo = str(repo)
            self.repos_dir = None
            self.targets = None
            self.results_dir = str(tmp_path / "results")
            self.config = str(tmp_path / "no.yml")
            self.tools = ["trufflehog"]  # Updated from gitleaks (removed in v0.5.0)
            self.timeout = 5
            self.threads = 1
            self.allow_missing_tools = True
            self.fail_on = None
            self.profile = True

    # `cmd_ci` runs `cmd_scan`, which unconditionally calls
    # `_show_kofi_reminder()` (#933) -- resolves `Path.home()` with no
    # injection point.
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    rc = cmd_ci(Args())
    # Expect 0 because no findings and fail_on not set
    assert rc in (0, 1)
    # Verify outputs
    outdir = Path(Args().results_dir) / "summaries"
    assert (outdir / "findings.json").exists()
    assert (outdir / "dashboard.html").exists() or (outdir / "SUMMARY.md").exists()
    # timings.json should be present due to profile=True
    assert (outdir / "timings.json").exists()


def test_ci_runs_the_report_phase_exactly_once(tmp_path: Path, monkeypatch):
    """`cmd_scan` runs the report itself, and `cmd_ci` then ran it again.

    `cmd_scan` grew its own report call so that `--no-store-history` works for a
    bare `jmo scan`; `cmd_ci` already had one. Both fired, so a single `jmo ci`
    parsed, enriched and wrote all 14 artifacts twice -- and stored two history
    rows plus a doubled findings table for one scan. Measured on a real scan of
    the e2e fixture tree: `jmo ci` produced 2 scan rows / 34 finding rows where
    `jmo scan` produced 1 / 17.

    Spying on `jmo._cmd_report_impl` catches both call sites: `cmd_scan` looks
    it up as a module global, and the `cmd_ci` wrapper passes the same global
    in as `cmd_report_fn`.
    """
    import scripts.cli.jmo as jmo_mod

    monkeypatch.setenv("CI", "true")
    # `cmd_ci` runs `cmd_scan`, which unconditionally calls
    # `_show_kofi_reminder()` (#933) -- resolves `Path.home()` with no
    # injection point.
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    repo = tmp_path / "repo"
    repo.mkdir()

    calls: list[object] = []
    original = jmo_mod._cmd_report_impl

    def spy(args, log_fn):
        calls.append(args)
        return original(args, log_fn)

    monkeypatch.setattr(jmo_mod, "_cmd_report_impl", spy)

    class Args:
        def __init__(self):
            self.repo = str(repo)
            self.repos_dir = None
            self.targets = None
            self.results_dir = str(tmp_path / "results")
            self.config = str(tmp_path / "no.yml")
            self.tools = ["trufflehog"]
            self.timeout = 5
            self.threads = 1
            self.allow_missing_tools = True
            self.fail_on = None
            self.profile = False

    cmd_ci(Args())

    assert len(calls) == 1, (
        f"report phase ran {len(calls)} times for one `jmo ci`; "
        "cmd_scan's auto-report and cmd_ci's own report both fired"
    )
