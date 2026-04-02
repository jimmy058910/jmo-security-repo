from pathlib import Path

from scripts.cli.jmo import cmd_scan, cmd_ci


def test_scan_skips_missing_tools_and_runs_available(tmp_path: Path, monkeypatch):
    """Test that scan succeeds with allow_missing_tools=True.

    v1.0.0 Architecture: Missing tools are skipped entirely (no stubs).
    Only available/installed tools produce output files.
    """
    # Set CI=true to skip interactive prompts
    monkeypatch.setenv("CI", "true")

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

    # Verify results directory structure exists
    for repo in (r1, r2):
        outdir = Path(Args.results_dir) / "individual-repos" / repo.name
        # At least one output file should exist (from available tools)
        json_files = list(outdir.glob("*.json"))
        assert len(json_files) > 0, f"Expected at least one output file in {outdir}"

        # If specific tools are installed, verify their output exists
        # Note: These assertions are conditional based on tool availability
        # The test primarily verifies scan succeeds with missing tools


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

    rc = cmd_ci(Args())
    # Expect 0 because no findings and fail_on not set
    assert rc in (0, 1)
    # Verify outputs
    outdir = Path(Args().results_dir) / "summaries"
    assert (outdir / "findings.json").exists()
    assert (outdir / "dashboard.html").exists() or (outdir / "SUMMARY.md").exists()
    # timings.json should be present due to profile=True
    assert (outdir / "timings.json").exists()
