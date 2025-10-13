from pathlib import Path

from scripts.cli.jmo import cmd_scan, cmd_ci


def test_scan_writes_stubs_when_missing_tools(tmp_path: Path, monkeypatch):
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
        tools = ["gitleaks", "trufflehog", "semgrep", "noseyparker", "syft", "trivy", "hadolint", "checkov", "tfsec"]
        timeout = 5
        threads = 2
        allow_missing_tools = True

    rc = cmd_scan(Args())
    assert rc == 0

    # Verify stub files exist
    for repo in (r1, r2):
        outdir = Path(Args.results_dir) / "individual-repos" / repo.name
        assert (outdir / "gitleaks.json").exists()
        assert (outdir / "trufflehog.json").exists()
        assert (outdir / "semgrep.json").exists()
        assert (outdir / "noseyparker.json").exists()
        assert (outdir / "syft.json").exists()
        assert (outdir / "trivy.json").exists()
        assert (outdir / "hadolint.json").exists()
        assert (outdir / "checkov.json").exists()
        assert (outdir / "tfsec.json").exists()


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
            self.tools = ["gitleaks"]
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
