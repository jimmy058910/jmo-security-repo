from pathlib import Path

from scripts.cli.jmo import cmd_ci, cmd_scan


def test_scan_skips_missing_tools_and_runs_available(tmp_path: Path, monkeypatch):
    """Test that scan succeeds with allow_missing_tools=True.

    v1.0.0 Architecture: Missing tools are skipped entirely (no stubs).
    Only available/installed tools produce output files.

    Availability is arranged, not found. This used to request real tools and
    lean on bandit, a dev dependency on CI's PATH, as the one guaranteed to
    run -- skipping on a box where nothing resolved. bandit stopped being a
    scanner in v2.0.0 and no matrix tool is a dev dependency, so trufflehog
    now resolves to a stub binary with its execution mocked, and every other
    requested tool resolves to nothing, on every machine.
    """
    import subprocess

    from scripts.cli.scan_jobs import repository_scanner
    from scripts.cli.tool_manager import ToolManager
    from scripts.core import tool_runner

    # Set CI=true to skip interactive prompts
    monkeypatch.setenv("CI", "true")
    # `cmd_scan` unconditionally calls `_show_kofi_reminder()` (#933), which
    # resolves `Path.home()` with no injection point.
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

    available = "trufflehog"
    stub = tmp_path / "bin" / available
    stub.parent.mkdir()
    stub.write_bytes(b"")

    def resolve(name: str) -> str | None:
        return str(stub) if Path(name).name.removesuffix(".exe") == available else None

    # Both resolvers: the pre-flight check and the scanner's own lookup.
    monkeypatch.setattr(ToolManager, "_find_binary", lambda self, name: resolve(name))
    monkeypatch.setattr(repository_scanner, "find_tool", resolve)

    ran: list[str] = []

    def fake_run(cmd, *args, **kwargs):
        # Only the available tool can have been launched.
        assert Path(cmd[0]) == stub, f"launched an unavailable tool: {cmd}"
        ran.append(cmd[0])
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(tool_runner, "_run_bounded", fake_run)

    # Create two dummy repos
    rbase = tmp_path / "repos"
    r1 = rbase / "repo1"
    r2 = rbase / "repo2"
    r1.mkdir(parents=True)
    r2.mkdir(parents=True)

    missing = ["syft", "trivy", "checkov"]

    class Args:
        repo = None
        repos_dir = str(rbase)
        targets = None
        results_dir = str(tmp_path / "results")
        config = str(tmp_path / "no.yml")
        tools = [available, *missing]
        timeout = 30
        threads = 2
        allow_missing_tools = True

    rc = cmd_scan(Args())
    assert rc == 0, "Scan should succeed even with missing tools"
    assert ran, "the available tool never ran"

    for repo in (r1, r2):
        outdir = Path(Args.results_dir) / "individual-repos" / repo.name
        assert outdir.exists(), f"Expected results directory {outdir}"
        # The available tool ran for EVERY repo -- this catches a scan that
        # silently processes only the first target.
        assert (outdir / f"{available}.json").exists(), (
            f"Repo {repo.name!r} got no {available} output"
        )
        # And a missing tool leaves nothing behind: no stubs.
        stubs = sorted(t for t in missing if (outdir / f"{t}.json").exists())
        assert not stubs, f"missing tools wrote output for {repo.name}: {stubs}"


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
