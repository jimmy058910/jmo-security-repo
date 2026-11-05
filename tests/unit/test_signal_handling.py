import platform
import sys
import types
from pathlib import Path

import pytest

from scripts.cli import jmo


@pytest.mark.skipif(
    platform.system() == "Windows",
    reason="Unix signal handling not fully supported on Windows",
)
def test_cmd_scan_signal_stop(tmp_path: Path, monkeypatch):
    # Create two repos under repos_dir. Each holds a file: an empty tree fails
    # every tool before any runs (`failed:no files to scan`, G2), which would
    # make this a test of that rule instead of the signal path.
    base = tmp_path / "repos"
    for name in ("one", "two"):
        (base / name).mkdir(parents=True)
        (base / name / "README.md").write_bytes(b"# " + name.encode() + b"\n")
    out_base = tmp_path / "results"

    # Configure a single tool and thread. The tool is deliberately one the
    # scanners actually implement.
    #
    # This used to say `gitleaks`, which was removed in v0.5.0 and is
    # implemented **nowhere** -- not in any scan_jobs scanner, not in
    # `TOOL_SCAN_TYPES`, not in any profile, so
    # `filter_tools_for_scan_type(["gitleaks"], "repo")` returns `[]`. Both
    # repos were therefore scanned by zero tools and returned an empty status
    # map, and this test's `rc == 0` passed while the scan under it produced
    # nothing at all. `scan_all` had been logging "Requested but applicable to
    # no target type in this scan" on every run of it.
    #
    # It surfaced when chunk 4 made a target that produced nothing exit
    # non-zero (#809). The exit code was right; the fixture was stale -- the
    # same gitleaks/tfsec residue tracked in #796. With a real tool the signal
    # path this test is named for is actually exercised: uninstalled plus
    # `allow_missing_tools` still returns quickly via the stub.
    def fake_eff(_):
        return {
            "tools": ["trufflehog"],
            "threads": 1,
            "timeout": 5,
            "include": [],
            "exclude": [],
            "retries": 0,
            "per_tool": {},
        }

    monkeypatch.setattr(jmo, "_effective_scan_settings", fake_eff)
    # Mock _check_scan_tools to skip tool availability checks
    monkeypatch.setattr(jmo, "_check_scan_tools", lambda args, tools: (tools, []))
    # Note: _tool_exists removed in v0.9.0 refactoring - tools handled by scanners now
    # allow_missing_tools=True handles missing tools gracefully
    # `cmd_scan` unconditionally calls `_show_kofi_reminder()` (#933), which
    # resolves `Path.home()` with no injection point. This test's own
    # `skipif` above meant it never ran on the Windows box the original
    # writer-hunt (#802/#933) used to find real-state leaks, so it was
    # never caught there -- it still runs on Linux CI, where it wrote to
    # the real ~/.jmo/config.yml unpatched (#978 CI follow-up).
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

    # One Ctrl-C, delivered as the handler is installed: before any job is
    # submitted. Only for SIGINT: a second signal is the "quit at once" path,
    # which `os._exit`s and would take the test process with it.
    captured = {"handler": None}

    def fake_signal(sig, handler):
        captured["handler"] = handler
        if sig == 2:
            handler(2, None)
        return None

    # Ensure that the import inside cmd_scan picks up our fake module
    monkeypatch.setitem(
        sys.modules,
        "signal",
        types.SimpleNamespace(signal=fake_signal, SIGINT=2, SIGTERM=15),
    )

    args = types.SimpleNamespace(
        cmd="scan",
        repo=None,
        repos_dir=str(base),
        targets=None,
        results_dir=str(out_base),
        config=str(tmp_path / "cfg.yml"),
        tools=None,
        timeout=None,
        threads=1,
        allow_missing_tools=True,
        log_level=None,
        human_logs=False,
    )
    from scripts.core import tool_runner
    from scripts.core.tool_runner import clear_stop

    contained = []
    monkeypatch.setattr(
        tool_runner, "contain_process_tree", lambda: contained.append(True) or False
    )

    try:
        rc = jmo.cmd_scan(args)
    finally:
        # The stop is process-wide: left set, every later scan in this test
        # process would stop before its first tool.
        clear_stop()

    # Ctrl-C stops the scan (v2.0.0 Phase 7, B4; decided 2026-11-05): exit 130,
    # no report, the session kept for `jmo scan --resume`. It used to be only
    # logged, and this test asserted the scan then exited 0. It still has to
    # reach target setup, or it says nothing about the signal path.
    assert rc == 130
    # Windows' Job Object (a no-op elsewhere) is set up before any tool runs.
    assert contained == [True]
    assert (out_base / "individual-repos").exists(), (
        "the scan did not reach target setup, so this says nothing about "
        "signal handling"
    )
    assert not (out_base / "summaries").exists()
    assert (tmp_path / ".jmo" / "scan-session.json").exists()
    # Because of stop flag, at least one repo may not be scanned; ensure no crash
