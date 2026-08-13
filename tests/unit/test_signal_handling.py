import os
import platform
import sys
import types
from pathlib import Path

import pytest

from scripts.cli import jmo


@pytest.fixture(autouse=True)
def skip_react_build_check():
    """Skip React build check for all tests in this file (CI compatibility)."""
    os.environ["SKIP_REACT_BUILD_CHECK"] = "true"
    yield
    os.environ.pop("SKIP_REACT_BUILD_CHECK", None)


@pytest.mark.skipif(
    platform.system() == "Windows",
    reason="Unix signal handling not fully supported on Windows",
)
def test_cmd_scan_signal_stop(tmp_path: Path, monkeypatch):
    # Create two repos under repos_dir
    base = tmp_path / "repos"
    (base / "one").mkdir(parents=True)
    (base / "two").mkdir(parents=True)
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

    # Monkeypatch signal.signal to immediately invoke handler once to set stop flag
    captured = {"handler": None}

    def fake_signal(sig, handler):
        # Record and invoke once to simulate interrupt before jobs submit
        captured["handler"] = handler
        try:
            handler(2, None)
        except Exception as _e:
            # In tests we intentionally swallow errors from handler invocation
            # to simulate an interrupt being handled gracefully.
            return None
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
        profile_name=None,
        log_level=None,
        human_logs=False,
    )
    rc = jmo.cmd_scan(args)

    # Two conditions, not one. `rc == 0` alone held for years while the
    # configured tool applied to no target type, so the run it was blessing
    # scanned nothing -- an assertion that cannot distinguish "completed
    # cleanly" from "did nothing" is not testing the signal path.
    assert rc == 0
    assert (out_base / "individual-repos").exists(), (
        "the scan did not reach target setup, so this says nothing about "
        "signal handling"
    )
    # Because of stop flag, at least one repo may not be scanned; ensure no crash
