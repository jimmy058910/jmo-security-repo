import os
import types
from pathlib import Path
import sys

import pytest

from scripts.cli import jmo


@pytest.fixture(autouse=True)
def skip_react_build_check():
    """Skip React build check for all tests in this file (CI compatibility)."""
    os.environ["SKIP_REACT_BUILD_CHECK"] = "true"
    yield
    os.environ.pop("SKIP_REACT_BUILD_CHECK", None)


def test_cmd_scan_signal_stop(tmp_path: Path, monkeypatch):
    # Create two repos under repos_dir
    base = tmp_path / "repos"
    (base / "one").mkdir(parents=True)
    (base / "two").mkdir(parents=True)
    out_base = tmp_path / "results"

    # Configure single tool and thread; tool missing with allow_missing so job returns quickly
    def fake_eff(_):
        return {
            "tools": ["gitleaks"],
            "threads": 1,
            "timeout": 5,
            "include": [],
            "exclude": [],
            "retries": 0,
            "per_tool": {},
        }

    monkeypatch.setattr(jmo, "_effective_scan_settings", fake_eff)
    # Note: _tool_exists removed in v0.9.0 refactoring - tools handled by scanners now
    # allow_missing_tools=True handles missing tools gracefully

    # Monkeypatch signal.signal to immediately invoke handler once to set stop flag
    captured = {"handler": None}

    def fake_signal(sig, handler):  # noqa: ARG001
        # Record and invoke once to simulate interrupt before jobs submit
        captured["handler"] = handler
        try:
            handler(2, None)
        except Exception as _e:  # noqa: F841 - intentional swallow for test simulation
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
    assert rc == 0
    # Because of stop flag, at least one repo may not be scanned; ensure no crash
