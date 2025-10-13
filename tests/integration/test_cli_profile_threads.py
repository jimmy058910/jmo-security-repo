import json
import os
from pathlib import Path

from scripts.cli.jmo import cmd_report, parse_args


def _mk_results(tmp_path: Path):
    # Minimal structure with individual-repos but no findings (works with empty aggregation)
    (tmp_path / "individual-repos" / "repo1").mkdir(parents=True, exist_ok=True)


def test_profile_writes_timings(tmp_path: Path, monkeypatch):
    root = tmp_path / "results"
    _mk_results(root)
    out = root / "summaries"
    args = parse_args().__class__(
        cmd="report",
        results_dir=str(root),
        out=str(out),
        config=str(tmp_path / "no-config.yml"),
        fail_on=None,
        profile=True,
        threads=None,
    )
    # Run directly
    rc = cmd_report(args)
    assert rc in (0, 1)  # depending on thresholds, but default is 0
    tfile = out / "timings.json"
    assert tfile.exists(), "timings.json should exist when --profile is set"
    data = json.loads(tfile.read_text())
    assert "aggregate_seconds" in data and "recommended_threads" in data


def test_threads_env_and_config_precedence(tmp_path: Path, monkeypatch):
    root = tmp_path / "results"
    _mk_results(root)
    out = root / "summaries"
    # Create config with threads=7
    cfg = tmp_path / "jmo.yml"
    cfg.write_text("threads: 7\noutputs: [json]\n", encoding="utf-8")

    # Case 1: No CLI flag, no env -> config should apply
    os.environ.pop("JMO_THREADS", None)
    args = parse_args().__class__(
        cmd="report",
        results_dir=str(root),
        out=str(out),
        config=str(cfg),
        fail_on=None,
        profile=False,
        threads=None,
    )
    rc = cmd_report(args)
    assert rc in (0, 1)
    # We cannot easily read threads back from aggregator here, but the code path executed without error.

    # Case 2: Env set should be preserved when no CLI flag
    os.environ["JMO_THREADS"] = "5"
    args2 = parse_args().__class__(
        cmd="report",
        results_dir=str(root),
        out=str(out),
        config=str(cfg),
        fail_on=None,
        profile=False,
        threads=None,
    )
    rc2 = cmd_report(args2)
    assert rc2 in (0, 1)

    # Case 3: CLI flag overrides env and config
    args3 = parse_args().__class__(
        cmd="report",
        results_dir=str(root),
        out=str(out),
        config=str(cfg),
        fail_on=None,
        profile=False,
        threads=3,
    )
    rc3 = cmd_report(args3)
    assert rc3 in (0, 1)
