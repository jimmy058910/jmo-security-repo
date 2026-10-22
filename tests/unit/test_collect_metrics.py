"""Offline metrics regression tests: real files and reports, fake external commands."""

import copy
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import types
from datetime import date
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[2] / "scripts/dev/collect_metrics.py"
spec = importlib.util.spec_from_file_location("metrics_under_test", SOURCE)
metrics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(metrics)

PAYLOADS = {
    "github-repo": {
        "stargazers_count": 10,
        "watchers_count": 10,
        "forks_count": 2,
        "open_issues_count": 1,
    },
    "github-traffic": {"count": 12, "uniques": 3, "views": []},
    "github-clones": {"count": 4, "uniques": 2, "clones": []},
    "pypi-downloads": {"data": {"last_week": 10, "last_month": 30}},
    "docker-hub": {
        "pull_count": 22,
        "star_count": 1,
        "name": "fixture",
        "last_updated": "2026-10-01",
    },
}


@pytest.fixture
def harness(tmp_path, monkeypatch):
    state = {
        "payloads": copy.deepcopy(PAYLOADS),
        "failures": {},
        "calls": [],
        "auth": True,
        "now": "2026-10-12T12:00:00+00:00",
    }
    monkeypatch.setattr(metrics, "ROOT", tmp_path)
    monkeypatch.setattr(metrics, "utc_now", lambda: state["now"])
    # Fakes replace the collector's own module references, not the global
    # subprocess/shutil: a conftest teardown that imports croniter runs `file -b`
    # through the real subprocess.run, and must not reach the strict fake.
    monkeypatch.setattr(
        metrics, "shutil", types.SimpleNamespace(which=lambda tool: tool)
    )

    def fake_run(arguments, **options):
        assert isinstance(arguments, list)
        assert options["shell"] is False
        assert 0 < options["timeout"] <= 60
        assert options["encoding"] == "utf-8"
        assert options["capture_output"] is True
        state["calls"].append(arguments)
        if arguments[:3] == ["gh", "auth", "status"]:
            assert arguments[3:] == ["--hostname", "github.com"]
            return subprocess.CompletedProcess(
                arguments, 0 if state["auth"] else 1, "", "SECRET"
            )
        endpoint = arguments[-1]
        source = next(
            key for key, value in metrics.SOURCES.items() if value[1] == endpoint
        )
        if arguments[0] == "gh":
            assert arguments[1:6] == [
                "api",
                "--hostname",
                "github.com",
                "--method",
                "GET",
            ]
        else:
            assert arguments[:2] == ["curl", "--disable"]
            assert "--retry" not in arguments and "--data" not in arguments
        failure = state["failures"].get(source)
        if failure == "timeout":
            raise subprocess.TimeoutExpired(
                arguments, options["timeout"], stderr="SECRET"
            )
        if failure == "spawn":
            raise OSError("SECRET")
        if failure == "encoding":
            raise UnicodeError("SECRET")
        if failure == "exit":
            return subprocess.CompletedProcess(
                arguments, 22, "partial output SECRET", "SECRET"
            )
        content = state["payloads"][source]
        text = content if isinstance(content, str) else json.dumps(content)
        return subprocess.CompletedProcess(arguments, 0, text, "SECRET")

    monkeypatch.setattr(
        metrics,
        "subprocess",
        types.SimpleNamespace(run=fake_run, TimeoutExpired=subprocess.TimeoutExpired),
    )

    def collect(day="2026-10-12"):
        state["now"] = day + "T12:00:00+00:00"
        return metrics.collect(date.fromisoformat(day))

    state.update(root=tmp_path, collect=collect)
    return state


def summary(harness, day="2026-10-12"):
    return (harness["root"] / "metrics" / f"summary-{day}.md").read_text(
        encoding="utf-8"
    )


def record(harness, day="2026-10-12"):
    return json.loads(
        (harness["root"] / "metrics" / f"collection-{day}.json").read_text(
            encoding="utf-8"
        )
    )


def test_complete_report_and_legacy_counts_are_preserved(harness):
    result = harness["collect"]()
    assert result == record(harness)
    assert result["status"] == "complete"
    assert len(harness["calls"]) == 6
    assert "**Stars:** 10" in summary(harness)
    assert "**Last Week:** 10" in summary(harness)
    assert "**Pull Count:** 22" in summary(harness)
    for source, item in result["sources"].items():
        assert item["status"] == "ok" and item["deltas"] is None
        disk = json.loads(
            (harness["root"] / "metrics" / f"{source}-2026-10-12.json").read_text(
                encoding="utf-8"
            )
        )
        assert disk["_collection"]["run_id"] == result["run_id"]
        assert metrics.counts(source, disk) == metrics.counts(source, item["data"])
    assert not (harness["root"] / "metrics/.collect_metrics.lock").exists()
    assert result["sources"]["github-traffic"]["data"]["views_by_day"] == []
    assert result["sources"]["github-clones"]["data"]["clones_by_day"] == []


@pytest.mark.parametrize("source", PAYLOADS)
@pytest.mark.parametrize("failure", ["exit", "timeout", "spawn", "encoding"])
def test_one_source_failure_preserves_four_others_without_retry(
    harness, source, failure
):
    harness["failures"][source] = failure
    result = harness["collect"]()
    assert result["status"] == "partial"
    assert len(harness["calls"]) == 6
    assert sum(item["status"] == "ok" for item in result["sources"].values()) == 4
    assert result["sources"][source]["data"] is None
    assert "unavailable this run" in summary(harness)
    assert "SECRET" not in summary(harness) + json.dumps(result)


@pytest.mark.parametrize("source", PAYLOADS)
@pytest.mark.parametrize(
    "payload", ["{incomplete", "", [], {}, {"message": "API failed"}]
)
def test_invalid_json_or_missing_counts_is_a_source_gap(harness, source, payload):
    harness["payloads"][source] = payload
    result = harness["collect"]()
    assert result["status"] == "partial"
    assert result["sources"][source]["error"] == "invalid_json_or_required_counts"
    assert result["sources"][source]["data"] is None


@pytest.mark.parametrize(
    "invalid", [None, True, False, -1, "42", 4.5, float("nan"), float("inf")]
)
def test_invalid_numeric_counts_are_never_reported_as_zero(harness, invalid):
    harness["payloads"]["pypi-downloads"]["data"]["last_week"] = invalid
    result = harness["collect"]()
    assert result["sources"]["pypi-downloads"]["status"] == "unavailable"
    assert "**Last Week:**" not in summary(harness)


def test_real_zero_counts_are_valid(harness):
    harness["payloads"]["github-traffic"] = {"count": 0, "uniques": 0}
    result = harness["collect"]()
    assert result["status"] == "complete"
    assert "**Total Views:** 0" in summary(harness)


def test_all_sources_unavailable_produces_report_and_nonzero_exit(harness, capsys):
    harness["failures"] = dict.fromkeys(PAYLOADS, "exit")
    assert metrics.main(["--date", "2026-10-12"]) == 1
    assert record(harness)["status"] == "unavailable"
    assert "**Stars:**" not in summary(harness)
    assert json.loads(capsys.readouterr().out)["status"] == "unavailable"


def test_partial_cli_success_is_explicit_and_rooted_outside_cwd(
    harness, tmp_path, monkeypatch, capsys
):
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.chdir(other)
    harness["failures"]["docker-hub"] = "exit"
    assert metrics.main(["2026-10-12"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "partial"
    assert output["run_id"] == record(harness)["run_id"]
    assert not (other / "metrics").exists()


def test_auth_failure_stops_before_any_fetch_and_replaces_old_summary(harness, capsys):
    harness["collect"]()
    harness["auth"] = False
    harness["calls"].clear()
    assert metrics.main(["--date", "2026-10-12"]) == 1
    assert len(harness["calls"]) == 1
    assert record(harness)["status"] == "failed"
    assert "github_auth_preflight_failed" in summary(harness)
    assert "**Stars:**" not in summary(harness)
    assert "SECRET" not in summary(harness) + capsys.readouterr().out


@pytest.mark.parametrize("missing", ["gh", "curl"])
def test_missing_dependency_has_failed_report_and_no_fetch(
    harness, monkeypatch, missing
):
    monkeypatch.setattr(
        metrics.shutil, "which", lambda tool: None if tool == missing else tool
    )
    result = harness["collect"]()
    assert result["status"] == "failed"
    assert result["fatal_error"] == "missing_dependency_" + missing
    assert not harness["calls"]


def test_same_day_failed_source_overwrites_stale_success_without_using_it(harness):
    previous = harness["collect"]()
    harness["failures"]["github-traffic"] = "exit"
    result = harness["collect"]()
    assert result["run_id"] != previous["run_id"]
    assert result["comparison_date"] is None
    path = harness["root"] / "metrics/github-traffic-2026-10-12.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert "total_views" not in payload
    assert payload["_collection"]["run_id"] == result["run_id"]
    assert "**Total Views:**" not in summary(harness)


def test_legacy_summary_and_raw_json_are_not_a_comparison_baseline(harness):
    directory = harness["root"] / "metrics"
    directory.mkdir()
    (directory / "summary-2026-10-05.md").write_text("Stars: 999999", encoding="utf-8")
    (directory / "github-repo-2026-10-05.json").write_text(
        '{"stars":999999}', encoding="utf-8"
    )
    result = harness["collect"]()
    assert result["comparison_date"] is None
    assert "legacy summaries" in summary(harness)
    assert "999999" not in summary(harness)


def test_deltas_use_prior_date_and_surviving_sources_only(harness):
    harness["failures"]["github-traffic"] = "exit"
    harness["collect"]("2026-10-05")
    harness["failures"].clear()
    harness["payloads"]["github-repo"]["stargazers_count"] = 15
    harness["payloads"]["pypi-downloads"]["data"]["last_week"] = 5
    result = harness["collect"]()
    assert result["comparison_date"] == "2026-10-05"
    assert result["sources"]["github-repo"]["deltas"]["stars"] == {
        "change": 5,
        "percent": 50,
    }
    assert result["sources"]["pypi-downloads"]["deltas"]["last_week"] == {
        "change": -5,
        "percent": -50,
    }
    assert result["sources"]["github-traffic"]["deltas"] is None
    assert "7 days between report dates" in summary(harness)


def test_irregular_interval_is_not_called_week_over_week(harness):
    harness["collect"]("2026-10-10")
    harness["collect"]()
    assert "2 days between report dates" in summary(harness)
    assert "week-over-week" not in summary(harness)


def test_zero_baseline_does_not_divide_or_invent_percentage(harness):
    harness["payloads"]["github-repo"]["stargazers_count"] = 0
    harness["collect"]("2026-10-05")
    harness["payloads"]["github-repo"]["stargazers_count"] = 5
    result = harness["collect"]()
    assert result["sources"]["github-repo"]["deltas"]["stars"] == {
        "change": 5,
        "percent": None,
    }
    assert "percentage unavailable (prior value zero)" in summary(harness)


def test_does_not_reach_back_past_a_missing_recent_source(harness):
    harness["collect"]("2026-09-28")
    harness["failures"]["github-repo"] = "exit"
    harness["collect"]("2026-10-05")
    harness["failures"].clear()
    result = harness["collect"]()
    assert result["comparison_date"] == "2026-10-05"
    assert result["sources"]["github-repo"]["deltas"] is None


@pytest.mark.parametrize(
    "damage", ["json", "running", "schema", "timestamp", "date", "counts"]
)
def test_invalid_prior_is_reported_without_falling_back_silently(harness, damage):
    harness["collect"]("2026-09-28")
    before = harness["collect"]("2026-10-05")
    if damage == "running":
        before["status"] = "running"
    elif damage == "schema":
        before["schema_version"] = 999
    elif damage == "timestamp":
        before["finished_at"] = "2027-01-01T00:00:00+00:00"
    elif damage == "date":
        before["date"] = "2026-10-04"
    elif damage == "counts":
        before["sources"]["github-repo"]["data"]["stars"] = None
    path = harness["root"] / "metrics/collection-2026-10-05.json"
    path.write_text(
        "{truncated" if damage == "json" else json.dumps(before), encoding="utf-8"
    )
    result = harness["collect"]()
    assert result["comparison_date"] is None
    assert "invalid or unfinished" in summary(harness)
    assert all(item["deltas"] is None for item in result["sources"].values())


def test_running_marker_is_visible_before_requests(harness, monkeypatch):
    original = metrics.fetch

    def inspect(source):
        assert record(harness)["status"] == "running"
        assert "**Collection:** running" in summary(harness)
        return original(source)

    monkeypatch.setattr(metrics, "fetch", inspect)
    harness["collect"]()


@pytest.mark.parametrize("failure_at", ["source", "summary", "manifest"])
def test_write_failure_cannot_leave_finalized_success(
    harness, monkeypatch, capsys, failure_at
):
    harness["collect"]()
    original = metrics.os.replace
    counts = {}

    def fail(temporary, destination):
        name = Path(destination).name
        counts[name] = counts.get(name, 0) + 1
        if (
            (failure_at == "source" and name.startswith("github-repo-"))
            or (
                failure_at == "summary"
                and name.startswith("summary-")
                and counts[name] == 2
            )
            or (
                failure_at == "manifest"
                and name.startswith("collection-")
                and counts[name] == 2
            )
        ):
            raise PermissionError("SECRET")
        original(temporary, destination)

    monkeypatch.setattr(metrics.os, "replace", fail)
    assert metrics.main(["--date", "2026-10-12"]) == 1
    output = capsys.readouterr()
    assert not output.out and "SECRET" not in output.err
    assert record(harness)["status"] == "running"
    assert not list((harness["root"] / "metrics").glob(".*.json.*"))


def test_lock_blocks_overlap_and_preserves_previous_artifacts(harness, capsys):
    before = harness["collect"]()
    lock = harness["root"] / "metrics/.collect_metrics.lock"
    lock.write_text("crashed or active writer", encoding="utf-8")
    harness["calls"].clear()
    assert metrics.main(["--date", "2026-10-12"]) == 1
    assert record(harness) == before
    assert lock.read_text(encoding="utf-8") == "crashed or active writer"
    assert not harness["calls"] and not capsys.readouterr().out


def test_collector_only_writes_under_metrics(harness):
    sentinel = harness["root"] / "source.py"
    sentinel.write_text("unchanged", encoding="utf-8")
    harness["collect"]()
    assert sentinel.read_text(encoding="utf-8") == "unchanged"
    assert sorted(path.name for path in harness["root"].iterdir()) == [
        "metrics",
        "source.py",
    ]


@pytest.mark.parametrize(
    "arguments",
    [
        ["--date"],
        ["--date", "../escape"],
        ["--date", "2026-02-30"],
        ["--date", "20261012"],
        ["--unknown"],
        ["2026-10-12", "--date", "2026-10-12"],
    ],
)
def test_invalid_cli_date_or_options_never_fetch_or_write(harness, arguments):
    with pytest.raises(SystemExit) as error:
        metrics.main(arguments)
    assert error.value.code == 2
    assert not harness["calls"] and not (harness["root"] / "metrics").exists()


def test_abrupt_process_exit_preserves_unfinished_run_and_completed_source(tmp_path):
    target = tmp_path / "scripts/dev/collect_metrics.py"
    target.parent.mkdir(parents=True)
    shutil.copyfile(SOURCE, target)
    driver = tmp_path / "crash_fixture.py"
    driver.write_text(
        "import importlib.util, json, os, sys\n"
        "spec = importlib.util.spec_from_file_location('collector', sys.argv[1])\n"
        "module = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(module)\n"
        "module.shutil.which = lambda name: name\n"
        "def command(args):\n"
        "    if args[:3] == ['gh', 'auth', 'status']: return ''\n"
        "    if args[-1].endswith('/jmo-security-repo'):\n"
        "        return json.dumps(dict(stargazers_count=10, forks_count=2, open_issues_count=1))\n"
        "    os._exit(88)\n"
        "module.command = command\n"
        "sys.exit(module.main(['--date', '2026-10-12']))\n",
        encoding="utf-8",
        newline="\n",
    )
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in ("PYTHONPATH", "PYTHONSTARTUP", "GH_TOKEN", "GITHUB_TOKEN")
    }
    child = subprocess.run(
        [sys.executable, "-B", str(driver), str(target)],
        capture_output=True,
        encoding="utf-8",
        env=env,
        timeout=20,
        shell=False,
    )
    assert child.returncode == 88, child.stderr
    folder = tmp_path / "metrics"
    manifest = json.loads(
        (folder / "collection-2026-10-12.json").read_text(encoding="utf-8")
    )
    saved = json.loads(
        (folder / "github-repo-2026-10-12.json").read_text(encoding="utf-8")
    )
    assert manifest["status"] == "running"
    assert saved["stars"] == 10 and saved["_collection"]["run_id"] == manifest["run_id"]
    with pytest.raises(metrics.CollectionError, match="collector_locked"):
        metrics.collect(date(2026, 10, 12), root=tmp_path)
    assert (folder / ".collect_metrics.lock").exists()
