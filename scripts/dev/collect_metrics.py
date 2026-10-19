#!/usr/bin/env python3
"""Collect read-only adoption metrics; publish explicit per-run source health."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
REPO = "jimmy058910/jmo-security-repo"
SOURCES = {
    "github-repo": ("GitHub Repository", "repos/" + REPO),
    "github-traffic": (
        "GitHub Traffic (rolling 14 days)",
        "repos/" + REPO + "/traffic/views",
    ),
    "github-clones": (
        "GitHub Clones (rolling 14 days)",
        "repos/" + REPO + "/traffic/clones",
    ),
    "pypi-downloads": (
        "PyPI Downloads",
        "https://pypistats.org/api/packages/jmo-security/recent",
    ),
    "docker-hub": (
        "Docker Hub",
        "https://hub.docker.com/v2/repositories/jmogaming/jmo-security",
    ),
}
FIELDS = {
    "github-repo": {"stars": "Stars", "forks": "Forks", "open_issues": "Open Issues"},
    "github-traffic": {
        "total_views": "Total Views",
        "unique_visitors": "Unique Visitors",
    },
    "github-clones": {
        "total_clones": "Total Clones",
        "unique_cloners": "Unique Cloners",
    },
    "pypi-downloads": {"last_week": "Last Week", "last_month": "Last Month"},
    "docker-hub": {"pull_count": "Pull Count", "star_count": "Stars"},
}


class CollectionError(Exception):
    """A sanitized, safe-to-report collection error."""


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def atomic_write(path: Path, text: str) -> None:
    """Publish a whole file, never a partial JSON document or Markdown report."""
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            parent_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
    finally:
        Path(temporary).unlink(missing_ok=True)


def write_json(path: Path, data: dict) -> None:
    atomic_write(path, json.dumps(data, indent=2, allow_nan=False) + "\n")


@contextlib.contextmanager
def run_lock(directory: Path, run_id: str):
    lock = directory / ".collect_metrics.lock"
    try:
        stream = lock.open("x", encoding="utf-8")
    except FileExistsError:
        raise CollectionError(
            "collector_locked; inspect the active or interrupted run"
        ) from None
    with stream:
        stream.write(
            json.dumps({"run_id": run_id, "pid": os.getpid(), "started_at": utc_now()})
        )
        stream.flush()
        os.fsync(stream.fileno())
    try:
        yield
    finally:
        # A replaced lock belongs to someone else; do not silently remove it.
        if json.loads(lock.read_text(encoding="utf-8")).get("run_id") != run_id:
            raise CollectionError("collector_lock_changed")
        lock.unlink()


def command(arguments: list[str]) -> str:
    try:
        result = subprocess.run(
            arguments,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        raise CollectionError("command_timeout") from None
    except (OSError, UnicodeError):
        raise CollectionError("command_unavailable_or_invalid_encoding") from None
    if result.returncode:
        # Provider output can contain credential/configuration details. Never echo it.
        raise CollectionError(f"command_failed_exit_{result.returncode}")
    return result.stdout


def counts(source: str, data: dict) -> dict[str, int]:
    values = data.get("data") if source == "pypi-downloads" else data
    if not isinstance(values, dict):
        raise ValueError("missing object")
    result = {}
    for key in FIELDS[source]:
        value = values.get(key)
        if type(value) is not int or value < 0:
            raise ValueError("counts must be nonnegative integers")
        result[key] = value
    return result


def normalize(source: str, raw: str) -> dict:
    try:
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("expected object")
        if source == "github-repo":
            data = {
                target: data.get(origin)
                for target, origin in {
                    "stars": "stargazers_count",
                    "watchers": "watchers_count",
                    "forks": "forks_count",
                    "open_issues": "open_issues_count",
                    "size_kb": "size",
                    "created_at": "created_at",
                    "updated_at": "updated_at",
                    "default_branch": "default_branch",
                    "topics": "topics",
                }.items()
            }
        elif source in ("github-traffic", "github-clones"):
            names = list(FIELDS[source])
            series = "views" if source == "github-traffic" else "clones"
            data = {
                names[0]: data.get("count"),
                names[1]: data.get("uniques"),
                series + "_by_day": data.get(series),
            }
        elif source == "docker-hub":
            data = {
                key: data.get(key)
                for key in (
                    "pull_count",
                    "star_count",
                    "last_updated",
                    "name",
                    "description",
                    "is_automated",
                )
            }
        elif source == "pypi-downloads":
            data = {"data": data.get("data")}
        counts(source, data)
        # Reject JSON's nonstandard NaN/Infinity values, including unused metadata.
        json.dumps(data, allow_nan=False)
        return data
    except (ValueError, TypeError, RecursionError):
        raise CollectionError("invalid_json_or_required_counts") from None


def fetch(source: str) -> dict:
    endpoint = SOURCES[source][1]
    if source.startswith("github-"):
        arguments = [
            "gh",
            "api",
            "--hostname",
            "github.com",
            "--method",
            "GET",
            endpoint,
        ]
    else:
        arguments = [
            "curl",
            "--disable",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--connect-timeout",
            "15",
            "--max-time",
            "45",
            endpoint,
        ]
    return normalize(source, command(arguments))


def prior_collection(directory: Path, report: dict) -> tuple[dict | None, str]:
    """Use the closest prior date only; never fill its gaps with an older sample."""
    candidates = []
    for path in directory.glob("collection-*.json"):
        match = re.fullmatch(r"collection-(\d{4}-\d{2}-\d{2})\.json", path.name)
        if match and match[1] < report["date"]:
            try:
                date.fromisoformat(match[1])
            except ValueError:
                continue
            candidates.append(path)
    if not candidates:
        return (
            None,
            "No prior structured collection; legacy summaries are not numeric baselines.",
        )
    path = max(candidates)
    try:
        prior = json.loads(path.read_text(encoding="utf-8"))
        if (
            not isinstance(prior, dict)
            or prior.get("schema_version") != 1
            or prior.get("date") != path.stem.removeprefix("collection-")
            or prior.get("status")
            not in ("complete", "partial", "unavailable", "failed")
            or not isinstance(prior.get("run_id"), str)
            or not isinstance(prior.get("sources"), dict)
            or set(prior["sources"]) != set(SOURCES)
        ):
            raise ValueError("invalid prior record")
        previous_time = datetime.fromisoformat(prior["finished_at"])
        current_time = datetime.fromisoformat(report["started_at"])
        if previous_time.tzinfo is None or previous_time >= current_time:
            raise ValueError("invalid prior time")
        for source, result in prior["sources"].items():
            if not isinstance(result, dict) or result.get("status") not in (
                "ok",
                "unavailable",
            ):
                raise ValueError("invalid source status")
            if result["status"] == "ok":
                counts(source, result["data"])
        gap = (
            date.fromisoformat(report["date"]) - date.fromisoformat(prior["date"])
        ).days
        return prior, f"Change since {prior['date']} ({gap} days between report dates)."
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return (
            None,
            f"Prior collection {path.name} is unreadable, invalid or unfinished; no deltas.",
        )


def add_comparison(report: dict, prior: dict | None) -> None:
    for source, result in report["sources"].items():
        result["deltas"] = None
        if (
            result["status"] != "ok"
            or not prior
            or prior["sources"][source]["status"] != "ok"
        ):
            continue
        before = counts(source, prior["sources"][source]["data"])
        after = counts(source, result["data"])
        result["deltas"] = {
            key: {
                "change": value - before[key],
                "percent": round((value - before[key]) * 100 / before[key], 2)
                if before[key]
                else None,
            }
            for key, value in after.items()
        }


def render(report: dict) -> str:
    lines = [
        "# JMo Security - Metrics Summary",
        "",
        f"**Date:** {report['date']}",
        f"**Run ID:** {report['run_id']}",
        f"**Generated (UTC):** {report['started_at']}",
        f"**Collection:** {report['status']}",
        "",
        "## Source health",
        "",
    ]
    if report.get("fatal_error"):
        lines.extend(["**Needs Jimmy:** " + report["fatal_error"], ""])
    for source, result in report["sources"].items():
        detail = (
            "fetched"
            if result["status"] == "ok"
            else "unavailable this run: " + result["error"]
        )
        lines.append(f"- {SOURCES[source][0]}: {detail}")
    lines.extend(
        [
            "",
            "## Comparison",
            "",
            report.get("comparison_note", "Collection not finalized."),
            "The report date is a label; these requests fetch current values, not historical backfills.",
            "Rolling PyPI/traffic/clones windows may overlap; changes are not new unique users.",
            "Docker pulls and repository counts are snapshots. Clones can include CI activity.",
        ]
    )
    for source, result in report["sources"].items():
        lines.extend(["", "## " + SOURCES[source][0], ""])
        if result["status"] != "ok":
            lines.append("Unavailable this run; no counts or deltas.")
            continue
        for key, value in counts(source, result["data"]).items():
            delta = (result.get("deltas") or {}).get(key)
            change = "delta unavailable"
            if delta is not None:
                percent = (
                    "percentage unavailable (prior value zero)"
                    if delta["percent"] is None
                    else f"{delta['percent']:+g}%"
                )
                change = f"change {delta['change']:+d}; {percent}"
            lines.append(f"- **{FIELDS[source][key]}:** {value} ({change})")
    lines.extend(
        [
            "",
            "## Files",
            "",
            f"Authoritative record: `collection-{report['date']}.json`.",
            "Read only finalized records; match the Run ID before using this summary.",
            "Per-source JSON has an `_collection` marker; old files are never evidence of this run.",
            "",
        ]
    )
    return "\n".join(lines)


def collect(report_date: date, root: Path | None = None) -> dict:
    root = root or ROOT
    directory = root / "metrics"
    directory.mkdir(parents=True, exist_ok=True)
    day = report_date.isoformat()
    report: dict[str, Any] = {
        "schema_version": 1,
        "run_id": uuid.uuid4().hex,
        "date": day,
        "started_at": utc_now(),
        "finished_at": None,
        "status": "running",
        "sources": {
            source: {"status": "unavailable", "error": "not_collected", "data": None}
            for source in SOURCES
        },
    }
    manifest = directory / f"collection-{day}.json"
    summary = directory / f"summary-{day}.md"
    with run_lock(directory, report["run_id"]):
        # Invalidate earlier same-day success before fetching. Final JSON is the
        # commit marker, written AFTER all source files and the matching summary.
        write_json(manifest, report)
        atomic_write(summary, render(report))
        try:
            for tool in ("gh", "curl"):
                if shutil.which(tool) is None:
                    raise CollectionError("missing_dependency_" + tool)
            try:
                command(["gh", "auth", "status", "--hostname", "github.com"])
            except CollectionError:
                raise CollectionError("github_auth_preflight_failed") from None
            for source in SOURCES:
                result: dict[str, Any]
                try:
                    data = fetch(source)
                    result = {"status": "ok", "error": None, "data": data}
                except CollectionError as exc:
                    result = {"status": "unavailable", "error": str(exc), "data": None}
                report["sources"][source] = result
                payload = dict(result["data"] or {})
                payload["_collection"] = {
                    "run_id": report["run_id"],
                    "status": result["status"],
                    "date": day,
                    "observed_at": utc_now(),
                    "error": result["error"],
                }
                write_json(directory / f"{source}-{day}.json", payload)
            successful = sum(
                result["status"] == "ok" for result in report["sources"].values()
            )
            report["status"] = (
                "complete"
                if successful == len(SOURCES)
                else "partial"
                if successful
                else "unavailable"
            )
        except CollectionError as exc:
            report["status"] = "failed"
            report["fatal_error"] = str(exc)
        prior, report["comparison_note"] = prior_collection(directory, report)
        report["comparison_date"] = prior["date"] if prior else None
        add_comparison(report, prior)
        report["finished_at"] = utc_now()
        atomic_write(summary, render(report))
        write_json(manifest, report)
    return report


def parse_date(value: str) -> date:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise argparse.ArgumentTypeError("Use YYYY-MM-DD")
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Invalid calendar date") from None


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "report_date", nargs="?", type=parse_date, help="legacy positional date label"
    )
    parser.add_argument(
        "--date", type=parse_date, help="report label, not a historical API query"
    )
    args = parser.parse_args(arguments)
    if args.date and args.report_date:
        parser.error("Use either --date or a positional date, not both")
    try:
        report = collect(
            args.date or args.report_date or datetime.now().astimezone().date()
        )
    except (CollectionError, OSError, ValueError):
        # A prior summary must not be presented as this failed invocation's output.
        print(
            json.dumps(
                {
                    "status": "failed",
                    "error": "collector_setup_lock_or_write_failed; inspect metrics state",
                }
            ),
            file=sys.stderr,
        )
        return 1
    print(
        json.dumps(
            {
                "status": report["status"],
                "run_id": report["run_id"],
                "date": report["date"],
                "collection": str(
                    ROOT / "metrics" / f"collection-{report['date']}.json"
                ),
                "summary": str(ROOT / "metrics" / f"summary-{report['date']}.md"),
            }
        )
    )
    return 0 if report["status"] in ("complete", "partial") else 1


if __name__ == "__main__":
    raise SystemExit(main())
