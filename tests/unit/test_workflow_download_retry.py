"""A workflow's release download waits out a two-minute outage, not 15 seconds.

Every tool download in the workflows used `curl --retry 3 --retry-delay 5`:
four tries in 15 s. In nightly run 41998662852 (2026-11-05, Integration Tests,
attempt 1) github.com answered opengrep's release URL with 504 on all four, the
install step exited 22 and the nightly went red; attempt 2 of the same run,
five hours later, passed (#1580). That outage lasted at least 15 s, and how
much longer is not known.

The workflows now pass `--retry 8 --retry-delay 15`: nine tries over 120 s.
Measured against a local server answering 504 for 40 s and then 200, the old
flags gave up at 15 s (rc 22) and the new ones downloaded at 45 s; against one
that never recovers, the new ones give up at 120 s after 9 requests.

The Dockerfile's downloads are built at release and checked by
test_dockerfile_download_hardening.py; this covers `.github/`.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIN_RETRY_WINDOW_S = 120

RELEASE_ASSET = re.compile(r"https://github\.com/[^\s\"']+/releases/download/")


def _curl_commands() -> list[tuple[str, str]]:
    """Every `curl` command in a workflow or action, continuation lines joined."""
    found = []
    files = sorted((ROOT / ".github").rglob("*.yml"))
    for path in files:
        text = path.read_bytes().decode("utf-8")
        joined = re.sub(r"\\\n\s*", " ", text)
        for line in joined.splitlines():
            if re.search(r"(^|\s)curl\s", line) and not line.lstrip().startswith("#"):
                found.append((path.relative_to(ROOT).as_posix(), line.strip()))
    return found


def _release_downloads() -> list[tuple[str, str]]:
    """A release asset named in the command, or a download that retries: several
    name their URL through a variable (`"${base}/osv-scanner_SHA256SUMS"`)."""
    return [
        (f, cmd)
        for f, cmd in _curl_commands()
        if RELEASE_ASSET.search(cmd) or "--retry" in cmd
    ]


def test_the_scan_finds_the_workflows_release_downloads() -> None:
    # A regex that finds nothing passes every assertion built on it: 30 such
    # downloads were in ci.yml, scheduled.yml and release.yml on 2026-11-14.
    downloads = _release_downloads()
    assert len(downloads) >= 28, downloads
    assert {f for f, _ in downloads} >= {
        ".github/workflows/ci.yml",
        ".github/workflows/scheduled.yml",
        ".github/workflows/release.yml",
    }


def test_every_release_download_retries_for_two_minutes() -> None:
    short = []
    for path, cmd in _release_downloads():
        retries = re.search(r"--retry\s+(\d+)\b", cmd)
        delay = re.search(r"--retry-delay\s+(\d+)\b", cmd)
        window = int(retries[1]) * int(delay[1]) if retries and delay else 0
        if window < MIN_RETRY_WINDOW_S or "--retry-all-errors" not in cmd:
            short.append(f"{path}: {window} s: {cmd[:120]}")
    assert not short, (
        f"release downloads that give up inside {MIN_RETRY_WINDOW_S} s, or retry "
        "only some errors; use `curl -fsSL --retry 8 --retry-delay 15 "
        "--retry-all-errors --connect-timeout 30 --max-time 600`:\n" + "\n".join(short)
    )
