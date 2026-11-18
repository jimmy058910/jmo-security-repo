"""Every trufflehog scan this repo runs passes `--no-update` (#1625).

Without the flag, trufflehog checks for a newer release and replaces its own
binary before it scans. Measured 2026-11-14 under a scratch HOME: a 3.99.7
install read 3.99.9 after one `trufflehog filesystem <dir> --json`, with a
`trufflehog-updates.lock` beside it, while `trufflehog --version` left it at
3.99.7. So a CI step that installs the `versions.yaml` pin and then scans
without the flag runs whatever trufflehog released last. JMo's own scans pass
it (`scripts/core/tool_descriptors.py`, guarded by test_per_tool_flag_policy);
this covers the shell the workflows, the Dockerfile, the Makefile and the dev
scripts run.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# trufflehog's subcommands that scan a source. `--version` and `--help` do not
# update (measured, see above), and a bare `trufflehog` in a tool list
# (`for tool in ... trufflehog; do`, `--tools trufflehog opengrep`) is no command.
SCAN_SUBCOMMANDS = (
    "analyze",
    "circleci",
    "docker",
    "elasticsearch",
    "filesystem",
    "gcs",
    "git",
    "github",
    "github-experimental",
    "gitlab",
    "huggingface",
    "jenkins",
    "json-enumerator",
    "multi-scan",
    "postman",
    "s3",
    "stdin",
    "syslog",
    "travisci",
)
INVOCATION = re.compile(
    r"(?<![\w./-])trufflehog\s+(?:"
    + "|".join(map(re.escape, SCAN_SUBCOMMANDS))
    + r")\b"
)


def _sources() -> list[Path]:
    files = [
        *(ROOT / ".github").rglob("*.yml"),
        *ROOT.glob("Dockerfile*"),
        ROOT / "Makefile",
        *(ROOT / "scripts").rglob("*.sh"),
    ]
    return sorted(p for p in files if p.is_file())


def invocations(text: str) -> list[str]:
    """Each trufflehog scan command in `text`, its continuation lines joined.

    `text` comes from `read_text`, whose universal newlines turn a CRLF
    checkout's `\\\\\\r\\n` into `\\\\\\n` (windows-encoding.rules.md), so the join
    also works on windows-2022's checkout.
    """
    joined = re.sub(r"\\\n\s*", " ", text)
    return [
        line.strip()
        for line in joined.splitlines()
        if INVOCATION.search(line) and not line.lstrip().startswith("#")
    ]


def _all_invocations() -> list[tuple[str, str]]:
    return [
        (path.relative_to(ROOT).as_posix(), cmd)
        for path in _sources()
        for cmd in invocations(path.read_text(encoding="utf-8"))
    ]


def test_the_scan_finds_the_workflow_invocations() -> None:
    # A pattern that finds nothing passes the assertion below vacuously. On
    # 2026-11-17 the two workflow steps #1625 names and ci-local.sh ran it.
    found = _all_invocations()
    assert {f for f, _ in found} >= {
        ".github/workflows/ci.yml",
        ".github/workflows/scheduled.yml",
        "scripts/dev/ci-local.sh",
    }, found


def test_the_check_rejects_a_scan_without_the_flag() -> None:
    # The negative control: the pre-fix line from scheduled.yml, continuation
    # and all, is found, and lacks the flag.
    before = (
        "          trufflehog filesystem . --json --exclude-paths x.txt \\\n"
        "              --only-verified > out.json\n"
    )
    (cmd,) = invocations(before)
    assert "--only-verified" in cmd
    assert "--no-update" not in cmd
    # A tool list and a version probe are not scans.
    assert invocations("for t in opengrep trufflehog; do\ntrufflehog --version\n") == []


def test_every_trufflehog_scan_passes_no_update() -> None:
    missing = [
        f"{f}: {cmd[:140]}" for f, cmd in _all_invocations() if "--no-update" not in cmd
    ]
    assert not missing, (
        "trufflehog scans without --no-update replace the pinned binary with the "
        "newest release before they run (#1625):\n" + "\n".join(missing)
    )
