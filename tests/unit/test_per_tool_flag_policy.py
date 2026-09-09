#!/usr/bin/env python3
"""Guards for per-tool flag and timeout resolution (#822).

The failure this file prevents: **a documented config knob silently destroying a
tool's entire contribution.** JMo splices `per_tool.<tool>.flags` into the argv
*after* its own flags, and a scalar flag is last-one-wins, so
`flags: ["-f","table"]` made trivy write a table into `trivy.json`. The file
existed, so the tool graded `success`; the adapter could not read it; and the
scan exited 0. Measured: **2 findings to 0, rc=0, nothing on any stream.**

Second concern here: these helpers existed as five identical copies, one per
scanner, and only `repository_scanner`'s `get_tool_timeout` applied the
slow-tool floor. Consolidating them is what makes a single guard possible.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path

import pytest

from scripts.cli.scan_utils import (
    RESERVED_OUTPUT_FLAGS,
    TOOL_TIMEOUT_DEFAULTS,
    tool_flags,
    tool_timeout,
)

SCAN_JOBS = Path(__file__).resolve().parents[2] / "scripts" / "cli" / "scan_jobs"


class TestReservedFlagsAreRefused:
    """Flags that decide where a tool writes, and in what format, are JMo's."""

    def test_untouched_flags_pass_through(self):
        cfg = {"trivy": {"flags": ["--no-progress", "--scanners", "vuln,secret"]}}
        assert tool_flags(cfg, "trivy") == [
            "--no-progress",
            "--scanners",
            "vuln,secret",
        ]

    def test_reserved_flag_takes_its_value_with_it(self):
        """Dropping only the flag would be worse than the collision.

        `["-f", "table"]` reduced to `["table"]` leaves a bare word in the argv,
        and trivy reads a bare word as a **scan target**. The value has to go too.
        """
        assert tool_flags({"trivy": {"flags": ["-f", "table"]}}, "trivy") == []

    def test_inline_value_form_is_handled(self):
        """`--format=table` carries its value in the same token."""
        cfg = {"trivy": {"flags": ["--format=table", "--quiet"]}}
        assert tool_flags(cfg, "trivy") == ["--quiet"]

    def test_only_the_collision_is_removed(self):
        cfg = {"trivy": {"flags": ["-o", "/tmp/x.json", "--debug"]}}
        assert tool_flags(cfg, "trivy") == ["--debug"]

    def test_a_following_flag_is_not_eaten_as_a_value(self):
        """`-o` immediately followed by another flag must not consume it."""
        cfg = {"semgrep": {"flags": ["-o", "--verbose"]}}
        assert tool_flags(cfg, "semgrep") == ["--verbose"]

    def test_the_drop_is_announced(self, caplog):
        """Silently ignoring configuration is the #807 class; say so."""
        with caplog.at_level(logging.WARNING, logger="scripts.cli.scan_utils"):
            tool_flags({"trivy": {"flags": ["-f", "table"]}}, "trivy")

        visible = [
            r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING
        ]
        assert visible, "a dropped flag was not reported"
        assert any("trivy" in m for m in visible), visible
        assert any("-f table" in m for m in visible), visible

    def test_clean_config_stays_quiet(self, caplog):
        """The control. Without it an always-warn bug passes the test above."""
        with caplog.at_level(logging.WARNING, logger="scripts.cli.scan_utils"):
            tool_flags({"trivy": {"flags": ["--no-progress"]}}, "trivy")
        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]

    def test_repeatable_flags_are_deliberately_not_policed(self):
        """`--scanners` unions rather than replaces, so it is not load-bearing.

        Measured against trivy 0.70.0: `--scanners misconfig --scanners license`
        returns misconfig results, so a repeat widens rather than overrides.
        Policing it -- or `--exclude`, which tools legitimately repeat -- would
        break working configs to fix a problem that does not exist.
        """
        assert "--scanners" not in RESERVED_OUTPUT_FLAGS
        assert "--exclude" not in RESERVED_OUTPUT_FLAGS
        cfg = {"trivy": {"flags": ["--scanners", "vuln", "--scanners", "secret"]}}
        assert tool_flags(cfg, "trivy") == [
            "--scanners",
            "vuln",
            "--scanners",
            "secret",
        ]

    @pytest.mark.parametrize("junk", [None, "not-a-dict", 42, []])
    def test_degenerate_config_is_not_a_crash(self, junk):
        assert tool_flags({"trivy": junk}, "trivy") == []
        assert tool_flags({}, "trivy") == []


class TestTimeoutFloorReachesEveryTargetType:
    """The floor lived in repository_scanner, so only repo scans honoured it."""

    def test_floor_raises_a_low_profile_default(self):
        """`zap` needs 900 s and also runs on `url` targets.

        Measured before consolidation: a `balanced` URL scan gave zap the
        profile's 600 s -- **300 s short, a third of its budget** -- while the
        identical tool on a repository target got 900 s, because only
        `repository_scanner`'s copy of this helper applied the floor.
        """
        assert TOOL_TIMEOUT_DEFAULTS["zap"] == 900
        assert tool_timeout({}, "zap", 600) == 900

    def test_semgrep_carries_a_floor_above_every_profile_default(self):
        """#1204: semgrep had no floor, so it took the profile default.

        Its cost is its RULE COUNT, not the tree it walks -- it restricts itself
        to git-tracked files, so the vendored-directory exclusions #1080 added
        cannot move its number. Measured on this repository twice, same 541
        tracked files and the same 2,930 rules resolved from `--config auto`:
        **409.8 s** and, in #1204, **583 s**. 42% apart on one machine.

        The values are spelled out rather than read from PROFILES: a guard that
        derives its expectation from the thing it guards cannot fail when that
        thing changes (#1061). fast=300, slim=500, balanced=600, deep=900 are
        `jmo.yml`'s. #1204's own table said balanced=500 and deep=600, which is
        measured false and shifted by a row -- so the honest statement is that
        `fast` lost semgrep outright and `slim` cleared it by 90 s.
        """
        assert TOOL_TIMEOUT_DEFAULTS["semgrep"] == 900
        for profile_default in (300, 500, 600, 900):
            assert tool_timeout({}, "semgrep", profile_default) == 900

    def test_semgrep_secrets_is_a_separate_entry_and_has_no_floor(self):
        """`semgrep-secrets` runs `--config p/secrets`, a curated set rather
        than the 2,930 rules `auto` resolves, and it is a separate profile tool
        with its own command builder. Giving the binary's name a floor must not
        silently give the variant one -- the lookup is by tool name."""
        assert "semgrep-secrets" not in TOOL_TIMEOUT_DEFAULTS
        assert tool_timeout({}, "semgrep-secrets", 300) == 300

    def test_a_generous_profile_default_is_not_lowered(self):
        assert tool_timeout({}, "zap", 1800) == 1800

    def test_explicit_per_tool_timeout_wins_outright(self):
        """An operator who names a number gets it, floor or not."""
        assert tool_timeout({"zap": {"timeout": 120}}, "zap", 600) == 120

    def test_tools_without_a_floor_get_the_default(self):
        assert "trivy" not in TOOL_TIMEOUT_DEFAULTS
        assert tool_timeout({}, "trivy", 600) == 600

    @pytest.mark.parametrize("junk", [None, "600", 0, -1])
    def test_junk_override_falls_through_to_the_default(self, junk):
        assert tool_timeout({"trivy": {"timeout": junk}}, "trivy", 600) == 600


def _is_delegation_to(node: ast.FunctionDef, callee: str) -> bool:
    """True when the body is exactly `return <callee>(...)`, docstring aside.

    Asserted as the **positive shape** rather than as "does not mention
    per_tool_config". The first version of this guard excluded `ast.Return`
    nodes -- so that the legitimate `return tool_flags(per_tool_config, tool)`
    would not trip it -- and mutation testing walked straight through that hole
    with a one-line inline copy hidden inside a return:

        return [str(f) for f in per_tool_config.get(tool, {}).get("flags", [])]

    A guard written around the shape the bug had last time gets walked around.
    Requiring delegation, rather than forbidding one spelling of not-delegating,
    has no such gap.
    """
    body = [
        stmt
        for stmt in node.body
        if not (
            isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Constant)
            and isinstance(stmt.value.value, str)
        )
    ]
    if len(body) != 1 or not isinstance(body[0], ast.Return):
        return False
    value = body[0].value
    return (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id == callee
    )


def _scan_job_modules() -> list[Path]:
    return sorted(SCAN_JOBS.glob("*_scanner.py"))


def test_no_scanner_reimplements_the_helpers() -> None:
    """These may delegate, never re-derive.

    Asserted as a **property of the body** rather than by naming the five
    scanners: any `get_tool_flags` / `get_tool_timeout` that reads
    `per_tool_config` directly has grown its own copy again.

    This is the shape that caused the bug. Five identical `get_tool_flags`
    copies meant a filter had five homes and got none; five `get_tool_timeout`
    copies meant the slow-tool floor lived in exactly one and silently did not
    apply to the other four target types. Same family as #808 and the dead
    `_iter_*` helpers.
    """
    offenders: list[str] = []
    checked = 0
    delegates_to = {"get_tool_flags": "tool_flags", "get_tool_timeout": "tool_timeout"}

    for path in _scan_job_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            if node.name not in delegates_to:
                continue
            checked += 1
            if not _is_delegation_to(node, delegates_to[node.name]):
                offenders.append(f"{path.name}:{node.lineno} {node.name}")

    assert checked >= 8, (
        f"expected both helpers in several scanners, found only {checked} -- "
        "this guard may have stopped covering anything"
    )
    assert not offenders, (
        "these re-derive per-tool config instead of delegating to "
        "scan_utils.tool_flags / scan_utils.tool_timeout:\n  " + "\n  ".join(offenders)
    )


class TestShippedFlagsAreFlagsTheToolActuallyHas:
    """#1223: `jmo.yml` shipped kubescape `--silent`, which kubescape rejects.

    `per_tool.<tool>.flags` is spliced straight into argv. An **unknown** flag
    is a different failure from #822's wrong-value one and just as total: the
    tool exits before scanning, writes no output file, and JMo reports
    `findings are MISSING` -- which reads identically to a tool that ran and
    found nothing.

    Measured end to end, same command and same 4.0.13 binary, only the flag
    differing: `kubescape.json` **not written / 0 findings** with `--silent`,
    **179,810 bytes / 51 findings** without.

    **This is the third instance of the shape in this repository**, which is
    why the guard is a table rather than one assertion:

    - `trivy-rbac` passed `--scanners config` to `trivy config`, which has no
      such flag (#1206) -- dead since the v1.0.0 sixteen-tool commit.
    - `prowler` was passed `--quiet`, which prowler 5.x does not have. That fix
      left a comment **three lines above** the first kubescape `--silent`, in
      this same file, and nobody connected them.
    - `kubescape` was passed `--silent` (#1223) -- dead since 2025-12-14.

    What this guard is NOT: proof that a flag is valid. Only running the binary
    shows that, and the suite mocks `subprocess`. It is a memory of the three
    the project has already paid for, so a fourth cannot be the *same* one.
    """

    # (tool, flag) -> why the tool rejects it. Spelled out rather than derived:
    # a guard that reads its expectation from the file it guards cannot fail
    # when that file changes (#1061).
    REJECTED_FLAGS: dict[tuple[str, str], str] = {
        ("kubescape", "--silent"): (
            "kubescape has no --silent at 4.0.13 (`kubescape scan --help` "
            "matches it 0 times); it exits 1 having written nothing (#1223)"
        ),
        ("prowler", "--quiet"): (
            "prowler 5.x has no --quiet; argparse exits 2 before the scan "
            "starts. --no-banner is what suppresses its chatter, and the "
            "scanner passes that itself"
        ),
        ("trivy-rbac", "--scanners"): (
            "`trivy config` has no --scanners at 0.74.0: FATAL unknown flag, "
            "exit 1, no output file (#1206). It is also redundant -- "
            "`trivy config` IS the misconfiguration scanner"
        ),
    }

    @staticmethod
    def _shipped_per_tool_flags() -> dict[tuple[str, str], list[str]]:
        """{(profile, tool): flags} for every profile in the shipped jmo.yml."""
        import yaml

        config = Path(__file__).resolve().parents[2] / "jmo.yml"
        data = yaml.safe_load(config.read_text(encoding="utf-8"))
        out: dict[tuple[str, str], list[str]] = {}
        for profile, body in (data.get("profiles") or {}).items():
            for tool, entry in ((body or {}).get("per_tool") or {}).items():
                flags = (entry or {}).get("flags")
                if isinstance(flags, list):
                    out[(str(profile), str(tool))] = [str(f) for f in flags]
        for tool, entry in (data.get("per_tool") or {}).items():
            flags = (entry or {}).get("flags")
            if isinstance(flags, list):
                out[("<top-level>", str(tool))] = [str(f) for f in flags]
        return out

    def test_the_extractor_actually_finds_the_shipped_flags(self):
        """Meta-guard: an extractor that silently finds nothing passes every
        assertion built on it."""
        shipped = self._shipped_per_tool_flags()

        assert len(shipped) >= 8, f"only found {len(shipped)} per_tool flag lists"
        assert any(t == "trivy" for _p, t in shipped), "trivy carries flags in jmo.yml"
        assert any(p == "fast" for p, _t in shipped), "the fast profile sets flags"

    def test_no_profile_ships_a_flag_its_tool_rejects(self):
        shipped = self._shipped_per_tool_flags()

        offences = [
            f"profile {profile!r} passes {tool} {flag!r} -- {why}"
            for (profile, tool), flags in sorted(shipped.items())
            for (bad_tool, flag), why in self.REJECTED_FLAGS.items()
            if tool == bad_tool and flag in flags
        ]

        assert not offences, "jmo.yml ships flags the tool rejects:\n  " + "\n  ".join(
            offences
        )

    def test_kubescape_carries_no_flags_at_all(self):
        """The narrow regression, stated separately from the table.

        `--silent` was kubescape's ONLY flag in every profile that set one, so
        the honest post-fix state is that it takes none -- and a table entry
        alone would still pass if someone re-added it under a different
        spelling.
        """
        shipped = self._shipped_per_tool_flags()

        kubescape = {p: f for (p, t), f in shipped.items() if t == "kubescape"}

        assert kubescape == {}, f"kubescape should ship no flags, got {kubescape}"
