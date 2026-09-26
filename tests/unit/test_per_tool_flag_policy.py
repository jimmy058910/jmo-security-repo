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

    def test_floor_raises_a_low_scan_default(self):
        """`zap` needs 900 s and also runs on `url` targets.

        Measured before consolidation: a URL scan at the (then `balanced`
        profile's, now top-level) 600 s default gave zap **300 s short, a third
        of its budget** -- while the identical tool on a repository target got
        900 s, because only `repository_scanner`'s copy of this helper applied
        the floor.
        """
        assert TOOL_TIMEOUT_DEFAULTS["zap"] == 900
        assert tool_timeout({}, "zap", 600) == 900

    def test_semgrep_carries_a_floor_above_a_low_scan_default(self):
        """#1204: semgrep had no floor, so it took the scan default.

        Its cost is its RULE COUNT, not the tree it walks -- it restricts itself
        to git-tracked files, so the vendored-directory exclusions #1080 added
        cannot move its number. Measured on this repository twice, same 541
        tracked files and the same 2,930 rules resolved from `--config auto`:
        **409.8 s** and, in #1204, **583 s**. 42% apart on one machine.

        The values are spelled out rather than read from `jmo.yml`: a guard that
        derives its expectation from the thing it guards cannot fail when that
        thing changes (#1061). 300/500/600/900 are the four defaults v1's
        profiles shipped; v2.0.0's top-level default is 600.
        """
        assert TOOL_TIMEOUT_DEFAULTS["semgrep"] == 900
        for scan_default in (300, 500, 600, 900):
            assert tool_timeout({}, "semgrep", scan_default) == 900

    def test_a_generous_scan_default_is_not_lowered(self):
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
    delegates_to = {"get_tool_flags": "tool_flags", "get_tool_timeout": "tool_timeout"}

    jobs = _scan_job_modules()
    assert len(jobs) >= 6, f"found only {jobs}; this guard may cover nothing"
    for path in jobs:
        tree = ast.parse(path.read_bytes().decode("utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name in delegates_to:
                if not _is_delegation_to(node, delegates_to[node.name]):
                    offenders.append(f"{path.name}:{node.lineno} {node.name}")

    assert not offenders, (
        "these re-derive per-tool config instead of delegating to "
        "scan_utils.tool_flags / scan_utils.tool_timeout:\n  " + "\n  ".join(offenders)
    )

    # Since Phase 3 every job runs its tools through the one loop, so the copies
    # have one place to come back: assert that place uses both helpers.
    loop = ast.parse((SCAN_JOBS / "tool_loop.py").read_bytes().decode("utf-8"))
    called = {
        node.func.id
        for node in ast.walk(loop)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert {"tool_flags", "tool_timeout"} <= called, called


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

    **This shape has recurred four times in this repository**, which is why
    the guard is a table rather than one assertion. Three were on tools v2.0.0
    removed -- trivy-rbac `--scanners` (#1206), prowler `--quiet`, kubescape
    `--silent` (#1223) -- so their entries went with them. The fourth is on a
    tool that stays:

    - `yara` shipped `--max-rules-per-file=500`, which is not a yara option
      (recorded in `jmo.yml`'s own comment on the yara entry).

    What this guard is NOT: proof that a flag is valid. Only running the binary
    shows that, and the suite mocks `subprocess`. It is a memory of the ones
    the project has already paid for, so the next cannot be the *same* one.
    """

    # (tool, flag) -> why the tool rejects it. Spelled out rather than derived:
    # a guard that reads its expectation from the file it guards cannot fail
    # when that file changes (#1061).
    REJECTED_FLAGS: dict[tuple[str, str], str] = {
        ("yara", "--max-rules-per-file=500"): (
            "not a yara option: v4.5.8 defines `max-rules` and "
            "`max-strings-per-rule` and nothing of that name, so the scanner "
            "would be rejected on an unknown option"
        ),
    }

    @staticmethod
    def _jmo_yml() -> Path:
        return Path(__file__).resolve().parents[2] / "jmo.yml"

    @classmethod
    def _shipped_per_tool_flags(cls) -> dict[str, list[str]]:
        """{tool: flags} for the shipped jmo.yml's top-level `per_tool`."""
        import yaml

        data = yaml.safe_load(cls._jmo_yml().read_text(encoding="utf-8"))
        out: dict[str, list[str]] = {}
        for tool, entry in (data.get("per_tool") or {}).items():
            flags = (entry or {}).get("flags")
            if isinstance(flags, list):
                out[str(tool)] = [str(f) for f in flags]
        return out

    def test_the_extractor_actually_finds_the_shipped_flags(self):
        """Meta-guard: an extractor that silently finds nothing passes every
        assertion built on it.

        Checked against the product's own loader, an independent reading of
        the same file, rather than against a count.
        """
        from scripts.core.config import load_config

        shipped = self._shipped_per_tool_flags()
        loaded = load_config(str(self._jmo_yml())).per_tool
        assert shipped == {
            tool: entry["flags"]
            for tool, entry in loaded.items()
            if isinstance((entry or {}).get("flags"), list)
        }
        assert "trivy" in shipped, "trivy carries flags in jmo.yml"

    def test_jmo_yml_ships_no_flag_its_tool_rejects(self):
        shipped = self._shipped_per_tool_flags()

        offences = [
            f"per_tool.{tool} passes {flag!r} -- {why}"
            for tool, flags in sorted(shipped.items())
            for (bad_tool, flag), why in self.REJECTED_FLAGS.items()
            if tool == bad_tool and flag in flags
        ]

        assert not offences, "jmo.yml ships flags the tool rejects:\n  " + "\n  ".join(
            offences
        )
