"""Config precedence and CLI-shell contracts (v1.1.0 audit campaign, chunk 1).

Every precedence layer here is proven by **observing the resolved value**, not
by running the code path and asserting it did not raise. The pre-existing
coverage in ``tests/integration/test_cli_profile_threads.py`` sets
``JMO_THREADS=5``, calls ``cmd_report`` and asserts ``rc in (0, 1)`` under the
comment *"We cannot easily read threads back from aggregator here"* — so it
cannot go red if the ordering is reversed. These can.

Also pins the four contracts chunk 1 found broken: #787 (history recorded the
config's tool list instead of what ran), #788 (``tools check`` exited 0 with
tools missing), #789 (a destructive prompt raised ``EOFError`` on a non-TTY),
#790 (user-facing output named subcommands that do not exist).
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import io
import json
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.cli import jmo as jmo_mod
from scripts.core.config import Config, load_config_with_env_overrides

# `_get_max_workers` falls through to CPU auto-detection. Pin it to a value no
# other layer uses so "which layer won" is unambiguous rather than inferred.
SENTINEL_AUTO = 99


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Precedence tests must not inherit a JMO_* var from the developer's shell."""
    for var in ("JMO_THREADS", "JMO_DEDUP_THRESHOLD", "JMO_PROFILE"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def pinned_autodetect(monkeypatch: pytest.MonkeyPatch) -> int:
    monkeypatch.setattr(jmo_mod, "_auto_detect_threads", lambda _args: SENTINEL_AUTO)
    return SENTINEL_AUTO


# --------------------------------------------------------------------------
# threads: defaults -> jmo.yml -> env -> flags, one test per layer
# --------------------------------------------------------------------------


def _resolve_threads(eff_threads: object, cfg_threads: object) -> int | None:
    return jmo_mod._get_max_workers(
        argparse.Namespace(),
        {"threads": eff_threads},
        Config(threads=cfg_threads),  # type: ignore[arg-type]
    )


def test_threads_layer1_nothing_set_falls_through_to_autodetect(pinned_autodetect):
    """Layer 1 (defaults): no flag, no env, no config -> auto-detect."""
    assert _resolve_threads(None, None) == SENTINEL_AUTO


def test_threads_layer2_config_file_beats_the_default(pinned_autodetect):
    """Layer 2 (jmo.yml): `threads: 7` is used instead of auto-detect."""
    assert _resolve_threads(None, 7) == 7


def test_threads_layer3_env_beats_the_config_file(
    pinned_autodetect, monkeypatch: pytest.MonkeyPatch
):
    """Layer 3 (env): JMO_THREADS outranks `threads:` in jmo.yml."""
    monkeypatch.setenv("JMO_THREADS", "5")
    assert _resolve_threads(None, 7) == 5


def test_threads_layer4_flag_beats_env_and_config_file(
    pinned_autodetect, monkeypatch: pytest.MonkeyPatch
):
    """Layer 4 (flags): --threads outranks both env and jmo.yml."""
    monkeypatch.setenv("JMO_THREADS", "5")
    assert _resolve_threads(3, 7) == 3


def test_threads_auto_keyword_is_honoured_from_env_and_config(
    pinned_autodetect, monkeypatch: pytest.MonkeyPatch
):
    """'auto' means auto-detect wherever it is set, not int('auto')."""
    monkeypatch.setenv("JMO_THREADS", "auto")
    assert _resolve_threads(None, 7) == SENTINEL_AUTO
    monkeypatch.delenv("JMO_THREADS")
    assert _resolve_threads(None, "auto") == SENTINEL_AUTO


def test_threads_unparsable_env_falls_through_to_config_file(
    pinned_autodetect, monkeypatch: pytest.MonkeyPatch
):
    """A junk env value must not shadow a valid config value."""
    monkeypatch.setenv("JMO_THREADS", "not-a-number")
    assert _resolve_threads(None, 7) == 7


# --------------------------------------------------------------------------
# deduplication.similarity_threshold: same four layers, through the real loader
# --------------------------------------------------------------------------


def _write_cfg(tmp_path: Path, body: str) -> str:
    p = tmp_path / "jmo.yml"
    p.write_bytes(body.encode("utf-8"))  # write_bytes: Path.write_text flips LF->CRLF
    return str(p)


def test_dedup_layer1_default_when_no_config_file(tmp_path: Path):
    cfg = load_config_with_env_overrides(str(tmp_path / "absent.yml"))
    assert cfg.deduplication.similarity_threshold == 0.65


def test_dedup_layer2_config_file_beats_the_default(tmp_path: Path):
    path = _write_cfg(tmp_path, "deduplication:\n  similarity_threshold: 0.80\n")
    assert (
        load_config_with_env_overrides(path).deduplication.similarity_threshold == 0.80
    )


def test_dedup_layer3_env_beats_the_config_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    path = _write_cfg(tmp_path, "deduplication:\n  similarity_threshold: 0.80\n")
    monkeypatch.setenv("JMO_DEDUP_THRESHOLD", "0.90")
    assert (
        load_config_with_env_overrides(path).deduplication.similarity_threshold == 0.90
    )


@pytest.mark.parametrize("bad", ["abc", "2.0", "0.1"])
def test_dedup_out_of_range_or_junk_env_keeps_the_config_file_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: str
):
    """Rejected env values must leave the configured value standing, not reset it."""
    path = _write_cfg(tmp_path, "deduplication:\n  similarity_threshold: 0.80\n")
    monkeypatch.setenv("JMO_DEDUP_THRESHOLD", bad)
    assert (
        load_config_with_env_overrides(path).deduplication.similarity_threshold == 0.80
    )


# --------------------------------------------------------------------------
# per_tool: root block and per-profile block, "profile values win and are merged"
# --------------------------------------------------------------------------


_PER_TOOL_CFG = """\
default_profile: fast
per_tool:
  semgrep:
    timeout: 111
    flags: [--from-root]
  trivy:
    timeout: 999
profiles:
  fast:
    per_tool:
      semgrep:
        timeout: 222
"""


def _effective_per_tool(tmp_path: Path) -> dict:
    path = _write_cfg(tmp_path, _PER_TOOL_CFG)
    args = argparse.Namespace(
        config=path,
        profile_name=None,
        threads=None,
        timeout=None,
        tools=None,
        skip_tools=None,
        include=None,
        exclude=None,
        retries=None,
    )
    return jmo_mod._effective_scan_settings(args)["per_tool"]


def test_per_tool_profile_value_wins_over_the_root_value(tmp_path: Path):
    assert _effective_per_tool(tmp_path)["semgrep"]["timeout"] == 222


def test_per_tool_root_keys_survive_a_partial_profile_override(tmp_path: Path):
    """Regression for #791.

    USER_GUIDE.md:1652 promises the two blocks "are merged". A flat
    `dict.update()` replaced semgrep's whole entry, so overriding only its
    timeout silently dropped the root-level flags.
    """
    assert _effective_per_tool(tmp_path)["semgrep"]["flags"] == ["--from-root"]


def test_per_tool_tools_the_profile_never_mentions_are_untouched(tmp_path: Path):
    assert _effective_per_tool(tmp_path)["trivy"] == {"timeout": 999}


def test_per_tool_merge_does_not_mutate_the_loaded_config(tmp_path: Path):
    """The merge must copy: mutating cfg.per_tool would leak across profiles."""
    from scripts.core.config import load_config

    path = _write_cfg(tmp_path, _PER_TOOL_CFG)
    cfg = load_config(path)
    merged = jmo_mod._merge_per_tool(cfg.per_tool, cfg.profiles["fast"]["per_tool"])
    merged["semgrep"]["timeout"] = 777
    assert cfg.per_tool["semgrep"]["timeout"] == 111


# --------------------------------------------------------------------------
# #787 - history must record what ran, not what jmo.yml lists
# --------------------------------------------------------------------------


def test_history_records_the_tools_that_ran_not_the_configured_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Regression for #787.

    Before the fix this asserted the config's list: 1790 of 1833 rows in the
    real database named jmo.yml's 8 tools regardless of profile, including
    `nuclei`, which was not installed and so cannot have run in any of them.
    """
    results_dir = tmp_path / "results"
    (results_dir / "individual-repos" / "repo1").mkdir(parents=True)
    (results_dir / ".scan_metadata.json").write_bytes(
        json.dumps(
            {"profile": "deep", "tools": ["trufflehog"], "target_count": 1}
        ).encode("utf-8")
    )
    # A config whose tool list is deliberately nothing like what ran.
    cfg_path = _write_cfg(
        tmp_path,
        "default_profile: balanced\ntools:\n- semgrep\n- trivy\n- nuclei\noutputs:\n- json\n",
    )

    args = argparse.Namespace(
        cmd="report",
        results_dir=str(results_dir),
        out=str(results_dir / "summaries"),
        config=cfg_path,
        fail_on=None,
        profile=False,
        threads=None,
        store_history=True,
        history_db=str(tmp_path / "history.db"),  # never the real .jmo/history.db
        profile_name=None,
    )

    with patch("scripts.core.history_db.store_scan", return_value="scan-id") as store:
        jmo_mod.cmd_report(args)

    assert store.called, "report did not reach the history-storage hook"
    kwargs = store.call_args.kwargs
    assert kwargs["tools"] == ["trufflehog"], (
        "history recorded the configured tool list instead of what ran: "
        f"{kwargs['tools']}"
    )
    assert kwargs["profile"] == "deep", (
        f"history recorded the config default instead of the scanned profile: "
        f"{kwargs['profile']}"
    )


def test_history_falls_back_to_config_profile_when_no_scan_metadata(
    tmp_path: Path,
):
    """Without .scan_metadata.json there is nothing better than the config."""
    results_dir = tmp_path / "results"
    (results_dir / "individual-repos" / "repo1").mkdir(parents=True)
    cfg_path = _write_cfg(tmp_path, "default_profile: fast\noutputs:\n- json\n")

    args = argparse.Namespace(
        cmd="report",
        results_dir=str(results_dir),
        out=str(results_dir / "summaries"),
        config=cfg_path,
        fail_on=None,
        profile=False,
        threads=None,
        store_history=True,
        history_db=str(tmp_path / "history.db"),
        profile_name=None,
    )

    with patch("scripts.core.history_db.store_scan", return_value="scan-id") as store:
        jmo_mod.cmd_report(args)

    assert store.call_args.kwargs["profile"] == "fast"


def test_history_infers_tools_from_findings_when_scan_metadata_has_none(
    tmp_path: Path,
):
    """The middle rung of #787's chain: metadata absent, findings present.

    ``tools_used`` resolves scan metadata -> tools named by the findings ->
    nothing.  Rung 1 and the profile side of rung 2 are pinned above; this pins
    the tool side of rung 2, which is what runs whenever a results directory is
    reported without the scan's own ``.scan_metadata.json`` beside it (``jmo
    report`` on a directory copied off another machine, or produced before the
    metadata file existed).

    The config names a completely different tool, so a pass means the findings
    won and not merely that *some* list arrived.
    """
    results_dir = tmp_path / "results"
    repo = results_dir / "individual-repos" / "repo1"
    repo.mkdir(parents=True)
    # No .scan_metadata.json: rung 1 is unavailable by construction.
    (repo / "trufflehog.json").write_bytes(
        json.dumps(
            [
                {
                    "schemaVersion": "1.0.0",
                    "id": "finding-1",
                    "ruleId": "R1",
                    "message": "m",
                    "severity": "LOW",
                    "tool": {"name": "trufflehog", "version": "1"},
                    "location": {"path": "a.txt", "startLine": 1},
                }
            ]
        ).encode("utf-8")
    )
    cfg_path = _write_cfg(
        tmp_path,
        "default_profile: fast\ntools:\n- semgrep\n- nuclei\noutputs:\n- json\n",
    )

    args = argparse.Namespace(
        cmd="report",
        results_dir=str(results_dir),
        out=str(results_dir / "summaries"),
        config=cfg_path,
        fail_on=None,
        profile=False,
        threads=None,
        store_history=True,
        history_db=str(tmp_path / "history.db"),
        profile_name=None,
    )

    with patch("scripts.core.history_db.store_scan", return_value="scan-id") as store:
        jmo_mod.cmd_report(args)

    assert store.called, "report did not reach the history-storage hook"
    assert store.call_args.kwargs["tools"] == ["trufflehog"], (
        "history did not fall back to the tools the findings name: "
        f"{store.call_args.kwargs['tools']}"
    )


# --------------------------------------------------------------------------
# #788 - `jmo tools check` exit code is the same contract in every form
# --------------------------------------------------------------------------


def _summary(missing: int) -> dict:
    return {
        "profile": "p",
        "total": 10,
        "installed": 10 - missing,
        "missing": missing,
        "real_missing": missing,
        "manual_install_missing": 0,
        "ready": missing == 0,
        "warnings": [],
    }


@pytest.mark.parametrize("output_json", [True, False])
def test_bare_tools_check_exits_nonzero_when_a_profile_is_short_a_tool(output_json):
    """Regression for #788: readiness was computed and then discarded."""
    from scripts.cli.tool_commands import cmd_tools_check

    manager = MagicMock()
    manager.get_profile_summary.side_effect = lambda _p: _summary(missing=2)
    manager.get_critical_outdated.return_value = []

    args = argparse.Namespace(tools=None, profile=None, json=output_json)
    with (
        patch("scripts.cli.tool_commands.ToolManager", return_value=manager),
        patch("scripts.cli.tool_commands.print_profile_summary"),
        patch("builtins.print"),
    ):
        assert cmd_tools_check(args) == 1


@pytest.mark.parametrize("output_json", [True, False])
def test_bare_tools_check_exits_zero_when_every_profile_is_complete(output_json):
    from scripts.cli.tool_commands import cmd_tools_check

    manager = MagicMock()
    manager.get_profile_summary.side_effect = lambda _p: _summary(missing=0)
    manager.get_critical_outdated.return_value = []

    args = argparse.Namespace(tools=None, profile=None, json=output_json)
    with (
        patch("scripts.cli.tool_commands.ToolManager", return_value=manager),
        patch("scripts.cli.tool_commands.print_profile_summary"),
        patch("builtins.print"),
    ):
        assert cmd_tools_check(args) == 0


# --------------------------------------------------------------------------
# #789 - no destructive prompt may raise on a non-TTY
# --------------------------------------------------------------------------


def test_schedule_delete_declines_instead_of_raising_on_closed_stdin():
    """Regression for #789.

    Not reproducible end to end here — `schedule list` reports no schedules, so
    the real command returns early before the prompt. A stub manager puts the
    prompt in reach; before the fix this raised EOFError.
    """
    from scripts.cli.schedule_commands import _cmd_schedule_delete

    manager = MagicMock()
    manager.get.return_value = {"name": "nightly"}
    args = argparse.Namespace(name="nightly", force=False)

    with patch("builtins.input", side_effect=EOFError):
        rc = _cmd_schedule_delete(args, manager)

    assert rc == 0
    # A declined confirmation must not delete the schedule.
    manager.delete.assert_not_called()


# --------------------------------------------------------------------------
# #790 - user-facing output may not name a subcommand that does not exist
# --------------------------------------------------------------------------


def _parser_subcommands() -> set[str]:
    """Derive the subcommand set from the parser itself.

    Deliberately not a restated list: `cli_validator.MAIN_SUBCOMMANDS` is one of
    those and had drifted to 13 of 20 (#783). `parse_args()` builds and parses in
    one call, so capture the subparser action on the way past.
    """
    captured: dict[str, argparse._SubParsersAction] = {}
    original = argparse.ArgumentParser.add_subparsers

    def _capture(self, *a, **kw):
        action = original(self, *a, **kw)
        captured.setdefault(kw.get("dest") or "positional", action)
        return action

    argv = sys.argv
    argparse.ArgumentParser.add_subparsers = _capture  # type: ignore[method-assign]
    try:
        sys.argv = ["jmo", "--help"]
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
            contextlib.suppress(SystemExit),
        ):
            jmo_mod.parse_args()
    finally:
        argparse.ArgumentParser.add_subparsers = original  # type: ignore[method-assign]
        sys.argv = argv

    top = captured.get("cmd")
    assert top is not None, "could not capture the top-level subparsers action"
    return set(top.choices)


# Two unambiguous ways of naming a command: backtick-quoted, or followed by a
# flag. Plain prose ("the .jmo directory", "jmo entry point failed") matches
# neither, which is what keeps this guard from crying wolf.
_COMMAND_REF = re.compile(r"`jmo\s+([a-z][a-z0-9-]+)|\bjmo\s+([a-z][a-z0-9-]+)\s+--")


def test_no_user_facing_string_names_a_nonexistent_subcommand():
    """Regression for #790.

    Before the fix, first-run output told users to run `jmo config --email ...`
    and `jmo subscribe`, neither of which is in the parser's 20 subcommands.

    Scans string literals via `ast` rather than by line, so comments cannot
    trip it — the same approach as tests/cross_platform/test_encoding_drift_guard.py.
    """
    real = _parser_subcommands()
    assert len(real) >= 20, f"parser capture looks wrong: {sorted(real)}"

    offenders: list[str] = []
    for path in sorted(Path("scripts").rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:  # pragma: no cover - would fail elsewhere first
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                continue
            for match in _COMMAND_REF.finditer(node.value):
                name = match.group(1) or match.group(2)
                if name not in real:
                    offenders.append(f"{path.as_posix()}:{node.lineno}: jmo {name}")

    assert (
        not offenders
    ), "user-facing text names commands that do not exist:\n" + "\n".join(offenders)
