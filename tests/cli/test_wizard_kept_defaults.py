"""A setting the wizard user leaves at its default never becomes a flag.

Most cases are the timeout, where it mattered most.

Since #1486 a `--timeout` on the command line wins over a tool's minimum
(opengrep and zap: 900 s), where `jmo.yml`'s `timeout` cannot lower one. The
wizard's "Customize advanced settings?" offers `Timeout [600]`, and a user who
pressed Enter there got `--timeout 600` on the generated command, so opengrep
and zap ran with 600 s. For zap that is its whole plan's budget, so it scanned
less (#1627). The GitHub Actions workflow was worse: it wrote `--timeout 600`
whether or not the user customized anything.

The rule: an answer left blank is not an override and never reaches a command
line; a number the user typed is one, on every route, whatever its value.

Each case drives the real `configure_advanced`, builds every artifact the
wizard writes from its answers, asks the real parser for the `--timeout` each
`jmo` call carries, and resolves the per-tool timeout through the scan's own
code (`_effective_scan_settings`, `cli_timeout_over_floors`, `tool_timeout`)
against a copy of the shipped `jmo.yml`. The resolving cases compare against
`TOOL_TIMEOUT_DEFAULTS` rather than restating the floors; only the display
tests spell out the text the screen should show.

Threads follow the same rule. A kept `Threads [4]` wrote `--threads 4` over
jmo.yml's `threads: auto` (which the wizard read as 4), and every workflow
wrote `--threads`; those cases resolve the worker count through the scan's
`_get_max_workers`.
"""

from __future__ import annotations

import shlex
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.cli import jmo, wizard
from scripts.cli.scan_utils import (
    TOOL_TIMEOUT_DEFAULTS,
    cli_timeout_over_floors,
    tool_timeout,
)
from scripts.cli.wizard_flows.config_models import WizardConfig
from scripts.cli.wizard_generators import (
    JMO_DOCKER_IMAGE_FULL,
    generate_github_actions,
    generate_makefile_target,
    generate_shell_script,
)
from scripts.core.config import load_config
from tests.unit.test_wizard_generated_commands_parse import extract_commands

SHIPPED_JMO_YML = Path(__file__).resolve().parents[2] / "jmo.yml"
FLOORED = sorted(TOOL_TIMEOUT_DEFAULTS)

ROUTES = (
    "command",
    "docker-command",
    "makefile",
    "script",
    "workflow",
    "docker-workflow",
)


@pytest.fixture(autouse=True)
def _shipped_config(tmp_path, monkeypatch):
    """Run where the shipped jmo.yml is the one both the wizard and the scan read."""
    (tmp_path / "jmo.yml").write_bytes(SHIPPED_JMO_YML.read_bytes())
    monkeypatch.chdir(tmp_path)


def _answer_advanced(
    customize: bool, timeout_answer: str = "", threads_answer: str = ""
) -> WizardConfig:
    """The wizard's step 4 with `threads_answer` and `timeout_answer` typed
    (blank by default), on a machine with 4 CPUs."""
    tm = MagicMock()
    tm.get_tool_summary.return_value = MagicMock(execution_ready=1, total=1)
    with (
        patch.object(wizard, "_prompt_yes_no", return_value=customize),
        patch("builtins.input", side_effect=[threads_answer, timeout_answer]),
        patch.object(wizard, "_prompt_choice", return_value=""),
        patch.object(wizard, "get_cpu_count", return_value=4),
    ):
        threads, timeout, fail_on = wizard.configure_advanced(tm, ["opengrep", "zap"])
    config = WizardConfig()
    config.target.type = "repo"
    config.target.repo_mode = "repo"
    config.target.repo_path = "."
    config.threads, config.timeout, config.fail_on = threads, timeout, fail_on
    return config


def _scan_argvs(config: WizardConfig, route: str) -> list[list[str]]:
    """Every `jmo scan`/`jmo ci` argv (without `jmo`) that `route` writes."""
    if route in ("command", "docker-command"):
        config.use_docker = route == "docker-command"
        parts = wizard.generate_command_list(config)
        if config.use_docker:
            return [parts[parts.index(JMO_DOCKER_IMAGE_FULL) + 1 :]]
        return [parts[1:]]
    if route == "makefile":
        text = generate_makefile_target(config, wizard.generate_command(config))
    elif route == "script":
        text = generate_shell_script(config, wizard.generate_command(config))
    else:
        config.use_docker = route == "docker-workflow"
        text = generate_github_actions(config)
    argvs = [
        shlex.split(" ".join(argv))
        for argv in extract_commands(text)
        if argv[0] in ("scan", "ci")
    ]
    assert argvs, f"{route}: no jmo scan/ci call found in:\n{text}"
    return argvs


def _resolved(
    argv: list[str], tools: list[str] = FLOORED
) -> tuple[int | None, dict[str, int]]:
    """(--timeout as parsed, each of `tools`' timeout) for one argv."""
    args = jmo.build_parser().parse_args(argv)
    eff = jmo._effective_scan_settings(args)
    per_tool = cli_timeout_over_floors(
        eff.get("per_tool", {}) or {}, eff["tools"], args.timeout
    )
    return args.timeout, {
        tool: tool_timeout(per_tool, tool, int(eff["timeout"] or 600)) for tool in tools
    }


def test_the_floors_this_file_relies_on_exist():
    """Meta-guard: with no floored tool every case below passes vacuously."""
    assert {"opengrep", "zap"} <= set(FLOORED)
    assert all(TOOL_TIMEOUT_DEFAULTS[t] > 600 for t in ("opengrep", "zap"))


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("customize", [False, True], ids=["no-customize", "kept"])
def test_a_kept_default_keeps_the_floor(route, customize):
    """Enter at `Timeout [600]` (or no customizing at all) is not an override.

    Before #1627's fix, `kept` gave opengrep and zap 600 s on every route, and
    both workflows gave them 600 s even without customizing.
    """
    config = _answer_advanced(customize)
    for argv in _scan_argvs(config, route):
        cli_timeout, timeouts = _resolved(argv)
        assert cli_timeout is None, f"{route}: {shlex.join(argv)}"
        assert timeouts == TOOL_TIMEOUT_DEFAULTS, f"{route}: {shlex.join(argv)}"


@pytest.mark.parametrize("route", ROUTES)
def test_an_unparseable_answer_keeps_the_floor(route):
    """An answer that is not a number falls back to the default: no override."""
    config = _answer_advanced(True, "ten minutes")
    for argv in _scan_argvs(config, route):
        assert _resolved(argv) == (None, TOOL_TIMEOUT_DEFAULTS)


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("typed", ["600", "300"])
def test_a_typed_timeout_overrides_the_floor(route, typed):
    """A number the user typed reaches every route and wins over the floor.

    Typing the default's own value (600) counts: the user said it. A value
    below 900 is the only kind that shows the override; 1200 would come out
    1200 with or without one. This passed before the fix too: it guards the
    fix against overshooting into dropping what a user asked for.
    """
    config = _answer_advanced(True, typed)
    for argv in _scan_argvs(config, route):
        cli_timeout, timeouts = _resolved(argv)
        assert cli_timeout == int(typed), f"{route}: {shlex.join(argv)}"
        assert timeouts == {t: int(typed) for t in FLOORED}


@pytest.mark.parametrize(
    ("tools", "shown"),
    [(["opengrep", "zap", "trivy"], "(opengrep, zap: 900s)"), (["trivy"], None)],
)
def test_the_screen_shows_the_minimums_the_default_does_not_reach(tools, shown, capsys):
    """The wizard printed `Timeout: 600s` while opengrep and zap got 900 s.

    Its defaults and its prompt now name each minimum above the default, for
    the tools this scan runs, and say nothing about one it does not run.
    """
    tm = MagicMock()
    tm.get_tool_summary.return_value = MagicMock(execution_ready=1, total=1)
    with (
        patch.object(wizard, "_prompt_yes_no", return_value=True),
        patch("builtins.input", side_effect=["", ""]),
        patch.object(wizard, "_prompt_choice", return_value=""),
    ):
        wizard.configure_advanced(tm, tools)
    out = capsys.readouterr().out
    if shown:
        assert f"Timeout: 600s {shown}" in out
        assert f"Blank keeps the default, 600s {shown}" in out
    else:
        assert "Timeout: 600s\n" in out
        assert "Blank keeps" not in out


def test_the_screen_matches_what_each_tool_gets_with_per_tool_timeouts(
    tmp_path, capsys
):
    """A `per_tool.<tool>.timeout` wins over the default, the minimum and a
    typed value alike. The screen says so, and says the same thing the scan
    then resolves, tool by tool."""
    (tmp_path / "jmo.yml").write_bytes(
        b"timeout: 600\nper_tool:\n  zap:\n    timeout: 1800\n"
        b"  yara-x:\n    timeout: 900\n"
    )
    tools = ["opengrep", "zap", "yara-x", "trivy"]
    tm = MagicMock()
    tm.get_tool_summary.return_value = MagicMock(execution_ready=1, total=1)
    tm.check_matrix.return_value = {}
    with (
        patch.object(wizard, "_prompt_yes_no", return_value=True),
        patch("builtins.input", side_effect=["", "300"]),
        patch.object(wizard, "_prompt_choice", return_value=""),
    ):
        threads, timeout, fail_on = wizard.configure_advanced(tm, tools)
        config = WizardConfig()
        config.target.type = "repo"
        config.target.repo_mode = "repo"
        config.target.repo_path = "."
        config.threads, config.timeout, config.fail_on = threads, timeout, fail_on
        wizard.review_and_confirm(config, tm, tools)
    out = capsys.readouterr().out

    assert "Timeout: 600s (opengrep, yara-x: 900s; zap: 1800s)" in out
    assert "applies to every tool but yara-x, zap, whose jmo.yml per_tool" in out
    assert "Timeout: 300s (yara-x: 900s; zap: 1800s)" in out

    (argv,) = _scan_argvs(config, "command")
    assert _resolved(argv, tools) == (
        300,
        {"opengrep": 300, "zap": 1800, "yara-x": 900, "trivy": 300},
    )


@pytest.mark.parametrize("emit", ["workflow", "script"])
@pytest.mark.parametrize("timeout", [None, 300])
def test_yes_mode_passes_only_a_given_timeout(emit, timeout, tmp_path):
    """`jmo wizard --yes`, through `run_wizard` itself: with no `--timeout` the
    artifact it writes keeps the minimums, and `--timeout 300` reaches it.

    Before #1627's fix the workflow carried `--timeout 600` without one.
    """
    out = tmp_path / "artifact.txt"
    with (
        patch.object(wizard, "check_tools_for_matrix", return_value=(True, [])),
        patch.object(wizard, "_check_policy_tools", return_value=(True, False)),
        patch("scripts.cli.tool_manager.ToolManager"),
    ):
        rc = wizard.run_wizard(
            yes=True,
            target_type="repo",
            target=str(tmp_path),
            timeout=timeout,
            emit_gha=str(out) if emit == "workflow" else None,
            emit_script=str(out) if emit == "script" else None,
        )
    assert rc == 0
    argvs = [
        shlex.split(" ".join(argv))
        for argv in extract_commands(out.read_bytes().decode("utf-8"))
        if argv[0] in ("scan", "ci")
    ]
    assert argvs, out.read_bytes()
    expected = (
        TOOL_TIMEOUT_DEFAULTS if timeout is None else dict.fromkeys(FLOORED, timeout)
    )
    for argv in argvs:
        assert _resolved(argv) == (timeout, expected), shlex.join(argv)


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize(
    ("answer", "expected"), [("", None), ("not a number", None), ("2", 2)]
)
def test_threads_follow_the_same_rule(route, answer, expected, tmp_path, monkeypatch):
    """A blank or unparseable thread count passes no `--threads`, so jmo.yml's
    `threads: auto` stays auto; a typed count passes on every route.

    Before, `scan_defaults()` read `auto` as 4, the prompt offered `[4]`, and
    keeping it wrote `--threads 4`; every workflow wrote `--threads` as well.
    """
    monkeypatch.delenv("JMO_THREADS", raising=False)
    (tmp_path / "jmo.yml").write_bytes(b"threads: auto\ntimeout: 600\n")
    config = _answer_advanced(True, threads_answer=answer)
    for argv in _scan_argvs(config, route):
        args = jmo.build_parser().parse_args(argv)
        eff = jmo._effective_scan_settings(args)
        workers = jmo._get_max_workers(args, eff, load_config(args.config))
        assert args.threads == expected, f"{route}: {shlex.join(argv)}"
        auto = jmo._auto_detect_threads(args)
        assert workers == (auto if expected is None else expected)


def test_the_screen_says_auto_where_the_scan_is_auto(tmp_path, capsys):
    """With `threads: auto` the defaults and the prompt say `auto`, not 4."""
    (tmp_path / "jmo.yml").write_bytes(b"threads: auto\ntimeout: 600\n")
    _answer_advanced(True)
    out = capsys.readouterr().out
    assert "Threads: auto" in out
