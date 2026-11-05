"""Every subprocess call in the product passes `timeout=` (issue #1285).

`.claude/rules/python-safety.rules.md` requires it: a child that hangs with no
timeout stays behind as an orphan process, and on Windows pytest's thread
timeout cannot kill it. `jmo tools uninstall`'s `pip uninstall` and `pip show`,
and the cron installer's two `crontab` calls, had none.

One call is allowed none, named here by the function it is in: the wizard runs
the whole scan as one child, and each tool inside it already runs under its own
`--timeout`, so a ceiling on the scan would only cut a long one short.
"""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.core.cron_installer import CronInstaller, CronInstallError

REPO = Path(__file__).resolve().parents[2]
SCOPE = [REPO / "scripts" / "cli", REPO / "scripts" / "core"]
CALLS = {"run", "call", "check_call", "check_output"}

# (module, enclosing function) -> why it needs no timeout
ALLOWED = {
    ("scripts/cli/wizard.py", "execute_scan"): (
        "the scan itself; every tool in it runs under its own --timeout"
    ),
}


def _subprocess_calls(tree: ast.AST) -> list[tuple[ast.Call, str]]:
    """(call, enclosing function) for each subprocess.<CALLS>(...) in `tree`."""
    imported = {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "subprocess"
        for alias in node.names
        if alias.name in CALLS
    }
    found: list[tuple[ast.Call, str]] = []

    def visit(node: ast.AST, function: str) -> None:
        for child in ast.iter_child_nodes(node):
            name = function
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
                name = child.name
            if isinstance(child, ast.Call):
                f = child.func
                if (
                    isinstance(f, ast.Attribute)
                    and f.attr in CALLS
                    and isinstance(f.value, ast.Name)
                    and f.value.id == "subprocess"
                ) or (isinstance(f, ast.Name) and f.id in imported):
                    found.append((child, function))
            visit(child, name)

    visit(tree, "<module>")
    return found


def _passes_a_timeout(call: ast.Call) -> bool:
    """`timeout=` with a value other than None; `**kwargs` may carry one, and
    the guard cannot see through it, so it is given the benefit."""
    for keyword in call.keywords:
        if keyword.arg is None:
            return True
        if keyword.arg == "timeout":
            value = keyword.value
            return not (isinstance(value, ast.Constant) and value.value is None)
    return False


def _all_calls() -> list[tuple[str, int, str, bool]]:
    """(module, line, enclosing function, passes a timeout) for every call."""
    rows = []
    for root in SCOPE:
        for path in sorted(root.rglob("*.py")):
            module = path.relative_to(REPO).as_posix()
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for call, function in _subprocess_calls(tree):
                rows.append((module, call.lineno, function, _passes_a_timeout(call)))
    return rows


def test_every_subprocess_call_passes_a_timeout() -> None:
    missing = [
        f"{module}:{line} in {function}()"
        for module, line, function, timed in _all_calls()
        if not timed and (module, function) not in ALLOWED
    ]
    assert missing == [], (
        "subprocess calls with no timeout= (python-safety.rules.md):\n"
        + "\n".join(missing)
    )


def test_the_guard_sees_calls_and_its_exception_is_real() -> None:
    """A walker that finds nothing passes the test above; an allowance for a
    function that no longer makes the call excuses whatever replaces it."""
    rows = _all_calls()
    assert len(rows) >= 30, f"only {len(rows)} subprocess calls found"
    for module, function in ALLOWED:
        assert any((m, f, t) == (module, function, False) for m, _line, f, t in rows), (
            f"{module} {function}() no longer makes an untimed call"
        )


def test_a_hung_crontab_is_a_schedule_error_not_a_traceback() -> None:
    """`jmo schedule install` reports CronInstallError by name; a timeout from
    either crontab call has to arrive as one, not as TimeoutExpired."""
    hung = subprocess.TimeoutExpired(cmd=["crontab"], timeout=30)
    with patch("scripts.core.cron_installer.platform.system", return_value="Linux"):
        installer = CronInstaller()
    with patch("scripts.core.cron_installer.subprocess.run", side_effect=hung):
        with pytest.raises(CronInstallError, match="crontab -l"):
            installer._get_crontab()
        with pytest.raises(CronInstallError, match="installing"):
            installer._set_crontab(["# line"])


@pytest.mark.parametrize(
    ("source", "timed"),
    [
        ("subprocess.run(cmd, timeout=30)", True),
        ("subprocess.run(cmd, timeout=None)", False),
        ("subprocess.run(cmd)", False),
        ("subprocess.run(cmd, **options)", True),
    ],
    ids=["timeout", "timeout-None", "none", "kwargs"],
)
def test_the_walker_reads_a_timeout_as_the_rule_means_it(source, timed):
    """`timeout=None` is the default spelled out: no timeout at all."""
    ((call, _function),) = _subprocess_calls(ast.parse(f"import subprocess\n{source}"))

    assert _passes_a_timeout(call) is timed
