"""`assert_no_jmo_traceback` tells a JMo crash from a traceback JMo relayed.

The platform e2e suites used to assert `"traceback" not in <output>`. That
cannot distinguish JMo crashing from JMo doing its job: `jmo tools debug`
relays a broken tool's stderr, and a scan logs a failed tool's stderr. Measured
2026-09-24 under WSL: a `pip --user` semgrep run with the test's redirected
HOME printed its own ModuleNotFoundError traceback, and three Linux e2e tests
failed on a JMo that had not crashed.

Both directions are pinned here, and the crash case is a real traceback raised
inside a real JMo module, formatted on the platform running the test, so the
pattern is checked against this platform's actual path separators rather than a
hand-typed path.
"""

from __future__ import annotations

import json
import traceback

import pytest

from scripts.core.common_finding import fingerprint
from tests.conftest import assert_no_jmo_traceback

# Verbatim (as the callers lowercase it) from the 2026-09-24 WSL run: what a
# scan logs for a failed semgrep, and what `jmo tools debug semgrep` prints.
RELAYED_IN_A_LOG_LINE = (
    '{"ts": "2026-09-24t02:55:41.775813z", "level": "warn", "msg": "tool failed; '
    "stderr: traceback (most recent call last):\\n  file "
    '\\"/home/jimmy058910/.local/bin/semgrep\\", line 3, in <module>\\n    '
    "from semgrep.console_scripts.entrypoint import main\\nmodulenotfounderror: "
    "no module named 'semgrep')\"}"
)
RELAYED_BY_TOOLS_DEBUG = (
    "traceback (most recent call last):\n"
    '  file "/home/jimmy058910/.local/bin/semgrep", line 3, in <module>\n'
    "    from semgrep.console_scripts.entrypoint import main\n"
    "modulenotfounderror: no module named 'semgrep'\n"
)
# A Windows venv launcher lives in `Scripts\`; it is not JMo's `scripts/` package.
RELAYED_FROM_A_WINDOWS_LAUNCHER = (
    "traceback (most recent call last):\n"
    '  file "c:\\users\\x\\proj\\.venv\\scripts\\semgrep.exe\\__main__.py", line 4\n'
    "modulenotfounderror: no module named 'semgrep'\n"
)


@pytest.mark.parametrize(
    "output",
    [RELAYED_IN_A_LOG_LINE, RELAYED_BY_TOOLS_DEBUG, RELAYED_FROM_A_WINDOWS_LAUNCHER],
    ids=["log-line", "tools-debug", "windows-launcher"],
)
def test_a_relayed_tool_traceback_is_not_a_jmo_crash(output):
    assert "traceback" in output  # what the old assertion failed on
    assert_no_jmo_traceback(output)


def _real_jmo_traceback() -> str:
    try:
        fingerprint("tool", "rule", "path", 1, object())  # raises inside JMo
    except AttributeError as exc:
        return "".join(traceback.format_exception(exc))
    raise AssertionError("fingerprint() stopped raising; pick another JMo call")


@pytest.mark.parametrize(
    "encode",
    [lambda tb: tb.lower(), lambda tb: json.dumps({"msg": tb}).lower()],
    ids=["raw", "json-escaped-log-line"],
)
def test_a_traceback_raised_inside_jmo_fails_it(encode):
    output = encode(_real_jmo_traceback())
    with pytest.raises(AssertionError, match="JMo raised a traceback"):
        assert_no_jmo_traceback(output)
