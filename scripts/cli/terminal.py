"""Whether anyone is at the other end of a standard stream."""

from __future__ import annotations

import sys


def stream_is_tty(stream) -> bool:
    """Whether ``stream`` is a terminal; False for one that is missing or closed.

    ``sys.stdin`` is None when the process started with stdin closed
    (``jmo scan <&-``), and ``isatty()`` raises on a closed file. Every prompt
    guard asks through this, so a closed stream reads as "nobody is there" and
    the guard takes the branch it takes for a pipe, not a crash.

    Lives in its own module because the guards are spread over ``jmo.py`` and
    ``tool_commands.py``, and ``jmo.py`` imports ``tool_commands``.
    """
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def stdin_closed() -> bool:
    """Whether stdin is missing or closed, so no answer can ever arrive.

    Narrower than ``not stream_is_tty(sys.stdin)``: a pipe can still carry
    answers. A process started with ``<&-`` has ``sys.stdin`` set to None.
    """
    stdin = sys.stdin
    return stdin is None or bool(getattr(stdin, "closed", False))


def ask(prompt: str) -> str | None:
    """``input(prompt)``, or None when nobody can answer.

    With stdin closed ``input()`` raises ``RuntimeError: lost sys.stdin``, which
    the prompts' ``except EOFError`` did not catch, so ``jmo schedule delete
    <&-`` crashed with a traceback (#1553). None covers that and end of input
    alike; a caller guarding a destructive action reads it as "no".
    """
    if stdin_closed():
        return None
    try:
        return input(prompt)
    except EOFError:
        return None
