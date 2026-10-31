"""Whether anyone is at the other end of a standard stream."""

from __future__ import annotations


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
