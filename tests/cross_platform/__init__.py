"""Tests for behaviour that only differs across host platforms.

Currently: console-encoding hardening. `jmo` emits emoji and box-drawing
characters, but a Windows console is not UTF-8 -- piped stdout gets the ANSI
codepage (cp1252) and an attached console gets the OEM codepage (cp437/cp850).
An unguarded write of those characters raises UnicodeEncodeError and kills the
command. CI's main shards set PYTHONUTF8=1, so they cannot observe this class.
"""
