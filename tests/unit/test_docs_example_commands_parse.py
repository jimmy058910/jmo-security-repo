"""Every `jmo` command in docs/examples/*.yml and DOCKER_README is one `jmo` accepts.

The example files are copied into pipelines and compose projects as they are.
Measured 2026-11-05: 22 of the 58 `jmo` commands in them were rejected by
jmo's own parser. docker-compose.trends.yml called `trends export` and `trends
velocity`, which do not exist (`jmo trends --help` lists analyze, show,
regressions, score, compare, insights, explain and developers), and `--format
text`, `--limit` and `--scan-id-1`, which no trends subcommand takes; three CI
examples passed semgrep to `--tools`, removed in v2.0.0. docs/DOCKER_README.md
had 15 of its 42 `docker run` commands wrong the same way. The parser is the
oracle, as in test_wizard_generated_commands_parse.py.
"""

from __future__ import annotations

import io
import re
import shlex
import sys
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.cli import jmo

DOCS = Path(__file__).resolve().parents[2] / "docs"
EXAMPLES = DOCS / "examples"
FILES = sorted(EXAMPLES.glob("*.yml"))  # pathlib's * matches .gitlab-ci.yml too

_IMAGE = re.compile(r"(?:\S+/)?jmo-security:[\w.${}-]+")
_CALL = re.compile(r"(?:^|[\s(\"'])jmo\s+([a-z][a-z-]*\b.*)$")
_COMPOSE = re.compile(r"^\s*command:\s*>?\s*(.*)$")
_SHELL_OPS = re.compile(r"&&|\|\||;|\s\|\s")


def _argv(text: str) -> list[str]:
    return shlex.split(_SHELL_OPS.split(text)[0].strip().strip("\"'"))


def _joined(path: Path) -> str:
    """The file's text with each `\\`-continued line joined to the next.

    LF first: a Windows checkout has CRLF, which the continuation pattern does
    not match, and a backslash left before `\\r` stopped shlex with "No escaped
    character" while the module was collected, so no Windows test ran."""
    text = path.read_bytes().decode("utf-8").replace("\r\n", "\n")
    return re.sub(r"\\\n\s*", " ", text)


def extract(path: Path) -> list[list[str]]:
    """The argv of every `jmo` invocation in an example file."""
    lines = _joined(path).splitlines()
    found: list[list[str]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.lstrip().startswith("#"):
            i += 1
            continue
        compose = (
            _COMPOSE.match(line) if path.name.startswith("docker-compose") else None
        )
        if compose is not None:
            body = compose.group(1)
            if not body:  # a folded block: its indented lines
                j, parts = i + 1, []
                while j < len(lines) and (
                    lines[j].startswith("      ") or not lines[j].strip()
                ):
                    parts.append(lines[j].strip())
                    j += 1
                body, i = " ".join(p for p in parts if p), j - 1
            if body.startswith("-c "):  # `bash -c`: the jmo calls inside
                found += [_argv(m) for m in re.findall(r"\bjmo\s+([^&\"]+)", body)]
            else:
                found.append(_argv(body))
        elif "docker run" in line and (image := _IMAGE.search(line)):
            found.append(_argv(line[image.end() :]))
        else:
            for segment in re.split(r"&&|\|\||;", line):
                call = _CALL.search(segment)
                if call:
                    found.append(_argv(call.group(1)))
        i += 1
    return [argv for argv in found if argv]


def parse_ok(argv: list[str]) -> tuple[bool, str]:
    """Ask the real parser whether it accepts this command."""
    buf = io.StringIO()
    with patch.object(sys, "argv", ["jmo", *argv]), redirect_stderr(buf):
        try:
            jmo.parse_args()
        except SystemExit as exc:
            return exc.code in (0, None), buf.getvalue().strip()
    return True, ""


def docker_run_commands(path: Path) -> list[list[str]]:
    """The jmo argv of every `docker run <image> ...` in a markdown guide."""
    return [
        _argv(line[image.end() :])
        for line in _joined(path).splitlines()
        if "docker run" in line
        and (image := _IMAGE.search(line))
        and line[image.end() :].strip()
    ]


COMMANDS = [(path.name, argv) for path in FILES for argv in extract(path)] + [
    ("DOCKER_README.md", argv)
    for argv in docker_run_commands(DOCS / "DOCKER_README.md")
]


def test_the_extractor_finds_the_examples_commands() -> None:
    """An extractor that finds nothing passes every case built on it."""
    assert len(COMMANDS) >= 80
    assert sum(source == "DOCKER_README.md" for source, _ in COMMANDS) >= 40
    subcommands = {argv[0] for _, argv in COMMANDS}
    assert {"scan", "ci", "trends", "diff"} <= subcommands, subcommands


def test_a_crlf_checkout_yields_the_same_commands(tmp_path: Path) -> None:
    """Windows runners check the docs out with CRLF. Read that way, the guide's
    `\\`-continued commands crashed this module's collection, which interrupted
    the whole windows-2022 session before its first test."""
    for source in (DOCS / "DOCKER_README.md", *FILES):
        crlf = tmp_path / source.name
        lf_bytes = source.read_bytes().replace(b"\r\n", b"\n")
        crlf.write_bytes(lf_bytes.replace(b"\n", b"\r\n"))

        assert extract(crlf) == extract(source), source.name
        assert docker_run_commands(crlf) == docker_run_commands(source), source.name


def test_the_parser_rejects_a_command_that_does_not_exist() -> None:
    assert not parse_ok(["trends", "export", "html", "--output", "r.html"])[0]


@pytest.mark.parametrize(
    ("source", "argv"),
    COMMANDS,
    ids=[f"{source}:{' '.join(argv[:3])}" for source, argv in COMMANDS],
)
def test_every_example_command_is_accepted(source: str, argv: list[str]) -> None:
    ok, err = parse_ok(argv)
    assert ok, f"{source}: `jmo {' '.join(argv)}` is rejected by jmo's parser\n{err}"
