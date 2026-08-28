"""Every `jmo` command the wizard writes into a file must be one `jmo` accepts.

`jmo wizard` generates Makefiles, shell scripts, GitHub Actions workflows,
GitLab CI files and docker-compose files. Those are not documentation -- a user
commits them and a pipeline runs them. Measured on `origin/dev`, thirteen of the
`jmo ci` / `jmo report` invocations in `wizard_generators.py` exited **2**:

    $ jmo ci --repos-dir . --profile fast --fail-on HIGH
    jmo: error: unrecognized arguments: fast
    $ echo $?
    2

`--profile` is a boolean timing flag on both `ci` and `report`; profile
selection is `--profile-name` (#755). The unit tests in
`test_wizard_generators.py` asserted the generated strings *verbatim*, so they
were green for a command that could not run -- they compared the template to
itself.

This guard compares the template to the **parser** instead, which is the only
oracle that can say whether a command works. It covers the whole class, not the
one flag: any generated command using a flag that does not exist, a subcommand
that was renamed, or a value where a boolean is expected, fails here.
"""

from __future__ import annotations

import argparse
import io
import re
import sys
from contextlib import redirect_stderr
from dataclasses import dataclass, field
from unittest.mock import patch

import pytest

from scripts.cli import jmo
from scripts.cli.wizard_generators import (
    generate_docker_compose,
    generate_github_actions,
    generate_gitlab_ci,
    generate_makefile_target,
    generate_shell_script,
)

WORKFLOW_TYPES = ("repo", "stack", "cicd", "deployment", "dependency")
PROFILES = ("fast", "balanced", "deep")

# Subcommands whose invocations we extract. Anything else on a line beginning
# `jmo ` is still extracted -- an unknown subcommand is exactly the kind of
# breakage worth failing on.
_JMO_CALL = re.compile(r"\bjmo\s+([a-z][a-z-]*)\b(.*)$")
# docker-compose inline form: `command: report /scan/results --profile-name x`
_COMPOSE_INLINE = re.compile(r"^\s*command:\s+([a-z][a-z-]*)\s+(.+)$")


@dataclass
class _Target:
    type: str = "repo"
    repo_mode: str = "repo"
    image_name: str | None = None
    url: str | None = None
    iac_type: str | None = None
    gitlab_repo: str | None = None
    k8s_context: str | None = None


@dataclass
class _Config:
    profile: str = "balanced"
    threads: int | None = None
    timeout: int | None = None
    fail_on: str | None = None
    use_docker: bool = False
    target: _Target = field(default_factory=_Target)


def _folded_compose_commands(text: str) -> list[list[str]]:
    """Pull `command: >` folded blocks out of a docker-compose document.

    The subcommand and its flags sit on their own indented lines, so a
    line-oriented scan misses them entirely -- which is how three of the
    thirteen broken invocations survived every existing test.
    """
    out: list[list[str]] = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if not re.match(r"^\s*command:\s*>\s*$", line):
            continue
        indent = len(line) - len(line.lstrip())
        parts: list[str] = []
        for follow in lines[i + 1 :]:
            if not follow.strip():
                break
            if len(follow) - len(follow.lstrip()) <= indent:
                break
            parts.extend(follow.split())
        if parts:
            out.append(parts)
    return out


def extract_commands(text: str) -> list[list[str]]:
    """Every jmo invocation in a generated artifact, as argv lists."""
    found: list[list[str]] = []
    for raw in text.splitlines():
        line = raw.strip().lstrip("-").strip()
        line = line.split("||")[0].split("#")[0].strip().rstrip("\\").strip()
        if not line:
            continue
        inline = _COMPOSE_INLINE.match(raw)
        if inline and "jmo" not in raw:
            found.append([inline.group(1), *inline.group(2).split()])
            continue
        call = _JMO_CALL.search(line)
        if call:
            found.append([call.group(1), *call.group(2).split()])
    found.extend(_folded_compose_commands(text))
    return found


def generated_artifacts() -> list[tuple[str, str]]:
    """(label, content) for every artifact the wizard can write."""
    cfg = _Config()
    artifacts: list[tuple[str, str]] = []
    for wf in WORKFLOW_TYPES:
        artifacts.append(
            (
                f"makefile:{wf}",
                generate_makefile_target(
                    cfg, "jmo scan --repo . --profile-name balanced", wf
                ),
            )
        )
        for profile in PROFILES:
            artifacts.append(
                (f"gitlab-ci:{wf}:{profile}", generate_gitlab_ci(wf, profile))
            )
            artifacts.append(
                (f"docker-compose:{wf}:{profile}", generate_docker_compose(wf, profile))
            )
    artifacts.append(
        (
            "shell-script",
            generate_shell_script(cfg, "jmo scan --repo . --profile-name balanced"),
        )
    )
    profiles = {
        p: {"threads": 4, "timeout": 600, "tools": ["trufflehog", "semgrep"]}
        for p in PROFILES
    }
    for use_docker in (False, True):
        c = _Config(use_docker=use_docker)
        artifacts.append(
            (
                f"github-actions:docker={use_docker}",
                generate_github_actions(c, profiles),
            )
        )
    return artifacts


def parse_ok(argv: list[str]) -> tuple[bool, str]:
    """Ask the real parser whether it accepts this command."""
    buf = io.StringIO()
    with patch.object(sys, "argv", ["jmo", *argv]), redirect_stderr(buf):
        try:
            jmo.parse_args()
        except SystemExit as exc:
            if exc.code in (0, None):  # --help / --version
                return True, ""
            return False, buf.getvalue().strip()
        except argparse.ArgumentError as exc:  # pragma: no cover - defensive
            return False, str(exc)
    return True, ""


ALL_COMMANDS = [
    (label, cmd)
    for label, text in generated_artifacts()
    for cmd in extract_commands(text)
]


def test_extractor_meta_guard():
    """An extractor that finds nothing passes every assertion built on it.

    The count is a floor, not a fixture: it only has to be high enough that a
    silently-empty or line-oriented-only extractor cannot slip through. The
    named checks below pin the three artifact shapes -- a plain `jmo ...` line,
    a docker-compose inline `command:`, and a `command: >` folded block, which
    is the shape three broken invocations hid in.
    """
    assert len(ALL_COMMANDS) >= 40, f"extractor found only {len(ALL_COMMANDS)} commands"
    subcommands = {cmd[0] for _label, cmd in ALL_COMMANDS}
    for expected in ("scan", "ci", "report"):
        assert expected in subcommands, f"extractor found no `{expected}` invocation"

    compose = generate_docker_compose("cicd", "fast")
    folded = _folded_compose_commands(compose)
    assert folded, "folded `command: >` blocks are not being extracted"
    assert folded[0][0] == "ci", folded


@pytest.mark.parametrize(
    ("label", "argv"),
    [(label, cmd) for label, cmd in ALL_COMMANDS],
    ids=[f"{label}:{' '.join(cmd[:3])}" for label, cmd in ALL_COMMANDS],
)
def test_generated_command_is_accepted_by_the_parser(label, argv):
    ok, err = parse_ok(argv)
    assert ok, f"{label}: `jmo {' '.join(argv)}` is rejected by jmo's own parser\n{err}"


def _scan_option_strings(subcommand: str) -> set[str]:
    parser = jmo.build_parser()
    for action in parser._actions:
        if isinstance(getattr(action, "choices", None), dict):
            sub = action.choices.get(subcommand)
            if sub is None:
                return set()
            return {opt for act in sub._actions for opt in act.option_strings}
    return set()


@pytest.mark.parametrize(
    ("label", "argv"),
    [(label, cmd) for label, cmd in ALL_COMMANDS],
    ids=[f"{label}:{' '.join(cmd[:3])}" for label, cmd in ALL_COMMANDS],
)
def test_every_generated_flag_is_defined_exactly(label, argv):
    """Parsing is not enough: an abbreviation parses until it does not.

    The test above asks whether argparse ACCEPTS the command, and it accepts an
    unambiguous prefix. So `jmo scan --profile deep` passed it for as long as
    `--profile-name` was the only option starting with `--profile` -- twenty
    generated commands relied on that, across the Makefile, GitLab CI and
    docker-compose templates.

    The correctness of every generated artifact then rests on a constraint
    nobody knows about: that no second `jmo scan` option may ever begin with
    `--profile`. One plausible future flag breaks all twenty at once, with
    `ambiguous option`, and does NOT break the tests of the change that added
    it (#1019).
    """
    defined = _scan_option_strings(argv[0])
    if not defined:
        pytest.skip(f"`jmo {argv[0]}` is not a subcommand with options")
    undefined = sorted(
        tok for tok in argv if tok.startswith("--") and tok not in defined
    )
    assert not undefined, (
        f"{label}: `jmo {' '.join(argv)}` emits {undefined}, which "
        f"`jmo {argv[0]}` does not define. It may resolve by prefix today; "
        f"emit the canonical name (#1019)."
    )


def test_a_known_bad_command_is_actually_rejected():
    """Negative control.

    Without this, a `parse_ok` that returned True unconditionally -- or a
    parser that quietly tolerated anything -- would make every case above
    vacuous. This is the exact form the wizard used to emit.
    """
    ok, err = parse_ok(
        ["ci", "--repos-dir", ".", "--profile", "fast", "--fail-on", "HIGH"]
    )
    assert (
        not ok
    ), "the parser accepted `ci --profile fast`, so the guard proves nothing"
    assert "unrecognized arguments" in err.lower(), err
