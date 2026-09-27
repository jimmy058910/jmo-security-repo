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

v2.0.0 removed scan profiles outright: no `--profile-name`, no `jmo fast`,
`jmo balanced` or `jmo full`. The parser rejects all of them, so the parse test
already fails on any that come back -- but only if it is handed a command that
contains one. `test_no_generated_command_selects_a_profile` asserts on the text
itself, so a profile token hiding somewhere the extractor does not reach (a
comment the user will uncomment, a help line) cannot survive either.
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

# The subcommands that used to select a profile; `jmo <name>` is now an unknown
# subcommand. `deep` was only ever a profile name, never a subcommand.
REMOVED_PROFILE_SUBCOMMANDS = ("fast", "balanced", "full")

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


def _logical_lines(text: str) -> list[str]:
    """Physical lines with shell `\\` continuations joined into one.

    The GitHub Actions templates split one `jmo scan` over several lines of a
    `run: |` block. Read line by line, only `jmo scan` itself reached the
    parser and every flag on the continuation lines went unchecked.
    """
    lines: list[str] = []
    pending = ""
    for raw in text.splitlines():
        stripped = raw.rstrip()
        if stripped.endswith("\\"):
            pending += stripped[:-1] + " "
            continue
        lines.append(pending + raw)
        pending = ""
    if pending:
        lines.append(pending)
    return lines


def extract_commands(text: str) -> list[list[str]]:
    """Every jmo invocation in a generated artifact, as argv lists."""
    found: list[list[str]] = []
    for raw in _logical_lines(text):
        line = raw.strip().lstrip("-").strip()
        line = line.split("||")[0].split("#")[0].strip()
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


def _wizard_command(fail_on: str = "") -> str:
    """The `{command}` the wizard substitutes into Makefile / script templates.

    Built by the real command builder, not typed here: a hand-written stand-in
    is exactly how a template can stay green while the wizard emits something
    else (the mirror-of-a-mirror shape in `.claude/rules/testing.rules.md`).
    This file used `"jmo scan --repo . --profile-name balanced"`, and so never
    saw that the builder's own output with a severity threshold,
    `jmo scan ... --fail-on HIGH`, exits 2. Native mode, because that is the
    `jmo ...` form the extractor reads; the Docker form is
    `docker run ... <image> scan ...`.
    """
    from scripts.cli.wizard_flows.command_builder import build_command_parts
    from scripts.cli.wizard_flows.config_models import WizardConfig

    config = WizardConfig()
    config.target.type = "repo"
    config.target.repo_mode = "repo"
    config.target.repo_path = "."
    config.threads = 4
    config.timeout = 600
    config.fail_on = fail_on
    return " ".join(build_command_parts(config))


def generated_artifacts() -> list[tuple[str, str]]:
    """(label, content) for every artifact the wizard can write."""
    cfg = _Config()
    artifacts: list[tuple[str, str]] = []
    for wf in WORKFLOW_TYPES:
        artifacts.append(
            (
                f"makefile:{wf}",
                generate_makefile_target(cfg, _wizard_command("HIGH"), wf),
            )
        )
        artifacts.append((f"gitlab-ci:{wf}", generate_gitlab_ci(wf)))
        artifacts.append((f"docker-compose:{wf}", generate_docker_compose(wf)))
    for fail_on in ("", "HIGH"):
        artifacts.append(
            (
                f"shell-script:fail_on={fail_on or 'none'}",
                generate_shell_script(cfg, _wizard_command(fail_on)),
            )
        )
    for use_docker in (False, True):
        for fail_on in (None, "HIGH"):
            c = _Config(use_docker=use_docker, fail_on=fail_on)
            artifacts.append(
                (
                    f"github-actions:docker={use_docker}:fail_on={fail_on}",
                    generate_github_actions(c),
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

    This used to be a literal floor (`>= 40`), calibrated while gitlab-ci and
    docker-compose were generated once per profile. It is derived instead: every
    artifact the wizard writes must yield at least one command, which is the
    property the floor stood in for and cannot go stale when the artifact set
    changes. The named checks pin the three artifact shapes -- a plain
    `jmo ...` line, a docker-compose inline `command:`, and a `command: >`
    folded block, which is the shape three broken invocations hid in -- plus the
    continuation-joined GitHub Actions `run:` block, whose flags used to go
    unread.
    """
    labels = {label for label, _text in generated_artifacts()}
    assert len(ALL_COMMANDS) >= len(labels), (
        f"extractor found {len(ALL_COMMANDS)} commands in {len(labels)} artifacts"
    )
    silent = labels - {label for label, _cmd in ALL_COMMANDS}
    assert not silent, f"no jmo command extracted from {sorted(silent)}"
    subcommands = {cmd[0] for _label, cmd in ALL_COMMANDS}
    for expected in ("scan", "ci", "report"):
        assert expected in subcommands, f"extractor found no `{expected}` invocation"

    compose = generate_docker_compose("cicd")
    folded = _folded_compose_commands(compose)
    assert folded, "folded `command: >` blocks are not being extracted"
    assert folded[0][0] == "ci", folded

    # The scan step only: the native workflow also runs `jmo tools install --yes`.
    gha = [
        cmd
        for label, cmd in ALL_COMMANDS
        if label.startswith("github-actions") and cmd[0] in ("scan", "ci")
    ]
    assert gha and all("--threads" in cmd for cmd in gha), (
        f"continuation lines of the GitHub Actions `run:` block were not joined: {gha}"
    )


def _profile_selections(argv: list[str]) -> list[str]:
    """What in `argv` would select a scan profile, if anything."""
    found = []
    if argv and argv[0] in REMOVED_PROFILE_SUBCOMMANDS:
        found.append(f"the `jmo {argv[0]}` subcommand")
    if "--profile-name" in argv:
        found.append("--profile-name")
    return found


@pytest.mark.parametrize(
    ("label", "argv"),
    [(label, cmd) for label, cmd in ALL_COMMANDS],
    ids=[f"{label}:{' '.join(cmd[:3])}" for label, cmd in ALL_COMMANDS],
)
def test_no_generated_command_selects_a_profile(label, argv):
    """v2.0.0 has no scan profiles; a generated command must not ask for one."""
    selections = _profile_selections(argv)
    assert not selections, f"{label}: `jmo {' '.join(argv)}` uses {selections}"


@pytest.mark.parametrize(
    ("label", "text"),
    generated_artifacts(),
    ids=[label for label, _text in generated_artifacts()],
)
def test_no_generated_artifact_mentions_profile_selection(label, text):
    """The same property on the raw text, for what the extractor cannot see.

    A comment such as `# jmo scan --profile-name deep` is not a command today
    and is one after a user uncomments it.
    """
    assert "--profile-name" not in text, f"{label} mentions --profile-name"
    hit = re.search(r"\bjmo\s+(?:fast|balanced|full)\b", text)
    assert hit is None, f"{label} mentions `{hit.group(0) if hit else ''}`"


def test_the_profile_selection_check_bites():
    """Negative control for the two tests above, and for the parser beneath them.

    `_profile_selections` must flag both removed forms, and the parser must
    reject them too -- otherwise a profile token could pass both guards.
    """
    assert _profile_selections(["scan", "--repo", ".", "--profile-name", "fast"])
    for sub in REMOVED_PROFILE_SUBCOMMANDS:
        argv = [sub, "--repo", "."]
        assert _profile_selections(argv)
        ok, _err = parse_ok(argv)
        assert not ok, f"the parser still accepts `jmo {sub}`"
    ok, _err = parse_ok(["scan", "--repo", ".", "--profile-name", "fast"])
    assert not ok, "the parser still accepts `jmo scan --profile-name`"


@pytest.mark.parametrize(
    ("label", "argv"),
    [(label, cmd) for label, cmd in ALL_COMMANDS],
    ids=[f"{label}:{' '.join(cmd[:3])}" for label, cmd in ALL_COMMANDS],
)
def test_generated_command_is_accepted_by_the_parser(label, argv):
    ok, err = parse_ok(argv)
    assert ok, f"{label}: `jmo {' '.join(argv)}` is rejected by jmo's own parser\n{err}"


def _scan_option_strings(argv: list[str]) -> set[str]:
    """The options of the deepest parser `argv` reaches.

    `tools install --yes` defines `--yes` on `install`, not on `tools`, so
    stopping at the first subcommand called a real flag undefined.
    """
    parser = jmo.build_parser()
    depth = 0
    for token in argv:
        subparsers = next(
            (
                a
                for a in parser._actions
                if isinstance(getattr(a, "choices", None), dict)
            ),
            None,
        )
        if subparsers is None or token not in subparsers.choices:
            break
        parser = subparsers.choices[token]
        depth += 1
    if depth == 0:
        return set()  # not a subcommand at all: the parse test reports it
    return {opt for act in parser._actions for opt in act.option_strings}


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
    defined = _scan_option_strings(argv)
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


#: What each repository mode must leave on the parsed namespace, native and in
#: the container. `_wizard_command` fixes `repo_mode = "repo"`, which is why
#: this oracle never saw tsv mode's `--tsv`, rejected by `jmo scan` natively and
#: in Docker for as long as the mode existed (#1299).
_REPO_MODES = {
    "repo": {"repo"},
    "repos-dir": {"repos_dir"},
    "targets": {"targets"},
    "tsv": {"tsv", "dest"},
}


def _mode_argv(repo_mode: str, use_docker: bool, tmp_path) -> list[str]:
    """The argv `jmo` itself receives for one repository mode."""
    from scripts.cli.wizard_flows.command_builder import build_command_parts
    from scripts.cli.wizard_flows.config_models import WizardConfig
    from scripts.cli.wizard_generators import JMO_DOCKER_IMAGE_FULL

    config = WizardConfig()
    config.use_docker = use_docker
    config.results_dir = str(tmp_path / "results")
    config.target.type = "repo"
    config.target.repo_mode = repo_mode
    config.target.repo_path = str(tmp_path / "repo")
    config.target.tsv_path = str(tmp_path / "repos.tsv")
    parts = build_command_parts(config)
    anchor = JMO_DOCKER_IMAGE_FULL if use_docker else "jmo"
    return parts[parts.index(anchor) + 1 :]


@pytest.mark.parametrize("use_docker", [False, True], ids=["native", "docker"])
@pytest.mark.parametrize("repo_mode", sorted(_REPO_MODES))
def test_every_repository_mode_builds_a_command_that_scans_it(
    repo_mode, use_docker, tmp_path
):
    """Parses, names only flags `jmo` defines, and carries the mode's target.

    Parsing alone is not enough here: a command with no target at all parses,
    and that is exactly what the Docker branch emitted for tsv mode.
    """
    if use_docker and repo_mode == "targets":
        # A targets file lists host paths the container cannot see: refused
        # with a reason (`test_docker_targets_mode_is_refused_with_the_reason`).
        with pytest.raises(ValueError, match="container"):
            _mode_argv(repo_mode, use_docker, tmp_path)
        return

    argv = _mode_argv(repo_mode, use_docker, tmp_path)

    ok, err = parse_ok(argv)
    assert ok, f"`jmo {' '.join(argv)}` is rejected by jmo's own parser\n{err}"
    undefined = [
        tok
        for tok in argv
        if tok.startswith("--") and tok not in _scan_option_strings(argv)
    ]
    assert not undefined, f"`jmo {' '.join(argv)}` emits {undefined}"
    parsed = jmo.build_parser().parse_args(argv)
    for dest in _REPO_MODES[repo_mode]:
        assert getattr(parsed, dest), f"{repo_mode}: `{' '.join(argv)}` sets no {dest}"


def test_a_known_bad_command_is_actually_rejected():
    """Negative control.

    Without this, a `parse_ok` that returned True unconditionally -- or a
    parser that quietly tolerated anything -- would make every case above
    vacuous. This is the exact form the wizard used to emit.
    """
    ok, err = parse_ok(
        ["ci", "--repos-dir", ".", "--profile", "fast", "--fail-on", "HIGH"]
    )
    assert not ok, (
        "the parser accepted `ci --profile fast`, so the guard proves nothing"
    )
    assert "unrecognized arguments" in err.lower(), err
