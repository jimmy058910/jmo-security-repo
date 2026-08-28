#!/usr/bin/env python3
"""Guard: every flag a command-builder emits must be one its subcommand DEFINES.

Regression for #1019.

`jmo scan` defines `--profile-name` and no `--profile`. Nine call sites emitted
the short form anyway, and it worked because `argparse.ArgumentParser` defaults
to ``allow_abbrev=True`` and `--profile-name` was the only option with that
prefix. The correctness of every exported workflow, every installed crontab and
every wizard-generated command therefore rested on a constraint nobody knew
about: that no second `jmo scan` option may ever begin with `--profile`. A
single plausible future flag -- `--profile-config`, `--profile-timings`,
`--profiles` -- breaks all of them at once, with `ambiguous option`, and does
NOT break the tests of the change that introduced it.

`tests/unit/test_schedule_target_coverage.py` covers the two schedule workflow
generators and now requires exact names too. This file covers the emitters that
guard could not reach: the cron installer and `scripts/cli/wizard_flows/`.

## Two different severities were found here, not one

`jmo scan --profile X` resolved by abbreviation and ran correctly. But
`jmo ci --profile` is a **boolean** `store_true` timing flag, so
`jmo ci --profile balanced` is not an abbreviation at all -- it is a value
argparse has nowhere to put, and the command **exits 2**. `cicd_flow` and
`deployment_flow` built exactly that, showed it to the user in a preflight box,
and `base_flow.run()` then executed it with `subprocess.run`. That half was
never filed; #1019 named the two schedule generators only.

## Why this is derived rather than restated

The expectation is read out of the real parser at run time. A test that
enumerates the flags a builder *should* emit is a mirror of the builder, and
mirrors of a builder written on the same day by the same person share its
assumptions -- which is exactly how `test_wizard_flows.py` asserted
``"--profile" in cmd`` for years while the flag did not exist.
"""

from __future__ import annotations

import re
import shlex
import sys
from argparse import ArgumentParser
from pathlib import Path
from unittest.mock import patch

import pytest

sys.argv = ["jmo"]

from scripts.cli.jmo import build_parser  # noqa: E402
from scripts.cli.wizard_flows.cicd_flow import CICDFlow  # noqa: E402
from scripts.cli.wizard_flows.command_builder import (  # noqa: E402
    build_command_parts,
)
from scripts.cli.wizard_flows.config_models import WizardConfig  # noqa: E402
from scripts.cli.wizard_flows.dependency_flow import DependencyFlow  # noqa: E402
from scripts.cli.wizard_flows.deployment_flow import DeploymentFlow  # noqa: E402
from scripts.cli.wizard_flows.repo_flow import RepoFlow  # noqa: E402
from scripts.cli.wizard_flows.stack_flow import EntireStackFlow  # noqa: E402
from scripts.core.cron_installer import CronInstaller  # noqa: E402
from scripts.core.schedule_manager import (  # noqa: E402
    JobTemplateSpec,
    ScanSchedule,
    ScheduleMetadata,
    ScheduleSpec,
)


def _subparsers() -> dict[str, ArgumentParser]:
    for action in build_parser()._actions:
        if isinstance(getattr(action, "choices", None), dict):
            return action.choices  # type: ignore[return-value]
    raise AssertionError("no subparsers found on the jmo parser")


def _option_strings(subcommand: str) -> set[str]:
    sub = _subparsers()[subcommand]
    return {opt for action in sub._actions for opt in action.option_strings}


# --------------------------------------------------------------------------
# The emitters, each producing a real argv
# --------------------------------------------------------------------------


def _schedule() -> ScanSchedule:
    return ScanSchedule(
        metadata=ScheduleMetadata(name="nightly"),
        spec=ScheduleSpec(
            schedule="0 2 * * *",
            jobTemplate=JobTemplateSpec(
                profile="deep",
                targets={"repositories": {"repos_dir": "/srv/repos"}},
                results={},
                options={},
            ),
        ),
    )


def _wizard_config(*, use_docker: bool) -> WizardConfig:
    config = WizardConfig()
    config.profile = "balanced"
    config.results_dir = "results"
    config.use_docker = use_docker
    config.target.type = "repo"
    config.target.repo_mode = "repo"
    config.target.repo_path = "."
    return config


def _cron_argv() -> list[str]:
    """The command inside the crontab line, minus the five schedule fields.

    `CronInstaller.__init__` refuses to construct off Linux/macOS, but
    `_generate_cron_entry` is pure string building and is what this file is
    about. Patching the platform probe keeps the emitter covered on every
    runner -- skipping on Windows would leave it unchecked on the machine most
    of this work happens on.
    """
    with patch("scripts.core.cron_installer.platform.system", return_value="Linux"):
        installer = CronInstaller()
    entry = installer._generate_cron_entry(_schedule())
    # Drop anything from the first shell redirection onwards; a crontab line
    # ends in `>> log 2>&1` and those are not jmo flags.
    for cut in (">>", "2>&1", ">"):
        if cut in entry:
            entry = entry.split(cut)[0]
    # A crontab line is shell, so it legitimately carries a trailing marker
    # comment and command substitutions. `comments=True` drops the first; the
    # substitution is collapsed to one opaque token because `shlex` would
    # otherwise split `$(date +%Y-%m-%d)` into two words and the parser would
    # read the second as a stray positional.
    entry = re.sub(r"\$\([^)]*\)", "SUBSTITUTION", entry)
    tokens = shlex.split(entry, comments=True)
    return tokens[tokens.index("jmo") :]


def _repo_flow_argv() -> list[str]:
    return RepoFlow().build_command(
        {"repos": [Path(".")], "images": []}, {"profile": "deep"}
    )


def _stack_flow_argv() -> list[str]:
    return EntireStackFlow().build_command(
        {"repos": [Path(".")], "images": [], "iac": [], "web": []},
        {"profile": "balanced"},
    )


def _dependency_flow_argv() -> list[str]:
    return DependencyFlow().build_command(
        {"repos": [Path(".")], "images": []}, {"profile": "balanced"}
    )


def _cicd_flow_argv() -> list[str]:
    return CICDFlow().build_command(
        {"repos": [Path(".")], "pipeline_images": []},
        {"profile": "fast", "scan_files": True, "scan_images": False},
    )


def _deployment_flow_argv() -> list[str]:
    return DeploymentFlow().build_command(
        {"repos": [Path(".")], "images": [], "iac": [], "web": []},
        {"profile": "fast", "fail_on": "HIGH"},
    )


def _wizard_native_argv() -> list[str]:
    config = _wizard_config(use_docker=False)
    return build_command_parts(config)


def _wizard_docker_argv() -> list[str]:
    """The Docker branch of the same function.

    Worth its own row: the native branch was corrected to `--profile-name` by an
    earlier fix and the Docker branch beside it was not, so one function held
    both spellings.
    """
    parts = build_command_parts(_wizard_config(use_docker=True))
    # Strip the `docker run --rm -v ... <image>` prefix; the jmo command starts
    # at its subcommand.
    return ["jmo", *parts[parts.index("scan") :]]


EMITTERS = {
    "cron_installer": _cron_argv,
    "wizard_flows/repo_flow": _repo_flow_argv,
    "wizard_flows/stack_flow": _stack_flow_argv,
    "wizard_flows/dependency_flow": _dependency_flow_argv,
    "wizard_flows/cicd_flow": _cicd_flow_argv,
    "wizard_flows/deployment_flow": _deployment_flow_argv,
    "wizard_flows/command_builder[native]": _wizard_native_argv,
    "wizard_flows/command_builder[docker]": _wizard_docker_argv,
}


@pytest.mark.parametrize("name", sorted(EMITTERS))
def test_every_emitted_flag_is_defined_exactly(name: str) -> None:
    """No abbreviation resolution. That allowance is the defect."""
    argv = EMITTERS[name]()
    assert argv[0] == "jmo", f"{name} did not produce a jmo command: {argv}"
    subcommand = argv[1]
    defined = _option_strings(subcommand)

    undefined = sorted(
        tok for tok in {t for t in argv if t.startswith("--")} if tok not in defined
    )
    assert not undefined, (
        f"{name} emits {undefined}, which `jmo {subcommand}` does not define. "
        f"If argparse resolves one by prefix today, it does so only while no "
        f"second option shares that prefix (#1019)."
    )


@pytest.mark.parametrize("name", sorted(EMITTERS))
def test_every_emitted_command_actually_parses(name: str) -> None:
    """The severity the flag check alone would miss.

    An undefined flag that resolves by abbreviation still runs. A *value* passed
    to a `store_true` flag does not: `jmo ci --profile balanced` exits 2, which
    is what `cicd_flow` and `deployment_flow` built and `base_flow.run()`
    executed.

    Confirmed by mutation, and it is why both assertions exist rather than one.
    Reverting `cicd_flow` to `--profile` leaves the name check above GREEN --
    `jmo ci` genuinely DEFINES `--profile`, just as a boolean -- and only this
    test goes red. A guard that checked names alone would have been blind to the
    more severe of the two defects.
    """
    argv = EMITTERS[name]()
    try:
        build_parser().parse_args(argv[1:])
    except SystemExit as exc:  # pragma: no cover - only on a regression
        pytest.fail(f"{name} emits a command that exits {exc.code}: {' '.join(argv)}")


@pytest.mark.parametrize("name", sorted(EMITTERS))
def test_each_emitter_produced_something_to_check(name: str) -> None:
    """Meta-guard.

    A builder that returns `[]`, or one whose flags were all silently dropped by
    the extractor, satisfies both assertions above. Assert a floor and name one
    flag that must be present, so a blind extractor reddens instead of passing.
    """
    argv = EMITTERS[name]()
    assert len(argv) >= 4, f"{name} produced only {argv}"
    flags = {t for t in argv if t.startswith("--")}
    assert flags, f"{name} produced no flags at all: {argv}"
    assert "--profile-name" in flags, (
        f"{name} no longer emits --profile-name; either the profile stopped "
        f"being passed or the spelling regressed. Emitted: {sorted(flags)}"
    )
