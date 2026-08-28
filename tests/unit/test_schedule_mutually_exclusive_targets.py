#!/usr/bin/env python3
"""Guard: no schedule may store a target combination `jmo scan` rejects.

Regression for #1020.

`ScanSchedule.from_simple_args` wrote both `repositories.repo` and
`repositories.repos_dir` when handed both, with no exclusion of its own.
`jmo scan` puts those in a mutually exclusive group, so the schedule stored
cleanly and then rendered a command that exits 2 in every consumer -- the first
time the cron fired, in CI, long after anyone could connect it to the create.

## Two claims in the issue are measured wrong here

**Reachability.** The issue says `jmo schedule create` exposes `--repo` and
`--repos-dir`, so a user reaches this from the CLI. It does not: measured, that
subcommand's options are `--backend --cron --description --image --label --name
--profile --repos-dir --slack-webhook --timezone --url`, with **no** `--repo`.
`repo` arrives only through `from_simple_args`' `**kwargs`, so the reachable
paths are the Python API and a hand-edited `~/.jmo/schedules.json` -- which is
what the plan said and the issue did not.

**Arity.** The issue calls it a pair. The group has **three** members --
`--repo`, `--repos-dir`, `--targets` -- so a rule written for the filed pair
would be silently incomplete. No consumer emits `--targets` today, which is why
nothing had noticed.

## Why the rule is restated in core rather than derived there

`scripts/core/` may not import `scripts/cli/`; `check_import_direction.py`
enforces that. So `MUTUALLY_EXCLUSIVE_REPOSITORY_KEYS` states the rule where it
has to be enforced, and this file -- a test, which may import both -- reads the
real parser and fails if the two stop agreeing. That is the "derive from the
authority" move made at the only layer where it is legal.
"""

from __future__ import annotations

import shlex
import sys

import pytest
import yaml

sys.argv = ["jmo"]

from scripts.cli.jmo import build_parser  # noqa: E402
from scripts.core.schedule_manager import (  # noqa: E402
    MUTUALLY_EXCLUSIVE_REPOSITORY_KEYS,
    REPOSITORY_KEY_TO_SCAN_FLAG,
    ConflictingTargetsError,
    JobTemplateSpec,
    ScanSchedule,
    ScheduleMetadata,
    ScheduleSpec,
    _reject_conflicting_repository_targets,
)
from scripts.core.workflow_generators import (  # noqa: E402
    GitHubActionsGenerator,
    GitLabCIGenerator,
)


def _scan_exclusive_groups() -> list[set[str]]:
    scan = next(
        action.choices["scan"]
        for action in build_parser()._actions
        if isinstance(getattr(action, "choices", None), dict)
    )
    return [
        {opt for act in group._group_actions for opt in act.option_strings}
        for group in scan._mutually_exclusive_groups
    ]


# --------------------------------------------------------------------------
# The restated rule must keep matching the parser it restates
# --------------------------------------------------------------------------


def test_core_names_exactly_the_group_jmo_scan_declares() -> None:
    """The anti-drift check that makes the restatement safe.

    Fails in both directions: a fourth option joining the group, or one leaving
    it. Either would make `from_simple_args` enforce a rule the CLI no longer
    has -- and the first would let a real conflict through.
    """
    restated = {
        REPOSITORY_KEY_TO_SCAN_FLAG[key] for key in MUTUALLY_EXCLUSIVE_REPOSITORY_KEYS
    }
    groups = _scan_exclusive_groups()
    assert groups, "jmo scan declares no mutually exclusive groups at all"
    assert restated in groups, (
        f"scripts/core/schedule_manager.py restates the repository group as "
        f"{sorted(restated)}, which is not one of `jmo scan`'s actual groups "
        f"{[sorted(g) for g in groups]}. Update the constant, not this test."
    )


def test_the_mapping_covers_every_key_the_rule_names() -> None:
    """Meta-guard: a key with no flag would be skipped, not reported."""
    missing = [
        k
        for k in MUTUALLY_EXCLUSIVE_REPOSITORY_KEYS
        if k not in REPOSITORY_KEY_TO_SCAN_FLAG
    ]
    assert not missing, f"no scan flag mapped for {missing}"
    assert len(MUTUALLY_EXCLUSIVE_REPOSITORY_KEYS) >= 3, (
        "the group had three members when this was written; a shrink is a "
        "signal to re-measure, not to lower the floor"
    )


# --------------------------------------------------------------------------
# The defect itself
# --------------------------------------------------------------------------


def test_both_repo_and_repos_dir_is_rejected_at_creation() -> None:
    """The filed defect. It used to store cleanly and fail at scan time."""
    with pytest.raises(ConflictingTargetsError) as err:
        ScanSchedule.from_simple_args(
            name="nightly",
            cron="0 2 * * *",
            profile="balanced",
            repos_dir="/srv/repos",
            repo="/srv/one-repo",
        )
    message = str(err.value)
    assert "--repo" in message and "--repos-dir" in message, (
        "the error must name the conflicting flags; a caller who gets "
        "'invalid targets' has to go read the parser to find out what to drop"
    )


# The factory's vocabulary is narrower than the parser's group: it writes
# `repo` and `repos_dir` and has no notion of `targets` at all, because a
# schedule has no representation for a `--targets` TSV file. `targets` stays in
# the rule because the rule describes the PARSER's group, and a key that cannot
# be written is exactly the kind that gets added later without anyone
# rechecking the exclusion.
FACTORY_WRITABLE_KEYS = ("repo", "repos_dir")


@pytest.mark.parametrize("key", FACTORY_WRITABLE_KEYS)
def test_any_single_target_alone_is_accepted(key: str) -> None:
    """The control, one per key the factory can actually write.

    A rule that rejected the conflict by rejecting everything would pass the
    test above. Each key alone must still build a schedule.
    """
    schedule = ScanSchedule.from_simple_args(
        name="nightly",
        cron="0 2 * * *",
        profile="balanced",
        **{key: "/srv/target"},
    )
    assert schedule.spec.jobTemplate.targets["repositories"][key] == "/srv/target"


def test_the_rule_covers_the_member_the_factory_cannot_write() -> None:
    """`targets` has no factory path, so the helper is where it is reachable.

    Asserted directly rather than through `from_simple_args`, because routing it
    through a factory that would have to grow a `targets` parameter first would
    be adding a feature to test a rule.
    """
    with pytest.raises(ConflictingTargetsError) as err:
        _reject_conflicting_repository_targets(
            {"repos_dir": "/srv/many", "targets": "/srv/targets.tsv"}
        )
    assert "--targets" in str(err.value)


def test_the_factory_drops_an_empty_value_before_the_rule_sees_it() -> None:
    """`repos_dir=""` is absence, not a second target -- at the FACTORY layer.

    `from_simple_args` writes `repositories` under `if repos_dir:`, so a falsy
    value never becomes a key. This asserts that filtering, and nothing about
    the helper: a mutation to the helper's own emptiness test leaves this green,
    which is how the two layers were found to be conflated in the first place.
    """
    schedule = ScanSchedule.from_simple_args(
        name="nightly",
        cron="0 2 * * *",
        profile="balanced",
        repos_dir="",
        repo="/srv/one-repo",
    )
    assert schedule.spec.jobTemplate.targets["repositories"] == {
        "repo": "/srv/one-repo"
    }


def test_the_rule_itself_treats_an_empty_value_as_absent() -> None:
    """The same property at the HELPER layer, where it is actually reachable.

    The factory filters falsy values before calling in, so this branch has no
    live caller through `from_simple_args` -- it exists for the hand-edited
    `schedules.json` shape the render test below documents, and for any future
    caller. Asserted directly because that is the only place it can fire.

    Found by mutation: replacing the emptiness test with `key in repositories`
    left the factory-level test above GREEN, because the key was never there to
    begin with. The test named the helper and exercised the factory.
    """
    _reject_conflicting_repository_targets({"repo": "/srv/one", "repos_dir": ""})
    _reject_conflicting_repository_targets({"repo": "/srv/one", "targets": None})
    with pytest.raises(ConflictingTargetsError):
        _reject_conflicting_repository_targets(
            {"repo": "/srv/one", "repos_dir": "/srv/many"}
        )


# --------------------------------------------------------------------------
# The acceptance clause that is actually reachable: what the consumers render
# --------------------------------------------------------------------------


def _hand_built_conflicting_schedule() -> ScanSchedule:
    """The path the factory can no longer produce, but a JSON file still can."""
    return ScanSchedule(
        metadata=ScheduleMetadata(name="handwritten"),
        spec=ScheduleSpec(
            schedule="0 2 * * *",
            jobTemplate=JobTemplateSpec(
                profile="balanced",
                targets={
                    "repositories": {"repo": "/srv/one", "repos_dir": "/srv/many"}
                },
                results={},
                options={},
            ),
        ),
    )


def _github_argv(schedule: ScanSchedule) -> list[str]:
    return shlex.split(GitHubActionsGenerator()._build_scan_args(schedule))


def _gitlab_argv(schedule: ScanSchedule) -> list[str]:
    job = yaml.safe_load(GitLabCIGenerator().generate(schedule))["security-scan"]
    line = next(s for s in job["script"] if "jmo scan" in s)
    return shlex.split(line.replace("\\\n", " "))


@pytest.mark.parametrize(
    "render", [_github_argv, _gitlab_argv], ids=["github", "gitlab"]
)
def test_a_conflicting_schedule_still_renders_a_command_the_parser_rejects(
    render,
) -> None:
    """Documents the residue, and pins that it is a *read*-side gap.

    `from_simple_args` can no longer build this, but a hand-edited
    `~/.jmo/schedules.json` can, and the consumers will faithfully render both
    flags. Asserting the rejection here is what keeps that honest: if a future
    change makes the consumers silently drop one, this test fails and the
    dropping is a decision someone takes on purpose rather than a side effect.
    """
    argv = render(_hand_built_conflicting_schedule())
    assert "--repo" in argv and "--repos-dir" in argv
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(argv)
    assert exc.value.code == 2
