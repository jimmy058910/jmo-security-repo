"""The contract between what writes a schedule and what reads one.

Chunk 17 found that `ScanSchedule.from_simple_args` wrote six top-level
`targets` keys and its three consumers -- the GitHub Actions generator, the
GitLab CI generator and the cron installer -- read seven different ones, with
**zero** in common. A schedule built through the shipped factory therefore
exported a workflow that ran `jmo scan` with no target at all: rc 0, valid
YAML, no warning. The GitLab generator separately read a flat `targets["urls"]`
that nothing produces, so `--url` was dropped from GitLab exports only.

Both are the same failure: a producer and a consumer that agree with the tests
and with nothing else. The guards below are therefore **derived from the
sources** rather than restating them, so a future key rename fails here instead
of silently emptying a workflow.

Each derivation carries a meta-guard -- a floor plus named keys it must find --
because an extractor that silently finds nothing satisfies every assertion
built on top of it.
"""

from __future__ import annotations

import ast
import re
import shlex
from pathlib import Path

import pytest
import yaml

from scripts.core.schedule_manager import (
    JobTemplateSpec,
    ScanSchedule,
    ScheduleManager,
    ScheduleMetadata,
    ScheduleSpec,
)
from scripts.core.validation import validate_schedule_name
from scripts.core.workflow_generators import GitHubActionsGenerator, GitLabCIGenerator

REPO_ROOT = Path(__file__).resolve().parents[2]

CONSUMERS = (
    "scripts/core/workflow_generators/github_actions.py",
    "scripts/core/workflow_generators/gitlab_ci.py",
    "scripts/core/cron_installer.py",
)

# Read directly, not via `targets["..."]`, so an extractor that only looks for
# subscripts would miss it.
_MEMBERSHIP = re.compile(r"""["']([a-z_]+)["']\s+in\s+targets""")


def _keys_read_by_consumers() -> set[str]:
    """Top-level `targets` keys the three consumers actually test for."""
    found: set[str] = set()
    for rel in CONSUMERS:
        source = (REPO_ROOT / rel).read_text(encoding="utf-8")
        found |= set(_MEMBERSHIP.findall(source))
    return found


def _keys_written_by_factory() -> set[str]:
    """Top-level `targets` keys `from_simple_args` assigns.

    Parsed from the AST rather than run, so a key added on a branch no test
    exercises is still seen.
    """
    source = (REPO_ROOT / "scripts/core/schedule_manager.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    factory = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "from_simple_args"
    )
    written: set[str] = set()
    for node in ast.walk(factory):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Name)
                and target.value.id == "targets"
                and isinstance(target.slice, ast.Constant)
                and isinstance(target.slice.value, str)
            ):
                written.add(target.slice.value)
    return written


def test_extractors_actually_found_something():
    """Meta-guard: both derivations must be non-trivial and hit known keys.

    Without this, a regex or AST walk that quietly matches nothing turns every
    assertion below into a tautology.
    """
    read = _keys_read_by_consumers()
    written = _keys_written_by_factory()

    assert len(read) >= 5, f"consumer extractor found only {read}"
    assert {"repositories", "images", "web"} <= read, f"missing known keys: {read}"

    assert len(written) >= 3, f"factory extractor found only {written}"
    assert {"repositories", "images"} <= written, f"missing known keys: {written}"


def test_every_target_key_the_factory_writes_is_read_by_a_consumer():
    """The bug, stated as a property.

    Before the fix this set was all six written keys. The assertion is
    one-directional on purpose: a consumer may support a key the factory has no
    shorthand for (the CLI can still produce it), but a key the factory writes
    that nobody reads is a target silently dropped on the floor.
    """
    orphaned = _keys_written_by_factory() - _keys_read_by_consumers()
    assert not orphaned, (
        f"from_simple_args writes {sorted(orphaned)}, which no workflow "
        f"generator and no cron installer reads. A schedule built with these "
        f"exports a workflow with no target."
    )


def test_negative_control_pre_fix_shape_is_still_rejected():
    """The checker must still reject what it was written to catch.

    A guard that cannot fail on the original input is not a guard. This feeds
    the pre-fix key set in directly rather than trusting that the live code
    happens to be correct today.
    """
    pre_fix_written = {
        "repos_dir",
        "image",
        "url",
        "terraform_state",
        "gitlab_repo",
        "k8s_context",
    }
    assert pre_fix_written - _keys_read_by_consumers() == pre_fix_written, (
        "the pre-fix flat keys should be entirely unread by the consumers; if "
        "a consumer now reads one, this control needs updating deliberately"
    )


@pytest.mark.parametrize("generator", [GitHubActionsGenerator, GitLabCIGenerator])
def test_factory_built_schedule_carries_its_targets_into_the_workflow(generator):
    """End to end: the factory's output must survive into a generated workflow.

    The key-set assertions above are structural; this one runs the real
    generators, because grep finds syntax and only running finds behaviour.
    """
    schedule = ScanSchedule.from_simple_args(
        name="factory-built",
        cron="0 2 * * 1",
        profile="balanced",
        repos_dir="/srv/repos",
        image="nginx:1.27",
        url="https://example.test",
    )
    rendered = generator().generate(schedule)

    assert "/srv/repos" in rendered
    assert "nginx:1.27" in rendered
    assert "https://example.test" in rendered


def _gha_run_line(schedule: ScanSchedule) -> str:
    workflow = yaml.safe_load(GitHubActionsGenerator().generate(schedule))
    steps = workflow["jobs"]["security-scan"]["steps"]
    return next(s["run"] for s in steps if "Run JMo Security Scan" in s["name"])


def _schedule_with(targets: dict) -> ScanSchedule:
    return ScanSchedule(
        metadata=ScheduleMetadata(name="quoting"),
        spec=ScheduleSpec(
            schedule="0 2 * * *",
            jobTemplate=JobTemplateSpec(
                profile="fast", targets=targets, results={}, options={}
            ),
        ),
    )


def test_github_actions_run_line_quotes_shell_metacharacters():
    """A target value must reach the container as one argument, not as code.

    `_build_scan_args` joined its parts with a bare space and dropped the
    result into a `run:` shell line, so `--repos-dir '/tmp/r; touch /tmp/PWNED'`
    produced a workflow that ended the docker command at the `;` and ran the
    remainder with the job's permissions.

    The property asserted is the one that matters -- lexing the emitted line
    gives back exactly the original values -- rather than a particular quoting
    style, which would break the moment shlex chooses different quoting.
    """
    nasty_dir = "/tmp/r; touch /tmp/PWNED"
    nasty_image = "img$(id)"
    spaced_url = "https://x/?a=1 b"

    run = _gha_run_line(
        _schedule_with(
            {
                "repositories": {"repos_dir": nasty_dir},
                "images": [nasty_image],
                "web": {"urls": [spaced_url]},
            }
        )
    )

    words = shlex.split(run)
    assert nasty_dir in words
    assert nasty_image in words
    assert spaced_url in words
    # And the injected command is not a command: it survives only as part of a
    # single argument, never as its own word.
    assert "touch" not in [w for w in words if w == "touch"]


def test_github_actions_leaves_ordinary_values_unquoted():
    """The other arm: quoting appears only where it is needed.

    Without this, a generator that wrapped every argument in quotes -- including
    ones that must stay literal -- would pass the test above.
    """
    run = _gha_run_line(_schedule_with({"repositories": {"repos_dir": "/srv/repos"}}))
    assert "--repos-dir /srv/repos" in run
    assert "'/srv/repos'" not in run


@pytest.mark.parametrize(
    "name",
    [
        "ok-name",
        "weekly_balanced",
        "evil; rm -rf /",
        "../../etc/passwd",
        "9starts-with-digit",
        "has space",
        "x" * 65,
    ],
)
def test_schedule_create_accepts_exactly_what_the_installer_accepts(
    name, tmp_path, monkeypatch
):
    """`jmo schedule create` must reject every name `install` would reject.

    `create` validated nothing, so all five invalid names below were accepted
    and persisted at rc 0; the rejection surfaced later, at install time, on
    Linux -- and on Windows it could not surface at all.

    Driven through the **real parser and the real handler**, with
    `validate_schedule_name` as an independent oracle for the expected verdict.
    An earlier version of this test compared SCHEDULE_NAME_PATTERN to
    validate_schedule_name, which is a tautology -- the predicate is built from
    that pattern, so the two cannot disagree and the test could not fail.
    """
    import sys

    from scripts.cli import jmo as jmo_cli
    from scripts.cli.schedule_commands import _cmd_schedule_create

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "jmo",
            "schedule",
            "create",
            "--name",
            name,
            "--cron",
            "0 2 * * *",
            "--profile",
            "fast",
            "--repos-dir",
            "/srv/repos",
        ],
    )
    args = jmo_cli.parse_args()
    manager = ScheduleManager(config_dir=tmp_path)

    rc = _cmd_schedule_create(args, manager)
    should_be_accepted = validate_schedule_name(name)

    assert (rc == 0) is should_be_accepted, (
        f"create returned {rc} for {name!r} but the cron installer would "
        f"{'accept' if should_be_accepted else 'reject'} it"
    )
    # The persisted file is the evidence, not the return code.
    persisted = [s.metadata.name for s in manager.list()]
    assert (name in persisted) is should_be_accepted


def test_update_recomputes_the_next_run_time(tmp_path):
    """Changing the cron must change the next-run time it implies.

    `update` persisted the new cron and left `status.nextScheduleTime` derived
    from the old one, so `jmo schedule get` reported a run time the schedule
    could never produce -- measured at three days and three and a half hours
    out, on the wrong weekday, behind a success message.
    """
    from datetime import datetime

    from croniter import croniter

    manager = ScheduleManager(config_dir=tmp_path)
    schedule = ScanSchedule.from_simple_args(
        name="recompute", cron="0 2 * * *", profile="fast", repos_dir="/srv/repos"
    )
    manager.create(schedule)
    first = manager.get("recompute").status.nextScheduleTime

    schedule.spec.schedule = "30 5 * * 1"
    manager.update(schedule)
    after = manager.get("recompute").status.nextScheduleTime

    assert after != first
    # The real property: the stored time is one the stored cron actually fires.
    assert croniter.match("30 5 * * 1", datetime.fromisoformat(after))
    # Negative control -- it must NOT still satisfy the old expression, which is
    # exactly what the pre-fix value did.
    assert not croniter.match("30 5 * * 1", datetime.fromisoformat(first))
