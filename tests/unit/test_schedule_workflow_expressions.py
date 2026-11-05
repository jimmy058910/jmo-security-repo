"""No value a user writes may reach a GitHub Actions workflow holding `${{` (#1552).

GitHub evaluates `${{ ... }}` anywhere in a workflow before the shell sees the
line, quotes included. `jmo schedule create --image 'alpine:3.19${{
secrets.GITHUB_TOKEN }}'` then `jmo schedule export` wrote that into `run:`, so
the token was substituted into the command, and a value can send any secret the
workflow can read to a host it names. Passing values through `env:` would not
help: GitHub evaluates expressions in `env:` values too. No target, path or
option needs the sequence, so it is refused: when a schedule is stored, when one
edited by hand is validated or exported, and in the wizard's own workflow.

The generators' own expressions (`${{ secrets.GITLAB_TOKEN }}`,
`${{ github.run_number }}`) are not user values and stay.
"""

from __future__ import annotations

import json
from argparse import Namespace
from unittest.mock import patch

import pytest
import yaml

from scripts.cli.jmo import build_parser
from scripts.cli.schedule_commands import _cmd_schedule_validate, cmd_schedule
from scripts.cli.wizard_flows.config_models import WizardConfig
from scripts.cli.wizard_generators import generate_github_actions
from scripts.core.schedule_manager import (
    ScanSchedule,
    ScheduleManager,
    WorkflowExpressionError,
)
from scripts.core.workflow_generators import GitHubActionsGenerator

EXPRESSION = "${{ secrets.GITHUB_TOKEN }}"


@pytest.fixture
def manager(tmp_path):
    return ScheduleManager(config_dir=tmp_path)


def _cli(manager, argv: list[str]) -> int:
    with patch("scripts.cli.schedule_commands.ScheduleManager", return_value=manager):
        return cmd_schedule(build_parser().parse_args(argv))


def _stored(tmp_path) -> list:
    path = tmp_path / "schedules.json"
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))["schedules"]


def test_create_refuses_it_and_stores_nothing(manager, tmp_path, capsys):
    status = _cli(
        manager,
        [
            "schedule",
            "create",
            "--name",
            "inj",
            "--cron",
            "0 2 * * *",
            "--backend",
            "github-actions",
            "--image",
            f"alpine:3.19{EXPRESSION}",
        ],
    )

    said = capsys.readouterr()
    assert status == 1
    assert "spec.jobTemplate.targets.images[0]" in said.out + said.err
    assert _stored(tmp_path) == []


def test_update_refuses_it(manager):
    schedule = manager.create(
        ScanSchedule.from_simple_args(name="nightly", cron="0 2 * * *", image="a:1")
    )
    schedule.spec.jobTemplate.targets["images"] = [f"a:1{EXPRESSION}"]

    with pytest.raises(WorkflowExpressionError, match=r"targets\.images\[0\]"):
        manager.update(schedule)


def _hand_edited(manager, tmp_path, where: str) -> None:
    """A stored schedule, then `${{` written into `where` as an editor would."""
    manager.create(
        ScanSchedule.from_simple_args(
            name="nightly", cron="0 2 * * *", repos_dir="/srv/repos"
        )
    )
    path = tmp_path / "schedules.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    job = manifest["schedules"][0]["spec"]["jobTemplate"]
    if where == "target":
        job["targets"]["repositories"]["repos_dir"] = f"/srv/repos{EXPRESSION}"
    else:
        manifest["schedules"][0]["metadata"]["name"] = f"nightly{EXPRESSION}"
    path.write_text(json.dumps(manifest), encoding="utf-8")


@pytest.mark.parametrize("where", ["target", "name"])
def test_export_refuses_a_hand_edited_schedule(manager, tmp_path, where):
    _hand_edited(manager, tmp_path, where)
    (schedule,) = manager.list()

    with pytest.raises(WorkflowExpressionError) as refused:
        GitHubActionsGenerator().generate(schedule)

    # Named by field; the value itself may hold credentials.
    assert "secrets.GITHUB_TOKEN" not in str(refused.value)


def test_validate_refuses_a_hand_edited_schedule(manager, tmp_path, capsys):
    _hand_edited(manager, tmp_path, "target")

    status = _cmd_schedule_validate(Namespace(name="nightly"), manager)

    said = capsys.readouterr()
    assert status == 1
    assert "repos_dir" in said.out + said.err
    assert "Schedule configuration valid" not in said.out + said.err


def test_the_generators_own_expressions_are_untouched(manager):
    schedule = ScanSchedule.from_simple_args(
        name="nightly", cron="0 2 * * *", gitlab_repo="team/app"
    )
    schedule.spec.jobTemplate.targets["gitlab"]["token"] = True

    workflow = GitHubActionsGenerator().generate(manager.create(schedule))

    assert "${{ secrets.GITLAB_TOKEN }}" in workflow
    assert "${{ github.run_number }}" in workflow


@pytest.mark.parametrize("use_docker", [False, True], ids=["native", "docker"])
def test_the_wizards_workflow_refuses_it(use_docker):
    config = WizardConfig()
    config.use_docker = use_docker
    config.target.type = "image"
    config.target.image_name = f"alpine:3.19{EXPRESSION}"

    with pytest.raises(ValueError, match="image"):
        generate_github_actions(config)


def test_the_wizards_workflow_still_parses_without_one():
    config = WizardConfig()
    config.target.type = "image"
    config.target.image_name = "alpine:3.19"

    assert yaml.safe_load(generate_github_actions(config))["jobs"]


def test_a_key_holding_it_is_refused(manager):
    schedule = ScanSchedule.from_simple_args(
        name="nightly",
        cron="0 2 * * *",
        image="a:1",
        labels={"team${{ secrets.GITHUB_TOKEN }}": "x"},
    )

    with pytest.raises(WorkflowExpressionError, match=r"metadata\.labels"):
        manager.create(schedule)


def test_the_gitlab_token_reaches_the_container_by_environment(manager):
    """It was `--gitlab-token '${{ secrets.GITLAB_TOKEN }}'` on docker's argv:
    the secret on a command line, where the process list shows it. GitHub
    puts it in the step's environment and `-e` forwards it by name, as the
    wizard's own Docker command does."""
    schedule = ScanSchedule.from_simple_args(
        name="nightly", cron="0 2 * * *", gitlab_repo="team/app"
    )
    schedule.spec.jobTemplate.targets["gitlab"]["token"] = True

    workflow = yaml.safe_load(GitHubActionsGenerator().generate(schedule))
    (step,) = [
        s for s in workflow["jobs"]["security-scan"]["steps"] if "JMo" in s["name"]
    ]

    assert step["env"] == {"GITLAB_TOKEN": "${{ secrets.GITLAB_TOKEN }}"}
    assert "--gitlab-token" not in step["run"]
    assert "${{" not in step["run"]
    words = step["run"].split()
    image = next(w for w in words if w.startswith("ghcr.io/"))
    assert words.index("GITLAB_TOKEN") < words.index(image)
    assert words[words.index("GITLAB_TOKEN") - 1] == "-e"
