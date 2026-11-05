"""`--gitlab-group` is gone until JMo can list a group's projects (issue #1407).

It never listed them. The scan built one placeholder target, `group:<name>`,
cloned `<gitlab-url>/group:<name>.git` (not a project, so the clone failed) and
wrote its results under `individual-gitlab/group:<name>`, which on NTFS names an
alternate data stream, not a directory. Meanwhile the wizard offered "Entire
group (all repos)", and the cron, GitHub Actions and GitLab CI generators
emitted the flag. Every way in closes together, so no path can still produce
the placeholder.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from scripts.cli.jmo import build_parser
from scripts.cli.wizard_flows.config_models import TargetConfig
from scripts.cli.wizard_flows.target_configurators import configure_gitlab_target
from scripts.core.schedule_manager import (
    InvalidGitLabUrlError,
    ScanSchedule,
    gitlab_target_url,
)


@pytest.mark.parametrize("subcommand", ["scan", "ci"])
def test_the_flag_is_a_usage_error(subcommand: str, capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args([subcommand, "--gitlab-group", "platform"])
    assert exc.value.code == 2
    assert "--gitlab-group" in capsys.readouterr().err


@pytest.mark.parametrize(
    "target",
    [{"group": "platform"}, {"group": "platform", "url": "https://gitlab.example"}],
    ids=["group", "group-and-url"],
)
def test_a_schedule_naming_a_group_is_refused_with_the_reason(target) -> None:
    """Refused by name, not as an unknown key "which nothing reads".

    A schedule written before the removal still holds `group`, and the generic
    message would tell its owner the key was a typo.
    """
    with pytest.raises(InvalidGitLabUrlError, match="list a group's projects"):
        gitlab_target_url(target)


def test_the_schedule_factory_takes_no_group() -> None:
    with pytest.raises(TypeError, match="gitlab_group"):
        ScanSchedule.from_simple_args(
            name="nightly", cron="0 2 * * *", gitlab_group="platform"
        )


def test_the_wizard_asks_for_a_repository_and_offers_no_group(capsys) -> None:
    """Two answers: the instance and the repository. No scope question."""
    with (
        patch(
            "scripts.cli.wizard_flows.target_configurators.os.getenv",
            return_value="token-from-env",
        ),
        patch("builtins.input", side_effect=["https://gitlab.com", "team/app"]),
    ):
        config = configure_gitlab_target(TargetConfig, lambda *args: None)

    assert config.gitlab_repo == "team/app"
    assert not hasattr(config, "gitlab_group")
    assert "group (all repos)" not in capsys.readouterr().out
