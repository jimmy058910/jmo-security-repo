"""A schedule keeps the self-hosted GitLab URL it was given, in every command it makes.

`targets["gitlab"]` held a repository or a group and no URL, and the cron line,
the GitHub Actions workflow and the GitLab CI job emitted `--gitlab-repo` or
`--gitlab-group` without `--gitlab-url`. `jmo scan` then defaulted the URL to
`https://gitlab.com`, so a schedule for a self-hosted instance cloned its
project from gitlab.com and offered it the self-hosted instance's token (the
defect `tests/cli/test_gitlab_scanner.py::TestAGitlabUrlIsClonedFromTheHostItNames`
fixes in the scan itself).

No test here touches the network, a crontab or the real `~/.jmo`: the generators
only build text, and the stored-schedule tests use a manager rooted in `tmp_path`.
"""

from __future__ import annotations

import json
import shlex
import sys
from argparse import Namespace
from unittest.mock import patch

import pytest
import yaml

from scripts.cli.jmo import build_parser
from scripts.core.cron_installer import CronInstaller, CronValidationError
from scripts.core.schedule_manager import (
    InvalidGitLabUrlError,
    JobTemplateSpec,
    ScanSchedule,
    ScheduleManager,
    ScheduleMetadata,
    ScheduleSpec,
    gitlab_target_url,
)
from scripts.core.validation import gitlab_clone_base
from scripts.core.workflow_generators import GitHubActionsGenerator, GitLabCIGenerator

URL = "https://gitlab.example.test:8443"


def _schedule(gitlab: dict, name: str = "self-hosted") -> ScanSchedule:
    return ScanSchedule(
        metadata=ScheduleMetadata(name=name),
        spec=ScheduleSpec(
            schedule="0 2 * * *",
            jobTemplate=JobTemplateSpec(
                targets={"gitlab": gitlab}, results={}, options={}
            ),
        ),
    )


def _github_text(schedule: ScanSchedule) -> str:
    return GitHubActionsGenerator()._build_scan_args(schedule)


def _gitlab_ci_text(schedule: ScanSchedule) -> str:
    job = yaml.safe_load(GitLabCIGenerator().generate(schedule))["security-scan"]
    line = next(s for s in job["script"] if s.startswith("jmo "))
    return line.replace("\\\n", " ")


def _cron_text(schedule: ScanSchedule) -> str:
    """The command of the installed crontab line, as the shell receives it.

    cron turns `\\%` into `%` before the shell sees the line."""
    with patch("scripts.core.cron_installer.platform.system", return_value="Linux"):
        entry = CronInstaller()._generate_cron_entry(schedule)
    line = next(ln for ln in entry.splitlines() if ln.startswith("0 2 * * * "))
    return line.replace("\\%", "%").split(" ", 5)[5]


def _words(text: str) -> list[str]:
    """The `jmo` argv of a command line, lexed as a shell would, up to its
    `--results-dir`, after the subcommand's `jmo`."""
    argv = shlex.split(text)
    if argv[0] == "jmo":
        argv = argv[1:]
    return argv[: argv.index("--results-dir")] if "--results-dir" in argv else argv


GENERATORS = {
    "github_actions": (_github_text, InvalidGitLabUrlError),
    "gitlab_ci": (_gitlab_ci_text, InvalidGitLabUrlError),
    "cron": (_cron_text, CronValidationError),
}
CONSUMERS = [
    "github_actions",
    "gitlab_ci",
    pytest.param(
        "cron",
        marks=pytest.mark.skipif(
            sys.platform == "win32", reason="Cron scheduling not supported on Windows"
        ),
    ),
]


def _value_of(argv: list[str], flag: str) -> str:
    return argv[argv.index(flag) + 1]


@pytest.mark.parametrize("consumer", CONSUMERS)
class TestEveryGeneratorEmitsTheUrl:
    @pytest.mark.parametrize(
        ("target", "flag"),
        [({"repo": "dev/app"}, "--gitlab-repo"), ({"group": "dev"}, "--gitlab-group")],
        ids=["repo", "group"],
    )
    def test_a_self_hosted_url_is_emitted_with_the_target(self, consumer, target, flag):
        build, _error = GENERATORS[consumer]

        argv = _words(build(_schedule({**target, "url": URL})))

        assert _value_of(argv, "--gitlab-url") == URL
        assert flag in argv

    @pytest.mark.parametrize("url", [None, "", "   "], ids=["none", "empty", "blank"])
    def test_no_url_is_no_flag(self, consumer, url):
        """Absent means gitlab.com, as `jmo scan` without `--gitlab-url`."""
        build, _error = GENERATORS[consumer]
        gitlab = {"repo": "dev/app"} if url is None else {"repo": "dev/app", "url": url}

        argv = _words(build(_schedule(gitlab)))

        assert "--gitlab-url" not in argv
        assert _value_of(argv, "--gitlab-repo") == "dev/app"

    def test_a_bare_host_is_emitted_as_the_url_the_scan_clones_from(self, consumer):
        build, _error = GENERATORS[consumer]

        argv = _words(
            build(_schedule({"repo": "dev/app", "url": "gitlab.example.test/gl/"}))
        )

        assert _value_of(argv, "--gitlab-url") == "https://gitlab.example.test/gl"

    @pytest.mark.parametrize(
        "url",
        [
            "https://gitlab.example.test/$(touch${IFS}/tmp/pwned)",
            "https://gitlab.example.test/a;b&c|d",
            "https://gitlab.example.test/`id`",
            "https://gitlab.example.test/it's",
            'https://gitlab.example.test/say"hi"',
            "https://gitlab.example.test/gl%2Fprefix",
        ],
        ids=[
            "command-substitution",
            "separators",
            "backticks",
            "single-quote",
            "double-quotes",
            "percent-in-path",
        ],
    )
    def test_the_url_reaches_the_command_as_one_word_whatever_it_holds(
        self, consumer, url
    ):
        """The normaliser keeps `$`, `;`, quotes and `%` in a path, so each
        output quotes them: the text holds the URL shell-quoted, which a shell
        reads back as the URL and nothing more."""
        build, _error = GENERATORS[consumer]

        text = build(_schedule({"repo": "dev/app", "url": url}))
        argv = _words(text)

        assert f"--gitlab-url {shlex.quote(url)}" in text
        assert _value_of(argv, "--gitlab-url") == url
        assert argv.count("--gitlab-url") == 1

    def test_the_flag_is_one_the_jmo_parser_defines(self, consumer):
        """The emitted command is read by the real parser, to the same URL."""
        build, _error = GENERATORS[consumer]
        argv = _words(build(_schedule({"repo": "dev/app", "url": URL})))

        parsed = build_parser().parse_args(argv)

        assert parsed.gitlab_url == URL
        assert parsed.gitlab_repo == "dev/app"

    # (value, text its reason carries). The URL checks themselves are pinned by
    # TestAGitlabUrlIsClonedFromTheHostItNames; this is that each generator
    # asks them, and never echoes what it refused.
    @pytest.mark.parametrize(
        ("url", "named"),
        [
            ("ssh://git@gitlab.example.test", "ssh://"),
            ("https://gitlab.example.test@evil.example", "--gitlab-token"),
            ("https://deploy:hunter2@gitlab.example.test/", "--gitlab-token"),
            ("https:/gitlab.example.test", "scheme word"),
            ("https://", "names no host"),
            ("https://%67itlab.example.test", "% escape"),
        ],
        ids=["ssh", "host-at-host", "userinfo", "scheme-word", "no-host", "percent"],
    )
    def test_a_url_the_scan_would_refuse_is_refused(self, consumer, url, named):
        build, error = GENERATORS[consumer]

        with pytest.raises(error) as refused:
            build(_schedule({"repo": "dev/app", "url": url}))

        assert named in str(refused.value)
        assert "hunter2" not in str(refused.value)
        assert url not in str(refused.value)

    def test_a_url_that_is_not_text_is_refused(self, consumer):
        build, error = GENERATORS[consumer]

        with pytest.raises(error, match="text"):
            build(_schedule({"repo": "dev/app", "url": ["https://a.test"]}))


class TestAScheduleCannotStoreAUrlTheScanWouldRefuse:
    def test_the_factory_stores_the_url_the_scan_clones_from(self):
        schedule = ScanSchedule.from_simple_args(
            name="self-hosted",
            cron="0 2 * * *",
            gitlab_repo="dev/app",
            gitlab_url="gitlab.example.test:8443/",
        )

        assert schedule.spec.jobTemplate.targets["gitlab"] == {
            "repo": "dev/app",
            "url": URL,
        }

    @pytest.mark.parametrize("url", [None, "", "  "], ids=["none", "empty", "blank"])
    def test_the_factory_stores_no_url_for_the_default(self, url):
        schedule = ScanSchedule.from_simple_args(
            name="com", cron="0 2 * * *", gitlab_group="dev", gitlab_url=url
        )

        assert schedule.spec.jobTemplate.targets["gitlab"] == {"group": "dev"}

    def test_the_factory_refuses_a_url_the_scan_would_refuse(self):
        with pytest.raises(InvalidGitLabUrlError, match="ssh://"):
            ScanSchedule.from_simple_args(
                name="bad",
                cron="0 2 * * *",
                gitlab_repo="dev/app",
                gitlab_url="ssh://deploy:hunter2@gitlab.example.test",
            )

    def test_the_manager_refuses_to_create_one(self, manager, tmp_path):
        bad = _schedule({"repo": "dev/app", "url": "https://gitlab.example.test@evil"})

        with pytest.raises(InvalidGitLabUrlError, match="--gitlab-token"):
            manager.create(bad)

        stored = json.loads((tmp_path / "schedules.json").read_text(encoding="utf-8"))
        assert stored["schedules"] == []

    def test_the_manager_refuses_to_update_one_to_it(self, manager, tmp_path):
        schedule = manager.create(_schedule({"repo": "dev/app", "url": URL}))
        schedule.spec.jobTemplate.targets["gitlab"]["url"] = "ftp://gitlab.example.test"

        with pytest.raises(InvalidGitLabUrlError, match="ftp://"):
            manager.update(schedule)

        kept = manager.get("self-hosted")
        assert kept.spec.jobTemplate.targets["gitlab"]["url"] == URL

    def test_the_manager_keeps_the_url_it_was_given(self, manager):
        manager.create(_schedule({"repo": "dev/app", "url": URL}))

        kept = manager.get("self-hosted")

        assert kept.spec.jobTemplate.targets["gitlab"] == {
            "repo": "dev/app",
            "url": URL,
        }

    def test_a_hand_edited_file_is_still_listed_and_refused_when_exported(
        self, manager, tmp_path, capsys
    ):
        """`schedules.json` can be edited by hand, and one bad schedule must not
        take out `list`: the generators are the net, and `export` says why."""
        from scripts.cli.schedule_commands import cmd_schedule

        manager.create(_schedule({"repo": "dev/app", "url": URL}))
        path = tmp_path / "schedules.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        gitlab = manifest["schedules"][0]["spec"]["jobTemplate"]["targets"]["gitlab"]
        gitlab["url"] = "https://deploy:hunter2@gitlab.example.test"
        path.write_text(json.dumps(manifest), encoding="utf-8")

        with patch("scripts.cli.schedule_commands.ScheduleManager") as made:
            made.return_value = ScheduleManager(config_dir=tmp_path)
            listed = cmd_schedule(
                Namespace(schedule_action="list", format="json", label=None)
            )
            capsys.readouterr()
            exported = cmd_schedule(
                Namespace(
                    schedule_action="export",
                    name="self-hosted",
                    backend="github-actions",
                    output=None,
                )
            )

        said = capsys.readouterr()
        assert listed == 0
        assert exported == 1
        assert "--gitlab-token" in said.err + said.out
        assert "hunter2" not in said.err + said.out


KNOWN_KEYS = ("repo", "group", "url", "token")
CORP = "https://gl.corp.example"


def _hand_edit(tmp_path, gitlab) -> None:
    """Replace the stored schedule's GitLab target, as someone editing
    `schedules.json` would."""
    path = tmp_path / "schedules.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["schedules"][0]["spec"]["jobTemplate"]["targets"]["gitlab"] = gitlab
    path.write_text(json.dumps(manifest), encoding="utf-8")


@pytest.fixture
def manager(tmp_path):
    return ScheduleManager(config_dir=tmp_path)


@pytest.mark.parametrize("consumer", CONSUMERS)
class TestAMisspeltUrlKeyIsRefused:
    """`{"repo": ..., "token": true, "gitlab_url": "https://gl.corp.example"}`
    stored and exported with no `--gitlab-url`: the instance's token went to
    gitlab.com on one wrong word."""

    @pytest.mark.parametrize("key", ["gitlab_url", "base_url", "URL", "host"])
    def test_a_key_the_target_does_not_read_is_refused(self, consumer, key):
        build, error = GENERATORS[consumer]

        with pytest.raises(error) as refused:
            build(_schedule({"repo": "dev/app", "token": True, key: CORP}))

        message = str(refused.value)
        assert f"'{key}'" in message
        assert all(allowed in message for allowed in KNOWN_KEYS)
        assert "gl.corp.example" not in message

    def test_the_four_keys_it_reads_are_accepted(self, consumer):
        build, _error = GENERATORS[consumer]

        text = build(
            _schedule({"repo": "dev/app", "group": "dev", "url": URL, "token": True})
        )

        assert f"--gitlab-url {URL}" in text


class TestAMisspeltUrlKeyIsNotStored:
    @pytest.mark.parametrize("key", ["gitlab_url", "base_url", "URL", "host"])
    def test_the_manager_refuses_to_create_one(self, manager, tmp_path, key):
        bad = _schedule({"repo": "dev/app", "token": True, key: CORP})

        with pytest.raises(InvalidGitLabUrlError, match=f"'{key}'"):
            manager.create(bad)

        stored = json.loads((tmp_path / "schedules.json").read_text(encoding="utf-8"))
        assert stored["schedules"] == []

    @pytest.mark.parametrize("key", ["gitlab_url", "host"])
    def test_the_manager_refuses_to_update_one_to_it(self, manager, key):
        schedule = manager.create(_schedule({"repo": "dev/app", "url": URL}))
        schedule.spec.jobTemplate.targets["gitlab"][key] = CORP

        with pytest.raises(InvalidGitLabUrlError, match=f"'{key}'"):
            manager.update(schedule)


@pytest.mark.parametrize("consumer", CONSUMERS)
class TestATargetThatIsNotAMappingIsRefused:
    """`"gitlab": "dev/app"` raised AttributeError from `.get` on export."""

    @pytest.mark.parametrize("value", ["dev/app", ["dev/app"], None, 5])
    def test_a_generator_says_so_instead_of_raising_attribute_error(
        self, consumer, value
    ):
        build, error = GENERATORS[consumer]

        with pytest.raises(error, match="targets.gitlab must be a mapping"):
            build(_schedule(value))


class TestANonMappingTargetIsNotStored:
    @pytest.mark.parametrize("value", ["dev/app", [], None, ""])
    def test_the_manager_refuses_to_create_one(self, manager, value):
        with pytest.raises(InvalidGitLabUrlError, match="targets.gitlab must be"):
            manager.create(_schedule(value))

    def test_the_manager_refuses_to_update_one_to_it(self, manager):
        schedule = manager.create(_schedule({"repo": "dev/app"}))
        schedule.spec.jobTemplate.targets["gitlab"] = "dev/app"

        with pytest.raises(InvalidGitLabUrlError, match="targets.gitlab must be"):
            manager.update(schedule)

    def test_an_empty_mapping_names_nothing_and_is_still_accepted(self, manager):
        manager.create(_schedule({}))


@pytest.mark.parametrize("consumer", CONSUMERS)
class TestAUrlWithNothingToCloneIsRefused:
    @pytest.mark.parametrize(
        "gitlab",
        [{"url": URL}, {"url": URL, "token": True}, {"url": URL, "repo": ""}],
        ids=["url-only", "url-and-token", "empty-repo"],
    )
    def test_a_generator_refuses_it(self, consumer, gitlab):
        build, error = GENERATORS[consumer]

        with pytest.raises(error, match="gitlab.repo or gitlab.group"):
            build(_schedule(gitlab))


class TestAUrlWithNothingToCloneIsNotStored:
    def test_the_factory_refuses_it(self):
        with pytest.raises(InvalidGitLabUrlError, match="gitlab.repo or gitlab.group"):
            ScanSchedule.from_simple_args(
                name="lonely", cron="0 2 * * *", gitlab_url=URL
            )

    def test_the_factory_stores_no_target_for_a_blank_url_and_nothing_else(self):
        schedule = ScanSchedule.from_simple_args(
            name="blank", cron="0 2 * * *", repos_dir="/srv/r", gitlab_url="  "
        )

        assert "gitlab" not in schedule.spec.jobTemplate.targets

    def test_the_manager_refuses_to_create_it(self, manager):
        with pytest.raises(InvalidGitLabUrlError, match="gitlab.repo or gitlab.group"):
            manager.create(_schedule({"url": URL}))

    def test_a_url_with_a_group_alone_is_still_stored(self, manager):
        manager.create(_schedule({"group": "dev", "url": URL}))


class TestValidateChecksWhatExportChecks:
    """`jmo schedule validate` said "Schedule configuration valid" for a
    schedule that `export` and `install` refuse."""

    @pytest.fixture
    def stored(self, manager, tmp_path):
        manager.create(_schedule({"repo": "dev/app", "url": URL}))
        return manager

    def _validate(self, manager, capsys):
        from scripts.cli.schedule_commands import _cmd_schedule_validate

        status = _cmd_schedule_validate(Namespace(name="self-hosted"), manager)
        said = capsys.readouterr()
        return status, said.out + said.err

    def test_a_good_schedule_is_still_valid(self, stored, capsys):
        status, said = self._validate(stored, capsys)

        assert status == 0
        assert "Schedule configuration valid" in said

    @pytest.mark.parametrize(
        ("gitlab", "named"),
        [
            (
                {"repo": "dev/app", "url": "https://deploy:hunter2@gl.evil.example"},
                "--gitlab-token",
            ),
            ({"repo": "dev/app", "url": "ssh://git@gl.evil.example"}, "ssh://"),
            ({"repo": "dev/app", "gitlab_url": CORP}, "'gitlab_url'"),
            ({"url": URL}, "gitlab.repo or gitlab.group"),
            ("dev/app", "targets.gitlab must be a mapping"),
        ],
        ids=["userinfo", "ssh", "misspelt-key", "nothing-to-clone", "not-a-mapping"],
    )
    def test_a_target_export_refuses_is_not_valid(
        self, stored, tmp_path, capsys, gitlab, named
    ):
        _hand_edit(tmp_path, gitlab)

        status, said = self._validate(stored, capsys)

        assert status == 1
        assert named in said
        assert "Schedule configuration valid" not in said
        assert "Targets configured" not in said
        assert "hunter2" not in said
        assert "gl.corp.example" not in said


class TestTheStoredUrlIsWhatTheScanChecksAgain:
    @pytest.mark.parametrize(
        "url",
        [
            "gitlab.example.test",
            "gitlab.example.test:8443/gl/",
            "HTTPS://Gitlab.Example.test/",
            "http://gitlab.internal",
            "gitlab_web:8080",
            "[::1]:8443",
        ],
    )
    def test_checking_a_stored_url_again_changes_nothing(self, url):
        """The factory stores the checked URL and a generator checks it again."""
        once = gitlab_clone_base(url)

        assert gitlab_clone_base(once) == once
        assert gitlab_target_url({"repo": "dev/app", "url": once}) == once
