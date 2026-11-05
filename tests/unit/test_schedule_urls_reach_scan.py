"""Every web URL a schedule exports is a target of the scan it runs (#1423).

The GitHub Actions, GitLab CI and cron exports write one `--url` per entry in
`web.urls`, and `jmo scan --url` was a plain store: the last one won, so a
schedule listing three URLs scanned one, exit 0. Each export's command is fed to
the real `jmo scan` parser and the real target discovery.
"""

from __future__ import annotations

import re
import shlex
from unittest.mock import patch

import pytest
import yaml

from scripts.cli.jmo import build_parser
from scripts.cli.scan_orchestrator import ScanConfig, ScanOrchestrator
from scripts.core.workflow_generators.gitlab_ci import GitLabCIGenerator
from tests.unit.test_schedule_contract import (
    _gha_run_line,
    _schedule_with,
    _what_cron_hands_the_shell,
)

URLS = ["https://a.test/", "https://b.test/x", "http://c.test:8080/"]


def _gitlab_command(schedule) -> str:
    jobs = yaml.safe_load(GitLabCIGenerator().generate(schedule))
    (script,) = [
        line
        for job in jobs.values()
        if isinstance(job, dict)
        for line in job.get("script", [])
        if "jmo scan" in line
    ]
    return script.replace("\\\n", " ")


def _cron_command(schedule) -> str:
    from scripts.core.cron_installer import CronInstaller

    with patch("scripts.core.cron_installer.platform.system", return_value="Linux"):
        entry = CronInstaller()._generate_cron_entry(schedule)
    return _what_cron_hands_the_shell(entry)


COMMANDS = {
    "github-actions": _gha_run_line,
    "gitlab-ci": _gitlab_command,
    "cron": _cron_command,
}


@pytest.mark.parametrize("export", COMMANDS)
def test_every_url_a_schedule_exports_is_a_target_of_its_scan(tmp_path, export):
    command = COMMANDS[export](_schedule_with({"web": {"urls": URLS}}))
    # What the shell would substitute, before lexing.
    argv = shlex.split(re.sub(r"\$\([^)]*\)", "2026-11-05", command))

    args = build_parser().parse_args(argv[argv.index("scan") :])
    targets = ScanOrchestrator(
        ScanConfig(tools=["zap"], results_dir=tmp_path)
    ).discover_targets(args)

    assert argv.count("--url") == len(URLS), argv
    assert targets.urls == URLS
    assert targets.rejected == []


# Decided 2026-11-05: several --url with one --api-spec exits 2, like
# --api-spec without --url; plain URLs beside an API go in --urls-file.
SPEC = "/srv/openapi.yaml"


@pytest.mark.parametrize("export", COMMANDS)
def test_no_export_renders_a_spec_with_several_urls(export):
    """`jmo scan` refuses that command, so a schedule holding it would fail
    every run (#1423)."""
    schedule = _schedule_with({"web": {"urls": URLS, "api_spec": SPEC}})

    with pytest.raises(Exception, match="exactly one --url"):
        COMMANDS[export](schedule)


def test_a_schedule_cannot_be_built_with_a_spec_and_several_urls():
    from scripts.core.schedule_manager import ScanSchedule, SpecWithoutTargetError

    with pytest.raises(SpecWithoutTargetError, match="exactly one --url"):
        ScanSchedule.from_simple_args(
            name="api", cron="0 2 * * *", url=URLS[:2], api_spec=SPEC
        )

    # The control: one URL with the spec is the API it attacks.
    built = ScanSchedule.from_simple_args(
        name="api", cron="0 2 * * *", url=URLS[:1], api_spec=SPEC
    )
    assert built.spec.jobTemplate.targets["web"] == {
        "urls": URLS[:1],
        "api_spec": SPEC,
    }
