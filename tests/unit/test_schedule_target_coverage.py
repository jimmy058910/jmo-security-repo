"""Every consumer must carry every target type, or say which it drops (#928).

The GitLab CI generator emitted 3 of the 6 target types. An IaC, GitLab or
Kubernetes target exported to GitHub Actions or to local cron correctly and
exported to GitLab CI **with the target missing from the `jmo scan` command
line** -- valid YAML, rc 0, no warning.

`tests/unit/test_schedule_contract.py` could not catch this. Its guard is
*union*-based -- "every key the factory writes is read by **a** consumer" --
which is the right shape for the bug it was written for (a key nobody read at
all) and structurally blind to a key that one consumer reads and another does
not.

Measured on `dev` before this file, on a schedule carrying all six types:

    github_actions  15 flags   (all six types)
    gitlab_ci        5 flags   (repositories, images, web.urls)
    cron_installer  13 flags   (all six types)

which is **four** dropped things, not the three the issue names -- `web.api_spec`
is silently dropped by GitLab too, and both other consumers emit it.

And the gap runs in the other direction as well, which is why this file asserts
against the real `jmo scan` parser rather than against another generator:
GitLab was the only consumer handling `repositories.include` / `exclude`, and it
emitted them as `--include-pattern` / `--exclude-pattern`, **flags `jmo scan`
does not define**. So the one target key GitLab handled alone produced a command
that exits 2. A generator compared only against its peers would have looked
merely inconsistent; compared against the parser it was wrong.
"""

from __future__ import annotations

import shlex

import pytest
import yaml

from scripts.cli.jmo import build_parser
from scripts.core.schedule_manager import (
    JobTemplateSpec,
    ScanSchedule,
    ScheduleMetadata,
    ScheduleSpec,
)
from scripts.core.workflow_generators import GitHubActionsGenerator, GitLabCIGenerator

# One schedule carrying every documented target type, with a distinguishable
# value per field so a dropped field is identifiable rather than just absent.
#
# `repositories` carries `repos_dir` and NOT `repo`, deliberately: `jmo scan`
# makes `--repo` and `--repos-dir` mutually exclusive, while
# `ScanSchedule.from_simple_args` happily writes both (`if repo: ... if
# repos_dir: ...`, no exclusion), so a schedule carrying both renders a command
# that exits 2 in *every* consumer. That is a real defect and it is filed
# separately -- it is a writer/validation problem, not the dropping problem
# this file is about, and asserting it here would make the coverage guard fail
# for a reason unrelated to coverage. `--repo` is covered by
# `test_the_repo_form_is_carried_too` below.
MAXIMAL_TARGETS: dict[str, object] = {
    "repositories": {"repos_dir": "/srv/repos"},
    "images": ["nginx:1.27"],
    "iac": {
        "terraform_state": "/srv/state.tfstate",
        "cloudformation": "/srv/stack.yaml",
        "k8s_manifest": "/srv/deploy.yaml",
    },
    "web": {"urls": ["https://example.test/app"], "api_spec": "/srv/openapi.yaml"},
    "gitlab": {"repo": "group/project", "group": "mygroup"},
    "kubernetes": {"context": "prod-cluster", "namespace": "payments"},
}

# Every value above that must survive into a generated command line, paired
# with the flag that should carry it. Derived by hand *once*, then pinned by
# `test_the_expectation_covers_every_target_field` below so a new target field
# added to MAXIMAL_TARGETS cannot be silently left unasserted.
EXPECTED: list[tuple[str, str]] = [
    ("--repos-dir", "/srv/repos"),
    ("--image", "nginx:1.27"),
    ("--terraform-state", "/srv/state.tfstate"),
    ("--cloudformation", "/srv/stack.yaml"),
    ("--k8s-manifest", "/srv/deploy.yaml"),
    ("--url", "https://example.test/app"),
    ("--api-spec", "/srv/openapi.yaml"),
    ("--gitlab-repo", "group/project"),
    ("--gitlab-group", "mygroup"),
    ("--k8s-context", "prod-cluster"),
    ("--k8s-namespace", "payments"),
]


def _maximal_schedule(options: dict[str, object] | None = None) -> ScanSchedule:
    # A severity threshold by default, so the parse tests below exercise the
    # option that broke: with `options={}` they never reached `fail_on`, and
    # every exporter's `jmo scan --fail-on HIGH` (exit 2) went unseen (#1277).
    return ScanSchedule(
        metadata=ScheduleMetadata(name="maximal"),
        spec=ScheduleSpec(
            schedule="0 2 * * *",
            jobTemplate=JobTemplateSpec(
                targets=dict(MAXIMAL_TARGETS),
                results={},
                options={"fail_on": "HIGH"} if options is None else options,
            ),
        ),
    )


def _gitlab_scan_argv(schedule: ScanSchedule) -> list[str]:
    """The argv GitLab CI would hand `jmo`, lexed from the rendered YAML.

    Starts at the subcommand, like the GitHub argv: the leading `jmo` is the
    program, and a parser handed it as a subcommand rejects every command.
    """
    job = yaml.safe_load(GitLabCIGenerator().generate(schedule))["security-scan"]
    line = next(s for s in job["script"] if s.startswith("jmo "))
    # Collapse backslash-newline continuations first. `shlex` does NOT do this
    # -- a shell treats `\<newline>` as a line continuation, but shlex treats
    # the backslash as escaping the newline and emits a literal "\n" token,
    # which then reaches argparse as an unrecognised argument. Doing it here
    # rather than asserting on the raw string keeps the oracle honest: what is
    # tested is the argv a shell would actually build.
    return shlex.split(line.replace("\\\n", " "))[1:]


def _github_scan_argv(schedule: ScanSchedule) -> list[str]:
    """The argv GitHub Actions hands the image's `jmo` entrypoint."""
    return shlex.split(GitHubActionsGenerator()._build_scan_args(schedule))


ARGV_BUILDERS = {
    "gitlab_ci": _gitlab_scan_argv,
    "github_actions": _github_scan_argv,
}


# ---------------------------------------------------------------------------
# The bug: a target type that reaches one consumer and not another.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("consumer", sorted(ARGV_BUILDERS))
@pytest.mark.parametrize(("flag", "value"), EXPECTED, ids=[f for f, _ in EXPECTED])
def test_every_consumer_carries_every_target(
    consumer: str, flag: str, value: str
) -> None:
    """Each target field must appear, with its value, in each consumer's argv.

    Parametrised per (consumer, field) rather than asserted as one set
    difference so a failure names exactly which consumer drops which field --
    the pre-fix run reads as 12 GitLab failures, one per dropped field, not one
    opaque "sets differ".
    """
    argv = ARGV_BUILDERS[consumer](_maximal_schedule())

    assert flag in argv, f"{consumer} never emits {flag}"
    assert argv[argv.index(flag) + 1] == value, (
        f"{consumer} emits {flag} with the wrong value"
    )


def _option_strings(subcommand: str) -> set[str]:
    sub = build_parser()._subparsers._group_actions[0].choices[subcommand]  # type: ignore[union-attr]
    return {opt for action in sub._actions for opt in action.option_strings}


def _option_dests(subcommand: str) -> dict[str, str]:
    sub = build_parser()._subparsers._group_actions[0].choices[subcommand]  # type: ignore[union-attr]
    return {
        opt: action.dest for action in sub._actions for opt in action.option_strings
    }


@pytest.mark.parametrize("consumer", sorted(ARGV_BUILDERS))
def test_every_flag_a_consumer_emits_resolves_to_a_real_jmo_scan_flag(
    consumer: str,
) -> None:
    """The parser is the oracle, not the other generators.

    A generator checked only against its peers can be uniformly wrong. GitLab
    emitted `--include-pattern` / `--exclude-pattern` for
    `repositories.include` / `exclude`; no other consumer read those keys, so
    peer comparison would have called GitLab the *complete* one. `jmo scan`
    defines neither flag, so that export produced a command that exits 2.

    Resolution requires an EXACT option name, not argparse's own rule (an exact
    name, or an unambiguous prefix of exactly one). A flag that resolves only by
    prefix works only while no second option shares that prefix: adding one
    turns every previously exported workflow into `ambiguous option` at once,
    and does so without failing the tests of the change that added it (#1019).
    """
    # NOT `_maximal_schedule()`. MAXIMAL_TARGETS deliberately omits
    # `repositories.include` / `exclude` (they are correctly emitted as
    # nothing, so they have no row in EXPECTED), which meant this oracle ran
    # over a schedule that could not reach the very path it exists to police:
    # a mutation restoring `--include-pattern` left it green. Caught by
    # mutation testing, which is the point of doing it -- a guard scoped to an
    # input that cannot trigger it asserts nothing.
    schedule = _maximal_schedule()
    schedule.spec.jobTemplate.targets["repositories"] = {
        **schedule.spec.jobTemplate.targets["repositories"],  # type: ignore[dict-item]
        "include": ["app-*"],
        "exclude": ["*-deprecated"],
    }
    argv = ARGV_BUILDERS[consumer](schedule)
    # The subcommand the consumer chose, not an assumed `scan`: a threshold
    # makes it `ci`, which is the only one that defines --fail-on.
    defined = _option_strings(argv[0])

    undefined = sorted(
        tok for tok in {t for t in argv if t.startswith("--")} if tok not in defined
    )

    assert not undefined, (
        f"{consumer} emits {undefined}, which `jmo {argv[0]}` does not define. Any "
        f"that argparse resolves by prefix today works only while no second "
        f"option shares that prefix -- emit the canonical name (#1019)."
    )


def test_the_repo_form_is_carried_too() -> None:
    """`repositories.repo` is the other half of the repositories target.

    Its own schedule, because `--repo` and `--repos-dir` are mutually exclusive
    on `jmo scan` -- see MAXIMAL_TARGETS' comment.
    """
    schedule = ScanSchedule(
        metadata=ScheduleMetadata(name="repo-form"),
        spec=ScheduleSpec(
            schedule="0 2 * * *",
            jobTemplate=JobTemplateSpec(
                targets={"repositories": {"repo": "https://example.test/r.git"}},
                results={},
                options={},
            ),
        ),
    )

    for consumer, builder in ARGV_BUILDERS.items():
        argv = builder(schedule)
        assert "--repo" in argv, f"{consumer} never emits --repo"
        assert argv[argv.index("--repo") + 1] == "https://example.test/r.git"


@pytest.mark.parametrize("consumer", sorted(ARGV_BUILDERS))
def test_the_generated_command_actually_parses(consumer: str) -> None:
    """The whole argv, fed to the real parser, must be accepted.

    Stronger than the flag-name check above: it also catches a flag emitted
    with the wrong arity (a store_true given a value, or a value flag given
    none), which a name-only comparison passes.
    """
    argv = ARGV_BUILDERS[consumer](_maximal_schedule())

    # The emitted argv, whole: re-heading it with `scan` would test a command
    # the consumer never wrote.
    parsed = build_parser().parse_args(argv)

    # A threshold needs `jmo ci`: `jmo scan` has no --fail-on, and argparse
    # read `--fail-on HIGH` as the prefix of --fail-on-store-error, leaving
    # HIGH unrecognised (#1277).
    assert parsed.cmd == "ci", f"{consumer} emitted `jmo {parsed.cmd}`"
    assert parsed.fail_on == "HIGH"

    _assert_every_target_resolved(parsed, consumer)


@pytest.mark.parametrize("consumer", sorted(ARGV_BUILDERS))
def test_a_schedule_without_a_threshold_stays_a_scan(consumer: str) -> None:
    """The control for the test above: `ci` only when there is a threshold.

    The targets are checked here too, so both subcommands' command lines are
    proven to carry every target, not only the `ci` one.
    """
    parsed = build_parser().parse_args(
        ARGV_BUILDERS[consumer](_maximal_schedule(options={}))
    )

    assert parsed.cmd == "scan"
    _assert_every_target_resolved(parsed, consumer)


@pytest.mark.parametrize("consumer", sorted(ARGV_BUILDERS))
def test_every_consumer_carries_every_option(consumer: str) -> None:
    """A schedule's options must reach the command, as its targets do.

    GitHub Actions read `threads` and `fail_on` and dropped `timeout`
    silently; GitLab carried it. Same shape as #928, one level down.
    """
    options = {"threads": 4, "timeout": 900, "allow_missing_tools": True}

    parsed = build_parser().parse_args(
        ARGV_BUILDERS[consumer](_maximal_schedule(options=options))
    )

    assert (parsed.threads, parsed.timeout) == (4, 900)
    assert parsed.allow_missing_tools is True


def _assert_every_target_resolved(parsed, consumer: str) -> None:
    """Every target value must land on its own flag's dest.

    Asserting resolved values is what proves the command really parsed, rather
    than that a Namespace came back at all: a flag emitted with the wrong arity
    shifts the values after it onto the wrong dests, which parse_args accepts
    silently.
    """
    dests = _option_dests(parsed.cmd)
    for flag, value in EXPECTED:
        got = getattr(parsed, dests[flag])
        resolved = value in got if isinstance(got, list) else got == value
        assert resolved, f"{consumer}: {flag} parsed to {got!r}, not {value!r}"


# ---------------------------------------------------------------------------
# Meta-guards: an expectation table that drifts asserts nothing.
# ---------------------------------------------------------------------------


def test_the_expectation_covers_every_target_field() -> None:
    """EXPECTED must name every leaf value in MAXIMAL_TARGETS.

    Without this, adding a seventh target type to MAXIMAL_TARGETS and
    forgetting to add its row leaves it unasserted -- and the suite goes green
    on a target nobody checks, which is the original bug wearing a test.
    """

    def _leaves(node: object) -> list[str]:
        if isinstance(node, dict):
            return [v for child in node.values() for v in _leaves(child)]
        if isinstance(node, list):
            return [v for child in node for v in _leaves(child)]
        return [str(node)]

    asserted = {value for _, value in EXPECTED}
    missing = sorted(set(_leaves(MAXIMAL_TARGETS)) - asserted)

    assert not missing, f"MAXIMAL_TARGETS carries unasserted values: {missing}"


def test_the_argv_extractors_actually_found_something() -> None:
    """A lexer that quietly returns [] satisfies nothing above."""
    for consumer, builder in ARGV_BUILDERS.items():
        argv = builder(_maximal_schedule())
        assert len(argv) >= 10, f"{consumer} extractor produced only {argv}"
        assert "--repos-dir" in argv, f"{consumer} extractor missed --repos-dir"


# ---------------------------------------------------------------------------
# What GitLab cannot carry must be said out loud, not invented or dropped.
# ---------------------------------------------------------------------------


def _gitlab_script(targets: dict[str, object]) -> str:
    schedule = ScanSchedule(
        metadata=ScheduleMetadata(name="talkative"),
        spec=ScheduleSpec(
            schedule="0 2 * * *",
            jobTemplate=JobTemplateSpec(targets=targets, results={}, options={}),
        ),
    )
    job = yaml.safe_load(GitLabCIGenerator().generate(schedule))["security-scan"]
    return " ".join(job["script"])


def test_a_config_only_repository_key_warns_instead_of_inventing_a_flag(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """repositories.include/exclude have no `jmo scan` flag at all.

    They are a real feature -- jmo.yml's `include:` / `exclude:`, read into
    ScanConfig.include_patterns -- but config-only. The generator emitted
    `--include-pattern` / `--exclude-pattern`, so the one target key it handled
    and its peers did not produced a command `jmo scan` rejects.

    Both halves are asserted: the invented flag is gone, and the user is told
    where the feature actually lives. Dropping it silently would trade one
    silent failure for another.
    """
    logger_name = "scripts.core.workflow_generators.gitlab_ci"
    with caplog.at_level("WARNING", logger=logger_name):
        script = _gitlab_script(
            {"repositories": {"repos_dir": "/srv/r", "include": ["app-*"]}}
        )

    assert "--include-pattern" not in script
    assert "repositories.include" in caplog.text
    assert "jmo.yml" in caplog.text


def test_an_unhandled_target_key_is_reported(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A key this generator does not know must not vanish quietly.

    The catch-all is what stops #928 recurring for target type seven: a new key
    added to the schema and wired into the other consumers would otherwise be
    dropped here with valid YAML and rc 0, exactly as iac/gitlab/kubernetes
    were.
    """
    logger_name = "scripts.core.workflow_generators.gitlab_ci"
    with caplog.at_level("WARNING", logger=logger_name):
        _gitlab_script({"repositories": {"repos_dir": "/srv/r"}, "quantum": {"qpu": 1}})

    assert "quantum" in caplog.text


def test_a_handled_target_key_produces_no_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The negative control for the catch-all.

    A warning that fires on everything is noise, and it would also mean the
    test above passes for the wrong reason.
    """
    logger_name = "scripts.core.workflow_generators.gitlab_ci"
    with caplog.at_level("WARNING", logger=logger_name):
        _gitlab_script(dict(MAXIMAL_TARGETS))

    assert caplog.text == "", (
        f"unexpected warning on a fully handled schedule:\n{caplog.text}"
    )


def test_the_gitlab_token_is_a_variable_reference_not_a_literal() -> None:
    """A rendered .gitlab-ci.yml is committed to a repo; it must carry no secret."""
    script = _gitlab_script({"gitlab": {"repo": "g/p", "token": "glpat-SECRET-VALUE"}})

    assert "glpat-SECRET-VALUE" not in script
    assert "--gitlab-token ${GITLAB_TOKEN}" in script
