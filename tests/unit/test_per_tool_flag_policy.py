#!/usr/bin/env python3
"""Guards for per-tool flag and timeout resolution (#822).

The failure this file prevents: **a documented config knob silently destroying a
tool's entire contribution.** JMo splices `per_tool.<tool>.flags` into the argv
*after* its own flags, and a scalar flag is last-one-wins, so
`flags: ["-f","table"]` made trivy write a table into `trivy.json`. The file
existed, so the tool graded `success`; the adapter could not read it; and the
scan exited 0. Measured: **2 findings to 0, rc=0, nothing on any stream.**

Second concern here: these helpers existed as five identical copies, one per
scanner, and only `repository_scanner`'s `get_tool_timeout` applied the
slow-tool floor. Consolidating them is what makes a single guard possible.

Third (#1335): which spellings of a flag reach a tool is its own parser's
grammar, not one shared list. A shared set refused real flags (grype's `-f` is
`--fail-on`) and missed short flags chained in a cluster (`-qftable`).
"""

from __future__ import annotations

import ast
import importlib
import logging
from pathlib import Path

import pytest

from scripts.cli.scan_jobs import tool_loop
from scripts.cli.scan_utils import (
    TOOL_TIMEOUT_DEFAULTS,
    tool_flags,
    tool_timeout,
)
from scripts.core.tool_descriptors import DESCRIPTORS, FlagGrammar, ScanContext

SCAN_JOBS = Path(__file__).resolve().parents[2] / "scripts" / "cli" / "scan_jobs"


class TestReservedFlagsAreRefused:
    """Flags that decide where a tool writes, and in what format, are JMo's."""

    def test_untouched_flags_pass_through(self):
        cfg = {"trivy": {"flags": ["--no-progress", "--scanners", "vuln,secret"]}}
        assert tool_flags(cfg, "trivy") == [
            "--no-progress",
            "--scanners",
            "vuln,secret",
        ]

    def test_reserved_flag_takes_its_value_with_it(self):
        """Dropping only the flag would be worse than the collision.

        `["-f", "table"]` reduced to `["table"]` leaves a bare word in the argv,
        and trivy reads a bare word as a **scan target**. The value has to go too.
        """
        assert tool_flags({"trivy": {"flags": ["-f", "table"]}}, "trivy") == []

    def test_inline_value_form_is_handled(self):
        """`--format=table` carries its value in the same token."""
        cfg = {"trivy": {"flags": ["--format=table", "--quiet"]}}
        assert tool_flags(cfg, "trivy") == ["--quiet"]

    def test_only_the_collision_is_removed(self):
        cfg = {"trivy": {"flags": ["-o", "/tmp/x.json", "--debug"]}}
        assert tool_flags(cfg, "trivy") == ["--debug"]

    def test_a_following_flag_is_not_eaten_as_a_value(self):
        """`-o` immediately followed by another flag must not consume it."""
        cfg = {"semgrep": {"flags": ["-o", "--verbose"]}}
        assert tool_flags(cfg, "semgrep") == ["--verbose"]

    def test_the_drop_is_announced(self, caplog):
        """Silently ignoring configuration is the #807 class; say so."""
        with caplog.at_level(logging.WARNING, logger="scripts.cli.scan_utils"):
            tool_flags({"trivy": {"flags": ["-f", "table"]}}, "trivy")

        visible = [
            r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING
        ]
        assert visible, "a dropped flag was not reported"
        assert any("trivy" in m for m in visible), visible
        assert any("-f table" in m for m in visible), visible

    def test_clean_config_stays_quiet(self, caplog):
        """The control. Without it an always-warn bug passes the test above."""
        with caplog.at_level(logging.WARNING, logger="scripts.cli.scan_utils"):
            tool_flags({"trivy": {"flags": ["--no-progress"]}}, "trivy")
        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]

    def test_repeatable_flags_are_deliberately_not_policed(self):
        """`--scanners` unions rather than replaces, so it is not load-bearing.

        Measured against trivy 0.70.0: `--scanners misconfig --scanners license`
        returns misconfig results, so a repeat widens rather than overrides.
        Policing it -- or `--exclude`, which tools legitimately repeat -- would
        break working configs to fix a problem that does not exist.
        """
        assert "--scanners" not in DESCRIPTORS["trivy"].reserved_flags
        assert not [
            n for n, d in DESCRIPTORS.items() if "--exclude" in d.reserved_flags
        ]
        cfg = {"trivy": {"flags": ["--scanners", "vuln", "--scanners", "secret"]}}
        assert tool_flags(cfg, "trivy") == [
            "--scanners",
            "vuln",
            "--scanners",
            "secret",
        ]

    def test_an_attached_value_is_read_only_where_the_tool_reads_it(self):
        """gitleaks' flag parser reads `-cmine.toml` as `-c mine.toml`, so the
        attached form of its reserved short flags is dropped too (review of
        #1325). nuclei's single-dash flags merely start like one: `-fr` is
        `-follow-redirects`, and `-omit-raw` is not `-o`."""
        cfg = {
            "gitleaks": {"flags": ["-cmine.toml", "-rout.json", "-fjson", "-v"]},
            "nuclei": {"flags": ["-fr", "-omit-raw"]},
        }
        assert tool_flags(cfg, "gitleaks") == ["-v"]
        assert tool_flags(cfg, "nuclei") == ["-fr", "-omit-raw"]
        # Its value is attached, so the next token is not taken as it.
        kept = {"gitleaks": {"flags": ["-fjson", "stays"]}}
        assert tool_flags(kept, "gitleaks") == ["stays"]

    @pytest.mark.parametrize("junk", [None, "not-a-dict", 42, []])
    def test_degenerate_config_is_not_a_crash(self, junk):
        assert tool_flags({"trivy": junk}, "trivy") == []
        assert tool_flags({}, "trivy") == []


# --- each tool's own grammar (#1335) -------------------------------------------
#
# Each spelling was run against the tool itself (trivy 0.74.0, grype
# 0.118.0, syft 1.51.1, gitleaks 8.30.1, trufflehog 3.97.1, semgrep 1.175.0,
# checkov 3.3.16, hadolint 2.15.1, shellcheck 0.11.0, zizmor 1.30.1,
# osv-scanner 2.6.0, nuclei 3.11.1) and judged by what it did, except the
# flags taken from the tool's own help: osv-scanner's `--serve`, zap's
# `-quickout`, semgrep's `--gitlab-*`, and the exit-code flags. A refused
# spelling lost the findings or moved the report (trivy `-ftable` took 42
# findings to 0 with rc 0, grype `-otable` 7 to 0, gitleaks `-vr<path>` wrote
# its unredacted report into the scanned repository), repeats a flag JMo
# passes to a parser that refuses a repeat (zizmor `-o` is its `--offline`:
# rc 2, "cannot be used multiple times"), or sets an exit code the row does
# not accept (grype `-f high`: rc 2 on a HIGH match). A kept one is a real flag
# of that tool (semgrep's `-f` is `--config`, shellcheck's `-o` is
# `--enable`), or a spelling the tool itself rejects out loud (osv-scanner
# `-ftable`: "flag provided but not defined").
# Spelled out rather than derived from the descriptors: a guard reading its
# expectation from what it guards cannot fail when that changes.

REFUSED = [
    # pflag: a short flag's value attached, or chained after no-value flags.
    ("trivy", "-ftable"),
    ("trivy", "-f table"),
    ("trivy", "-f=table"),
    ("trivy", "--format=table"),
    ("trivy", "--format table"),
    ("trivy", "-fsarif"),
    ("trivy", "-ftemplate"),
    ("trivy", "-qftable"),
    ("trivy", "-dftable"),
    ("trivy", "-vftable"),
    ("trivy", "-dqftable"),
    ("trivy", "-qf table"),
    ("trivy", "-otable.txt"),
    ("trivy", "-o table.txt"),
    ("trivy", "-o=table.txt"),
    ("trivy", "--output=table.txt"),
    # `-format` is `-f ormat` to pflag, and `table` would be left a bare word.
    ("trivy", "-format table"),
    ("trivy", "-format=table"),
    ("trivy", "--exit-code 1"),
    ("trivy", "--exit-code=5"),
    # grype and syft: `-o` appends an output, so even `-ojson` breaks them;
    # `--file` redirects it and leaves stdout empty.
    ("grype", "-ojson"),
    ("grype", "-otable"),
    ("grype", "-o table"),
    ("grype", "-o=table"),
    ("grype", "--output=table"),
    ("grype", "-otemplate"),
    ("grype", "-qotable"),
    ("grype", "-votable"),
    ("grype", "-qo table"),
    ("grype", "--file x.json"),
    ("grype", "--file=x.json"),
    # Exit code: rc 2 on a match at that severity, which the row does not accept.
    ("grype", "-f high"),
    ("grype", "-fhigh"),
    ("grype", "--fail-on high"),
    ("grype", "-qf high"),
    ("syft", "-ojson"),
    ("syft", "-otable"),
    ("syft", "-o table"),
    ("syft", "-o=table"),
    ("syft", "--output=table"),
    ("syft", "-qotable"),
    ("syft", "-qo table"),
    ("syft", "-ojson=other.json"),
    ("syft", "-o json=other.json"),
    ("syft", "--file other.json"),
    ("syft", "--file=x.json"),
    ("gitleaks", "-fjson"),
    ("gitleaks", "-f=json"),
    ("gitleaks", "--report-format=json"),
    ("gitleaks", "-vfjson"),
    ("gitleaks", "-vf json"),
    ("gitleaks", "-vrREPORT.sarif"),
    ("gitleaks", "-vr REPORT.sarif"),
    ("gitleaks", "--report-path=x.sarif"),
    ("gitleaks", "-cmine.toml"),
    ("gitleaks", "-vcmine.toml"),
    ("gitleaks", "-vc mine.toml"),
    ("gitleaks", "--redact"),
    ("gitleaks", "--redact=50"),
    ("gitleaks", "--exit-code=1"),
    ("gitleaks", "-report-format json"),
    # kingpin: what JMo already passes cannot be given twice ("flag 'json'
    # cannot be repeated", no output), and `--no-X` is X given again.
    ("trufflehog", "--no-verification"),
    ("trufflehog", "--no-no-verification"),
    ("trufflehog", "--no-update"),
    ("trufflehog", "-j"),
    ("trufflehog", "--json"),
    ("trufflehog", "--no-json"),
    ("trufflehog", "--json=false"),
    ("trufflehog", "--json-legacy"),
    ("trufflehog", "--sarif"),
    ("trufflehog", "--github-actions"),
    # JMo always passes its own exclusions file ("flag 'exclude-paths'
    # cannot be repeated"), and `-jx` is `-j -x`, whose value goes too.
    ("trufflehog", "--exclude-paths mine.txt"),
    ("trufflehog", "--exclude-paths=mine.txt"),
    ("trufflehog", "-x mine.txt"),
    ("trufflehog", "-jx mine.txt"),
    ("trufflehog", "--fail"),
    ("trufflehog", "--no-fail"),
    ("trufflehog", "--fail-on-scan-errors"),
    # Cmdliner: rc 2 and no output file, or a text report in JMo's JSON file.
    ("semgrep", "-oother.json"),
    ("semgrep", "-o other.json"),
    ("semgrep", "-o=other.json"),
    ("semgrep", "--output=other.json"),
    ("semgrep", "-qoother.json"),
    ("semgrep", "--json"),
    ("semgrep", "--text"),
    ("semgrep", "--sarif"),
    ("semgrep", "--emacs"),
    ("semgrep", "--vim"),
    ("semgrep", "--junit-xml"),
    ("semgrep", "--gitlab-sast"),
    ("semgrep", "--gitlab-secrets"),
    ("semgrep", "--error"),
    ("semgrep", "--strict"),
    # argparse (configargparse): chains, and reads a long option's prefix.
    ("checkov", "-ocli"),
    ("checkov", "-o cli"),
    ("checkov", "-o=cli"),
    ("checkov", "--output=cli"),
    ("checkov", "-osarif"),
    ("checkov", "-ojson"),
    ("checkov", "-socli"),
    ("checkov", "-so cli"),
    ("checkov", "--outp cli"),
    ("checkov", "--outpu=cli"),
    ("checkov", "-s"),
    ("checkov", "--soft-fail"),
    ("checkov", "--soft-fail-on CKV_AWS_1"),
    ("checkov", "--hard-fail-on HIGH"),
    ("checkov", "--no-fail-on-crash"),
    # A reserved no-value flag chained before a value-taking one: its value
    # is the next token, and it goes too.
    ("checkov", "-sc CKV_AWS_1"),
    # optparse-applicative: a second `-f json` prints the report twice.
    ("hadolint", "-fjson"),
    ("hadolint", "-ftty"),
    ("hadolint", "-f tty"),
    ("hadolint", "-f=tty"),
    ("hadolint", "--format=tty"),
    ("hadolint", "--format tty"),
    ("hadolint", "-fsarif"),
    ("hadolint", "-Vftty"),
    ("hadolint", "-Vf tty"),
    ("hadolint", "--no-fail"),
    ("hadolint", "-tnone"),
    ("hadolint", "-t none"),
    ("hadolint", "--failure-threshold=none"),
    # Haskell's GetOpt: chains, and reads any unique prefix (`--fo=tty`).
    ("shellcheck", "-ftty"),
    ("shellcheck", "-f tty"),
    ("shellcheck", "-f=tty"),
    ("shellcheck", "--format=tty"),
    ("shellcheck", "--format tty"),
    ("shellcheck", "-fjson1"),
    ("shellcheck", "-xftty"),
    ("shellcheck", "-xf tty"),
    ("shellcheck", "--form=tty"),
    ("shellcheck", "--fo=tty"),
    ("shellcheck", "--f=tty"),
    ("zizmor", "--format=plain"),
    ("zizmor", "--format plain"),
    ("zizmor", "--format=json"),
    # clap: JMo passes `--offline` (`-o`) and `--no-exit-codes`, and any of
    # them again is rc 2 (measured against JMo's own command line).
    ("zizmor", "-o"),
    ("zizmor", "-qo"),
    ("zizmor", "--offline"),
    ("zizmor", "--no-exit-codes"),
    ("zizmor", "--strict-collection"),
    # Go's flag package: one dash or two, never chained.
    ("osv-scanner", "-f table"),
    ("osv-scanner", "-f=table"),
    ("osv-scanner", "--format=table"),
    ("osv-scanner", "--format table"),
    ("osv-scanner", "-format table"),
    ("osv-scanner", "-format=table"),
    ("osv-scanner", "--output-file other.sarif"),
    ("osv-scanner", "--output-file=other.sarif"),
    ("osv-scanner", "-output-file other.sarif"),
    ("osv-scanner", "--output other.sarif"),
    ("osv-scanner", "--output=other.sarif"),
    ("osv-scanner", "--download-offline-databases"),
    ("osv-scanner", "--serve"),
    ("nuclei", "-o x.txt"),
    ("nuclei", "-o=x.txt"),
    ("nuclei", "-output x.txt"),
    ("nuclei", "-output=x.txt"),
    ("nuclei", "--output x.txt"),
    ("nuclei", "--output=x.txt"),
    ("nuclei", "-jsonl=false"),
    ("nuclei", "-j=false"),
    ("nuclei", "--jsonl=false"),
    ("zap", "-quickout other.html"),
    # JMo's own runners: a second --target re-points the scan (argparse is
    # last-one-wins), and argparse's default reads a long option's prefix.
    ("yara", "--output x.json"),
    ("yara", "--target elsewhere"),
    ("yara", "--o x.json"),
    ("yara", "--ou x.json"),
    ("yara", "--outp x.json"),
    ("jmo-native", "--output x.sarif"),
    ("jmo-native", "--target elsewhere"),
    ("jmo-native", "--outp x.sarif"),
]

KEPT = [
    # Real flags a shared `-o`/`-f` refused. semgrep's `--config` is a list:
    # a second one adds rules (measured beside JMo's own `--config`).
    ("semgrep", "-f rules.yaml"),
    ("semgrep", "-frules.yaml"),
    ("semgrep", "--config rules.yaml"),
    ("semgrep", "--exclude tests"),
    ("checkov", "-f main.tf"),
    ("shellcheck", "-o all"),
    ("shellcheck", "-oall"),
    # A value-taking or unknown letter ends the walk: the rest is its value.
    ("trivy", "-sHIGH"),
    ("trivy", "-sCRITICAL,HIGH -q"),
    ("trivy", "-cconfig.yaml"),
    ("trivy", "-ttpl.tpl"),
    ("trivy", "-q"),
    ("grype", "-cconfig.yaml"),
    ("grype", "-sall-layers"),
    ("grype", "-ttpl.tmpl"),
    ("grype", "-vv"),
    ("syft", "-cconfig.yaml"),
    ("gitleaks", "-linfo"),
    ("gitleaks", "-lwarn"),
    ("gitleaks", "-l warn"),
    ("gitleaks", "-v"),
    ("gitleaks", "--max-target-megabytes 5"),
    ("checkov", "-cCKV_AWS_1"),
    ("checkov", "-qocli"),
    ("checkov", "--compact"),
    ("checkov", "--quiet"),
    # Longer than `--output`, so not a prefix of it: another option.
    ("checkov", "--output-file-path ofp"),
    ("checkov", "--output-f=ofp"),
    ("hadolint", "-cfoo.yaml"),
    ("hadolint", "--ignore DL3007"),
    ("shellcheck", "-Sstyle"),
    ("shellcheck", "--color=always"),
    # A tool that takes no prefix rejects this itself, out loud.
    ("semgrep", "--outp other.json"),
    ("hadolint", "--form tty"),
    ("zizmor", "--form=plain"),
    ("semgrep", "--json-output=other.json"),
    ("semgrep", "--sarif-output=s.sarif"),
    ("trufflehog", "--results=unverified"),
    ("trufflehog", "--results=verified,unverified,unknown"),
    ("trufflehog", "--no-color"),
    ("trufflehog", "--concurrency=2"),
    # zizmor 1.30.1 with JMo's own command line: rc 0.
    ("zizmor", "-q"),
    ("zizmor", "-p"),
    ("zizmor", "--persona=auditor"),
    ("zizmor", "--min-severity=high"),
    # Go's flag package rejects an attached value itself (rc 127).
    ("osv-scanner", "-fjson"),
    ("osv-scanner", "-ftable"),
    ("osv-scanner", "-oother.sarif"),
    ("osv-scanner", "--all-packages"),
    ("osv-scanner", "--verbosity error"),
    # nuclei's single-dash names only start like a reserved one.
    ("nuclei", "-omit-raw"),
    ("nuclei", "-or"),
    ("nuclei", "-ot"),
    ("nuclei", "-fr"),
    ("nuclei", "-je x.json"),
    ("nuclei", "-se x.sarif"),
    ("nuclei", "-ox.txt"),
    ("nuclei", "-silent=false"),
    ("nuclei", "-severity critical,high,medium"),
    ("zap", "-config api.disablekey=true"),
    ("yara", "--exclude-dir build"),
    ("yara", "--timeout 5"),
    ("jmo-native", "--exclude-dir build"),
]


def _ids(cases: list[tuple[str, str]]) -> list[str]:
    return [f"{tool}: {flags}" for tool, flags in cases]


class TestEachToolsOwnGrammar:
    @pytest.mark.parametrize(("tool", "flags"), REFUSED, ids=_ids(REFUSED))
    def test_a_spelling_the_tool_reads_as_its_output_flag_is_refused(self, tool, flags):
        assert tool_flags({tool: {"flags": flags.split()}}, tool) == []

    @pytest.mark.parametrize(("tool", "flags"), KEPT, ids=_ids(KEPT))
    def test_a_real_flag_is_kept(self, tool, flags):
        assert tool_flags({tool: {"flags": flags.split()}}, tool) == flags.split()

    def test_every_row_declares_its_parser(self):
        """Spelled out, so a new row has to say which parser it has."""
        assert {name: d.flag_grammar for name, d in DESCRIPTORS.items()} == {
            "trufflehog": FlagGrammar.KINGPIN,
            "gitleaks": FlagGrammar.PFLAG,
            "semgrep": FlagGrammar.CMDLINER,
            "syft": FlagGrammar.PFLAG,
            "trivy": FlagGrammar.PFLAG,
            "checkov": FlagGrammar.ARGPARSE,
            "hadolint": FlagGrammar.OPTPARSE_APPLICATIVE,
            "shellcheck": FlagGrammar.GETOPT,
            "zizmor": FlagGrammar.CLAP,
            "jmo-native": FlagGrammar.ARGPARSE,
            "yara": FlagGrammar.ARGPARSE,
            "grype": FlagGrammar.PFLAG,
            "osv-scanner": FlagGrammar.GO_FLAG,
            "zap": FlagGrammar.ZAP,
            "nuclei": FlagGrammar.GO_FLAG,
        }

    def test_what_each_parser_does_with_a_spelling(self):
        """Measured per parser: `-jx ex.txt` is trufflehog's `-j -x ex.txt`
        and zizmor's `-qcfile` its `-q -c file`; Go's flag package rejects
        `-ftable` and reads `-format` as `--format`; checkov takes
        `--output-f=` for `--output-file-path` and shellcheck `--fo=` for
        `--format=`, where semgrep, hadolint and zizmor reject `--outp` and
        `--form`; kingpin reads `--no-json` as `--json` given again. A flag
        given twice is rc 2 or 1 for trufflehog, zizmor and semgrep, and rc 0
        for zap (`-cmd -cmd`), hadolint and the pflag tools."""
        assert {g for g in FlagGrammar if g.clusters} == {
            FlagGrammar.PFLAG,
            FlagGrammar.KINGPIN,
            FlagGrammar.CMDLINER,
            FlagGrammar.GETOPT,
            FlagGrammar.OPTPARSE_APPLICATIVE,
            FlagGrammar.ARGPARSE,
            FlagGrammar.CLAP,
        }
        assert {g for g in FlagGrammar if g.abbreviates} == {
            FlagGrammar.GETOPT,
            FlagGrammar.ARGPARSE,
        }
        assert {g for g in FlagGrammar if g.either_dash} == {FlagGrammar.GO_FLAG}
        assert {g for g in FlagGrammar if g.negates} == {FlagGrammar.KINGPIN}
        assert {g for g in FlagGrammar if g.refuses_repeats} == {
            FlagGrammar.KINGPIN,
            FlagGrammar.CLAP,
            FlagGrammar.CMDLINER,
        }

    def test_no_row_reserves_a_flag_only_another_tool_has(self):
        """The shared set's defect: one list for every tool refused semgrep's
        `--config` as `-f`. Each row's own list is its own spellings."""
        assert "-f" not in DESCRIPTORS["semgrep"].reserved_flags
        assert "-f" not in DESCRIPTORS["checkov"].reserved_flags
        assert "-o" not in DESCRIPTORS["shellcheck"].reserved_flags


# Flags JMo passes that the parser takes more than once: a list option.
# Measured beside JMo's own (semgrep 1.175.0, rc 0): a second `--config` adds
# rules, a second `--exclude` adds exclusions.
REPEATABLE = {("semgrep", "--config"), ("semgrep", "--exclude")}


def _passed_flags(name: str, tmp_path: Path) -> set[str]:
    """Every flag the row's builders put on the command line, and its
    exclusion flag, which the scan loop adds on a repository."""
    d = DESCRIPTORS[name]
    repo = tmp_path / name
    repo.mkdir()
    passed = {d.exclusion_flag} if d.exclusion_flag else set()
    for key, build in d.invocations.items():
        ctx = ScanContext(
            tool=name,
            target_type=key,
            target=repo,
            out_dir=tmp_path,
            binary=name,
            history=True,
            files=(str(repo / "input"),),
        )
        for invocation in build(ctx):
            passed |= {
                token.partition("=")[0]
                for token in invocation.command[1:]
                if token.startswith("-")
            }
    return passed


class TestAFlagJmoPassesIsNotGivenTwice:
    """A parser that refuses a flag given twice fails the run when a user's
    flags repeat one JMo passes: zizmor's `-o` is its `--offline`, which JMo
    passes, and was rc 2 ("the argument '--offline' cannot be used multiple
    times"). So every flag JMo passes such a row is that row's."""

    def test_every_flag_jmo_passes_a_parser_that_refuses_a_repeat_is_reserved(
        self, tmp_path
    ):
        checked = {}
        for name, d in DESCRIPTORS.items():
            if d.flag_grammar.refuses_repeats:
                checked[name] = _passed_flags(name, tmp_path)
        # The derivation found what it has to: an empty set passes anything.
        assert set(checked) == {"trufflehog", "semgrep", "zizmor"}
        assert {"--json", "--no-verification", "--exclude-paths"} <= checked[
            "trufflehog"
        ]
        assert {"--format", "--offline", "--no-exit-codes"} <= checked["zizmor"]

        unreserved = sorted(
            f"{name} {flag}"
            for name, passed in checked.items()
            for flag in passed
            if DESCRIPTORS[name].reserved_spelling(flag) is None
            and (name, flag) not in REPEATABLE
        )
        assert not unreserved, unreserved

    def test_zizmor_is_handed_its_offline_flag_once(self, tmp_path):
        repo = tmp_path / "repo"
        workflow = repo / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_bytes(b"on: push\njobs: {}\n")
        out = tmp_path / "out"
        out.mkdir()
        commands: list[list[str]] = []

        class Recorder:
            def __init__(self, tools, progress_callback=None):
                commands.extend(t.command for t in tools)

            def run_all_parallel(self):
                return []

        tool_loop.run_tools(
            tools=["zizmor"],
            target_type="repo",
            target=repo,
            target_label="t",
            out_dir=out,
            timeout=60,
            retries=0,
            per_tool_config={"zizmor": {"flags": ["-o", "-qo", "-p"]}},
            allow_missing_tools=False,
            runner_cls=Recorder,
            find_tool_func=lambda name: "/bin/zizmor",
            repo_root=repo,
        )

        (command,) = commands
        assert command.count("--offline") == 1, command
        assert "-o" not in command and "-qo" not in command, command
        # A flag JMo does not pass still reaches it.
        assert "-p" in command, command


class TestEachRefusalSaysWhy:
    @pytest.mark.parametrize(
        ("tool", "flags", "why"),
        [
            ("trivy", "-ftable", "where the tool writes"),
            ("zizmor", "-o", "JMo already passes it"),
            ("grype", "-f high", "--fail-on"),
            ("yara", "--target elsewhere", "another target"),
            ("trufflehog", "--no-verification", "per_tool.trufflehog.verify: true"),
            ("osv-scanner", "--download-offline-databases", "jmo tools update"),
        ],
        ids=["output", "passed", "exit code", "target", "verify", "download"],
    )
    def test_the_warning_gives_the_reason_for_its_class(self, caplog, tool, flags, why):
        with caplog.at_level(logging.WARNING, logger="scripts.cli.scan_utils"):
            assert tool_flags({tool: {"flags": flags.split()}}, tool) == []
        (message,) = [r.getMessage() for r in caplog.records]
        assert why in message, message


class TestTheClusterWalk:
    """A chaining parser reads `-qftable` as `-q -f table`: the walk passes
    over no-value flags until it reaches a reserved one (refused) or one
    that takes a value (the rest of the token is that value: kept)."""

    def test_a_value_taking_letter_ends_the_walk(self):
        # trivy's `-s` takes a value: `-sqf` is severity `qf`, not `-q -f`.
        assert tool_flags({"trivy": {"flags": ["-sqf"]}}, "trivy") == ["-sqf"]

    def test_an_attached_value_leaves_the_next_token(self):
        cfg = {"trivy": {"flags": ["-qftable", "--no-progress"]}}
        assert tool_flags(cfg, "trivy") == ["--no-progress"]
        kept = {"trivy": {"flags": ["-qftable", "stays"]}}
        assert tool_flags(kept, "trivy") == ["stays"]

    def test_a_reserved_letter_ending_the_token_takes_the_next_one(self):
        cfg = {"trivy": {"flags": ["-qf", "table", "--no-progress"]}}
        assert tool_flags(cfg, "trivy") == ["--no-progress"]

    def test_a_single_dash_long_name_takes_its_value(self):
        """pflag reads `-format` as `-f ormat`, and would take `table` as a
        scan target: refused as `--format`, so its value goes with it."""
        cfg = {"trivy": {"flags": ["-format", "table", "--no-progress"]}}
        assert tool_flags(cfg, "trivy") == ["--no-progress"]
        cfg = {"gitleaks": {"flags": ["-report-format", "json"]}}
        assert tool_flags(cfg, "gitleaks") == []

    def test_a_reserved_no_value_flag_takes_no_value(self):
        # zizmor's `-o` is `--offline`: what follows it is not its value.
        assert tool_flags({"zizmor": {"flags": ["-o", "stays"]}}, "zizmor") == ["stays"]

    def test_a_parser_that_does_not_chain_gets_no_walk(self):
        """nuclei's `-or` is `-omit-raw`, not `-o r`: the walk would refuse
        it, which is why the rule is the parser's and not every tool's."""
        assert tool_flags({"nuclei": {"flags": ["-or"]}}, "nuclei") == ["-or"]


class TestEachRefusalIsNamed:
    def test_the_warning_names_the_spelling_and_the_flag_it_sets(self, caplog):
        cfg = {"trivy": {"flags": ["-qftable", "--no-progress", "-o", "x.txt"]}}
        with caplog.at_level(logging.WARNING, logger="scripts.cli.scan_utils"):
            assert tool_flags(cfg, "trivy") == ["--no-progress"]

        messages = [
            r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING
        ]
        assert len(messages) == 2, messages
        assert "`-qftable`" in messages[0] and "`-f`" in messages[0], messages
        assert "`-o x.txt`" in messages[1] and "`-o`" in messages[1], messages
        assert all("per_tool.trivy.flags" in m for m in messages), messages

    def test_an_abbreviation_is_named_by_the_flag_it_abbreviates(self, caplog):
        with caplog.at_level(logging.WARNING, logger="scripts.cli.scan_utils"):
            tool_flags({"checkov": {"flags": ["--outp", "cli"]}}, "checkov")
        (message,) = [r.getMessage() for r in caplog.records]
        assert "`--outp cli`" in message and "`--output`" in message, message


class TestJmosOwnRunnersTakeNoAbbreviation:
    """argparse reads any unambiguous prefix of a long option by default, so
    `--outp x` would have moved yara's report. Stopped in the runner itself
    (`allow_abbrev=False`), not only in the flag filter."""

    @pytest.mark.parametrize(
        ("module", "required"),
        [
            ("yara_runner", ["--rules", "r", "--target", "t", "--output", "o"]),
            ("native_checks", ["--target", "t", "--output", "o"]),
        ],
        ids=["yara", "jmo-native"],
    )
    @pytest.mark.parametrize("abbreviation", ["--outp", "--targ", "--o"])
    def test_a_prefix_of_a_long_option_is_an_error(
        self, module, required, abbreviation
    ):
        parse = importlib.import_module(f"scripts.core.{module}")._parse_args
        parse(required)  # the control: the full spelling parses
        with pytest.raises(SystemExit):
            parse([*required, abbreviation, "x"])


# A `.cmd` launcher: cmd.exe re-reads its whole command line, so none of
# these survives in an argument (`.claude/rules/windows-encoding.rules.md`).
CMD_METACHARACTERS = "&|^<>%"
CHECKOV_CMD = "C:/Users/u/.jmo/tools/venvs/checkov/Scripts/checkov.cmd"


class TestALauncherGetsNoCmdMetacharacter:
    """On Windows checkov resolves to `checkov.cmd` and zap to `zap.bat`, and
    `CreateProcess` runs either through `cmd.exe /c`, which re-parses the
    command line: `--skip-check A|B` pipes into a command named `B`. No
    quoting survives it, so such a flag is refused. Decided by the resolved
    executable, not the tool's name."""

    def test_a_value_holding_one_is_dropped_with_its_flag(self, caplog):
        cfg = {"checkov": {"flags": ["--skip-check", "A|B", "--quiet"]}}
        with caplog.at_level(logging.WARNING, logger="scripts.cli.scan_utils"):
            kept = tool_flags(cfg, "checkov", executable=CHECKOV_CMD)

        assert kept == ["--quiet"]
        (message,) = [r.getMessage() for r in caplog.records]
        assert "`--skip-check A|B`" in message, message
        assert "cmd.exe" in message and "checkov.cmd" in message, message
        # checkov's own alternative for a list.
        assert "A,B" in message, message

    @pytest.mark.parametrize("char", list(CMD_METACHARACTERS))
    def test_each_metacharacter_is_refused(self, char):
        value = f"--skip-check=CKV_AWS_1{char}CKV_AWS_2"
        cfg = {"checkov": {"flags": [value, "--quiet"]}}
        assert tool_flags(cfg, "checkov", executable=CHECKOV_CMD) == ["--quiet"]

    @pytest.mark.parametrize("launcher", ["zap.bat", "CHECKOV.CMD"])
    def test_a_bat_or_an_upper_case_suffix_is_a_launcher_too(self, launcher):
        cfg = {"checkov": {"flags": ["--skip-check", "A|B"]}}
        assert tool_flags(cfg, "checkov", executable=f"C:/x/{launcher}") == []

    @pytest.mark.parametrize(
        "executable",
        [None, "/usr/local/bin/checkov", "C:/x/checkov.exe"],
        ids=["unknown", "posix", "exe"],
    )
    def test_an_executable_that_is_not_a_launcher_keeps_it(self, executable):
        """The control: without it, "refuse every `|`" passes the tests above."""
        cfg = {"checkov": {"flags": ["--skip-check", "A|B"]}}
        assert tool_flags(cfg, "checkov", executable=executable) == [
            "--skip-check",
            "A|B",
        ]

    @pytest.mark.parametrize(
        ("resolved", "flags"),
        [
            (CHECKOV_CMD, ("--quiet",)),
            ("/usr/local/bin/checkov", ("--skip-check", "A|B", "--quiet")),
        ],
        ids=["cmd", "posix"],
    )
    def test_the_scan_loop_hands_over_the_resolved_executable(
        self, tmp_path, monkeypatch, resolved, flags
    ):
        seen: list[tuple[str, ...]] = []

        def recording_builder(ctx: ScanContext) -> list:
            seen.append(ctx.flags)
            return []

        monkeypatch.setitem(
            DESCRIPTORS["checkov"].invocations, "repo", recording_builder
        )
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "main.tf").write_bytes(b'resource "aws_s3_bucket" "b" {}\n')
        out = tmp_path / "out"
        out.mkdir()

        tool_loop.run_tools(
            tools=["checkov"],
            target_type="repo",
            target=repo,
            target_label="t",
            out_dir=out,
            timeout=60,
            retries=0,
            per_tool_config={"checkov": {"flags": ["--skip-check", "A|B", "--quiet"]}},
            allow_missing_tools=False,
            runner_cls=lambda **kw: type("R", (), {"run_all_parallel": lambda s: []})(),
            find_tool_func=lambda name: resolved,
            repo_root=repo,
        )

        assert seen == [flags]

    @pytest.mark.parametrize(
        ("resolved", "history_flags"),
        [
            ("C:/x/trufflehog.cmd", ("--branch", "main")),
            (
                "/usr/local/bin/trufflehog",
                ("--since-commit", "a|b", "--branch", "main"),
            ),
        ],
        ids=["cmd", "posix"],
    )
    def test_the_history_run_gets_the_same_check(
        self, tmp_path, monkeypatch, resolved, history_flags
    ):
        """`history_flags` are filtered by their own call: both must be
        handed the executable."""
        seen: list[tuple[str, ...]] = []

        def recording_builder(ctx: ScanContext) -> list:
            seen.append(ctx.history_flags)
            return []

        monkeypatch.setitem(
            DESCRIPTORS["trufflehog"].invocations, "repo", recording_builder
        )
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "a.py").write_bytes(b"x = 1\n")
        out = tmp_path / "out"
        out.mkdir()

        tool_loop.run_tools(
            tools=["trufflehog"],
            target_type="repo",
            target=repo,
            target_label="t",
            out_dir=out,
            timeout=60,
            retries=0,
            per_tool_config={
                "trufflehog": {
                    "history_flags": ["--since-commit", "a|b", "--branch", "main"]
                }
            },
            allow_missing_tools=False,
            runner_cls=lambda **kw: type("R", (), {"run_all_parallel": lambda s: []})(),
            find_tool_func=lambda name: resolved,
            repo_root=repo,
        )

        assert seen == [history_flags]


class TestTimeoutFloorReachesEveryTargetType:
    """The floor lived in repository_scanner, so only repo scans honoured it."""

    def test_floor_raises_a_low_scan_default(self):
        """`zap` needs 900 s and also runs on `url` targets.

        Measured before consolidation: a URL scan at the (then `balanced`
        profile's, now top-level) 600 s default gave zap **300 s short, a third
        of its budget** -- while the identical tool on a repository target got
        900 s, because only `repository_scanner`'s copy of this helper applied
        the floor.
        """
        assert TOOL_TIMEOUT_DEFAULTS["zap"] == 900
        assert tool_timeout({}, "zap", 600) == 900

    def test_semgrep_carries_a_floor_above_a_low_scan_default(self):
        """#1204: semgrep had no floor, so it took the scan default.

        Its cost is its RULE COUNT, not the tree it walks -- it restricts itself
        to git-tracked files, so the vendored-directory exclusions #1080 added
        cannot move its number. Measured on this repository twice, same 541
        tracked files and the same 2,930 rules resolved from `--config auto`:
        **409.8 s** and, in #1204, **583 s**. 42% apart on one machine.

        The values are spelled out rather than read from `jmo.yml`: a guard that
        derives its expectation from the thing it guards cannot fail when that
        thing changes (#1061). 300/500/600/900 are the four defaults v1's
        profiles shipped; v2.0.0's top-level default is 600.
        """
        assert TOOL_TIMEOUT_DEFAULTS["semgrep"] == 900
        for scan_default in (300, 500, 600, 900):
            assert tool_timeout({}, "semgrep", scan_default) == 900

    def test_a_generous_scan_default_is_not_lowered(self):
        assert tool_timeout({}, "zap", 1800) == 1800

    def test_explicit_per_tool_timeout_wins_outright(self):
        """An operator who names a number gets it, floor or not."""
        assert tool_timeout({"zap": {"timeout": 120}}, "zap", 600) == 120

    def test_tools_without_a_floor_get_the_default(self):
        assert "trivy" not in TOOL_TIMEOUT_DEFAULTS
        assert tool_timeout({}, "trivy", 600) == 600

    @pytest.mark.parametrize("junk", [None, "600", 0, -1])
    def test_junk_override_falls_through_to_the_default(self, junk):
        assert tool_timeout({"trivy": {"timeout": junk}}, "trivy", 600) == 600


def _is_delegation_to(node: ast.FunctionDef, callee: str) -> bool:
    """True when the body is exactly `return <callee>(...)`, docstring aside.

    Asserted as the **positive shape** rather than as "does not mention
    per_tool_config". The first version of this guard excluded `ast.Return`
    nodes -- so that the legitimate `return tool_flags(per_tool_config, tool)`
    would not trip it -- and mutation testing walked straight through that hole
    with a one-line inline copy hidden inside a return:

        return [str(f) for f in per_tool_config.get(tool, {}).get("flags", [])]

    A guard written around the shape the bug had last time gets walked around.
    Requiring delegation, rather than forbidding one spelling of not-delegating,
    has no such gap.
    """
    body = [
        stmt
        for stmt in node.body
        if not (
            isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Constant)
            and isinstance(stmt.value.value, str)
        )
    ]
    if len(body) != 1 or not isinstance(body[0], ast.Return):
        return False
    value = body[0].value
    return (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id == callee
    )


def _scan_job_modules() -> list[Path]:
    return sorted(SCAN_JOBS.glob("*_scanner.py"))


def test_no_scanner_reimplements_the_helpers() -> None:
    """These may delegate, never re-derive.

    Asserted as a **property of the body** rather than by naming the five
    scanners: any `get_tool_flags` / `get_tool_timeout` that reads
    `per_tool_config` directly has grown its own copy again.

    This is the shape that caused the bug. Five identical `get_tool_flags`
    copies meant a filter had five homes and got none; five `get_tool_timeout`
    copies meant the slow-tool floor lived in exactly one and silently did not
    apply to the other four target types. Same family as #808 and the dead
    `_iter_*` helpers.
    """
    offenders: list[str] = []
    delegates_to = {"get_tool_flags": "tool_flags", "get_tool_timeout": "tool_timeout"}

    jobs = _scan_job_modules()
    assert len(jobs) >= 6, f"found only {jobs}; this guard may cover nothing"
    for path in jobs:
        tree = ast.parse(path.read_bytes().decode("utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name in delegates_to:
                if not _is_delegation_to(node, delegates_to[node.name]):
                    offenders.append(f"{path.name}:{node.lineno} {node.name}")

    assert not offenders, (
        "these re-derive per-tool config instead of delegating to "
        "scan_utils.tool_flags / scan_utils.tool_timeout:\n  " + "\n  ".join(offenders)
    )

    # Since Phase 3 every job runs its tools through the one loop, so the copies
    # have one place to come back: assert that place uses both helpers.
    loop = ast.parse((SCAN_JOBS / "tool_loop.py").read_bytes().decode("utf-8"))
    called = {
        node.func.id
        for node in ast.walk(loop)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert {"tool_flags", "tool_timeout"} <= called, called


class TestShippedFlagsAreFlagsTheToolActuallyHas:
    """#1223: `jmo.yml` shipped kubescape `--silent`, which kubescape rejects.

    `per_tool.<tool>.flags` is spliced straight into argv. An **unknown** flag
    is a different failure from #822's wrong-value one and just as total: the
    tool exits before scanning, writes no output file, and JMo reports
    `findings are MISSING` -- which reads identically to a tool that ran and
    found nothing.

    Measured end to end, same command and same 4.0.13 binary, only the flag
    differing: `kubescape.json` **not written / 0 findings** with `--silent`,
    **179,810 bytes / 51 findings** without.

    **This shape has recurred four times in this repository**, which is why
    the guard is a table rather than one assertion. Three were on tools v2.0.0
    removed -- trivy-rbac `--scanners` (#1206), prowler `--quiet`, kubescape
    `--silent` (#1223) -- so their entries went with them. The fourth is on a
    tool that stays:

    - `yara` shipped `--max-rules-per-file=500`, which is not a yara option
      (recorded in `jmo.yml`'s own comment on the yara entry).

    What this guard is NOT: proof that a flag is valid. Only running the binary
    shows that, and the suite mocks `subprocess`. It is a memory of the ones
    the project has already paid for, so the next cannot be the *same* one.
    """

    # (tool, flag) -> why the tool rejects it. Spelled out rather than derived:
    # a guard that reads its expectation from the file it guards cannot fail
    # when that file changes (#1061).
    REJECTED_FLAGS: dict[tuple[str, str], str] = {
        ("yara", "--max-rules-per-file=500"): (
            "not a yara option: v4.5.8 defines `max-rules` and "
            "`max-strings-per-rule` and nothing of that name, so the scanner "
            "would be rejected on an unknown option"
        ),
    }

    @staticmethod
    def _jmo_yml() -> Path:
        return Path(__file__).resolve().parents[2] / "jmo.yml"

    @classmethod
    def _shipped_per_tool_flags(cls) -> dict[str, list[str]]:
        """{tool: flags} for the shipped jmo.yml's top-level `per_tool`."""
        import yaml

        data = yaml.safe_load(cls._jmo_yml().read_text(encoding="utf-8"))
        out: dict[str, list[str]] = {}
        for tool, entry in (data.get("per_tool") or {}).items():
            flags = (entry or {}).get("flags")
            if isinstance(flags, list):
                out[str(tool)] = [str(f) for f in flags]
        return out

    def test_the_extractor_actually_finds_the_shipped_flags(self):
        """Meta-guard: an extractor that silently finds nothing passes every
        assertion built on it.

        Checked against the product's own loader, an independent reading of
        the same file, rather than against a count.
        """
        from scripts.core.config import load_config

        shipped = self._shipped_per_tool_flags()
        loaded = load_config(str(self._jmo_yml())).per_tool
        assert shipped == {
            tool: entry["flags"]
            for tool, entry in loaded.items()
            if isinstance((entry or {}).get("flags"), list)
        }
        assert "trivy" in shipped, "trivy carries flags in jmo.yml"

    def test_jmo_yml_ships_no_flag_its_tool_rejects(self):
        shipped = self._shipped_per_tool_flags()

        offences = [
            f"per_tool.{tool} passes {flag!r} -- {why}"
            for tool, flags in sorted(shipped.items())
            for (bad_tool, flag), why in self.REJECTED_FLAGS.items()
            if tool == bad_tool and flag in flags
        ]

        assert not offences, "jmo.yml ships flags the tool rejects:\n  " + "\n  ".join(
            offences
        )
