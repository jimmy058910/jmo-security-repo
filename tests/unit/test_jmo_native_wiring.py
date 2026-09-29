"""jmo-native wired as a descriptor row (v2.0.0 Phase 4, PR N, task N1b).

jmo-native is JMo's own check pack (`scripts/core/native_checks.py`): six
checks over Next.js, Supabase and Firebase code, written as SARIF, with no rule
engine. The row runs it on the interpreter JMo runs on, as yara's row runs
`yara_runner`, and unlike yara it ships inside JMo: no package, no rule bundle,
no `versions.yaml` pin, nothing for `jmo tools install` or `update` to do.

Nothing here is `requires_tools`, the end-to-end scan included: the row needs
nothing installed, so every CI shard runs it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from scripts.cli import jmo
from scripts.cli.scan_jobs import tool_loop
from scripts.cli.scan_utils import tool_exclusion_flags
from scripts.cli.tool_commands import cmd_tools_install, cmd_tools_update
from scripts.cli.tool_installer import ToolInstaller
from scripts.cli.tool_manager import ToolManager
from scripts.core import native_checks
from scripts.core.install_config import ISOLATED_TOOLS
from scripts.core.scan_timings import SKIP_REASONS, Reason
from scripts.core.tool_descriptors import (
    DESCRIPTORS,
    VENDORED_DIRS,
    ExclusionStyle,
    ScanContext,
)
from scripts.core.tool_registry import BUILTIN_TOOLS, ToolRegistry
from scripts.core.tool_utils import find_tool
from tests.unit.test_native_checks import FIXTURE, _readme_expected_triples

TOOL = "jmo-native"


class TestTheRow:
    def test_it_runs_the_runner_on_the_given_interpreter(self, tmp_path):
        d = DESCRIPTORS[TOOL]
        ctx = ScanContext(
            tool=TOOL,
            target_type="repo",
            target=tmp_path,
            out_dir=tmp_path / "out",
            binary="PY",
            flags=("--flag",),
            exclusion_args=("--exclude-dir=results",),
        )

        [inv] = d.invocations["repo"](ctx)

        assert inv.command == (
            "PY",
            "-m",
            "scripts.core.native_checks",
            "--target",
            str(tmp_path),
            "--output",
            str(ctx.output),
            "--exclude-dir=results",
            "--flag",
        )
        assert inv.output_file == ctx.output
        # The runner writes --output itself; 2 is "did not scan".
        assert inv.capture_stdout is False
        assert inv.ok_return_codes == (0, 1)

    def test_it_reads_repositories_only(self):
        assert DESCRIPTORS[TOOL].target_types == {"repo", "gitlab"}

    def test_its_empty_result_is_an_empty_sarif_document(self):
        assert DESCRIPTORS[TOOL].stub == {"version": "2.1.0", "runs": []}

    def test_the_runner_accepts_the_exclusions_the_row_renders(self):
        """INLINE, `--exclude-dir=NAME`: what yara's row passes yara_runner.
        The runner prunes VENDORED_DIRS itself, so they are redundant there
        but harmless; the results directory is the one that matters."""
        d = DESCRIPTORS[TOOL]
        assert (d.exclusion_style, d.exclusion_flag) == (
            ExclusionStyle.INLINE,
            "--exclude-dir",
        )
        rendered = tool_exclusion_flags(TOOL, results_dir_name="results")

        args = native_checks._parse_args(["--target", ".", "--output", "o", *rendered])

        assert args.exclude_dir == [*VENDORED_DIRS, "results"]

    def test_the_version_probe_reads_the_runners_own_version(self):
        probe = DESCRIPTORS[TOOL].version_probe
        assert probe.command == [
            sys.executable,
            "-m",
            "scripts.core.native_checks",
            "--version",
        ]
        match = probe.pattern.search(f"jmo-native {native_checks.JMO_VERSION}\n")
        assert match is not None
        assert match.group(1) == native_checks.JMO_VERSION

    def test_it_joins_no_policys_tool_list(self):
        """Ruling 71: zero-secrets included. A policy that names tools names
        them in its Rego; none names this one."""
        policies = Path(__file__).resolve().parents[2] / "policies"
        rego = list(policies.rglob("*.rego"))
        assert rego
        assert not [p for p in rego if TOOL.encode() in p.read_bytes()]


# --- the trigger (Ruling 68) --------------------------------------------------

# One file each; the content is what the runner would report if it read the
# file, so each case also says whether the runner reads it.
_LLM = b"const c = new OpenAI({ dangerouslyAllowBrowser: true });\n"
_ENV = b"NEXT_PUBLIC_STRIPE_SECRET_KEY=placeholder\n"
_RULES = b"allow read, write: if true;\n"
_SQL = b"create table notes (id int);\n"

READ = [
    *[(f"app/page{suffix}", _LLM) for suffix in native_checks.CODE_SUFFIXES],
    *[(name, _RULES) for name in native_checks.RULES_FILE_NAMES],
    (".env", _ENV),
    (".env.local", _ENV),
    (".env.example", _ENV),
    ("config/prod.env", _ENV),
    ("supabase/migrations/20260101000000_init.sql", _SQL),
    # Code beside the migrations is still code.
    ("supabase/migrations/seed.ts", _LLM),
]
NOT_READ = [
    ("lib.py", _LLM),
    ("README.md", _ENV),
    ("firebase.json", _RULES),
    ("db/schema.sql", _SQL),
    # A nested app's migrations: the runner reads the root's only
    # (docs/KNOWN_LIMITATIONS.md).
    ("apps/web/supabase/migrations/1.sql", _SQL),
    # Next.js's build cache, which the runner prunes.
    (".next/static/chunk.js", _LLM),
]


def _trigger(repo: Path) -> Reason | None:
    ctx = ScanContext(
        tool=TOOL,
        target_type="repo",
        target=repo,
        out_dir=repo.parent / "out",
        iter_files=lambda: tool_loop.iter_repo_files(repo),
    )
    trigger = DESCRIPTORS[TOOL].trigger
    assert trigger is not None
    return trigger(ctx)


def _plant(repo: Path, rel: str, body: bytes) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)


class TestTrigger:
    def test_the_reason_says_what_the_pack_reads(self):
        reason = Reason.NO_WEB_APP_FILES
        assert reason in SKIP_REASONS
        for kind in ("JS/TS", ".env", "Firebase rules", "Supabase migrations"):
            assert kind in reason.value

    @pytest.mark.parametrize(("rel", "body"), READ)
    def test_it_runs_on_each_kind_of_file_the_pack_reads(self, tmp_path, rel, body):
        repo = tmp_path / "repo"
        _plant(repo, rel, body)
        assert _trigger(repo) is None

    @pytest.mark.parametrize(("rel", "body"), NOT_READ)
    def test_it_skips_a_repository_with_nothing_the_pack_reads(
        self, tmp_path, rel, body
    ):
        repo = tmp_path / "repo"
        _plant(repo, rel, body)
        assert _trigger(repo) is Reason.NO_WEB_APP_FILES

    @pytest.mark.parametrize(("rel", "body"), READ + NOT_READ)
    def test_the_trigger_and_the_runner_agree(self, tmp_path, rel, body):
        """The trigger imports the runner's constants rather than copying them,
        and this is what fails if the two ever diverge: on every case, the row
        runs exactly when the runner would report the file's content. A skip
        the runner disagrees with drops findings; a run it disagrees with is
        a row reading `ran` that looked at nothing."""
        repo = tmp_path / "repo"
        _plant(repo, rel, body)

        rc = native_checks.main(
            ["--target", str(repo), "--output", str(tmp_path / "o.sarif")]
        )

        assert rc in (0, 1)
        assert (_trigger(repo) is None) == (rc == 1), rel


# --- built in (Ruling 69) -----------------------------------------------------


class TestBuiltIn:
    def test_it_is_the_one_built_in_tool(self):
        assert frozenset({TOOL}) == BUILTIN_TOOLS

    def test_its_binary_is_this_interpreter_wherever_home_is(
        self, tmp_path, monkeypatch
    ):
        """No `~/.jmo/bin`, nothing on PATH: it still resolves, because it
        ships in the package JMo runs from."""
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setenv("PATH", str(tmp_path))
        assert find_tool(TOOL) == sys.executable

    def test_tools_check_reads_ok_at_jmos_version(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        status = ToolManager().check_tool(TOOL)

        assert status.installed
        assert status.execution_ready
        assert status.installed_version == native_checks.JMO_VERSION
        assert status.expected_version == native_checks.JMO_VERSION
        assert not status.is_outdated
        assert status.status_text == "OK"

    def test_nothing_pins_or_installs_it(self):
        """No versions.yaml entry, so `jmo tools uninstall --all` (which walks
        the registry) and `jmo tools list` never see it, and no isolated venv,
        so `jmo tools clean` has nothing of its to remove."""
        assert ToolRegistry().get_tool(TOOL) is None
        assert TOOL not in ISOLATED_TOOLS

    @pytest.mark.parametrize("force", [False, True])
    def test_install_says_it_is_built_in(self, capsys, force):
        args = argparse.Namespace(
            tools=[TOOL], force=force, yes=True, dry_run=False, print_script=False
        )
        with patch("scripts.cli.tool_installer.ToolInstaller") as installer:
            rc = cmd_tools_install(args)

        out = capsys.readouterr().out
        assert rc == 0
        assert "built into JMo" in out
        assert "not found" not in out.lower()
        installer.assert_not_called()

    def test_update_says_it_is_built_in(self, capsys):
        args = argparse.Namespace(tools=[TOOL], critical_only=False, yes=True)
        with patch("scripts.cli.tool_installer.ToolInstaller") as installer:
            rc = cmd_tools_update(args)

        out = capsys.readouterr().out
        assert rc == 0
        assert "built into JMo" in out
        installer.assert_not_called()

    def test_the_installer_itself_downloads_nothing_for_it(self):
        """Every other entry point (the wizard, the scan-time auto-install)
        reaches `install_tool`; with `force` it would have read versions.yaml
        and failed `Unknown tool`."""
        installer = ToolInstaller()
        installer._install_special = MagicMock()  # type: ignore[method-assign]

        result = installer.install_tool(TOOL, force=True)

        assert result.success
        assert result.method == "builtin"
        assert "built into jmo" in result.message.lower()
        installer._install_special.assert_not_called()


# --- end to end through `jmo scan` and `jmo report` (Ruling 66) ---------------


@pytest.fixture
def scan(tmp_path: Path, monkeypatch):
    """Run `jmo scan --tools jmo-native` then `jmo report` on a repository and
    return findings.json's findings and the scan's rows.

    `cmd_scan` bumps a counter in `~/.jmo/config.yml`, so `Path.home` moves;
    that also proves the row needs nothing under `~/.jmo`."""
    cfg = tmp_path / "jmo.yml"
    cfg.write_bytes(yaml.safe_dump({"outputs": ["json"]}).encode())
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CI", "true")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

    def run(repo: Path) -> tuple[list[dict], dict[str, dict]]:
        results = tmp_path / f"results-{repo.name}"
        argv = [
            "jmo",
            "scan",
            "--repo",
            str(repo),
            "--tools",
            TOOL,
            "--results-dir",
            str(results),
            "--config",
            str(cfg),
            "--history-db",
            str(tmp_path / "history.db"),
        ]
        with patch.object(sys, "argv", argv):
            assert jmo.cmd_scan(jmo.parse_args()) == 0
        with patch.object(
            sys, "argv", ["jmo", "report", str(results), "--config", str(cfg)]
        ):
            assert jmo.cmd_report(jmo.parse_args()) == 0
        findings = json.loads((results / "summaries" / "findings.json").read_bytes())
        meta = json.loads((results / ".scan_metadata.json").read_bytes())
        return findings["findings"], {r["tool"]: r for r in meta["tool_runs"]}

    return run


def test_the_tracked_fixture_through_jmo_scan(scan) -> None:
    findings, rows = scan(FIXTURE)

    assert rows[TOOL]["state"] == "ran", rows[TOOL]
    triples = sorted(
        (f["ruleId"], f["location"]["path"], f["location"]["startLine"])
        for f in findings
    )
    assert triples == sorted(_readme_expected_triples())

    for f in findings:
        meta = native_checks.RULES[f["ruleId"]]
        assert f["tool"]["name"] == TOOL
        assert f["severity"] == meta.severity, f["ruleId"]
        if meta.cwe is None:
            assert "cwe" not in f["risk"], f["ruleId"]
        else:
            assert f["risk"]["cwe"] == [meta.cwe], f["ruleId"]
    assert sorted(f["severity"] for f in findings) == ["HIGH"] * 7 + ["LOW"]

    # The four negatives, by file and rule rather than by count.
    by_path = {}
    for f in findings:
        by_path.setdefault(f["location"]["path"], []).append(f["ruleId"])
    assert "app/api/admin/route.ts" not in by_path
    assert "storage.rules" not in by_path
    assert by_path["src/lib/supabase.ts"] == [native_checks.RULE_SERVICE_ROLE]
    assert not any(
        f["location"]["path"].endswith(".sql") and f["location"]["startLine"] < 5
        for f in findings
    ), "the `profiles` table (lines 2-4) has RLS and a policy"


def test_a_repository_with_nothing_it_reads_is_skipped(tmp_path, scan) -> None:
    repo = tmp_path / "service"
    _plant(repo, "main.py", b"print('hello')\n")

    findings, rows = scan(repo)

    assert rows[TOOL]["state"] == "skipped"
    assert rows[TOOL]["reason"] == Reason.NO_WEB_APP_FILES.value
    assert findings == []
