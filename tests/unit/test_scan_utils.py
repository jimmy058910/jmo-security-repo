"""Unit tests for scan_utils.py.

Tests cover:
- tool_exists() with found and missing tools
- write_stub() for all supported tool formats (JSON and NDJSON)
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from scripts.cli.scan_utils import TOOL_INSTALL_HINTS, tool_exists, write_stub

# ========== Category 1: tool_exists() Tests ==========


def test_tool_exists_found():
    """Test tool_exists returns True when the resolver finds the tool."""
    with patch("scripts.core.tool_utils.find_tool") as mock_find:
        mock_find.return_value = "/usr/bin/trivy"

        result = tool_exists("trivy")

        assert result is True
        mock_find.assert_called_once_with("trivy")


def test_tool_exists_not_found_with_hint():
    """Test tool_exists returns False and logs hint when tool not found.

    Patches `find_tool`, the seam `tool_exists` actually depends on (#1105).
    This used to patch `shutil.which`, but `find_tool` also searches the
    isolated venvs, `~/.jmo/bin/` and the interpreter's own `Scripts/`, so on
    any machine with a semgrep isolated venv the test failed with
    `assert True is False` while CI stayed green only because semgrep is
    absent there. A test that inherits its precondition from the host is not
    stating one.
    """
    with (
        patch("scripts.core.tool_utils.find_tool") as mock_find,
        patch("logging.getLogger") as mock_logger,
    ):
        mock_find.return_value = None
        mock_log = MagicMock()
        mock_logger.return_value = mock_log

        result = tool_exists("semgrep")

        assert result is False
        mock_find.assert_called_once_with("semgrep")

        # Verify error logged with installation hint
        mock_log.error.assert_called_once()
        error_msg = mock_log.error.call_args[0][0]
        assert "semgrep" in error_msg
        assert "not found" in error_msg
        assert "Install" in error_msg or "pip install semgrep" in error_msg


def test_tool_exists_not_found_without_hint():
    """Test tool_exists handles unknown tool without specific hint."""
    with patch("shutil.which") as mock_which, patch("logging.getLogger") as mock_logger:
        mock_which.return_value = None
        mock_log = MagicMock()
        mock_logger.return_value = mock_log

        result = tool_exists("unknown-tool")

        assert result is False

        # Should log generic hint
        mock_log.error.assert_called_once()
        error_msg = mock_log.error.call_args[0][0]
        assert "unknown-tool" in error_msg
        assert "Install unknown-tool" in error_msg


# ========== Category 2: write_stub() Tests - JSON Tools ==========


def test_write_stub_trufflehog(tmp_path):
    """Test write_stub creates correct empty stub for trufflehog."""
    out_path = tmp_path / "trufflehog.json"

    write_stub("trufflehog", out_path)

    assert out_path.exists()
    content = json.loads(out_path.read_text())
    assert content == []


def test_write_stub_semgrep(tmp_path):
    """Test write_stub creates correct empty stub for semgrep."""
    out_path = tmp_path / "semgrep.json"

    write_stub("semgrep", out_path)

    assert out_path.exists()
    content = json.loads(out_path.read_text())
    assert content == {"results": []}


def test_write_stub_trivy(tmp_path):
    """Test write_stub creates correct empty stub for trivy."""
    out_path = tmp_path / "trivy.json"

    write_stub("trivy", out_path)

    assert out_path.exists()
    content = json.loads(out_path.read_text())
    assert content == {"Results": []}


def test_write_stub_checkov(tmp_path):
    """Test write_stub creates correct empty stub for checkov."""
    out_path = tmp_path / "checkov.json"

    write_stub("checkov", out_path)

    assert out_path.exists()
    content = json.loads(out_path.read_text())
    assert content == {"results": {"failed_checks": []}}


def test_write_stub_syft(tmp_path):
    """Test write_stub creates correct empty stub for syft."""
    out_path = tmp_path / "syft.json"

    write_stub("syft", out_path)

    assert out_path.exists()
    content = json.loads(out_path.read_text())
    assert content == {"artifacts": []}


def test_write_stub_bandit(tmp_path):
    """Test write_stub creates correct empty stub for bandit."""
    out_path = tmp_path / "bandit.json"

    write_stub("bandit", out_path)

    assert out_path.exists()
    content = json.loads(out_path.read_text())
    assert content == {"results": []}


def test_write_stub_zap(tmp_path):
    """Test write_stub creates correct empty stub for ZAP."""
    out_path = tmp_path / "zap.json"

    write_stub("zap", out_path)

    assert out_path.exists()
    content = json.loads(out_path.read_text())
    assert content == {"site": []}


def test_write_stub_aflplusplus(tmp_path):
    """Test write_stub creates correct empty stub for AFL++."""
    out_path = tmp_path / "afl++.json"

    write_stub("afl++", out_path)

    assert out_path.exists()
    content = json.loads(out_path.read_text())
    assert content == {"crashes": []}


def test_write_stub_noseyparker(tmp_path):
    """Test write_stub creates correct empty stub for noseyparker."""
    out_path = tmp_path / "noseyparker.json"

    write_stub("noseyparker", out_path)

    assert out_path.exists()
    content = json.loads(out_path.read_text())
    assert content == {"matches": []}


def test_write_stub_grype(tmp_path):
    """Test write_stub creates correct empty stub for grype.

    Bug #2 fix: grype was missing from stub dictionary, causing
    grype failures to produce {} instead of {"matches": []}.
    """
    out_path = tmp_path / "grype.json"

    write_stub("grype", out_path)

    assert out_path.exists()
    content = json.loads(out_path.read_text())
    assert content == {"matches": []}


# ========== Category 3: write_stub() Tests - NDJSON Tools ==========


def test_write_stub_nuclei_ndjson(tmp_path):
    """Test write_stub creates empty string for NDJSON tools (nuclei)."""
    out_path = tmp_path / "nuclei.json"

    write_stub("nuclei", out_path)

    assert out_path.exists()
    content = out_path.read_text()
    assert content == ""  # Empty string for NDJSON


# ========== Category 4: write_stub() Tests - Unknown Tools ==========


def test_write_stub_unknown_tool(tmp_path):
    """Test write_stub creates empty dict for unknown tools."""
    out_path = tmp_path / "unknown.json"

    write_stub("unknown-tool", out_path)

    assert out_path.exists()
    content = json.loads(out_path.read_text())
    assert content == {}


def test_write_stub_creates_parent_directories(tmp_path):
    """Test write_stub creates parent directories if missing."""
    out_path = tmp_path / "nested" / "dirs" / "tool.json"

    write_stub("trivy", out_path)

    assert out_path.exists()
    assert out_path.parent.exists()


# ========== Category 10: TOOL_INSTALL_HINTS Coverage ==========


def test_tool_install_hints_complete():
    """Test TOOL_INSTALL_HINTS contains all supported tools."""
    expected_tools = [
        "trufflehog",
        "semgrep",
        "trivy",
        "syft",
        "checkov",
        "hadolint",
        "nuclei",
        "bandit",
        "noseyparker",
        "zap",
        "falco",
        "afl++",
    ]

    for tool in expected_tools:
        assert tool in TOOL_INSTALL_HINTS
        hint = TOOL_INSTALL_HINTS[tool]
        assert "Install" in hint or "see" in hint


class TestFilterTrivyFlags:
    """jmo.yml configures flags per tool; trivy's flag surface is per subcommand.

    All four shipped profiles set --no-progress, which `trivy config` rejects
    fatally at argument parsing - so every IaC scan produced 0 findings where
    the same file and tool yield 12 (#804).
    """

    def test_no_progress_is_dropped_for_trivy_config(self):
        from scripts.cli.scan_utils import filter_trivy_flags

        assert filter_trivy_flags("config", ["--no-progress"]) == []

    def test_other_subcommands_keep_it(self):
        from scripts.cli.scan_utils import filter_trivy_flags

        for subcommand in ("fs", "image", "k8s"):
            assert filter_trivy_flags(subcommand, ["--no-progress"]) == [
                "--no-progress"
            ]

    def test_supported_flags_survive_and_keep_their_values(self):
        """--scanners is accepted by every subcommand, including config, and
        takes a value - dropping a flag must never orphan its argument."""
        from scripts.cli.scan_utils import filter_trivy_flags

        flags = ["--no-progress", "--scanners", "vuln,secret,misconfig"]

        assert filter_trivy_flags("config", flags) == [
            "--scanners",
            "vuln,secret,misconfig",
        ]

    def test_the_drop_is_announced(self, caplog):
        import logging

        from scripts.cli.scan_utils import filter_trivy_flags

        with caplog.at_level(logging.WARNING):
            filter_trivy_flags("config", ["--no-progress"])

        assert "--no-progress" in caplog.text

    def test_unknown_subcommand_is_left_alone(self):
        from scripts.cli.scan_utils import filter_trivy_flags

        assert filter_trivy_flags("rootfs", ["--no-progress"]) == ["--no-progress"]


class TestToolExclusionFlags:
    """`.horusec/` must not be walked by the tools that run beside horusec.

    horusec stages a copy of the entire repository into `<repo>/.horusec/<uuid>`
    and deletes it as it finishes, while every other scanner is still walking
    the tree - so a concurrent scanner records an error, not a skip. Measured on
    juice-shop (Windows, deep): 346 `No such file or directory` errors in
    semgrep-secrets alone (#1132).
    """

    def test_semgrep_uses_a_repeated_exclude_equals(self):
        from scripts.cli.scan_utils import tool_exclusion_flags

        assert tool_exclusion_flags("semgrep") == ["--exclude=.horusec"]

    def test_semgrep_secrets_is_covered_too(self):
        """The 346 measured errors came from semgrep-secrets, not from semgrep.

        They are separate entries in the profile and separate command builders,
        so covering only the tool the flag is named after would leave the
        measured defect in place.
        """
        from scripts.cli.scan_utils import tool_exclusion_flags

        assert tool_exclusion_flags("semgrep-secrets") == ["--exclude=.horusec"]

    def test_trivy_puts_the_value_in_its_own_token(self):
        from scripts.cli.scan_utils import tool_exclusion_flags

        assert tool_exclusion_flags("trivy") == ["--skip-dirs", ".horusec"]

    def test_trivy_rbac_is_covered_too(self):
        from scripts.cli.scan_utils import tool_exclusion_flags

        assert tool_exclusion_flags("trivy-rbac") == ["--skip-dirs", ".horusec"]

    def test_bandit_resends_upstreams_defaults(self):
        """bandit's -x REPLACES its defaults rather than adding to them.

        Measured on bandit 1.9.2 against a tree holding `.tox/vendored.py` and
        `.horusec/staged.py`: with no -x, bandit reports the `.horusec` file and
        skips the `.tox` one; with `-x .horusec` the two swap places. So
        excluding one directory must not quietly start scanning nine others -
        `.tox`, `.eggs` and `*.egg` hold vendored third-party code, and the
        regression would surface as a flood of findings the user does not own.

        The expected value is spelled out rather than read from
        BANDIT_DEFAULT_EXCLUDED_PATHS: a guard that takes its expectation from
        the constant it guards cannot fail when that constant empties (#1061).
        """
        from scripts.cli.scan_utils import tool_exclusion_flags

        assert tool_exclusion_flags("bandit") == [
            "-x",
            ".svn,CVS,.bzr,.hg,.git,__pycache__,.tox,.eggs,*.egg,.horusec",
        ]

    def test_bandit_sends_exactly_one_value_token(self):
        """`-x` takes a single comma-separated argument.

        A second bare token after it would be parsed as a scan *target*, which
        is the same shape as the trivy bug in filter_trivy_flags' docstring.
        """
        from scripts.cli.scan_utils import tool_exclusion_flags

        assert len(tool_exclusion_flags("bandit")) == 2

    def test_dependency_check_needs_an_ant_pattern(self):
        """ODC spells it `--exclude` too, but wants an Ant pattern.

        A bare `.horusec` is a gitignore-style glob that semgrep matches at any
        depth; Ant does not, so ODC needs `**/.horusec/**`. Measured against
        dependency-check 12.1.0 on a tree with a real and a staged
        package.json: 2 dependencies without the flag, 1 with it, and the one
        kept is the real one. This is why the table stores a style per tool
        rather than deriving it from the flag name.
        """
        from scripts.cli.scan_utils import tool_exclusion_flags

        assert tool_exclusion_flags("dependency-check") == [
            "--exclude",
            "**/.horusec/**",
        ]

    def test_the_two_exclude_spellings_do_not_collide(self):
        """semgrep and dependency-check share a flag name and must not share a
        pattern - the bug this guards is one tool silently getting the other's
        form."""
        from scripts.cli.scan_utils import tool_exclusion_flags

        semgrep = tool_exclusion_flags("semgrep")
        odc = tool_exclusion_flags("dependency-check")

        # Both non-empty first: an absent table entry returns [], which would
        # satisfy a bare `!=` and make this guard pass for the wrong reason.
        assert semgrep and odc
        assert semgrep != odc

    def test_an_unmapped_tool_gets_nothing(self):
        """An unlisted tool must not be handed a flag it would reject.

        trivy and semgrep both fail fatally at argument parsing on an unknown
        flag, so silence is the only safe default for a tool whose exclusion
        spelling has not been measured against the real binary.
        """
        from scripts.cli.scan_utils import tool_exclusion_flags

        assert tool_exclusion_flags("trufflehog") == []
        assert tool_exclusion_flags("horusec") == []
        assert tool_exclusion_flags("gosec") == []


@pytest.mark.requires_tools
def test_bandit_upstream_defaults_have_not_drifted():
    """JMo copies bandit's default -x list; catch upstream changing it.

    This is a property of the installed binary rather than of our source, so it
    can only run where bandit exists - the nightly installs the real tools, and
    that is the environment this guard is for.
    """
    import re
    import subprocess

    from scripts.cli.scan_utils import BANDIT_DEFAULT_EXCLUDED_PATHS
    from scripts.core.tool_utils import find_tool

    bandit = find_tool("bandit")
    if not bandit:
        pytest.skip("bandit is not installed")

    help_text = subprocess.run(
        [bandit, "--help"], capture_output=True, text=True, timeout=60
    ).stdout
    match = re.search(
        r"-x EXCLUDED_PATHS.*?\(default:\s*([^)]+)\)", help_text, re.DOTALL
    )
    assert match, "could not find bandit's -x default in --help"

    upstream = {p.strip() for p in match.group(1).split(",") if p.strip()}
    missing = upstream - set(BANDIT_DEFAULT_EXCLUDED_PATHS)
    assert not missing, (
        "bandit's default excluded paths drifted; passing -x would stop "
        f"excluding {sorted(missing)}"
    )


class TestTruffleHogExcludePatterns:
    """#1134: TruffleHog walked `.git/` and `.jmo/` in filesystem mode.

    A secret reported at `.git/objects/03/f8eab...` names no commit and no
    source file, and the reflog's 40-hex commit ids trip keyword-plus-40-char
    detectors as Cloudflare tokens. `.jmo/history.db` stores the raw findings of
    every previous scan, so scanning it re-reports all of them.

    Measured across the 2026-09-02 dogfood: 41 findings under `.git/` and 394
    under `.jmo/` - the latter 51% of jmo-security-repo's 773.
    """

    def test_git_and_jmo_are_both_excluded(self):
        from scripts.cli.scan_utils import TRUFFLEHOG_EXCLUDE_PATTERNS

        assert TRUFFLEHOG_EXCLUDE_PATTERNS == (
            r"[\\/]\.git[\\/]",
            r"[\\/]\.jmo[\\/]",
        )

    def test_the_patterns_do_not_match_dot_github(self):
        """The separator class is load-bearing, not decoration.

        A bare `\\.git` is a substring match, so TruffleHog also skips
        `.github/workflows/*.yml` - measured against trufflehog 3.97.1 on a tree
        with a secret in each - and that is exactly where real deployment
        credentials live. This asserts the property (what the regex matches)
        rather than the spelling, so it still bites if someone rewrites the
        pattern a different way.
        """
        import re

        from scripts.cli.scan_utils import TRUFFLEHOG_EXCLUDE_PATTERNS

        keep = [
            "/repo/.github/workflows/deploy.yml",
            r"C:\repo\.github\workflows\deploy.yml",
            "/repo/src/.gitignore",
            "/repo/src/app.py",
        ]
        for path in keep:
            for pattern in TRUFFLEHOG_EXCLUDE_PATTERNS:
                assert not re.search(pattern, path), (
                    f"{pattern!r} would exclude {path!r}, which is not a VCS "
                    "internal or a JMo artifact"
                )

    def test_the_patterns_match_both_separators(self):
        """POSIX and Windows paths both have to be caught: the scan runs on
        whichever the host uses, and the dogfood measured these on Windows."""
        import re

        from scripts.cli.scan_utils import TRUFFLEHOG_EXCLUDE_PATTERNS

        drop = [
            "/repo/.git/logs/HEAD",
            r"C:\repo\.git\objects\03\f8eab",
            "/repo/.jmo/history.db",
            r"C:\repo\.jmo\history.db.snapshot-20260808",
        ]
        for path in drop:
            assert any(
                re.search(p, path) for p in TRUFFLEHOG_EXCLUDE_PATTERNS
            ), f"nothing excluded {path!r}"

    def test_the_exclude_file_is_written_with_lf(self, tmp_path):
        """TruffleHog splits the file on newlines, so a CRLF file would leave a
        trailing `\\r` inside each regex. `Path.write_text` would produce
        exactly that on Windows, which is why the writer uses `write_bytes`.
        """
        from scripts.cli.scan_utils import write_trufflehog_exclude_file

        path = write_trufflehog_exclude_file(tmp_path)

        raw = path.read_bytes()
        assert b"\r" not in raw
        assert raw.decode("utf-8").splitlines() == [
            r"[\\/]\.git[\\/]",
            r"[\\/]\.jmo[\\/]",
        ]

    def test_the_exclude_file_lands_beside_the_results(self, tmp_path):
        """It must not be a `.json`, or the report phase would try to parse it:
        `normalize_and_report` globs `*.json` in each target directory."""
        from scripts.cli.scan_utils import write_trufflehog_exclude_file

        path = write_trufflehog_exclude_file(tmp_path)

        assert path.parent == tmp_path
        assert path.suffix == ".txt"
