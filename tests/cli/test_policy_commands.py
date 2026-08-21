"""
Tests for policy_commands.py - Policy-as-Code CLI commands.

Coverage targets:
- get_builtin_policies_dir()
- get_user_policies_dir()
- discover_policies() with builtin and user policies
- cmd_policy_list() with no policies, builtin only, user only, both
- cmd_policy_validate() with valid/invalid policies
- cmd_policy_test() with passing/failing policies, missing files
- cmd_policy_show() with metadata and content display
- cmd_policy_install() with new install, existing policy, force flag
- cmd_policy() dispatcher
"""

import argparse
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.cli.policy_commands import (
    cmd_policy,
    cmd_policy_install,
    cmd_policy_list,
    cmd_policy_show,
    cmd_policy_test,
    cmd_policy_validate,
    discover_policies,
    get_builtin_policies_dir,
    get_user_policies_dir,
)

# =============================================================================
# Helper path functions tests
# =============================================================================


def test_get_builtin_policies_dir():
    """Test get_builtin_policies_dir returns correct path."""
    result = get_builtin_policies_dir()
    assert result.name == "builtin"
    assert result.parent.name == "policies"
    assert result.is_absolute()


def test_get_user_policies_dir():
    """Test get_user_policies_dir returns correct path."""
    result = get_user_policies_dir()
    assert result == Path.home() / ".jmo" / "policies"


# =============================================================================
# discover_policies() tests
# =============================================================================


def test_discover_policies_no_directories(tmp_path):
    """Test discover_policies when no policy directories exist."""
    # Mock directories to non-existent paths
    with (
        patch(
            "scripts.cli.policy_commands.get_builtin_policies_dir",
            return_value=tmp_path / "nonexistent-builtin",
        ),
        patch(
            "scripts.cli.policy_commands.get_user_policies_dir",
            return_value=tmp_path / "nonexistent-user",
        ),
    ):
        policies = discover_policies()
        assert policies == {}


def test_discover_policies_builtin_only(tmp_path):
    """Test discover_policies with only builtin policies."""
    builtin_dir = tmp_path / "builtin"
    builtin_dir.mkdir()

    # Create test policies
    (builtin_dir / "policy1.rego").write_text("package policy1")
    (builtin_dir / "policy2.rego").write_text("package policy2")

    with (
        patch(
            "scripts.cli.policy_commands.get_builtin_policies_dir",
            return_value=builtin_dir,
        ),
        patch(
            "scripts.cli.policy_commands.get_user_policies_dir",
            return_value=tmp_path / "nonexistent-user",
        ),
    ):
        policies = discover_policies()

        assert len(policies) == 2
        assert "policy1" in policies
        assert "policy2" in policies
        assert policies["policy1"] == builtin_dir / "policy1.rego"


def test_discover_policies_user_only(tmp_path):
    """Test discover_policies with only user policies."""
    user_dir = tmp_path / "user"
    user_dir.mkdir()

    # Create test policies
    (user_dir / "custom1.rego").write_text("package custom1")
    (user_dir / "custom2.rego").write_text("package custom2")

    with (
        patch(
            "scripts.cli.policy_commands.get_builtin_policies_dir",
            return_value=tmp_path / "nonexistent-builtin",
        ),
        patch(
            "scripts.cli.policy_commands.get_user_policies_dir", return_value=user_dir
        ),
    ):
        policies = discover_policies()

        assert len(policies) == 2
        assert "custom1" in policies
        assert "custom2" in policies
        assert policies["custom1"] == user_dir / "custom1.rego"


def test_discover_policies_user_overrides_builtin(tmp_path):
    """Test discover_policies where user policy overrides builtin."""
    builtin_dir = tmp_path / "builtin"
    builtin_dir.mkdir()
    (builtin_dir / "policy1.rego").write_text("package builtin_policy1")

    user_dir = tmp_path / "user"
    user_dir.mkdir()
    (user_dir / "policy1.rego").write_text("package user_policy1")

    with (
        patch(
            "scripts.cli.policy_commands.get_builtin_policies_dir",
            return_value=builtin_dir,
        ),
        patch(
            "scripts.cli.policy_commands.get_user_policies_dir", return_value=user_dir
        ),
    ):
        policies = discover_policies()

        assert len(policies) == 1
        assert "policy1" in policies
        # User policy should override builtin
        assert policies["policy1"] == user_dir / "policy1.rego"


# =============================================================================
# cmd_policy_list() tests
# =============================================================================


@pytest.fixture
def mock_policy_engine():
    """Create mock PolicyEngine."""
    mock_engine = MagicMock()
    mock_engine.get_metadata.return_value = {
        "version": "1.0.0",
        "description": "Test policy",
    }
    return mock_engine


def test_cmd_policy_list_no_policies(tmp_path, capsys):
    """Test cmd_policy_list when no policies exist."""
    builtin_dir = tmp_path / "builtin"
    user_dir = tmp_path / "user"

    with (
        patch(
            "scripts.cli.policy_commands.get_builtin_policies_dir",
            return_value=builtin_dir,
        ),
        patch(
            "scripts.cli.policy_commands.get_user_policies_dir", return_value=user_dir
        ),
        patch("scripts.cli.policy_commands.PolicyEngine"),
    ):
        rc = cmd_policy_list(argparse.Namespace())

        captured = capsys.readouterr()
        assert "No policies found" in captured.out
        assert str(builtin_dir) in captured.out
        assert str(user_dir) in captured.out
        assert rc == 0


def test_cmd_policy_list_builtin_only(tmp_path, capsys, mock_policy_engine):
    """Test cmd_policy_list with only builtin policies."""
    builtin_dir = tmp_path / "builtin"
    builtin_dir.mkdir()
    (builtin_dir / "policy1.rego").write_text("package policy1")

    user_dir = tmp_path / "user"

    with (
        patch(
            "scripts.cli.policy_commands.get_builtin_policies_dir",
            return_value=builtin_dir,
        ),
        patch(
            "scripts.cli.policy_commands.get_user_policies_dir", return_value=user_dir
        ),
        patch(
            "scripts.cli.policy_commands.PolicyEngine",
            return_value=mock_policy_engine,
        ),
    ):
        rc = cmd_policy_list(argparse.Namespace())

        captured = capsys.readouterr()
        assert "Built-in Policies (1)" in captured.out
        assert "policy1" in captured.out
        assert "Test policy" in captured.out
        assert rc == 0


def test_cmd_policy_list_user_only(tmp_path, capsys, mock_policy_engine):
    """Test cmd_policy_list with only user policies."""
    builtin_dir = tmp_path / "builtin"
    user_dir = tmp_path / "user"
    user_dir.mkdir()
    (user_dir / "custom1.rego").write_text("package custom1")

    with (
        patch(
            "scripts.cli.policy_commands.get_builtin_policies_dir",
            return_value=builtin_dir,
        ),
        patch(
            "scripts.cli.policy_commands.get_user_policies_dir", return_value=user_dir
        ),
        patch(
            "scripts.cli.policy_commands.PolicyEngine",
            return_value=mock_policy_engine,
        ),
    ):
        rc = cmd_policy_list(argparse.Namespace())

        captured = capsys.readouterr()
        assert "User Policies (1)" in captured.out
        assert "custom1" in captured.out
        assert rc == 0


def test_cmd_policy_list_both_builtin_and_user(tmp_path, capsys, mock_policy_engine):
    """Test cmd_policy_list with both builtin and user policies."""
    builtin_dir = tmp_path / "builtin"
    builtin_dir.mkdir()
    (builtin_dir / "policy1.rego").write_text("package policy1")

    user_dir = tmp_path / "user"
    user_dir.mkdir()
    (user_dir / "custom1.rego").write_text("package custom1")

    with (
        patch(
            "scripts.cli.policy_commands.get_builtin_policies_dir",
            return_value=builtin_dir,
        ),
        patch(
            "scripts.cli.policy_commands.get_user_policies_dir", return_value=user_dir
        ),
        patch(
            "scripts.cli.policy_commands.PolicyEngine",
            return_value=mock_policy_engine,
        ),
    ):
        rc = cmd_policy_list(argparse.Namespace())

        captured = capsys.readouterr()
        assert "Built-in Policies (1)" in captured.out
        assert "User Policies (1)" in captured.out
        assert "policy1" in captured.out
        assert "custom1" in captured.out
        assert "Total: 2 policies" in captured.out
        assert rc == 0


# =============================================================================
# cmd_policy_validate() tests
# =============================================================================


def test_cmd_policy_validate_policy_not_found(capsys):
    """Test cmd_policy_validate when policy doesn't exist."""
    args = argparse.Namespace(policy="nonexistent")

    with patch("scripts.cli.policy_commands.discover_policies", return_value={}):
        rc = cmd_policy_validate(args)

        assert (
            rc == 2
        )  # usage error, not a verdict: see docs/CLI_REFERENCE.md "Exit Codes" (#925)


def test_cmd_policy_validate_valid_policy(tmp_path, capsys):
    """Test cmd_policy_validate with valid policy."""
    policy_path = tmp_path / "valid.rego"
    policy_path.write_text("package valid")

    args = argparse.Namespace(policy="valid")

    mock_engine = MagicMock()
    mock_engine.validate_policy.return_value = (True, None)

    with (
        patch(
            "scripts.cli.policy_commands.discover_policies",
            return_value={"valid": policy_path},
        ),
        patch("scripts.cli.policy_commands.PolicyEngine", return_value=mock_engine),
    ):
        rc = cmd_policy_validate(args)

        captured = capsys.readouterr()
        assert "✅ Policy 'valid' is valid" in captured.out
        assert rc == 0


def test_cmd_policy_validate_invalid_policy(tmp_path, capsys):
    """Test cmd_policy_validate with invalid policy."""
    policy_path = tmp_path / "invalid.rego"
    policy_path.write_text("invalid syntax")

    args = argparse.Namespace(policy="invalid")

    mock_engine = MagicMock()
    mock_engine.validate_policy.return_value = (False, "Syntax error on line 1")

    with (
        patch(
            "scripts.cli.policy_commands.discover_policies",
            return_value={"invalid": policy_path},
        ),
        patch("scripts.cli.policy_commands.PolicyEngine", return_value=mock_engine),
    ):
        rc = cmd_policy_validate(args)

        captured = capsys.readouterr()
        assert "❌ Policy 'invalid' is invalid" in captured.out
        assert "Syntax error on line 1" in captured.out
        assert rc == 1


# =============================================================================
# cmd_policy_test() tests
# =============================================================================


def test_cmd_policy_test_findings_file_not_found():
    """Test cmd_policy_test when findings file doesn't exist."""
    args = argparse.Namespace(policy="test", findings_file="nonexistent.json")

    rc = cmd_policy_test(args)
    assert (
        rc == 2
    )  # usage error, not a verdict: see docs/CLI_REFERENCE.md "Exit Codes" (#925)


def test_cmd_policy_test_policy_not_found(tmp_path):
    """Test cmd_policy_test when policy doesn't exist."""
    findings_file = tmp_path / "findings.json"
    findings_file.write_text("[]")

    args = argparse.Namespace(policy="nonexistent", findings_file=str(findings_file))

    with patch("scripts.cli.policy_commands.discover_policies", return_value={}):
        rc = cmd_policy_test(args)
        assert (
            rc == 2
        )  # usage error, not a verdict: see docs/CLI_REFERENCE.md "Exit Codes" (#925)


def test_cmd_policy_test_passed(tmp_path, capsys):
    """Test cmd_policy_test with passing policy."""
    findings_file = tmp_path / "findings.json"
    findings_file.write_text("[]")

    policy_path = tmp_path / "test.rego"
    policy_path.write_text("package test")

    args = argparse.Namespace(policy="test", findings_file=str(findings_file))

    mock_result = MagicMock()
    mock_result.passed = True
    mock_result.message = "All checks passed"
    mock_result.violation_count = 0
    mock_result.warnings = []
    mock_result.violations = []

    mock_engine = MagicMock()
    mock_engine.test_policy.return_value = mock_result

    with (
        patch(
            "scripts.cli.policy_commands.discover_policies",
            return_value={"test": policy_path},
        ),
        patch("scripts.cli.policy_commands.PolicyEngine", return_value=mock_engine),
    ):
        rc = cmd_policy_test(args)

        captured = capsys.readouterr()
        assert "✅ PASSED" in captured.out
        assert "All checks passed" in captured.out
        assert rc == 0


def test_cmd_policy_test_failed(tmp_path, capsys):
    """Test cmd_policy_test with failing policy."""
    findings_file = tmp_path / "findings.json"
    findings_file.write_text('[{"severity": "HIGH"}]')

    policy_path = tmp_path / "test.rego"
    policy_path.write_text("package test")

    args = argparse.Namespace(policy="test", findings_file=str(findings_file))

    mock_result = MagicMock()
    mock_result.passed = False
    mock_result.message = "Found HIGH severity findings"
    mock_result.violation_count = 1
    mock_result.warnings = ["Warning 1"]
    mock_result.violations = [{"id": "v1", "severity": "HIGH"}]

    mock_engine = MagicMock()
    mock_engine.test_policy.return_value = mock_result

    with (
        patch(
            "scripts.cli.policy_commands.discover_policies",
            return_value={"test": policy_path},
        ),
        patch("scripts.cli.policy_commands.PolicyEngine", return_value=mock_engine),
    ):
        rc = cmd_policy_test(args)

        captured = capsys.readouterr()
        assert "❌ FAILED" in captured.out
        assert "Found HIGH severity findings" in captured.out
        assert "Violations:" in captured.out
        assert "Warnings:" in captured.out
        assert rc == 1


def test_cmd_policy_test_exception(tmp_path):
    """Test cmd_policy_test when test_policy raises exception."""
    findings_file = tmp_path / "findings.json"
    findings_file.write_text("[]")

    policy_path = tmp_path / "test.rego"
    policy_path.write_text("package test")

    args = argparse.Namespace(policy="test", findings_file=str(findings_file))

    mock_engine = MagicMock()
    mock_engine.test_policy.side_effect = RuntimeError("OPA evaluation failed")

    with (
        patch(
            "scripts.cli.policy_commands.discover_policies",
            return_value={"test": policy_path},
        ),
        patch("scripts.cli.policy_commands.PolicyEngine", return_value=mock_engine),
    ):
        rc = cmd_policy_test(args)
        assert rc == 1


# =============================================================================
# cmd_policy_show() tests
# =============================================================================


def test_cmd_policy_show_policy_not_found():
    """Test cmd_policy_show when policy doesn't exist."""
    args = argparse.Namespace(policy="nonexistent")

    with patch("scripts.cli.policy_commands.discover_policies", return_value={}):
        rc = cmd_policy_show(args)
        assert (
            rc == 2
        )  # usage error, not a verdict: see docs/CLI_REFERENCE.md "Exit Codes" (#925)


def test_cmd_policy_show_with_metadata(tmp_path, capsys):
    """Test cmd_policy_show displays policy metadata."""
    policy_path = tmp_path / "test.rego"
    policy_content = "\n".join([f"# Line {i}" for i in range(1, 31)])
    policy_path.write_text(policy_content)

    args = argparse.Namespace(policy="test")

    mock_engine = MagicMock()
    mock_engine.get_metadata.return_value = {
        "version": "1.0.0",
        "description": "Test policy",
        "author": "JMo Security",
        "frameworks": ["OWASP", "CWE"],
    }

    with (
        patch(
            "scripts.cli.policy_commands.discover_policies",
            return_value={"test": policy_path},
        ),
        patch(
            "scripts.cli.policy_commands.get_builtin_policies_dir",
            return_value=tmp_path / "builtin",
        ),
        patch("scripts.cli.policy_commands.PolicyEngine", return_value=mock_engine),
    ):
        rc = cmd_policy_show(args)

        captured = capsys.readouterr()
        assert "Policy: test" in captured.out
        assert "Path:" in captured.out
        assert "Metadata:" in captured.out
        assert "version: 1.0.0" in captured.out
        assert "description: Test policy" in captured.out
        assert "frameworks: OWASP, CWE" in captured.out
        assert "Policy Content (first 20 lines):" in captured.out
        assert "... (10 more lines)" in captured.out
        assert rc == 0


def test_cmd_policy_show_no_metadata(tmp_path, capsys):
    """Test cmd_policy_show when no metadata found."""
    policy_path = tmp_path / "test.rego"
    policy_path.write_text("package test")

    args = argparse.Namespace(policy="test")

    mock_engine = MagicMock()
    mock_engine.get_metadata.return_value = {}

    with (
        patch(
            "scripts.cli.policy_commands.discover_policies",
            return_value={"test": policy_path},
        ),
        patch(
            "scripts.cli.policy_commands.get_builtin_policies_dir",
            return_value=tmp_path / "builtin",
        ),
        patch("scripts.cli.policy_commands.PolicyEngine", return_value=mock_engine),
    ):
        rc = cmd_policy_show(args)

        captured = capsys.readouterr()
        assert "No metadata found in policy" in captured.out
        assert rc == 0


# =============================================================================
# cmd_policy_install() tests
# =============================================================================


def test_cmd_policy_install_builtin_not_found(tmp_path):
    """Test cmd_policy_install when builtin policy doesn't exist."""
    builtin_dir = tmp_path / "builtin"

    args = argparse.Namespace(policy="nonexistent", force=False)

    with patch(
        "scripts.cli.policy_commands.get_builtin_policies_dir", return_value=builtin_dir
    ):
        rc = cmd_policy_install(args)
        assert (
            rc == 2
        )  # usage error, not a verdict: see docs/CLI_REFERENCE.md "Exit Codes" (#925)


def test_cmd_policy_install_success(tmp_path, capsys):
    """Test cmd_policy_install successfully installs policy."""
    builtin_dir = tmp_path / "builtin"
    builtin_dir.mkdir()
    (builtin_dir / "test.rego").write_text("package test")

    user_dir = tmp_path / "user"

    args = argparse.Namespace(policy="test", force=False)

    with (
        patch(
            "scripts.cli.policy_commands.get_builtin_policies_dir",
            return_value=builtin_dir,
        ),
        patch(
            "scripts.cli.policy_commands.get_user_policies_dir", return_value=user_dir
        ),
    ):
        rc = cmd_policy_install(args)

        captured = capsys.readouterr()
        assert "✅ Installed policy 'test'" in captured.out
        assert (user_dir / "test.rego").exists()
        assert (user_dir / "test.rego").read_text() == "package test"
        assert rc == 0


def test_cmd_policy_install_already_exists_no_force(tmp_path):
    """Test cmd_policy_install when policy already installed without --force."""
    builtin_dir = tmp_path / "builtin"
    builtin_dir.mkdir()
    (builtin_dir / "test.rego").write_text("package test_builtin")

    user_dir = tmp_path / "user"
    user_dir.mkdir()
    (user_dir / "test.rego").write_text("package test_user")

    args = argparse.Namespace(policy="test", force=False)

    with (
        patch(
            "scripts.cli.policy_commands.get_builtin_policies_dir",
            return_value=builtin_dir,
        ),
        patch(
            "scripts.cli.policy_commands.get_user_policies_dir", return_value=user_dir
        ),
    ):
        rc = cmd_policy_install(args)

        # Should fail without --force
        assert rc == 1
        # User policy should not be overwritten
        assert (user_dir / "test.rego").read_text() == "package test_user"


def test_cmd_policy_install_already_exists_with_force(tmp_path, capsys):
    """Test cmd_policy_install overwrites with --force flag."""
    builtin_dir = tmp_path / "builtin"
    builtin_dir.mkdir()
    (builtin_dir / "test.rego").write_text("package test_builtin")

    user_dir = tmp_path / "user"
    user_dir.mkdir()
    (user_dir / "test.rego").write_text("package test_user")

    args = argparse.Namespace(policy="test", force=True)

    with (
        patch(
            "scripts.cli.policy_commands.get_builtin_policies_dir",
            return_value=builtin_dir,
        ),
        patch(
            "scripts.cli.policy_commands.get_user_policies_dir", return_value=user_dir
        ),
    ):
        rc = cmd_policy_install(args)

        captured = capsys.readouterr()
        assert "✅ Installed policy 'test'" in captured.out
        # User policy should be overwritten with builtin
        assert (user_dir / "test.rego").read_text() == "package test_builtin"
        assert rc == 0


# =============================================================================
# cmd_policy() dispatcher tests
# =============================================================================


def test_cmd_policy_list_dispatch():
    """Test cmd_policy dispatches to cmd_policy_list."""
    args = argparse.Namespace(policy_command="list")

    with patch(
        "scripts.cli.policy_commands.cmd_policy_list", return_value=0
    ) as mock_list:
        rc = cmd_policy(args)
        assert mock_list.called
        assert rc == 0


def test_cmd_policy_validate_dispatch():
    """Test cmd_policy dispatches to cmd_policy_validate."""
    args = argparse.Namespace(policy_command="validate")

    with patch(
        "scripts.cli.policy_commands.cmd_policy_validate", return_value=0
    ) as mock_validate:
        rc = cmd_policy(args)
        assert mock_validate.called
        assert rc == 0


def test_cmd_policy_test_dispatch():
    """Test cmd_policy dispatches to cmd_policy_test."""
    args = argparse.Namespace(policy_command="test")

    with patch(
        "scripts.cli.policy_commands.cmd_policy_test", return_value=0
    ) as mock_test:
        rc = cmd_policy(args)
        assert mock_test.called
        assert rc == 0


def test_cmd_policy_show_dispatch():
    """Test cmd_policy dispatches to cmd_policy_show."""
    args = argparse.Namespace(policy_command="show")

    with patch(
        "scripts.cli.policy_commands.cmd_policy_show", return_value=0
    ) as mock_show:
        rc = cmd_policy(args)
        assert mock_show.called
        assert rc == 0


def test_cmd_policy_install_dispatch():
    """Test cmd_policy dispatches to cmd_policy_install."""
    args = argparse.Namespace(policy_command="install")

    with patch(
        "scripts.cli.policy_commands.cmd_policy_install", return_value=0
    ) as mock_install:
        rc = cmd_policy(args)
        assert mock_install.called
        assert rc == 0


def test_cmd_policy_unknown_command():
    """Test cmd_policy with unknown command."""
    args = argparse.Namespace(policy_command="unknown")

    rc = cmd_policy(args)
    assert (
        rc == 2
    )  # usage error, not a verdict: see docs/CLI_REFERENCE.md "Exit Codes" (#925)


# ============================================================================
# What the user actually sees (chunk 16)
#
# Everything above mocks PolicyEngine and asserts the CLI's plumbing. These
# assert the three presentation defects that plumbing tests cannot reach: an
# exception surfaced as a traceback, a recovery hint written to a log level
# nothing renders, and policy-authored text sent to a console it cannot encode.
# ============================================================================


class _Cp1252Stream:
    """A stdout that behaves like a real Windows console: cp1252, no emoji.

    safe_print probes ``stream.encoding`` rather than deciding from the codec's
    name, so this is what makes the substitution path run under a UTF-8 pytest.
    """

    encoding = "cp1252"

    def __init__(self):
        self.text = ""

    def write(self, s):
        s.encode(self.encoding)  # raises exactly as a real console would
        self.text += s
        return len(s)

    def flush(self):
        pass


def test_missing_opa_reports_the_install_hint_not_a_traceback(capsys):
    """OPANotFoundException must not reach Python's default excepthook.

    Four of the five subcommands build a PolicyEngine in their first statement,
    and nothing caught the exception its constructor raises -- so `jmo policy
    list` answered a first-run condition (opa is in no profile's tool list) with
    an 18-line traceback whose last line was the friendly message the exception
    class exists to carry. `jmo report --policy` already degraded gracefully.
    """
    from scripts.core.exceptions import OPANotFoundException

    args = argparse.Namespace(policy_command="list")
    with patch(
        "scripts.cli.policy_commands.cmd_policy_list",
        side_effect=OPANotFoundException(),
    ):
        rc = cmd_policy(args)

    assert rc == 1
    assert "Traceback" not in capsys.readouterr().err


def test_unknown_policy_name_lists_the_available_ones(tmp_path, capsys):
    """The recovery hint has to be rendered, not merely constructed.

    It used to go out at logger.info. `jmo policy` declares no --log-level, so
    configure_scan_logging pins the `scripts` logger to WARNING, which discards
    INFO at the source for every `scripts.*` child at every flag setting. A user
    who typed `zero-secret` got "Policy not found" and no way to find the "s".
    """
    (tmp_path / "zero-secrets.rego").write_text("package t", encoding="utf-8")
    (tmp_path / "owasp-top-10.rego").write_text("package t", encoding="utf-8")

    args = argparse.Namespace(policy="zero-secret")
    with (
        patch(
            "scripts.cli.policy_commands.get_builtin_policies_dir",
            return_value=tmp_path,
        ),
        patch(
            "scripts.cli.policy_commands.get_user_policies_dir",
            return_value=tmp_path / "nope",
        ),
    ):
        rc = cmd_policy_validate(args)

    assert (
        rc == 2
    )  # usage error, not a verdict: see docs/CLI_REFERENCE.md "Exit Codes" (#925)
    err = capsys.readouterr().err
    assert "zero-secrets" in err, err
    assert "owasp-top-10" in err, err


def test_policy_message_survives_a_console_that_cannot_encode_it(tmp_path, monkeypatch):
    """The .rego-authored message must go through the fallback table.

    All five builtin policies put emoji in `message`, and it used to be written
    with a bare print(). On a Windows console that degraded to a bare "?" --
    two lines below a correctly rendered "[OK]" from the _safe_print call above
    it. The violations block is exempt: json.dumps defaults to
    ensure_ascii=True, so it is already pure ASCII.
    """
    findings_file = tmp_path / "findings.json"
    findings_file.write_text('{"findings": []}', encoding="utf-8")
    policy_path = tmp_path / "p.rego"
    policy_path.write_text("package t", encoding="utf-8")

    result = MagicMock()
    result.passed = False
    result.message = "❌ Found 3 OWASP Top 10 violations"
    result.violation_count = 3
    result.violations = []
    result.warnings = ["⚠️ PCI DSS 6.2.4: weak crypto"]

    engine = MagicMock()
    engine.test_policy.return_value = result

    stream = _Cp1252Stream()
    monkeypatch.setattr("sys.stdout", stream)
    with (
        patch(
            "scripts.cli.policy_commands.discover_policies",
            return_value={"p": policy_path},
        ),
        patch("scripts.cli.policy_commands.PolicyEngine", return_value=engine),
    ):
        rc = cmd_policy_test(
            argparse.Namespace(policy="p", findings_file=str(findings_file))
        )

    assert rc == 1
    # Rendered through the table, not lost to errors="replace".
    assert "[X] Found 3 OWASP Top 10 violations" in stream.text, stream.text
    assert "[!] PCI DSS 6.2.4" in stream.text, stream.text
    assert "?" not in stream.text, stream.text


def test_list_total_counts_addressable_policies_not_files(tmp_path, capsys):
    """A user copy shadowing a builtin is ONE policy, not two.

    discover_policies() resolves the user copy over the builtin of the same
    name, so validate / test / show see 5 names after installing one of the 5
    builtins -- while `list` summed the two sections and said 6.
    """
    builtin = tmp_path / "builtin"
    user = tmp_path / "user"
    builtin.mkdir()
    user.mkdir()
    for name in ("zero-secrets", "owasp-top-10"):
        (builtin / f"{name}.rego").write_text("package t", encoding="utf-8")
    (user / "zero-secrets.rego").write_text("package t", encoding="utf-8")

    engine = MagicMock()
    engine.get_metadata.return_value = {"version": "1.0.0", "description": "d"}

    with (
        patch(
            "scripts.cli.policy_commands.get_builtin_policies_dir", return_value=builtin
        ),
        patch("scripts.cli.policy_commands.get_user_policies_dir", return_value=user),
        patch("scripts.cli.policy_commands.PolicyEngine", return_value=engine),
    ):
        rc = cmd_policy_list(argparse.Namespace())

    assert rc == 0
    out = capsys.readouterr().out
    assert "Total: 2 policies" in out, out
    assert "zero-secrets" in out

    # And the count must agree with what the other subcommands can address.
    with (
        patch(
            "scripts.cli.policy_commands.get_builtin_policies_dir", return_value=builtin
        ),
        patch("scripts.cli.policy_commands.get_user_policies_dir", return_value=user),
    ):
        assert len(discover_policies()) == 2
