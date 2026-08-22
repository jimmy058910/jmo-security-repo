"""
Tests for mark_resolved MCP tool.

Coverage:
- All valid resolution types (fixed, false_positive, wont_fix, risk_accepted)
- Invalid resolution types
- Finding validation (existence check)
- Optional comment field
- Edge cases (empty comments, unicode, special characters)
- Rate limiting integration
"""

import json
from datetime import datetime
from pathlib import Path

import pytest

from scripts.jmo_mcp.jmo_server import (
    mark_resolved,
    rate_limiter,
)


@pytest.fixture
def mock_findings_file(tmp_path):
    """Create temporary findings.json fixture"""
    fixtures_dir = Path(__file__).parent / "fixtures"
    findings_json = fixtures_dir / "findings.json"

    # Copy fixture to temp results directory
    results_dir = tmp_path / "results" / "summaries"
    results_dir.mkdir(parents=True, exist_ok=True)

    with open(findings_json, encoding="utf-8") as f:
        findings_data = json.load(f)

    output_path = results_dir / "findings.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(findings_data, f, indent=2)

    return tmp_path


@pytest.fixture
def mock_env(mock_findings_file, monkeypatch):
    """Mock environment variables for MCP server"""
    monkeypatch.setenv("MCP_RESULTS_DIR", str(mock_findings_file / "results"))
    monkeypatch.setenv("MCP_REPO_ROOT", str(mock_findings_file))
    monkeypatch.setenv("JMO_MCP_RATE_LIMIT_ENABLED", "false")

    # Reload module to apply new environment
    import importlib

    from scripts.jmo_mcp import jmo_server

    importlib.reload(jmo_server)

    yield mock_findings_file

    # Restore rate limiter state
    if rate_limiter:
        rate_limiter.buckets.clear()


@pytest.fixture(autouse=True)
def real_repo_config_is_untouched():
    """Fail loudly if any test in this module writes the repository's own config.

    `mark_resolved` writes to `MCP_REPO_ROOT / "jmo.suppress.yml"`, and
    `MCP_REPO_ROOT` defaults to `.`. A test that sets `MCP_RESULTS_DIR` but
    forgets `MCP_REPO_ROOT` therefore writes into the working tree -- chunk 17
    lost time to exactly this, with a mutation that wrote five schedules into
    the real `~/.jmo`. This makes that impossible to do quietly.
    """
    real = Path(__file__).resolve().parents[2] / "jmo.suppress.yml"
    before = real.read_bytes() if real.exists() else None
    yield
    after = real.read_bytes() if real.exists() else None
    assert after == before, f"a test in this module wrote to the real {real}"


def _reason(repo_root, finding_id: str) -> str:
    """The reason the REAL loader reads back for *finding_id*.

    Asserting against the loader rather than the file text is deliberate: a
    reason that is on disk but does not survive parsing is not recorded.
    """
    from scripts.core.suppress import load_suppressions

    return load_suppressions(str(repo_root / "jmo.suppress.yml"))[finding_id].reason


# ==============================================================================
# Valid Resolution Types Tests
# ==============================================================================


def test_mark_resolved_fixed(mock_env):
    """`fixed` is validated, reported, and deliberately not suppressed."""
    result = mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="fixed",
        comment="Manually fixed by adding DOMPurify sanitization",
    )

    assert result["success"] is False
    assert result["suppressed"] is False
    assert result["finding_id"] == "fingerprint-xss-001"
    assert result["resolution"] == "fixed"
    assert "timestamp" in result
    assert result["timestamp"].endswith("Z")  # ISO format with UTC marker
    assert not (mock_env / "jmo.suppress.yml").exists()


def test_mark_resolved_false_positive(mock_env):
    """Test marking finding as false positive"""
    result = mark_resolved(
        finding_id="fingerprint-sqli-001",
        resolution="false_positive",
        comment="This is a test file that intentionally shows SQL injection examples",
    )

    assert result["success"] is True
    assert result["suppressed"] is True
    assert result["finding_id"] == "fingerprint-sqli-001"
    assert result["resolution"] == "false_positive"
    assert "timestamp" in result


def test_mark_resolved_wont_fix(mock_env):
    """Test marking finding as won't fix"""
    result = mark_resolved(
        finding_id="fingerprint-crypto-001",
        resolution="wont_fix",
        comment="Legacy system compatibility requires MD5",
    )

    assert result["success"] is True
    assert result["suppressed"] is True
    assert result["finding_id"] == "fingerprint-crypto-001"
    assert result["resolution"] == "wont_fix"
    assert "timestamp" in result


def test_mark_resolved_risk_accepted(mock_env):
    """Test marking finding as risk accepted"""
    result = mark_resolved(
        finding_id="fingerprint-path-traversal-001",
        resolution="risk_accepted",
        comment="Risk accepted after security review, internal tool only",
    )

    assert result["success"] is True
    assert result["suppressed"] is True
    assert result["finding_id"] == "fingerprint-path-traversal-001"
    assert result["resolution"] == "risk_accepted"
    assert "timestamp" in result


# ==============================================================================
# Optional Comment Tests
# ==============================================================================


def test_mark_resolved_without_comment(mock_env):
    """Test marking resolved without comment (optional field).

    Deliberately a *suppressible* resolution. These three tests used `fixed`,
    which now returns before the write -- so they would have gone on passing
    while testing nothing at all about how a comment is recorded.
    """
    result = mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="false_positive",
    )

    assert result["success"] is True
    assert result["finding_id"] == "fingerprint-xss-001"
    assert result["resolution"] == "false_positive"
    assert (
        _reason(mock_env, "fingerprint-xss-001")
        == "false_positive via MCP mark_resolved"
    )


def test_mark_resolved_with_empty_comment(mock_env):
    """Test marking resolved with empty string comment"""
    result = mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="false_positive",
        comment="",
    )

    assert result["success"] is True
    assert (
        _reason(mock_env, "fingerprint-xss-001")
        == "false_positive via MCP mark_resolved"
    )


def test_mark_resolved_with_long_comment(mock_env):
    """Test marking resolved with very long comment"""
    long_comment = "This is a detailed explanation. " * 100  # ~3000 characters

    result = mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="false_positive",
        comment=long_comment,
    )

    assert result["success"] is True
    assert long_comment in _reason(mock_env, "fingerprint-xss-001")


# ==============================================================================
# Validation Tests
# ==============================================================================


def test_mark_resolved_invalid_resolution_type(mock_env):
    """Test invalid resolution type raises ValueError"""
    with pytest.raises(ValueError, match="Invalid resolution type"):
        mark_resolved(
            finding_id="fingerprint-xss-001",
            resolution="invalid_type",
            comment="Test",
        )


def test_mark_resolved_case_sensitive_resolution(mock_env):
    """Test resolution types are case-sensitive"""
    with pytest.raises(ValueError, match="Invalid resolution type"):
        mark_resolved(
            finding_id="fingerprint-xss-001",
            resolution="FIXED",  # Uppercase, should fail
            comment="Test",
        )


def test_mark_resolved_finding_not_found(mock_env):
    """Test marking non-existent finding raises ValueError"""
    with pytest.raises(ValueError, match="Finding not found"):
        mark_resolved(
            finding_id="does-not-exist",
            resolution="fixed",
            comment="Test",
        )


def test_mark_resolved_all_finding_ids_valid(mock_env):
    """Test all fixture finding IDs are recognized"""
    finding_ids = [
        "fingerprint-xss-001",
        "fingerprint-sqli-001",
        "fingerprint-crypto-001",
        "fingerprint-path-traversal-001",
        "fingerprint-hardcoded-secret-001",
    ]

    for finding_id in finding_ids:
        result = mark_resolved(
            finding_id=finding_id,
            resolution="false_positive",
            comment="Test validation",
        )
        assert result["success"] is True
        assert result["finding_id"] == finding_id

    # Five distinct ids -> five distinct rules, not one overwritten five times.
    assert _rule_count(mock_env) == len(finding_ids)


def test_mark_resolved_all_resolution_types_valid(mock_env):
    """Every valid type is accepted; only `fixed` declines to suppress."""
    for resolution in ["fixed", "false_positive", "wont_fix", "risk_accepted"]:
        result = mark_resolved(
            finding_id="fingerprint-xss-001",
            resolution=resolution,
            comment=f"Test resolution type: {resolution}",
        )
        assert result["resolution"] == resolution
        assert result["suppressed"] is (resolution != "fixed")
        assert result["success"] is (resolution != "fixed")


# ==============================================================================
# Timestamp Tests
# ==============================================================================


def test_mark_resolved_timestamp_format(mock_env):
    """Test timestamp is in ISO 8601 format with UTC marker"""
    result = mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="fixed",
        comment="Test timestamp",
    )

    timestamp = result["timestamp"]

    # Should be ISO 8601 format ending with Z
    assert timestamp.endswith("Z")

    # Should be parseable by datetime
    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        pytest.fail(f"Timestamp {timestamp} is not valid ISO 8601 format")


def test_mark_resolved_multiple_calls_different_timestamps(mock_env):
    """Test multiple resolutions have different timestamps"""
    import time

    result1 = mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="fixed",
    )

    time.sleep(0.1)  # Small delay to ensure different timestamps

    result2 = mark_resolved(
        finding_id="fingerprint-sqli-001",
        resolution="false_positive",
    )

    # Timestamps should be different (at least microseconds different)
    assert result1["timestamp"] != result2["timestamp"]


# ==============================================================================
# Edge Cases
# ==============================================================================


# These four used `resolution="fixed"`, which now returns before the write.
# Left alone they would keep passing while exercising nothing -- the shape
# chunk 20 found in a file titled for a tool it called zero times. Each is a
# YAML-quoting hazard, so each now round-trips through the real loader: what
# the client sent is what the parser reads back, or the test fails.


def test_mark_resolved_special_characters_in_comment(mock_env):
    """Test comment with special characters"""
    comment = "Fixed: <script>alert('XSS')</script> & \"quotes\" & 'apostrophes'"

    result = mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="false_positive",
        comment=comment,
    )

    assert result["success"] is True
    assert _reason(mock_env, "fingerprint-xss-001").endswith(comment)


def test_mark_resolved_unicode_in_comment(mock_env):
    """Test comment with unicode characters"""
    comment = "已修复 XSS 漏洞 🔒 使用 DOMPurify 清理用户输入"

    result = mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="false_positive",
        comment=comment,
    )

    assert result["success"] is True
    assert _reason(mock_env, "fingerprint-xss-001").endswith(comment)


def test_mark_resolved_multiline_comment(mock_env):
    """Test comment with newlines"""
    comment = """Fixed the XSS vulnerability by:
1. Adding DOMPurify sanitization
2. Validating all user input
3. Adding CSP headers"""

    result = mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="false_positive",
        comment=comment,
    )

    assert result["success"] is True
    assert _reason(mock_env, "fingerprint-xss-001").endswith(comment)


def test_mark_resolved_comment_with_escape_sequences(mock_env):
    """Test comment with escape sequences"""
    comment = 'Fixed by escaping: \\n\\t\\r\\" and \\u0000'

    result = mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="false_positive",
        comment=comment,
    )

    assert result["success"] is True
    assert _reason(mock_env, "fingerprint-xss-001").endswith(comment)


def test_mark_resolved_missing_findings_file(tmp_path, monkeypatch):
    """Test behavior when findings.json doesn't exist"""
    monkeypatch.setenv("MCP_RESULTS_DIR", str(tmp_path))
    monkeypatch.setenv("JMO_MCP_RATE_LIMIT_ENABLED", "false")

    import importlib

    from scripts.jmo_mcp import jmo_server

    importlib.reload(jmo_server)

    # Should raise when trying to load findings
    with pytest.raises(Exception):  # FileNotFoundError or ValueError
        mark_resolved(
            finding_id="fingerprint-xss-001",
            resolution="fixed",
            comment="Test",
        )


# ==============================================================================
# Rate Limiting Integration Tests
# ==============================================================================


def test_mark_resolved_rate_limit_enforcement(mock_findings_file, monkeypatch):
    """Test rate limiting is enforced when enabled"""
    # Set aggressive rate limit (1 request capacity)
    monkeypatch.setenv("MCP_RESULTS_DIR", str(mock_findings_file / "results"))
    # MCP_REPO_ROOT was absent here, so REPO_ROOT fell back to "." -- harmless
    # while the tool wrote nothing, and a write into the working tree now.
    monkeypatch.setenv("MCP_REPO_ROOT", str(mock_findings_file))
    monkeypatch.setenv("JMO_MCP_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("JMO_MCP_RATE_LIMIT_CAPACITY", "1")
    monkeypatch.setenv("JMO_MCP_RATE_LIMIT_REFILL_RATE", "0.1")

    import importlib

    from scripts.jmo_mcp import jmo_server

    importlib.reload(jmo_server)

    # First request should succeed
    result1 = jmo_server.mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="false_positive",
        comment="Test",
    )
    assert result1["success"] is True

    # Second request should fail (bucket exhausted)
    with pytest.raises(ValueError, match="Rate limit exceeded"):
        jmo_server.mark_resolved(
            finding_id="fingerprint-sqli-001",
            resolution="false_positive",
            comment="Test",
        )

    # The refused call must not have written. The limiter runs in a decorator,
    # so "refused" and "wrote anyway" are separable failures.
    from scripts.core.suppress import load_suppressions

    rules = load_suppressions(str(mock_findings_file / "jmo.suppress.yml"))
    assert "fingerprint-sqli-001" not in rules


def test_mark_resolved_rate_limit_disabled(mock_env):
    """Test rate limiting can be disabled"""
    # Rate limiting disabled via mock_env fixture

    # Should be able to make multiple requests
    for i in range(10):
        result = mark_resolved(
            finding_id="fingerprint-xss-001",
            resolution="false_positive",
            comment=f"Test {i}",
        )
        assert result["success"] is True


# ==============================================================================
# Response Structure Tests
# ==============================================================================


def test_mark_resolved_response_structure(mock_env):
    """Test response contains all required fields"""
    result = mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="fixed",
        comment="Test",
    )

    # Required fields
    assert "success" in result
    assert "finding_id" in result
    assert "resolution" in result
    assert "timestamp" in result

    # Field types
    assert isinstance(result["success"], bool)
    assert isinstance(result["finding_id"], str)
    assert isinstance(result["resolution"], str)
    assert isinstance(result["timestamp"], str)

    # Values match input
    assert result["success"] is False
    assert result["suppressed"] is False
    assert result["finding_id"] == "fingerprint-xss-001"
    assert result["resolution"] == "fixed"


def test_mark_resolved_writes_only_the_suppression_config(mock_env):
    """The write is confined to jmo.suppress.yml -- no second store appears.

    Replaces `test_mark_resolved_writes_nothing_anywhere`, which asserted the
    tool's unimplemented state. The in-code TODO proposed `.jmo/resolutions.json`
    plus dashboard badges plus report filtering; that would have been a second
    implementation of a feature the product already ships, so this asserts the
    second store did NOT appear.
    """
    before = {
        p: p.stat().st_mtime_ns for p in sorted(mock_env.rglob("*")) if p.is_file()
    }

    for resolution in ("fixed", "false_positive", "wont_fix", "risk_accepted"):
        mark_resolved(
            finding_id="fingerprint-xss-001",
            resolution=resolution,
            comment="recorded as a suppression, and nowhere else",
        )

    after = {
        p: p.stat().st_mtime_ns for p in sorted(mock_env.rglob("*")) if p.is_file()
    }
    assert set(after) - set(before) == {mock_env / "jmo.suppress.yml"}
    assert not (mock_env / ".jmo" / "resolutions.json").exists()
    assert not (mock_env / "resolutions.json").exists()
    # The temp file the atomic write goes through must not survive it.
    assert not list(mock_env.glob("*.jmo-write"))


def test_mark_resolved_still_rejects_an_unknown_finding_id(mock_env):
    """An unknown id must fail before any success value is believed.

    Distinguishes "not implemented" from "did not even look" -- the id is
    validated against the loaded findings first, so a client cannot mistake a
    typo'd id for a recorded resolution.
    """
    with pytest.raises(ValueError, match="Finding not found"):
        mark_resolved(finding_id="no-such-finding-zzz", resolution="fixed")


# ==============================================================================
# Suppression Write-Through (#951a)
# ==============================================================================
#
# `mark_resolved` used to persist nothing and say so. It now records the
# decision where the product already keeps decisions of that kind:
# `jmo.suppress.yml`. The tests below are the contract for that write.
#
# THE FILE'S COMMENTS ARE PART OF THE CONTRACT. The shipped config is ~5 KB of
# which most is explanation, and this tool is its FIRST writer. A
# `yaml.safe_dump` round-trip would silently delete every one of those bytes,
# so `test_..._preserves_the_configs_comments` asserts the prefix is
# byte-identical rather than asserting "comments still present".


# The real shipped config -- not a fabricated stand-in. Chunk 8 found that the
# config JMo ships was never the format its parser reads, so a test written
# against a hand-rolled fixture proves nothing about the file users have.
# parents[2] and not the cwd: cwd-relative paths in this suite were measured
# failing 3/20 from a foreign working directory.
SHIPPED_SUPPRESS_CONFIG = Path(__file__).resolve().parents[2] / "jmo.suppress.yml"


@pytest.fixture
def mock_env_with_config(mock_env):
    """`mock_env`, plus a copy of the real shipped jmo.suppress.yml at the root."""
    target = mock_env / "jmo.suppress.yml"
    target.write_bytes(SHIPPED_SUPPRESS_CONFIG.read_bytes())
    return mock_env


def _rule_count(repo_root) -> int:
    """Rules the REAL loader sees -- not a count of lines or of YAML entries."""
    from scripts.core.suppress import load_suppressions

    return len(load_suppressions(str(repo_root / "jmo.suppress.yml")))


def test_mark_resolved_writes_a_suppression_entry(mock_env_with_config):
    """A resolution reaches disk, and the real loader gains exactly one rule."""
    before = _rule_count(mock_env_with_config)

    result = mark_resolved(
        finding_id="fingerprint-sqli-001",
        resolution="false_positive",
        comment="Test fixture, not production code",
    )

    assert result["success"] is True
    assert result["suppressed"] is True
    assert _rule_count(mock_env_with_config) == before + 1


def test_mark_resolved_entry_is_keyed_on_the_finding_id(mock_env_with_config):
    """The new rule is reachable by the id the client passed.

    `load_suppressions` keys an `id` entry by that id, so this is the lookup a
    caller would do. If the entry landed under a selector key instead, the
    write would be real and still not answer the request that was made.
    """
    from scripts.core.suppress import load_suppressions

    mark_resolved(
        finding_id="fingerprint-sqli-001",
        resolution="false_positive",
        comment="Test fixture",
    )

    rules = load_suppressions(str(mock_env_with_config / "jmo.suppress.yml"))
    assert "fingerprint-sqli-001" in rules
    assert "Test fixture" in rules["fingerprint-sqli-001"].reason


def test_mark_resolved_preserves_the_configs_comments(mock_env_with_config):
    """Every byte that was in the file before the write is still there, in order.

    Stronger than "comments survived": the prefix must be byte-identical, which
    also catches a rewrite that preserves comments but reflows quoting,
    reorders keys, or -- on Windows -- translates the whole file's LF to CRLF.
    """
    config = mock_env_with_config / "jmo.suppress.yml"
    before = config.read_bytes()

    mark_resolved(
        finding_id="fingerprint-sqli-001",
        resolution="wont_fix",
        comment="Accepted",
    )

    after = config.read_bytes()
    assert after.startswith(
        before
    ), "the write rewrote bytes it should have appended to"
    assert len(after) > len(before)


def test_mark_resolved_leaves_the_pre_existing_rules_loading(mock_env_with_config):
    """Chunk 8's shape: a write that makes the config parse to fewer rules."""
    from scripts.core.suppress import load_suppressions

    config = str(mock_env_with_config / "jmo.suppress.yml")
    before = set(load_suppressions(config))
    assert before, "fixture is inert -- the shipped config loaded to zero rules"

    mark_resolved(
        finding_id="fingerprint-sqli-001",
        resolution="risk_accepted",
        comment="Reviewed",
    )

    after = set(load_suppressions(config))
    assert before <= after, f"the write dropped rules: {sorted(before - after)}"


def test_mark_resolved_entry_is_honoured_by_the_suppressor(mock_env_with_config):
    """The round trip that matters: the finding is actually filtered afterwards.

    Every other assertion here is about the file. This one is about the
    consequence -- a resolution the suppressor does not act on is a resolution
    that was recorded and not honoured, which is the defect this replaces
    wearing different clothes.
    """
    from scripts.core.suppress import filter_suppressed, load_suppressions

    config = str(mock_env_with_config / "jmo.suppress.yml")
    finding = {
        "id": "fingerprint-sqli-001",
        "severity": "HIGH",
        "location": {"path": "app/db.py", "startLine": 12},
    }

    assert filter_suppressed([finding], load_suppressions(config)) == [finding]

    mark_resolved(
        finding_id="fingerprint-sqli-001",
        resolution="false_positive",
        comment="Parameterised query, scanner cannot see the binding",
    )

    assert filter_suppressed([finding], load_suppressions(config)) == []


def test_mark_resolved_defaults_to_a_ninety_day_expiry(mock_env_with_config):
    """A suppression written by an AI client is time-boxed by default."""
    import datetime as dt

    from scripts.core.suppress import load_suppressions

    result = mark_resolved(
        finding_id="fingerprint-sqli-001",
        resolution="false_positive",
        comment="Test fixture",
    )

    expected = dt.date.today() + dt.timedelta(days=90)
    assert result["expires"] == expected.isoformat()

    rule = load_suppressions(str(mock_env_with_config / "jmo.suppress.yml"))[
        "fingerprint-sqli-001"
    ]
    assert rule.is_active(expected) is True
    assert rule.is_active(expected + dt.timedelta(days=1)) is False


def test_mark_resolved_accepts_an_expiry_at_the_cap(mock_env_with_config):
    """The negative control for the cap: 365 days is accepted.

    Without this, `expires_days` rejecting everything would satisfy the test
    below and the guard would be a check that can only fire.
    """
    import datetime as dt

    result = mark_resolved(
        finding_id="fingerprint-sqli-001",
        resolution="risk_accepted",
        comment="Annual review",
        expires_days=365,
    )

    assert result["success"] is True
    assert result["expires"] == (dt.date.today() + dt.timedelta(days=365)).isoformat()


def test_mark_resolved_rejects_an_expiry_beyond_the_cap(mock_env_with_config):
    """A permanent suppression cannot be requested through this tool."""
    config = mock_env_with_config / "jmo.suppress.yml"
    before = config.read_bytes()

    with pytest.raises(ValueError, match="expires_days"):
        mark_resolved(
            finding_id="fingerprint-sqli-001",
            resolution="risk_accepted",
            comment="Forever",
            expires_days=3650,
        )

    assert config.read_bytes() == before, "a rejected call still wrote"


def test_mark_resolved_rejects_a_non_positive_expiry(mock_env_with_config):
    """An already-expired entry is inert; writing one would look like success."""
    with pytest.raises(ValueError, match="expires_days"):
        mark_resolved(
            finding_id="fingerprint-sqli-001",
            resolution="wont_fix",
            comment="Zero",
            expires_days=0,
        )


def test_mark_resolved_fixed_writes_no_suppression(mock_env_with_config):
    """`fixed` is verified by the next scan, not by hiding the finding.

    Suppressing a finding the client says it FIXED would mask a fix that did
    not take -- the scan would stop reporting it either way, so the one signal
    that distinguishes a real fix from a failed one is destroyed. The other
    three resolutions are decisions not to act, which is what suppression
    means. This asymmetry is deliberate; see the tool's docstring.
    """
    config = mock_env_with_config / "jmo.suppress.yml"
    before = config.read_bytes()

    result = mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="fixed",
        comment="Added DOMPurify",
    )

    assert result["success"] is False
    assert result["suppressed"] is False
    assert "re-scan" in result["error"].lower() or "rescan" in result["error"].lower()
    assert config.read_bytes() == before


def test_mark_resolved_creates_the_config_when_it_is_absent(mock_env):
    """A repo with no jmo.suppress.yml gets a valid one, not a crash."""
    config = mock_env / "jmo.suppress.yml"
    assert not config.exists()

    result = mark_resolved(
        finding_id="fingerprint-sqli-001",
        resolution="false_positive",
        comment="First suppression in this repo",
    )

    assert result["success"] is True
    assert _rule_count(mock_env) == 1


def test_mark_resolved_does_not_write_for_an_unknown_finding(mock_env_with_config):
    """The id is validated against loaded findings BEFORE anything is written."""
    config = mock_env_with_config / "jmo.suppress.yml"
    before = config.read_bytes()

    with pytest.raises(ValueError, match="Finding not found"):
        mark_resolved(finding_id="no-such-finding-zzz", resolution="false_positive")

    assert config.read_bytes() == before


def test_mark_resolved_twice_does_not_duplicate_the_entry(mock_env_with_config):
    """A repeated call is not an error, and does not append a second rule.

    `load_suppressions` de-duplicates by key and warns "the later one wins", so
    a blind second append would leave the rule count unchanged while the file
    grew -- the file and the loader disagreeing about how many rules exist.
    """
    first = mark_resolved(
        finding_id="fingerprint-sqli-001",
        resolution="false_positive",
        comment="First",
    )
    after_first = (mock_env_with_config / "jmo.suppress.yml").read_bytes()

    second = mark_resolved(
        finding_id="fingerprint-sqli-001",
        resolution="false_positive",
        comment="Second",
    )

    assert first["success"] is True
    assert second["success"] is True
    assert second["already_suppressed"] is True
    assert (mock_env_with_config / "jmo.suppress.yml").read_bytes() == after_first


def test_mark_resolved_reports_the_expiry_that_is_actually_on_disk(
    mock_env_with_config,
):
    """A second call reports the FILE's expiry, not a freshly computed one.

    Nothing is written the second time, so returning `today + expires_days`
    would name a date the config does not contain -- a return value describing
    a disk state that is not the disk state. Same family as the tool reporting
    work it had not done.
    """
    mark_resolved(
        finding_id="fingerprint-sqli-001",
        resolution="false_positive",
        comment="First",
        expires_days=7,
    )

    second = mark_resolved(
        finding_id="fingerprint-sqli-001",
        resolution="false_positive",
        comment="Second",
        expires_days=300,
    )

    from scripts.core.suppress import load_suppressions

    on_disk = load_suppressions(str(mock_env_with_config / "jmo.suppress.yml"))[
        "fingerprint-sqli-001"
    ].expires
    assert second["already_suppressed"] is True
    assert second["expires"] == str(on_disk)


def test_mark_resolved_comment_cannot_inject_a_second_rule(mock_env_with_config):
    """A comment is a YAML *value*, never YAML *structure*.

    The obvious payload: a comment carrying a newline and a `- path: "*"` item
    would, in a naive f-string renderer, become a second suppression matching
    every finding in the scan -- a whole-scan mute delivered through a free-text
    field. The entry is serialised by the YAML dumper, so quoting is not this
    function's job to get right by hand.
    """
    from scripts.core.suppress import load_suppressions

    before = _rule_count(mock_env_with_config)

    mark_resolved(
        finding_id="fingerprint-sqli-001",
        resolution="false_positive",
        comment='benign\n  - path: "*"\n    reason: "pwned"\n',
    )

    config = str(mock_env_with_config / "jmo.suppress.yml")
    assert _rule_count(mock_env_with_config) == before + 1
    assert "path=*" not in load_suppressions(config)


def test_mark_resolved_refuses_to_write_into_an_unparseable_config(mock_env):
    """Validate-then-write: a config the loader cannot read is never clobbered.

    `_read_entries` swallows a YAML error and reports zero rules, so an append
    here would produce a file that still loads to zero -- the write would
    "succeed" and suppress nothing. Refusing keeps the user's file intact and
    the failure visible.
    """
    config = mock_env / "jmo.suppress.yml"
    config.write_bytes(b"suppressions: [unclosed\n")
    before = config.read_bytes()

    result = mark_resolved(
        finding_id="fingerprint-sqli-001",
        resolution="false_positive",
        comment="Test",
    )

    assert result["success"] is False
    assert result["suppressed"] is False
    assert config.read_bytes() == before
    # Pin the SPECIFIC diagnosis. Without this the generic post-condition
    # downstream also refuses the write, so removing this guard changes only
    # the message -- and the message is the whole value of a guard that fires
    # on a file the user has to go and fix by hand.
    assert "could not be parsed" in result["error"]


def test_mark_resolved_refuses_a_flow_style_list_rather_than_corrupting_it(mock_env):
    """`suppressions: []` cannot take an appended block item -- refuse, don't guess.

    The natural way to write an empty list is flow style, and a block sequence
    item after it is invalid YAML. This is what proves the post-condition is a
    real guard rather than an unreachable assertion: the candidate is built,
    fails to load, and the original file is left untouched.
    """
    config = mock_env / "jmo.suppress.yml"
    config.write_bytes(b"suppressions: []\n")
    before = config.read_bytes()

    result = mark_resolved(
        finding_id="fingerprint-sqli-001",
        resolution="false_positive",
        comment="Test",
    )

    assert result["success"] is False
    assert result["suppressed"] is False
    assert config.read_bytes() == before
    assert "flow style" in result["error"]


def test_mark_resolved_keeps_a_crlf_config_all_crlf(mock_env):
    """A CRLF config stays CRLF -- the appended entry matches the file's endings.

    This repo has no `.gitattributes` and `core.autocrlf=false`, so line endings
    are per-file and a Windows user's config really can be CRLF. Appending LF
    into it would make the file mixed, which every later diff of that file then
    carries.
    """
    config = mock_env / "jmo.suppress.yml"
    config.write_bytes(
        b"suppressions:\r\n  - path: 'vendor/*'\r\n    reason: 'third party'\r\n"
    )
    before = config.read_bytes()

    mark_resolved(
        finding_id="fingerprint-sqli-001",
        resolution="false_positive",
        comment="CRLF host",
    )

    after = config.read_bytes()
    assert after.startswith(before)
    assert after.count(b"\r\n") == after.count(b"\n"), "the append introduced bare LF"
    assert _rule_count(mock_env) == 2


def test_mark_resolved_matches_the_configs_own_indentation(mock_env):
    """A zero-indented sequence stays zero-indented.

    YAML allows a block sequence at the same column as its key, and mixing that
    with a 2-space item in the SAME sequence is a parse error -- so imposing a
    house style here would produce a file that no longer loads. The loader is
    what catches it: the rule count is the assertion, not the indentation.
    """
    config = mock_env / "jmo.suppress.yml"
    config.write_bytes(b"suppressions:\n- path: 'vendor/*'\n  reason: 'third party'\n")

    mark_resolved(
        finding_id="fingerprint-sqli-001",
        resolution="false_positive",
        comment="Flat config",
    )

    assert _rule_count(mock_env) == 2


def test_mark_resolved_reports_where_it_wrote(mock_env_with_config):
    """The return value names the file, so a client can show its work."""
    result = mark_resolved(
        finding_id="fingerprint-sqli-001",
        resolution="wont_fix",
        comment="Legacy",
    )

    assert Path(result["config_path"]) == (mock_env_with_config / "jmo.suppress.yml")
