"""
Tests for apply_fix MCP tool.

Coverage:
- Dry-run mode (preview patch)
- Patch application (currently returns "not implemented")
- Validation (finding existence, patch format)
- Edge cases (invalid finding ID, empty patch)
- Rate limiting integration
"""

import json
from pathlib import Path

import pytest

from scripts.jmo_mcp.jmo_server import (
    apply_fix,
    rate_limiter,
)

# A real unified diff. Most of this file used to pass "test patch" / "test" --
# strings that are not diffs at all -- and every assertion still read
# success=True, because apply_fix echoed whatever it was handed. The tests fed
# the code an input that could not expose the defect. Anything previewable has
# to have a hunk header.
VALID_PATCH = """--- a/src/app.js
+++ b/src/app.js
@@ -40,5 +40,5 @@
   const userInput = req.query.q;
-  res.send(userInput);
+  res.send(DOMPurify.sanitize(userInput));
"""


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


# ==============================================================================
# Dry-Run Mode Tests
# ==============================================================================


def test_apply_fix_dry_run_success(mock_env):
    """Test dry-run mode returns patch preview"""
    patch = """diff --git a/src/app.js b/src/app.js
index abc123..def456 100644
--- a/src/app.js
+++ b/src/app.js
@@ -40,5 +40,5 @@ app.get('/search', (req, res) => {
   const userInput = req.query.q;

-  res.send(userInput);
+  res.send(DOMPurify.sanitize(userInput));
 });
"""

    result = apply_fix(
        finding_id="fingerprint-xss-001",
        patch=patch,
        confidence=0.95,
        explanation="Added DOMPurify sanitization to prevent XSS",
        dry_run=True,
    )

    assert result["success"] is True
    assert "dry_run_preview" in result
    assert result["dry_run_preview"] == patch
    assert "error" not in result


def test_apply_fix_dry_run_with_invalid_finding(mock_env):
    """Test dry-run with non-existent finding ID raises ValueError"""
    patch = VALID_PATCH

    with pytest.raises(ValueError, match="Finding not found"):
        apply_fix(
            finding_id="nonexistent-finding",
            patch=patch,
            confidence=0.9,
            explanation="Fix attempt",
            dry_run=True,
        )


@pytest.mark.parametrize(
    "bad_patch, expected",
    [
        ("", "must not be empty"),
        ("   \n\t ", "must not be empty"),
        ("rm -rf / ; not a diff", "not a unified diff"),
        ("just some prose about the fix", "not a unified diff"),
        ("diff --git a/x b/x", "not a unified diff"),  # header, but no hunk
    ],
)
def test_apply_fix_rejects_anything_that_is_not_a_diff(mock_env, bad_patch, expected):
    """A preview of a non-diff is not a preview.

    This test replaces one titled "empty patch (should still work)" which
    asserted success is True for patch="". apply_fix echoed its argument back
    verbatim with success=True whatever it was -- measured, it accepted
    "rm -rf / ; not a diff" as a reviewable change.
    """
    with pytest.raises(ValueError, match=expected):
        apply_fix(
            finding_id="fingerprint-xss-001",
            patch=bad_patch,
            confidence=0.9,
            explanation="not a real fix",
            dry_run=True,
        )


@pytest.mark.parametrize("bad_confidence", [99.0, -4.0, 1.0001, -0.0001])
def test_apply_fix_rejects_confidence_outside_zero_to_one(mock_env, bad_confidence):
    """The docstring documented 0.0-1.0 and the code accepted 99.0 and -4.0.

    "Recommend 0.9+ for auto-apply" is advice about a number with no scale
    unless the scale is enforced.
    """
    with pytest.raises(ValueError, match="between 0.0 and 1.0"):
        apply_fix(
            finding_id="fingerprint-xss-001",
            patch=VALID_PATCH,
            confidence=bad_confidence,
            explanation="out of range",
            dry_run=True,
        )


@pytest.mark.parametrize("ok_confidence", [0.0, 0.5, 1.0])
def test_apply_fix_accepts_the_documented_confidence_range(mock_env, ok_confidence):
    """Negative control: the guard must accept the whole documented interval.

    Without this, a validator that rejected everything would pass the test
    above and look correct.
    """
    result = apply_fix(
        finding_id="fingerprint-xss-001",
        patch=VALID_PATCH,
        confidence=ok_confidence,
        explanation="in range",
        dry_run=True,
    )
    assert result["success"] is True


def test_dry_run_and_write_path_are_distinguishable_in_the_return_value(mock_env):
    """A successful preview carries dry_run=True; the write path never succeeds."""
    preview = apply_fix(
        finding_id="fingerprint-xss-001",
        patch=VALID_PATCH,
        confidence=0.9,
        explanation="preview",
        dry_run=True,
    )
    write = apply_fix(
        finding_id="fingerprint-xss-001",
        patch=VALID_PATCH,
        confidence=0.9,
        explanation="write",
        dry_run=False,
    )

    assert preview["success"] is True
    assert preview["dry_run"] is True
    assert write["success"] is False
    assert "dry_run" not in write
    assert preview != write


def test_a_real_apply_fix_changes_nothing_on_disk(mock_env, tmp_path):
    """The write path is unimplemented; prove it writes nothing, anywhere.

    Acceptance criterion for chunk 20: a dry_run and a real apply_fix must be
    distinguishable. They are -- by return value, and by the fact that neither
    touches the filesystem, because applying is not implemented at all.
    """
    before = {p: p.stat().st_mtime_ns for p in mcp_env_files(mock_env)}

    result = apply_fix(
        finding_id="fingerprint-xss-001",
        patch=VALID_PATCH,
        confidence=0.99,
        explanation="would fix it",
        dry_run=False,
    )

    after = {p: p.stat().st_mtime_ns for p in mcp_env_files(mock_env)}
    assert result["success"] is False
    assert before == after, "apply_fix reported failure but touched the tree"
    assert not (mock_env / ".jmo" / "backups").exists()


def mcp_env_files(root):
    """Every file under *root*, for before/after comparison."""
    return sorted(p for p in root.rglob("*") if p.is_file())


def test_apply_fix_dry_run_multiline_patch(mock_env):
    """Test dry-run preserves multiline patch formatting"""
    patch = """diff --git a/src/database.py b/src/database.py
--- a/src/database.py
+++ b/src/database.py
@@ -12,7 +12,8 @@ def get_user_by_id(user_id):
     conn = sqlite3.connect('users.db')
     cursor = conn.cursor()

-    query = f"SELECT * FROM users WHERE id = {user_id}"
+    query = "SELECT * FROM users WHERE id = ?"
+    cursor.execute(query, (user_id,))

     cursor.execute(query)
     result = cursor.fetchone()
"""

    result = apply_fix(
        finding_id="fingerprint-sqli-001",
        patch=patch,
        confidence=0.98,
        explanation="Convert to parameterized query",
        dry_run=True,
    )

    assert result["success"] is True
    assert result["dry_run_preview"] == patch
    assert result["dry_run_preview"].count("\n") == patch.count("\n")


# ==============================================================================
# Patch Application Tests (Currently Returns "Not Implemented")
# ==============================================================================


def test_apply_fix_not_implemented(mock_env):
    """Test patch application returns 'not implemented' error"""
    patch = VALID_PATCH

    result = apply_fix(
        finding_id="fingerprint-xss-001",
        patch=patch,
        confidence=0.95,
        explanation="Fix XSS vulnerability",
        dry_run=False,  # Attempt actual application
    )

    assert result["success"] is False
    assert "error" in result
    assert "not yet implemented" in result["error"].lower()


def test_apply_fix_high_confidence_not_implemented(mock_env):
    """Test high-confidence fix still returns not implemented"""
    patch = VALID_PATCH

    result = apply_fix(
        finding_id="fingerprint-hardcoded-secret-001",
        patch=patch,
        confidence=0.99,  # Very high confidence
        explanation="Move API key to environment variable",
        dry_run=False,
    )

    assert result["success"] is False
    assert "not yet implemented" in result["error"].lower()


def test_apply_fix_low_confidence_not_implemented(mock_env):
    """Test low-confidence fix still returns not implemented"""
    patch = VALID_PATCH

    result = apply_fix(
        finding_id="fingerprint-crypto-001",
        patch=patch,
        confidence=0.6,  # Lower confidence
        explanation="Replace MD5 with SHA-256",
        dry_run=False,
    )

    assert result["success"] is False
    assert "not yet implemented" in result["error"].lower()


# ==============================================================================
# Validation Tests
# ==============================================================================


def test_apply_fix_finding_not_found(mock_env):
    """Test applying fix to non-existent finding raises ValueError"""
    with pytest.raises(ValueError, match="Finding not found"):
        apply_fix(
            finding_id="does-not-exist",
            patch=VALID_PATCH,
            confidence=0.9,
            explanation="Test",
            dry_run=False,
        )


def test_apply_fix_all_finding_ids_valid(mock_env):
    """Test all fixture finding IDs are recognized"""
    finding_ids = [
        "fingerprint-xss-001",
        "fingerprint-sqli-001",
        "fingerprint-crypto-001",
        "fingerprint-path-traversal-001",
        "fingerprint-hardcoded-secret-001",
    ]

    for finding_id in finding_ids:
        result = apply_fix(
            finding_id=finding_id,
            patch=VALID_PATCH,
            confidence=0.9,
            explanation="Test validation",
            dry_run=True,
        )
        assert result["success"] is True


def test_apply_fix_confidence_values(mock_env):
    """Test various confidence values (no validation enforced yet)"""
    # Currently no confidence validation, but test the field is accepted
    confidence_values = [0.0, 0.5, 0.9, 0.95, 0.99, 1.0]

    for confidence in confidence_values:
        result = apply_fix(
            finding_id="fingerprint-xss-001",
            patch=VALID_PATCH,
            confidence=confidence,
            explanation=f"Confidence test: {confidence}",
            dry_run=True,
        )
        assert result["success"] is True


# ==============================================================================
# Edge Cases
# ==============================================================================


def test_apply_fix_special_characters_in_patch(mock_env):
    """Test patch with special characters"""
    patch = """--- a/src/app.js
+++ b/src/app.js
@@ -1,1 +1,1 @@
-  res.send("Hello 'world' & <script>alert(1)</script>");
+  res.send(sanitize("Hello 'world' & <script>alert(1)</script>"));
"""

    result = apply_fix(
        finding_id="fingerprint-xss-001",
        patch=patch,
        confidence=0.9,
        explanation="Sanitize HTML entities",
        dry_run=True,
    )

    assert result["success"] is True
    assert result["dry_run_preview"] == patch


def test_apply_fix_unicode_in_explanation(mock_env):
    """Test explanation with unicode characters"""
    result = apply_fix(
        finding_id="fingerprint-xss-001",
        patch=VALID_PATCH,
        confidence=0.9,
        explanation="Fix XSS vulnerability 🔒 使用 DOMPurify 清理",
        dry_run=True,
    )

    assert result["success"] is True


def test_apply_fix_very_long_patch(mock_env):
    """Test handling of large patches"""
    # Generate a long patch (1000 lines). It needs a real hunk header -- so
    # does any patch a client would actually send.
    lines = ["--- a/src/app.js\n", "+++ b/src/app.js\n", "@@ -1,0 +1,1000 @@\n"]
    for i in range(1000):
        lines.append(f"+  // Fixed line {i}\n")
    long_patch = "".join(lines)

    result = apply_fix(
        finding_id="fingerprint-xss-001",
        patch=long_patch,
        confidence=0.9,
        explanation="Large refactoring",
        dry_run=True,
    )

    assert result["success"] is True
    assert len(result["dry_run_preview"]) == len(long_patch)


def test_apply_fix_missing_findings_file(tmp_path, monkeypatch):
    """Test behavior when findings.json doesn't exist"""
    monkeypatch.setenv("MCP_RESULTS_DIR", str(tmp_path))
    monkeypatch.setenv("JMO_MCP_RATE_LIMIT_ENABLED", "false")

    import importlib

    from scripts.jmo_mcp import jmo_server

    importlib.reload(jmo_server)

    # Should raise when trying to load findings
    with pytest.raises(Exception):  # FileNotFoundError or ValueError
        apply_fix(
            finding_id="fingerprint-xss-001",
            patch=VALID_PATCH,
            confidence=0.9,
            explanation="Test",
            dry_run=True,
        )


# ==============================================================================
# Rate Limiting Integration Tests
# ==============================================================================


def test_apply_fix_rate_limit_enforcement(mock_findings_file, monkeypatch):
    """Test rate limiting is enforced when enabled"""
    # Set aggressive rate limit (1 request capacity)
    monkeypatch.setenv("MCP_RESULTS_DIR", str(mock_findings_file / "results"))
    monkeypatch.setenv("JMO_MCP_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("JMO_MCP_RATE_LIMIT_CAPACITY", "1")
    monkeypatch.setenv("JMO_MCP_RATE_LIMIT_REFILL_RATE", "0.1")

    import importlib

    from scripts.jmo_mcp import jmo_server

    importlib.reload(jmo_server)

    # First request should succeed
    result1 = jmo_server.apply_fix(
        finding_id="fingerprint-xss-001",
        patch=VALID_PATCH,
        confidence=0.9,
        explanation="Test",
        dry_run=True,
    )
    assert result1["success"] is True

    # Second request should fail (bucket exhausted)
    with pytest.raises(ValueError, match="Rate limit exceeded"):
        jmo_server.apply_fix(
            finding_id="fingerprint-xss-001",
            patch=VALID_PATCH,
            confidence=0.9,
            explanation="Test",
            dry_run=True,
        )


def test_apply_fix_rate_limit_disabled(mock_env):
    """Test rate limiting can be disabled"""
    # Rate limiting disabled via mock_env fixture

    # Should be able to make multiple requests
    for _ in range(10):
        result = apply_fix(
            finding_id="fingerprint-xss-001",
            patch=VALID_PATCH,
            confidence=0.9,
            explanation="Test",
            dry_run=True,
        )
        assert result["success"] is True


# ==============================================================================
# Response Structure Tests
# ==============================================================================


def test_apply_fix_dry_run_response_structure(mock_env):
    """Test dry-run response contains required fields"""
    result = apply_fix(
        finding_id="fingerprint-xss-001",
        patch=VALID_PATCH,
        confidence=0.9,
        explanation="Test",
        dry_run=True,
    )

    # Dry-run response structure
    assert "success" in result
    assert "dry_run_preview" in result
    assert isinstance(result["success"], bool)
    assert isinstance(result["dry_run_preview"], str)


def test_apply_fix_not_implemented_response_structure(mock_env):
    """Test not-implemented response contains required fields"""
    result = apply_fix(
        finding_id="fingerprint-xss-001",
        patch=VALID_PATCH,
        confidence=0.9,
        explanation="Test",
        dry_run=False,
    )

    # Not-implemented response structure
    assert "success" in result
    assert "error" in result
    assert result["success"] is False
    assert isinstance(result["error"], str)
