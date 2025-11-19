"""
Tests for suppression_reporter.py - Suppression report generation.

Coverage targets:
- write_suppression_report with suppressions
- Empty suppressions list
- Suppression with missing details (no reason, no expires)
- Expired vs active suppressions
- Suppression not in dict (skipped)
- Parent directory creation
- Pathlib Path and str inputs
- Unicode handling
- Markdown table structure
- UTF-8 encoding
"""

from pathlib import Path

import pytest

from scripts.core.reporters.suppression_reporter import write_suppression_report
from scripts.core.suppress import Suppression


@pytest.fixture
def sample_suppressions():
    """Create sample suppressions for testing."""
    return {
        "fp-123": Suppression(
            id="fp-123",
            reason="False positive - test data",
            expires="2999-12-31",
        ),
        "fp-456": Suppression(
            id="fp-456",
            reason="Accepted risk",
            expires="2020-01-01",  # Expired
        ),
        "fp-789": Suppression(
            id="fp-789",
            reason="Legacy code - planned refactor",
            expires=None,  # Never expires
        ),
    }


def test_write_suppression_report_basic(tmp_path, sample_suppressions):
    """Test basic suppression report generation."""
    output_path = tmp_path / "SUPPRESSIONS.md"
    suppressed_ids = ["fp-123", "fp-789"]

    write_suppression_report(suppressed_ids, sample_suppressions, output_path)

    assert output_path.exists()
    content = output_path.read_text(encoding="utf-8")

    # Verify structure
    assert "# Suppressions Applied" in content
    assert "The following findings were suppressed:" in content
    assert "| Fingerprint | Reason | Expires | Active |" in content
    assert "fp-123" in content
    assert "False positive - test data" in content
    assert "2999-12-31" in content
    assert "yes" in content  # Active


def test_write_suppression_report_empty(tmp_path):
    """Test report generation with empty suppressions list."""
    output_path = tmp_path / "SUPPRESSIONS.md"
    suppressed_ids = []
    suppressions = {}

    write_suppression_report(suppressed_ids, suppressions, output_path)

    assert output_path.exists()
    content = output_path.read_text(encoding="utf-8")

    assert "# Suppressions Applied" in content
    assert "No suppressions matched any findings." in content
    assert "| Fingerprint |" not in content  # No table


def test_write_suppression_report_missing_details(tmp_path):
    """Test suppression with no reason or expires."""
    output_path = tmp_path / "SUPPRESSIONS.md"
    suppressions = {
        "fp-empty": Suppression(id="fp-empty", reason="", expires=None),
    }
    suppressed_ids = ["fp-empty"]

    write_suppression_report(suppressed_ids, suppressions, output_path)

    content = output_path.read_text(encoding="utf-8")

    # Verify empty cells
    assert "fp-empty" in content
    assert "yes" in content  # Active (no expiration = always active)
    # Reason and Expires should be empty cells
    lines = content.split("\n")
    fp_line = next(line for line in lines if "fp-empty" in line)
    assert " |  |  | yes |" in fp_line  # Empty reason and expires


def test_write_suppression_report_expired_suppression(tmp_path):
    """Test expired suppression shows active=no."""
    output_path = tmp_path / "SUPPRESSIONS.md"

    # Create suppression with past expiration date
    suppression = Suppression(
        id="fp-expired",
        reason="Old issue",
        expires="2020-01-01",
    )

    # Verify it's actually expired (sanity check)
    # 2020-01-01 is in the past, so is_active() should return False
    assert not suppression.is_active(), "Suppression should be expired"

    suppressions = {"fp-expired": suppression}
    suppressed_ids = ["fp-expired"]

    write_suppression_report(suppressed_ids, suppressions, output_path)

    content = output_path.read_text(encoding="utf-8")

    assert "fp-expired" in content
    assert "Old issue" in content
    assert "2020-01-01" in content
    assert "| no |" in content  # Expired


def test_write_suppression_report_active_suppression(tmp_path):
    """Test active suppression shows active=yes."""
    output_path = tmp_path / "SUPPRESSIONS.md"
    suppressions = {
        "fp-active": Suppression(
            id="fp-active",
            reason="Current issue",
            expires="2999-12-31",
        ),
    }
    suppressed_ids = ["fp-active"]

    write_suppression_report(suppressed_ids, suppressions, output_path)

    content = output_path.read_text(encoding="utf-8")

    assert "fp-active" in content
    assert "Current issue" in content
    assert "2999-12-31" in content
    assert "| yes |" in content  # Active


def test_write_suppression_report_suppression_not_in_dict(tmp_path):
    """Test suppressed ID not in suppressions dict is skipped."""
    output_path = tmp_path / "SUPPRESSIONS.md"
    suppressions = {
        "fp-123": Suppression(id="fp-123", reason="Test"),
    }
    suppressed_ids = ["fp-123", "fp-missing", "fp-456"]  # fp-missing not in dict

    write_suppression_report(suppressed_ids, suppressions, output_path)

    content = output_path.read_text(encoding="utf-8")

    # Only fp-123 should appear (fp-missing skipped, fp-456 not in dict)
    assert "fp-123" in content
    assert "fp-missing" not in content
    assert "fp-456" not in content


def test_write_suppression_report_creates_parent_directory(tmp_path):
    """Test parent directory created if doesn't exist."""
    output_path = tmp_path / "nested" / "dir" / "SUPPRESSIONS.md"
    suppressions = {
        "fp-test": Suppression(id="fp-test", reason="Test"),
    }
    suppressed_ids = ["fp-test"]

    write_suppression_report(suppressed_ids, suppressions, output_path)

    assert output_path.exists()
    assert output_path.parent.exists()


def test_write_suppression_report_path_and_str(tmp_path, sample_suppressions):
    """Test both pathlib.Path and str inputs."""
    suppressed_ids = ["fp-123"]

    # Test with Path object
    path1 = tmp_path / "suppress1.md"
    write_suppression_report(suppressed_ids, sample_suppressions, path1)
    assert path1.exists()

    # Test with string path
    path2 = str(tmp_path / "suppress2.md")
    write_suppression_report(suppressed_ids, sample_suppressions, path2)
    assert Path(path2).exists()


def test_write_suppression_report_unicode_reason(tmp_path):
    """Test Unicode characters in reason text."""
    output_path = tmp_path / "SUPPRESSIONS.md"
    suppressions = {
        "fp-unicode": Suppression(
            id="fp-unicode",
            reason="Test with emoji: 🔒 🛡️ 测试 テスト",
            expires=None,
        ),
    }
    suppressed_ids = ["fp-unicode"]

    write_suppression_report(suppressed_ids, suppressions, output_path)

    content = output_path.read_text(encoding="utf-8")

    # Verify Unicode preserved
    assert "🔒" in content
    assert "测试" in content
    assert "テスト" in content


def test_write_suppression_report_mixed_active_expired(tmp_path):
    """Test mix of active and expired suppressions."""
    output_path = tmp_path / "SUPPRESSIONS.md"
    suppressions = {
        "fp-active": Suppression(id="fp-active", reason="Active", expires="2999-12-31"),
        "fp-expired": Suppression(
            id="fp-expired", reason="Expired", expires="2020-01-01"
        ),
        "fp-no-expiry": Suppression(
            id="fp-no-expiry", reason="No expiry", expires=None
        ),
    }
    suppressed_ids = ["fp-active", "fp-expired", "fp-no-expiry"]

    # Verify expiration status (sanity check)
    assert suppressions["fp-active"].is_active(), "Future date should be active"
    assert not suppressions["fp-expired"].is_active(), "Past date should be expired"
    assert suppressions["fp-no-expiry"].is_active(), "No expiry should be active"

    write_suppression_report(suppressed_ids, suppressions, output_path)

    content = output_path.read_text(encoding="utf-8")

    # Verify all three appear with correct active status
    lines = content.split("\n")
    active_line = next(line for line in lines if "fp-active" in line)
    expired_line = next(line for line in lines if "fp-expired" in line)
    no_expiry_line = next(line for line in lines if "fp-no-expiry" in line)

    assert "| yes |" in active_line
    assert "| no |" in expired_line
    assert "| yes |" in no_expiry_line


def test_write_suppression_report_no_expires(tmp_path):
    """Test suppression with no expiration (always active)."""
    output_path = tmp_path / "SUPPRESSIONS.md"
    suppressions = {
        "fp-permanent": Suppression(
            id="fp-permanent",
            reason="Permanent suppression",
            expires=None,
        ),
    }
    suppressed_ids = ["fp-permanent"]

    write_suppression_report(suppressed_ids, suppressions, output_path)

    content = output_path.read_text(encoding="utf-8")

    assert "fp-permanent" in content
    assert "Permanent suppression" in content
    assert "| yes |" in content  # Always active


def test_write_suppression_report_table_structure(tmp_path, sample_suppressions):
    """Test markdown table structure is correct."""
    output_path = tmp_path / "SUPPRESSIONS.md"
    suppressed_ids = ["fp-123", "fp-789"]

    write_suppression_report(suppressed_ids, sample_suppressions, output_path)

    content = output_path.read_text(encoding="utf-8")
    lines = content.split("\n")

    # Verify table header
    assert "| Fingerprint | Reason | Expires | Active |" in content
    assert "|-------------|--------|---------|--------|" in content

    # Verify at least 2 data rows (fp-123, fp-789)
    data_rows = [line for line in lines if line.startswith("| `fp-")]
    assert len(data_rows) >= 2


def test_write_suppression_report_utf8_encoding(tmp_path):
    """Test file is written with UTF-8 encoding."""
    output_path = tmp_path / "SUPPRESSIONS.md"
    suppressions = {
        "fp-utf8": Suppression(
            id="fp-utf8",
            reason="UTF-8 test: © ® ™ € ¥ £",
            expires=None,
        ),
    }
    suppressed_ids = ["fp-utf8"]

    write_suppression_report(suppressed_ids, suppressions, output_path)

    # Read with explicit UTF-8 encoding
    content = output_path.read_text(encoding="utf-8")

    # Verify special characters preserved
    assert "©" in content
    assert "€" in content
    assert "¥" in content
