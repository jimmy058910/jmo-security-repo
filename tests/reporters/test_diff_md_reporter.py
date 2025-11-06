"""Tests for Markdown diff reporter."""


import pytest

from scripts.core.diff_engine import DiffResult, DiffSource, ModifiedFinding
from scripts.core.reporters.diff_md_reporter import write_markdown_diff


@pytest.fixture
def sample_diff_result():
    """Create sample DiffResult for testing."""
    baseline_source = DiffSource(
        source_type="directory",
        path="baseline-results/",
        timestamp="2025-11-04T10:00:00Z",
        profile="balanced",
        total_findings=150,
    )

    current_source = DiffSource(
        source_type="directory",
        path="current-results/",
        timestamp="2025-11-05T10:00:00Z",
        profile="balanced",
        total_findings=142,
    )

    new_findings = [
        {
            "schemaVersion": "1.2.0",
            "id": "abc123def456",
            "severity": "CRITICAL",
            "ruleId": "CWE-89",
            "tool": {"name": "semgrep", "version": "1.50.0"},
            "location": {"path": "src/db.py", "startLine": 89},
            "message": "SQL injection vulnerability detected",
            "remediation": "Use parameterized queries",
            "compliance": {
                "owaspTop10_2021": ["A03:2021"],
                "cweTop25_2024": [{"cweId": "CWE-89", "rank": 3}],
            },
        },
        {
            "schemaVersion": "1.2.0",
            "id": "xyz789abc123",
            "severity": "HIGH",
            "ruleId": "G101",
            "tool": {"name": "trufflehog", "version": "3.70.0"},
            "location": {"path": "src/auth.py", "startLine": 42},
            "message": "Hardcoded secret detected",
        },
        {
            "schemaVersion": "1.2.0",
            "id": "medium123",
            "severity": "MEDIUM",
            "ruleId": "CWE-79",
            "tool": {"name": "semgrep", "version": "1.50.0"},
            "location": {"path": "src/views.py", "startLine": 120},
            "message": "XSS vulnerability",
        },
    ]

    resolved_findings = [
        {
            "schemaVersion": "1.2.0",
            "id": "old123def456",
            "severity": "HIGH",
            "ruleId": "CWE-79",
            "tool": {"name": "semgrep", "version": "1.50.0"},
            "location": {"path": "src/views.py", "startLine": 150},
            "message": "XSS vulnerability in template",
        },
        {
            "schemaVersion": "1.2.0",
            "id": "old456",
            "severity": "MEDIUM",
            "ruleId": "CWE-200",
            "tool": {"name": "trivy", "version": "0.68.0"},
            "location": {"path": "src/info.py", "startLine": 15},
            "message": "Information disclosure",
        },
    ]

    modified_findings = [
        ModifiedFinding(
            fingerprint="def456abc123",
            changes={"severity": ["MEDIUM", "HIGH"], "priority": [45.2, 78.9]},
            baseline={
                "schemaVersion": "1.2.0",
                "id": "def456abc123",
                "severity": "MEDIUM",
                "ruleId": "G101",
                "location": {"path": "auth/session.py", "startLine": 89},
                "message": "Hardcoded password",
            },
            current={
                "schemaVersion": "1.2.0",
                "id": "def456abc123",
                "severity": "HIGH",
                "ruleId": "G101",
                "location": {"path": "auth/session.py", "startLine": 89},
                "message": "Hardcoded password",
            },
            risk_delta="worsened",
        )
    ]

    statistics = {
        "total_new": 3,
        "total_resolved": 2,
        "total_unchanged": 130,
        "total_modified": 1,
        "net_change": 1,
        "trend": "worsening",
        "new_by_severity": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1},
        "resolved_by_severity": {"HIGH": 1, "MEDIUM": 1},
        "modifications_by_type": {"severity": 1, "priority": 1},
    }

    return DiffResult(
        new=new_findings,
        resolved=resolved_findings,
        unchanged=[],
        modified=modified_findings,
        baseline_source=baseline_source,
        current_source=current_source,
        statistics=statistics,
    )


def test_markdown_header(tmp_path, sample_diff_result):
    """Test Markdown report header."""
    out_path = tmp_path / "diff.md"
    write_markdown_diff(sample_diff_result, out_path)

    content = out_path.read_text()

    # Check header elements
    assert "# 🔍 Security Diff Report" in content
    assert "**Baseline:** `baseline-results/`" in content
    assert "**Current:** `current-results/`" in content
    assert "2025-11-04" in content
    assert "2025-11-05" in content
    assert "balanced profile" in content


def test_markdown_summary_table(tmp_path, sample_diff_result):
    """Test summary statistics table."""
    out_path = tmp_path / "diff.md"
    write_markdown_diff(sample_diff_result, out_path)

    content = out_path.read_text()

    # Check summary section
    assert "## 📊 Summary" in content
    assert "| Metric | Count | Change |" in content
    assert "| **New Findings** | 3 | 🔴 +3 |" in content
    assert "| **Resolved Findings** | 2 | ✅ -2 |" in content
    assert "| **Modified Findings** | 1 | ⚠️ 1 |" in content
    assert "| **Net Change** | +1 | 🔴 Worsening |" in content


def test_markdown_severity_breakdown(tmp_path, sample_diff_result):
    """Test new findings severity breakdown."""
    out_path = tmp_path / "diff.md"
    write_markdown_diff(sample_diff_result, out_path)

    content = out_path.read_text()

    # Check severity breakdown
    assert "### New Findings by Severity" in content
    assert "- 🔴 **CRITICAL**: 1" in content
    assert "- 🔴 **HIGH**: 1" in content
    assert "- 🟡 **MEDIUM**: 1" in content


def test_markdown_new_findings_section(tmp_path, sample_diff_result):
    """Test new findings detailed section."""
    out_path = tmp_path / "diff.md"
    write_markdown_diff(sample_diff_result, out_path)

    content = out_path.read_text()

    # Check new findings section
    assert "## ⚠️ New Findings (3)" in content
    assert "### 🔴 CRITICAL (1)" in content
    assert "### 🔴 HIGH (1)" in content
    assert "### 🟡 MEDIUM (1)" in content

    # Check collapsible details
    assert "<details>" in content
    assert "<summary><b>SQL injection vulnerability detected</b></summary>" in content
    assert "**Rule:** `CWE-89`" in content
    assert "**File:** `src/db.py:89`" in content
    assert "**Tool:** semgrep v1.50.0" in content


def test_markdown_remediation(tmp_path, sample_diff_result):
    """Test remediation section in findings."""
    out_path = tmp_path / "diff.md"
    write_markdown_diff(sample_diff_result, out_path)

    content = out_path.read_text()

    # Check remediation present
    assert "**Remediation:**" in content
    assert "Use parameterized queries" in content


def test_markdown_compliance(tmp_path, sample_diff_result):
    """Test compliance frameworks section."""
    out_path = tmp_path / "diff.md"
    write_markdown_diff(sample_diff_result, out_path)

    content = out_path.read_text()

    # Check compliance frameworks
    assert "**Compliance:**" in content
    assert "OWASP Top 10 2021: A03:2021" in content
    assert "CWE Top 25 2024: CWE-89, Rank #3" in content


def test_markdown_resolved_findings(tmp_path, sample_diff_result):
    """Test resolved findings section."""
    out_path = tmp_path / "diff.md"
    write_markdown_diff(sample_diff_result, out_path)

    content = out_path.read_text()

    # Check resolved section
    assert "## ✅ Resolved Findings (2)" in content
    assert "### 🔴 HIGH (1)" in content
    assert "### 🟡 MEDIUM (1)" in content
    assert "✅ **XSS vulnerability in template** in `src/views.py:150`" in content
    assert "(semgrep, CWE-79)" in content


def test_markdown_modified_findings(tmp_path, sample_diff_result):
    """Test modified findings section."""
    out_path = tmp_path / "diff.md"
    write_markdown_diff(sample_diff_result, out_path)

    content = out_path.read_text()

    # Check modified section
    assert "## 🔄 Modified Findings (1)" in content
    assert "### ⚠️ Severity Upgraded: MEDIUM → HIGH" in content
    assert "**Rule:** `G101`" in content
    assert "**File:** `auth/session.py:89`" in content
    assert "**What changed:**" in content
    assert "- **Severity:** MEDIUM → **HIGH** (⚠️ worsened)" in content
    assert "- **Priority:** 45.2 → 78.9 (⚠️ worsened)" in content


def test_markdown_footer(tmp_path, sample_diff_result):
    """Test Markdown report footer."""
    out_path = tmp_path / "diff.md"
    write_markdown_diff(sample_diff_result, out_path)

    content = out_path.read_text()

    # Check footer
    assert "**Generated by JMo Security v1.0.0**" in content


def test_markdown_empty_sections(tmp_path):
    """Test Markdown with empty new/resolved/modified sections."""
    baseline_source = DiffSource(
        source_type="directory",
        path="baseline/",
        timestamp="2025-11-04T10:00:00Z",
        profile="fast",
        total_findings=100,
    )

    current_source = DiffSource(
        source_type="directory",
        path="current/",
        timestamp="2025-11-05T10:00:00Z",
        profile="fast",
        total_findings=100,
    )

    diff = DiffResult(
        new=[],
        resolved=[],
        unchanged=[],
        modified=[],
        baseline_source=baseline_source,
        current_source=current_source,
        statistics={
            "total_new": 0,
            "total_resolved": 0,
            "total_unchanged": 100,
            "total_modified": 0,
            "net_change": 0,
            "trend": "stable",
            "new_by_severity": {},
            "resolved_by_severity": {},
            "modifications_by_type": {},
        },
    )

    out_path = tmp_path / "empty-diff.md"
    write_markdown_diff(diff, out_path)

    content = out_path.read_text()

    # Should have header and summary but no findings sections
    assert "# 🔍 Security Diff Report" in content
    assert "## 📊 Summary" in content
    assert "| **Net Change** | 0 | ➖ Stable |" in content

    # No findings sections
    assert "## ⚠️ New Findings" not in content
    assert "## ✅ Resolved Findings" not in content
    assert "## 🔄 Modified Findings" not in content


def test_markdown_improving_trend(tmp_path):
    """Test Markdown with improving trend."""
    baseline_source = DiffSource(
        source_type="directory",
        path="baseline/",
        timestamp="2025-11-04T10:00:00Z",
        profile="balanced",
        total_findings=120,
    )

    current_source = DiffSource(
        source_type="directory",
        path="current/",
        timestamp="2025-11-05T10:00:00Z",
        profile="balanced",
        total_findings=100,
    )

    resolved = [
        {
            "id": "resolved1",
            "severity": "HIGH",
            "ruleId": "CWE-79",
            "tool": {"name": "semgrep"},
            "location": {"path": "test.py", "startLine": 10},
            "message": "Fixed vulnerability",
        }
        for _ in range(20)
    ]

    diff = DiffResult(
        new=[],
        resolved=resolved,
        unchanged=[],
        modified=[],
        baseline_source=baseline_source,
        current_source=current_source,
        statistics={
            "total_new": 0,
            "total_resolved": 20,
            "total_unchanged": 100,
            "total_modified": 0,
            "net_change": -20,
            "trend": "improving",
            "new_by_severity": {},
            "resolved_by_severity": {"HIGH": 20},
            "modifications_by_type": {},
        },
    )

    out_path = tmp_path / "improving-diff.md"
    write_markdown_diff(diff, out_path)

    content = out_path.read_text()

    # Check improving trend indicator
    assert "| **Net Change** | -20 | ✅ Improving |" in content


def test_markdown_unicode_handling(tmp_path):
    """Test Markdown handles Unicode characters correctly."""
    baseline_source = DiffSource(
        source_type="directory",
        path="baseline/",
        timestamp="2025-11-04T10:00:00Z",
        profile="balanced",
        total_findings=0,
    )

    current_source = DiffSource(
        source_type="directory",
        path="current/",
        timestamp="2025-11-05T10:00:00Z",
        profile="balanced",
        total_findings=1,
    )

    new_findings = [
        {
            "id": "unicode123",
            "severity": "HIGH",
            "ruleId": "CWE-79",
            "tool": {"name": "semgrep", "version": "1.50.0"},
            "location": {"path": "test/файл.py", "startLine": 10},
            "message": "XSS vulnerability: 你好 🚨 مرحبا",
        }
    ]

    diff = DiffResult(
        new=new_findings,
        resolved=[],
        unchanged=[],
        modified=[],
        baseline_source=baseline_source,
        current_source=current_source,
        statistics={
            "total_new": 1,
            "total_resolved": 0,
            "total_unchanged": 0,
            "total_modified": 0,
            "net_change": 1,
            "trend": "worsening",
            "new_by_severity": {"HIGH": 1},
            "resolved_by_severity": {},
            "modifications_by_type": {},
        },
    )

    out_path = tmp_path / "unicode-diff.md"
    write_markdown_diff(diff, out_path)

    content = out_path.read_text(encoding="utf-8")

    # Verify Unicode preserved
    assert "你好" in content
    assert "🚨" in content
    assert "مرحبا" in content
    assert "файл.py" in content


def test_markdown_creates_parent_directory(tmp_path):
    """Test that parent directories are created if they don't exist."""
    out_path = tmp_path / "nested" / "dir" / "diff.md"

    baseline_source = DiffSource(
        source_type="directory",
        path="baseline/",
        timestamp="2025-11-04T10:00:00Z",
        profile="fast",
        total_findings=0,
    )

    current_source = DiffSource(
        source_type="directory",
        path="current/",
        timestamp="2025-11-05T10:00:00Z",
        profile="fast",
        total_findings=0,
    )

    diff = DiffResult(
        new=[],
        resolved=[],
        unchanged=[],
        modified=[],
        baseline_source=baseline_source,
        current_source=current_source,
        statistics={
            "total_new": 0,
            "total_resolved": 0,
            "total_unchanged": 0,
            "total_modified": 0,
            "net_change": 0,
            "trend": "stable",
            "new_by_severity": {},
            "resolved_by_severity": {},
            "modifications_by_type": {},
        },
    )

    # Should create parent directories
    write_markdown_diff(diff, out_path)

    assert out_path.exists()
    assert out_path.parent.exists()


def test_markdown_modification_types(tmp_path):
    """Test different modification types are formatted correctly."""
    baseline_source = DiffSource(
        source_type="directory",
        path="baseline/",
        timestamp="2025-11-04T10:00:00Z",
        profile="balanced",
        total_findings=3,
    )

    current_source = DiffSource(
        source_type="directory",
        path="current/",
        timestamp="2025-11-05T10:00:00Z",
        profile="balanced",
        total_findings=3,
    )

    modified_findings = [
        ModifiedFinding(
            fingerprint="fp1",
            changes={
                "compliance_added": ["owaspTop10_2021:A03:2021", "cweTop25_2024:CWE-79"]
            },
            baseline={
                "id": "fp1",
                "location": {"path": "test1.py", "startLine": 10},
                "ruleId": "R1",
            },
            current={
                "id": "fp1",
                "location": {"path": "test1.py", "startLine": 10},
                "ruleId": "R1",
            },
            risk_delta="unchanged",
        ),
        ModifiedFinding(
            fingerprint="fp2",
            changes={"cwe": ["CWE-79", "CWE-89"]},
            baseline={
                "id": "fp2",
                "location": {"path": "test2.py", "startLine": 20},
                "ruleId": "R2",
            },
            current={
                "id": "fp2",
                "location": {"path": "test2.py", "startLine": 20},
                "ruleId": "R2",
            },
            risk_delta="worsened",
        ),
        ModifiedFinding(
            fingerprint="fp3",
            changes={"message": ["Old message" * 10, "New message" * 15]},
            baseline={
                "id": "fp3",
                "location": {"path": "test3.py", "startLine": 30},
                "ruleId": "R3",
            },
            current={
                "id": "fp3",
                "location": {"path": "test3.py", "startLine": 30},
                "ruleId": "R3",
            },
            risk_delta="unchanged",
        ),
    ]

    diff = DiffResult(
        new=[],
        resolved=[],
        unchanged=[],
        modified=modified_findings,
        baseline_source=baseline_source,
        current_source=current_source,
        statistics={
            "total_new": 0,
            "total_resolved": 0,
            "total_unchanged": 0,
            "total_modified": 3,
            "net_change": 0,
            "trend": "stable",
            "new_by_severity": {},
            "resolved_by_severity": {},
            "modifications_by_type": {"compliance_added": 1, "cwe": 1, "message": 1},
        },
    )

    out_path = tmp_path / "mod-types-diff.md"
    write_markdown_diff(diff, out_path)

    content = out_path.read_text()

    # Check different modification type headers
    assert "### 📋 Compliance Frameworks Added: 2" in content
    assert "### 🔄 Metadata Changed" in content

    # Check change details
    assert "- **Compliance:** +2 framework mappings" in content
    assert "- **CWE:** CWE-79 → CWE-89" in content
    assert "- **Message:** Changed" in content
