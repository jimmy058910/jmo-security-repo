from pathlib import Path

from scripts.core.reporters.basic_reporter import (
    to_markdown_summary,
    write_json,
    _get_severity_emoji,
    _truncate_path,
    _get_top_issue_summary,
    _get_remediation_priorities,
    _get_category_summary,
)


def test_markdown_summary_counts(tmp_path: Path):
    sample = [
        {"severity": "HIGH", "ruleId": "aws-key"},
        {"severity": "LOW", "ruleId": "dummy"},
        {"severity": "HIGH", "ruleId": "aws-key"},
        {"severity": "INFO", "ruleId": "meta"},
    ]
    md = to_markdown_summary(sample)
    assert "Total findings: 4" in md
    assert "HIGH: 2" in md
    assert "LOW: 1" in md
    assert "INFO: 1" in md
    assert "Top Rules" in md


def test_write_json_roundtrip(tmp_path: Path):
    """Test write_json() with v1.0.0 metadata wrapper structure."""
    sample = [
        {
            "schemaVersion": "1.0.0",
            "severity": "HIGH",
            "ruleId": "x",
            "id": "1",
            "tool": {"name": "t", "version": "v"},
            "location": {"path": "a", "startLine": 1},
            "message": "m",
        }
    ]
    out = tmp_path / "out.json"
    write_json(sample, out)
    s = out.read_text(encoding="utf-8")

    # v1.0.0: JSON now has metadata wrapper {"meta": {...}, "findings": [...]}
    import json

    data = json.loads(s)
    assert "meta" in data
    assert "findings" in data
    assert data["findings"] == sample
    assert data["meta"]["output_version"] == "1.0.0"
    assert "\n" in s and "schemaVersion" in s


# Tests for enhanced markdown summary features (ROADMAP #5)


def test_markdown_summary_with_emoji_badges():
    """Test that emoji badges appear in severity breakdown."""
    sample = [
        {
            "severity": "CRITICAL",
            "ruleId": "critical-vuln",
            "tool": {"name": "trivy", "version": "1.0"},
            "location": {"path": "app.py"},
            "tags": ["vulnerability"],
        },
        {
            "severity": "HIGH",
            "ruleId": "high-issue",
            "tool": {"name": "semgrep", "version": "1.0"},
            "location": {"path": "app.py"},
            "tags": ["sast"],
        },
    ]
    md = to_markdown_summary(sample)
    assert "🔴" in md  # Should have red emoji for CRITICAL/HIGH
    assert "Total findings: 2" in md


def test_markdown_summary_top_risks_by_file():
    """Test that file breakdown table appears with top risks."""
    sample = [
        {
            "severity": "HIGH",
            "ruleId": "aws-key",
            "tool": {"name": "gitleaks", "version": "1.0"},
            "location": {"path": "config.yaml"},
            "tags": ["secrets"],
        },
        {
            "severity": "MEDIUM",
            "ruleId": "misc-issue",
            "tool": {"name": "semgrep", "version": "1.0"},
            "location": {"path": "app.py"},
            "tags": ["sast"],
        },
        {
            "severity": "HIGH",
            "ruleId": "another-secret",
            "tool": {"name": "gitleaks", "version": "1.0"},
            "location": {"path": "config.yaml"},
            "tags": ["secrets"],
        },
    ]
    md = to_markdown_summary(sample)
    assert "## Top Risks by File" in md
    assert "| File | Findings | Severity | Top Issue |" in md
    assert "config.yaml" in md
    assert "app.py" in md


def test_markdown_summary_tool_breakdown():
    """Test that tool breakdown with severity counts appears."""
    sample = [
        {
            "severity": "HIGH",
            "ruleId": "secret-1",
            "tool": {"name": "gitleaks", "version": "1.0"},
            "location": {"path": "a.txt"},
            "tags": ["secrets"],
        },
        {
            "severity": "MEDIUM",
            "ruleId": "code-1",
            "tool": {"name": "semgrep", "version": "1.0"},
            "location": {"path": "b.py"},
            "tags": ["sast"],
        },
        {
            "severity": "HIGH",
            "ruleId": "secret-2",
            "tool": {"name": "gitleaks", "version": "1.0"},
            "location": {"path": "c.txt"},
            "tags": ["secrets"],
        },
    ]
    md = to_markdown_summary(sample)
    assert "## By Tool" in md
    assert "**gitleaks**" in md
    assert "**semgrep**" in md
    # Should show severity breakdown per tool
    assert "2 findings" in md or "2 finding" in md


def test_markdown_summary_remediation_priorities():
    """Test that remediation priorities section appears with actionable items."""
    sample = [
        {
            "severity": "HIGH",
            "ruleId": "generic-api-key",
            "tool": {"name": "gitleaks", "version": "1.0"},
            "location": {"path": "secrets.txt"},
            "tags": ["secrets"],
        },
        {
            "severity": "HIGH",
            "ruleId": "missing-user",
            "tool": {"name": "hadolint", "version": "1.0"},
            "location": {"path": "Dockerfile"},
            "tags": ["docker"],
        },
    ]
    md = to_markdown_summary(sample)
    assert "## Remediation Priorities" in md
    # Should suggest rotating secrets
    assert "Rotate" in md or "secret" in md.lower()


def test_markdown_summary_category_grouping():
    """Test that category grouping by tags appears."""
    sample = [
        {
            "severity": "HIGH",
            "ruleId": "secret-1",
            "tool": {"name": "gitleaks", "version": "1.0"},
            "location": {"path": "a.txt"},
            "tags": ["secrets"],
        },
        {
            "severity": "MEDIUM",
            "ruleId": "docker-1",
            "tool": {"name": "hadolint", "version": "1.0"},
            "location": {"path": "Dockerfile"},
            "tags": ["docker"],
        },
        {
            "severity": "LOW",
            "ruleId": "code-1",
            "tool": {"name": "semgrep", "version": "1.0"},
            "location": {"path": "app.py"},
            "tags": ["sast"],
        },
    ]
    md = to_markdown_summary(sample)
    assert "## By Category" in md
    assert "🔑 Secrets" in md or "Secrets" in md
    assert "🐳 IaC/Container" in md or "IaC" in md or "Container" in md


def test_get_severity_emoji():
    """Test severity emoji mapping."""
    assert _get_severity_emoji("CRITICAL") == "🔴"
    assert _get_severity_emoji("HIGH") == "🔴"
    assert _get_severity_emoji("MEDIUM") == "🟡"
    assert _get_severity_emoji("LOW") == "⚪"
    assert _get_severity_emoji("INFO") == "🔵"
    assert _get_severity_emoji("UNKNOWN") == "⚪"  # Default


def test_truncate_path_short():
    """Test that short paths are not truncated."""
    path = "src/app.py"
    assert _truncate_path(path) == path


def test_truncate_path_long():
    """Test that long paths are truncated with ... in the middle."""
    path = "very/long/path/to/some/deeply/nested/directory/structure/file.py"
    truncated = _truncate_path(path, max_len=30)
    assert len(truncated) <= 30
    assert "..." in truncated
    assert truncated.startswith("very/long")
    assert truncated.endswith("file.py")


def test_get_top_issue_summary():
    """Test top issue summary generation for a file."""
    findings = [
        {"ruleId": "aws-key", "severity": "HIGH"},
        {"ruleId": "aws-key", "severity": "HIGH"},
        {"ruleId": "github-token", "severity": "HIGH"},
    ]
    summary = _get_top_issue_summary(findings)
    assert "aws-key" in summary
    assert "2×" in summary  # Should show count


def test_get_top_issue_summary_single():
    """Test top issue summary with single finding."""
    findings = [{"ruleId": "single-issue", "severity": "MEDIUM"}]
    summary = _get_top_issue_summary(findings)
    assert "single-issue" in summary
    assert "×" not in summary  # No multiplier for single issue


def test_get_top_issue_summary_empty():
    """Test top issue summary with no findings."""
    assert _get_top_issue_summary([]) == "N/A"


def test_get_remediation_priorities_secrets():
    """Test that secrets are prioritized in remediation."""
    findings = [
        {
            "severity": "HIGH",
            "ruleId": "aws-key",
            "tags": ["secrets"],
            "tool": {"name": "gitleaks"},
            "location": {"path": "a.txt"},
        },
        {
            "severity": "HIGH",
            "ruleId": "github-token",
            "tags": ["secrets"],
            "tool": {"name": "gitleaks"},
            "location": {"path": "b.txt"},
        },
    ]
    priorities = _get_remediation_priorities(findings)
    assert len(priorities) > 0
    assert any("Rotate" in p or "secret" in p.lower() for p in priorities)


def test_get_remediation_priorities_docker():
    """Test that Docker issues are included in remediation priorities."""
    findings = [
        {
            "severity": "HIGH",
            "ruleId": "missing-user",
            "tags": ["docker"],
            "tool": {"name": "hadolint"},
            "location": {"path": "Dockerfile"},
        }
    ]
    priorities = _get_remediation_priorities(findings)
    # Should include Docker-related priority
    assert len(priorities) > 0


def test_get_remediation_priorities_mixed():
    """Test remediation priorities with mixed finding types."""
    findings = [
        {
            "severity": "HIGH",
            "ruleId": "secret",
            "tags": ["secrets"],
            "tool": {"name": "gitleaks"},
            "location": {"path": "a.txt"},
        },
        {
            "severity": "HIGH",
            "ruleId": "docker-issue",
            "tags": ["docker"],
            "tool": {"name": "hadolint"},
            "location": {"path": "Dockerfile"},
        },
        {
            "severity": "HIGH",
            "ruleId": "terraform-issue",
            "tags": ["iac", "terraform"],
            "tool": {"name": "tfsec"},
            "location": {"path": "main.tf"},
        },
    ]
    priorities = _get_remediation_priorities(findings)
    # Should have multiple priorities
    assert 1 <= len(priorities) <= 5


def test_get_category_summary_with_tags():
    """Test category summary groups findings correctly by tags."""
    findings = [
        {
            "tags": ["secrets"],
            "tool": {"name": "gitleaks"},
            "ruleId": "aws-key",
            "location": {"path": "a"},
        },
        {
            "tags": ["secrets"],
            "tool": {"name": "gitleaks"},
            "ruleId": "github",
            "location": {"path": "b"},
        },
        {
            "tags": ["docker"],
            "tool": {"name": "hadolint"},
            "ruleId": "user",
            "location": {"path": "Dockerfile"},
        },
        {
            "tags": ["sast"],
            "tool": {"name": "semgrep"},
            "ruleId": "sql",
            "location": {"path": "app.py"},
        },
    ]
    categories = _get_category_summary(findings)
    assert "🔑 Secrets" in categories
    assert categories["🔑 Secrets"] == 2
    assert "🐳 IaC/Container" in categories
    assert categories["🐳 IaC/Container"] == 1


def test_get_category_summary_fallback_inference():
    """Test category summary infers category from tool/rule when tags missing."""
    findings = [
        {
            "tags": [],
            "tool": {"name": "gitleaks", "version": "1.0"},
            "ruleId": "generic-key",
            "location": {"path": "a"},
        },
        {
            "tags": [],
            "tool": {"name": "trivy", "version": "1.0"},
            "ruleId": "CVE-2023-1234",
            "location": {"path": "b"},
        },
        {
            "tags": [],
            "tool": {"name": "hadolint", "version": "1.0"},
            "ruleId": "DL3000",
            "location": {"path": "c"},
        },
    ]
    categories = _get_category_summary(findings)
    # Should infer from tool names
    assert "🔑 Secrets" in categories  # gitleaks
    assert (
        "🛡️ Vulnerabilities" in categories or "🐳 IaC/Container" in categories
    )  # trivy or hadolint


def test_markdown_summary_empty_findings():
    """Test markdown summary handles empty findings gracefully."""
    md = to_markdown_summary([])
    assert "Total findings: 0" in md
    assert "## By Severity" in md
    # Should not crash, should show zero counts


def test_markdown_summary_header_with_severity_badges():
    """Test that header includes severity badge summary."""
    sample = [
        {
            "severity": "CRITICAL",
            "ruleId": "crit",
            "tool": {"name": "t"},
            "location": {"path": "a"},
            "tags": [],
        },
        {
            "severity": "HIGH",
            "ruleId": "high",
            "tool": {"name": "t"},
            "location": {"path": "b"},
            "tags": [],
        },
        {
            "severity": "HIGH",
            "ruleId": "high2",
            "tool": {"name": "t"},
            "location": {"path": "c"},
            "tags": [],
        },
        {
            "severity": "MEDIUM",
            "ruleId": "med",
            "tool": {"name": "t"},
            "location": {"path": "d"},
            "tags": [],
        },
    ]
    md = to_markdown_summary(sample)
    # Should have enhanced header with badges
    assert "Total findings: 4" in md
    assert "CRITICAL" in md
    assert "2 HIGH" in md or "HIGH" in md
    assert "MEDIUM" in md


def test_markdown_summary_top_rules_simplification():
    """Test that long rule IDs are simplified in Top Rules section."""
    sample = [
        {
            "severity": "HIGH",
            "ruleId": "yaml.docker-compose.security.no-new-privileges.no-new-privileges",
            "tool": {"name": "semgrep", "version": "1.0"},
            "location": {"path": "docker-compose.yml"},
            "tags": ["docker"],
        }
    ]
    md = to_markdown_summary(sample)
    assert "## Top Rules" in md
    # Should show simplified version with note about full rule
    assert "no-new-privileges" in md


def test_markdown_backward_compatibility():
    """Test that enhanced markdown still includes all traditional sections."""
    sample = [
        {
            "severity": "HIGH",
            "ruleId": "aws-key",
            "tool": {"name": "gitleaks", "version": "1.0"},
            "location": {"path": "secrets.txt"},
            "tags": ["secrets"],
        }
    ]
    md = to_markdown_summary(sample)

    # Traditional sections should still exist
    assert "# Security Summary" in md
    assert "Total findings:" in md
    assert "## By Severity" in md
    assert "## Top Rules" in md

    # New sections should also exist
    assert "## Top Risks by File" in md
    assert "## By Tool" in md
    assert "## By Category" in md


def test_get_category_summary_with_eslint():
    """Test category summary includes Code Quality for eslint findings."""
    findings = [
        {
            "tool": {"name": "eslint"},
            "ruleId": "no-unused-vars",
            "severity": "MEDIUM",
            "location": {"path": "test.js"},
        },
        {
            "tool": {"name": "semgrep"},
            "ruleId": "python.lang.correctness.useless-eqeq.python-useless-eq-check",
            "severity": "HIGH",
            "location": {"path": "app.py"},
        },
    ]

    categories = _get_category_summary(findings)

    # ESLint should be categorized as Code Quality
    assert categories.get("🔧 Code Quality", 0) >= 1
    # Semgrep should also be categorized appropriately
    assert (
        categories.get("🛡️ Security", 0) >= 1
        or categories.get("🔧 Code Quality", 0) >= 1
    )


def test_get_category_summary_with_bandit():
    """Test category summary with bandit (Python security) findings."""
    findings = [
        {
            "tool": {"name": "bandit"},
            "ruleId": "B101",
            "severity": "LOW",
            "location": {"path": "test.py"},
        }
    ]

    categories = _get_category_summary(findings)

    # Bandit should be categorized as Code Quality
    assert categories.get("🔧 Code Quality", 0) == 1
