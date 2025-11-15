"""
Integration tests for full prioritization workflow.

Tests end-to-end priority enrichment including:
- EPSS/KEV data fetching
- Priority calculation
- Finding enrichment
- HTML dashboard integration
- SUMMARY.md generation
"""

import json
from unittest.mock import Mock, patch

import pytest

from scripts.core.epss_integration import EPSSScore
from scripts.core.kev_integration import KEVEntry
from scripts.core.normalize_and_report import gather_results, _enrich_with_priority
from scripts.core.reporters.basic_reporter import to_markdown_summary
from scripts.core.reporters.html_reporter import write_html


@pytest.fixture
def temp_results_dir(tmp_path):
    """Create temporary results directory with mock findings."""
    results_dir = tmp_path / "results"
    repo_dir = results_dir / "individual-repos" / "test-repo"
    repo_dir.mkdir(parents=True)

    # Create mock trivy output with CVE
    trivy_findings = {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1234",
                        "PkgName": "lodash",
                        "InstalledVersion": "4.17.19",
                        "FixedVersion": "4.17.21",
                        "Severity": "CRITICAL",
                        "Title": "Prototype Pollution",
                        "Description": "lodash is vulnerable to prototype pollution",
                        "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-1234",
                    }
                ]
            }
        ]
    }

    (repo_dir / "trivy.json").write_text(json.dumps(trivy_findings))

    # Create mock semgrep output with different CVE
    semgrep_findings = {
        "results": [
            {
                "check_id": "CVE-2024-5678",
                "path": "app/api.py",
                "start": {"line": 42},
                "extra": {
                    "severity": "HIGH",
                    "message": "SQL Injection vulnerability detected",
                    "metadata": {
                        "cve": "CVE-2024-5678",
                        "vulnerability_class": ["SQL Injection"],
                    },
                },
            }
        ]
    }

    (repo_dir / "semgrep.json").write_text(json.dumps(semgrep_findings))

    return results_dir


class TestPrioritizationWorkflow:
    """Integration tests for prioritization workflow."""

    @patch("scripts.core.priority_calculator.EPSSClient")
    @patch("scripts.core.priority_calculator.KEVClient")
    def test_full_prioritization_workflow(
        self, mock_kev_client_class, mock_epss_client_class, temp_results_dir
    ):
        """Test complete prioritization workflow from findings to enriched output."""
        # Mock EPSS responses
        mock_epss_client = Mock()

        # Mock get_score for individual calls
        def mock_get_score(cve):
            scores = {
                "CVE-2024-1234": EPSSScore(
                    cve="CVE-2024-1234", epss=0.95, percentile=0.999, date="2024-10-01"
                ),
                "CVE-2024-5678": EPSSScore(
                    cve="CVE-2024-5678", epss=0.50, percentile=0.80, date="2024-10-01"
                ),
            }
            return scores.get(cve)

        mock_epss_client.get_score.side_effect = mock_get_score

        # Mock get_scores_bulk for bulk calls
        mock_epss_client.get_scores_bulk.return_value = {
            "CVE-2024-1234": EPSSScore(
                cve="CVE-2024-1234", epss=0.95, percentile=0.999, date="2024-10-01"
            ),
            "CVE-2024-5678": EPSSScore(
                cve="CVE-2024-5678", epss=0.50, percentile=0.80, date="2024-10-01"
            ),
        }
        mock_epss_client_class.return_value = mock_epss_client

        # Mock KEV responses
        mock_kev_client = Mock()
        mock_kev_client.is_kev.side_effect = lambda cve: cve == "CVE-2024-1234"
        mock_kev_client.get_entry.return_value = KEVEntry(
            cve="CVE-2024-1234",
            vendor="Example Vendor",
            product="lodash",
            vulnerability_name="Prototype Pollution",
            date_added="2024-09-15",
            short_description="Critical prototype pollution",
            required_action="Apply patches immediately",
            due_date="2024-10-15",
        )
        mock_kev_client_class.return_value = mock_kev_client

        # Gather and enrich findings
        findings = gather_results(temp_results_dir)

        assert len(findings) >= 2  # At least trivy + semgrep findings

        # Verify priority enrichment
        priority_findings = [f for f in findings if "priority" in f and f["priority"]]
        assert len(priority_findings) >= 1  # At least one CVE finding enriched

        # Find KEV finding
        kev_findings = [
            f for f in priority_findings if f.get("priority", {}).get("is_kev", False)
        ]
        assert len(kev_findings) == 1

        kev_finding = kev_findings[0]
        assert "CVE-2024-1234" in kev_finding["ruleId"]
        assert kev_finding["priority"]["is_kev"] is True
        assert kev_finding["priority"]["kev_due_date"] == "2024-10-15"
        assert kev_finding["priority"]["epss"] == 0.95
        assert kev_finding["priority"]["priority"] == 100.0  # Capped at 100

        # Verify components
        components = kev_finding["priority"]["components"]
        assert "severity_score" in components
        assert "epss_multiplier" in components
        assert "kev_multiplier" in components
        assert components["kev_multiplier"] == 3.0

    @patch("scripts.core.priority_calculator.EPSSClient")
    @patch("scripts.core.priority_calculator.KEVClient")
    def test_priority_in_markdown_summary(
        self, mock_kev_client_class, mock_epss_client_class
    ):
        """Test that priority section appears in SUMMARY.md."""
        # Mock clients
        mock_epss_client = Mock()
        mock_epss_client.get_scores_bulk.return_value = {
            "CVE-2024-9999": EPSSScore(
                cve="CVE-2024-9999", epss=0.85, percentile=0.95, date="2024-10-01"
            )
        }
        mock_epss_client_class.return_value = mock_epss_client

        mock_kev_client = Mock()
        mock_kev_client.is_kev.return_value = True
        mock_kev_client.get_entry.return_value = KEVEntry(
            cve="CVE-2024-9999",
            vendor="Test",
            product="TestApp",
            vulnerability_name="Test Vuln",
            date_added="2024-09-01",
            short_description="Test",
            required_action="Patch",
            due_date="2024-10-01",
        )
        mock_kev_client_class.return_value = mock_kev_client

        # Create mock findings
        findings = [
            {
                "id": "test-001",
                "ruleId": "CVE-2024-9999",
                "severity": "CRITICAL",
                "message": "Critical vulnerability",
                "location": {"path": "app/api.py", "startLine": 42},
                "tool": {"name": "trivy", "version": "0.50.0"},
                "priority": {
                    "priority": 95.0,
                    "epss": 0.85,
                    "epss_percentile": 0.95,
                    "is_kev": True,
                    "kev_due_date": "2024-10-01",
                    "components": {
                        "severity_score": 10,
                        "epss_multiplier": 4.4,
                        "kev_multiplier": 3.0,
                        "reachability_multiplier": 1.0,
                    },
                },
            }
        ]

        # Generate markdown
        markdown = to_markdown_summary(findings)

        # Verify priority section exists
        assert "## Priority Analysis (EPSS/KEV)" in markdown
        assert "⚠️ CISA KEV:" in markdown
        assert "Actively Exploited" in markdown
        assert "CVE-2024-9999" in markdown
        assert "Priority: 95/100" in markdown or "Priority: 95.0/100" in markdown
        assert "Due: 2024-10-01" in markdown

        # Verify priority distribution
        assert "Priority Distribution" in markdown
        assert "Critical Priority (≥80)" in markdown

    @patch("scripts.core.priority_calculator.EPSSClient")
    @patch("scripts.core.priority_calculator.KEVClient")
    def test_priority_in_html_dashboard(
        self, mock_kev_client_class, mock_epss_client_class, tmp_path
    ):
        """Test that priority column and KEV badges appear in HTML dashboard."""
        # Mock clients
        mock_epss_client = Mock()
        mock_epss_client_class.return_value = mock_epss_client

        mock_kev_client = Mock()
        mock_kev_client_class.return_value = mock_kev_client

        # Create mock findings with priority
        findings = [
            {
                "id": "test-001",
                "ruleId": "CVE-2024-1234",
                "severity": "CRITICAL",
                "message": "KEV vulnerability",
                "location": {"path": "app/main.py", "startLine": 10},
                "tool": {"name": "trivy", "version": "0.50.0"},
                "priority": {
                    "priority": 100.0,
                    "epss": 0.95,
                    "epss_percentile": 0.999,
                    "is_kev": True,
                    "kev_due_date": "2024-10-15",
                    "components": {},
                },
            },
            {
                "id": "test-002",
                "ruleId": "CVE-2024-5678",
                "severity": "HIGH",
                "message": "High EPSS vulnerability",
                "location": {"path": "app/api.py", "startLine": 42},
                "tool": {"name": "semgrep", "version": "1.45.0"},
                "priority": {
                    "priority": 65.0,
                    "epss": 0.75,
                    "epss_percentile": 0.90,
                    "is_kev": False,
                    "kev_due_date": None,
                    "components": {},
                },
            },
        ]

        # Write HTML
        output_path = tmp_path / "dashboard.html"
        write_html(findings, output_path)

        html_content = output_path.read_text()

        # React implementation: Verify data is embedded with priority field
        # Check that findings are embedded with priority data
        assert "test-001" in html_content  # Finding ID
        assert "test-002" in html_content  # Finding ID
        assert '"priority":' in html_content  # Priority field in JSON data

        # Verify priority sub-fields are embedded (epss, is_kev, etc.)
        assert '"epss":' in html_content  # EPSS score field
        assert '"is_kev":' in html_content  # KEV boolean field
        assert "0.95" in html_content  # EPSS value from test-001
        assert "0.75" in html_content  # EPSS value from test-002

        # React dashboard has root div for mounting
        assert '<div id="root"></div>' in html_content or 'id="root"' in html_content

    @patch("scripts.core.priority_calculator.EPSSClient")
    @patch("scripts.core.priority_calculator.KEVClient")
    def test_enrichment_without_cves(
        self, mock_kev_client_class, mock_epss_client_class
    ):
        """Test that enrichment handles findings without CVEs gracefully."""
        # Mock clients
        mock_epss_client = Mock()
        mock_epss_client.get_scores_bulk.return_value = {}
        mock_epss_client_class.return_value = mock_epss_client

        mock_kev_client = Mock()
        mock_kev_client.is_kev.return_value = False
        mock_kev_client_class.return_value = mock_kev_client

        # Create findings without CVEs
        findings = [
            {
                "id": "test-001",
                "ruleId": "hardcoded-secret",
                "severity": "HIGH",
                "message": "Hardcoded API key detected",
                "location": {"path": "config.py", "startLine": 10},
                "tool": {"name": "trufflehog", "version": "3.63.0"},
            }
        ]

        # Enrich
        _enrich_with_priority(findings)

        # Verify finding has priority (severity-only)
        assert "priority" in findings[0]
        assert findings[0]["priority"]["priority"] > 0
        assert findings[0]["priority"]["epss"] is None
        assert findings[0]["priority"]["is_kev"] is False

    @patch("scripts.core.priority_calculator.EPSSClient")
    @patch("scripts.core.priority_calculator.KEVClient")
    def test_bulk_priority_calculation_performance(
        self, mock_kev_client_class, mock_epss_client_class
    ):
        """Test that bulk calculation is used for performance."""
        # Mock clients
        mock_epss_client = Mock()

        # Mock get_score for individual calls (fallback)
        def mock_get_score(cve):
            return EPSSScore(cve=cve, epss=0.5, percentile=0.8, date="2024-10-01")

        mock_epss_client.get_score.side_effect = mock_get_score

        # Mock get_scores_bulk for bulk calls
        mock_epss_client.get_scores_bulk.return_value = {
            f"CVE-2024-{i:04d}": EPSSScore(
                cve=f"CVE-2024-{i:04d}", epss=0.5, percentile=0.8, date="2024-10-01"
            )
            for i in range(100)
        }
        mock_epss_client_class.return_value = mock_epss_client

        mock_kev_client = Mock()
        mock_kev_client.is_kev.return_value = False
        mock_kev_client_class.return_value = mock_kev_client

        # Create 100 findings with CVEs
        findings = [
            {
                "id": f"test-{i:03d}",
                "ruleId": f"CVE-2024-{i:04d}",
                "severity": "HIGH",
                "message": f"Vulnerability {i}",
                "location": {"path": f"app/file{i}.py", "startLine": 10},
                "tool": {"name": "trivy", "version": "0.50.0"},
            }
            for i in range(100)
        ]

        # Enrich
        _enrich_with_priority(findings)

        # Verify bulk API was called (not individual calls)
        mock_epss_client.get_scores_bulk.assert_called_once()

        # Verify all findings enriched
        assert all("priority" in f for f in findings)

    @patch("scripts.core.priority_calculator.EPSSClient")
    @patch("scripts.core.priority_calculator.KEVClient")
    def test_priority_score_ranges(self, mock_kev_client_class, mock_epss_client_class):
        """Test that priority scores fall within expected ranges."""
        # Mock clients
        mock_epss_client = Mock()
        mock_epss_client.get_scores_bulk.return_value = {}
        mock_epss_client_class.return_value = mock_epss_client

        mock_kev_client = Mock()
        mock_kev_client.is_kev.return_value = False
        mock_kev_client_class.return_value = mock_kev_client

        # Test different severity levels
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        findings = [
            {
                "id": f"test-{i}",
                "ruleId": f"rule-{i}",
                "severity": sev,
                "message": f"{sev} issue",
                "location": {"path": "app/main.py", "startLine": 10},
                "tool": {"name": "semgrep", "version": "1.45.0"},
            }
            for i, sev in enumerate(severities)
        ]

        # Enrich
        _enrich_with_priority(findings)

        # Verify priority scores decrease with severity
        priorities = [f["priority"]["priority"] for f in findings]

        # CRITICAL should have higher priority than INFO
        assert priorities[0] > priorities[-1]

        # All priorities should be in range [0, 100]
        assert all(0 <= p <= 100 for p in priorities)
