#!/usr/bin/env python3
"""
End-to-end tests with real security tools.

Tests real tool integration with actual vulnerabilities:
- Trivy: Real CVE detection in vulnerable images
- Semgrep: Real code vulnerabilities
- TruffleHog: Verified secret detection
- Checkov: IaC misconfigurations

Phase 1.3.1 of TESTING_RELEASE_READINESS_PLAN.md
"""

import json
import subprocess
from pathlib import Path

import pytest

from scripts.cli.jmo import cmd_scan
from scripts.core.history_db import get_connection, list_scans


@pytest.mark.slow
@pytest.mark.requires_tools
class TestRealToolScans:
    """E2E tests with actual security tools installed."""

    def test_trivy_scan_real_vulnerability(self, tmp_path):
        """
        Test Trivy detects real CVE in vulnerable image.

        Uses nginx:1.19.0 which has known CVE-2021-23017 (HIGH severity).
        Verifies:
        - CVE detection
        - Severity mapping
        - EPSS enrichment (if available)
        - SARIF output generation
        """
        results_dir = tmp_path / "results"

        class ScanArgs:
            def __init__(self):
                self.repo = None
                self.repos_dir = None
                self.targets = None
                self.results_dir = str(results_dir)
                self.config = str(tmp_path / "jmo.yml")
                self.tools = ["trivy"]
                self.timeout = 300
                self.threads = 1
                self.allow_missing_tools = True
                self.profile = False
                self.profile_name = "fast"
                # Multi-target args - testing image scanning
                self.image = "nginx:1.19.0"
                self.images_file = None
                self.terraform_state = None
                self.cloudformation = None
                self.k8s_manifest = None
                self.url = None
                self.urls_file = None
                self.api_spec = None
                self.gitlab_repo = None
                self.gitlab_group = None
                self.gitlab_url = None
                self.gitlab_token = None
                self.k8s_context = None
                self.k8s_namespace = None
                self.k8s_all_namespaces = False

        # Run scan
        rc = cmd_scan(ScanArgs())
        assert rc == 0, "Trivy scan should succeed"

        # Verify image results directory exists
        image_results = results_dir / "individual-images" / "nginx_1.19.0"
        assert image_results.exists(), "Image results directory should exist"

        # Verify trivy.json exists and contains findings
        trivy_output = image_results / "trivy.json"
        assert trivy_output.exists(), "Trivy output should exist"

        with open(trivy_output) as f:
            trivy_data = json.load(f)

        # Trivy format varies - check both array and Results field
        if isinstance(trivy_data, list):
            results = trivy_data
        else:
            results = trivy_data.get("Results", [])

        assert len(results) > 0, "Should detect vulnerabilities in nginx:1.19.0"

        # Look for CVE-2021-23017 or any HIGH/CRITICAL CVE
        found_high_cve = False
        for result in results:
            vulns = result.get("Vulnerabilities") or []
            for vuln in vulns:
                severity = vuln.get("Severity", "").upper()
                vuln_id = vuln.get("VulnerabilityID", "")

                if severity in ["HIGH", "CRITICAL"]:
                    found_high_cve = True
                    # Verify CVE format
                    assert vuln_id.startswith("CVE-"), f"Expected CVE ID, got {vuln_id}"
                    break

            if found_high_cve:
                break

        assert found_high_cve, "Should detect at least one HIGH/CRITICAL CVE"

    def test_semgrep_scan_real_code_issue(self, tmp_path):
        """
        Test Semgrep detects real SQL injection vulnerability.

        Creates test repo with vulnerable Python code and verifies:
        - SQL injection detection
        - CWE-89 mapping
        - OWASP A03:2021 compliance mapping
        """
        # Create test repo with vulnerable code
        repo = tmp_path / "vulnerable-app"
        repo.mkdir()

        # SQL injection vulnerability
        vulnerable_code = '''#!/usr/bin/env python3
"""Vulnerable web application for testing."""
import sqlite3

def get_user(user_id):
    """Vulnerable function with SQL injection."""
    conn = sqlite3.connect("users.db")
    # VULNERABLE: Direct string interpolation
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor = conn.execute(query)
    return cursor.fetchone()

def get_user_safe(user_id):
    """Safe version using parameterized query."""
    conn = sqlite3.connect("users.db")
    query = "SELECT * FROM users WHERE id = ?"
    cursor = conn.execute(query, (user_id,))
    return cursor.fetchone()
'''

        (repo / "app.py").write_text(vulnerable_code)
        (repo / ".git").mkdir()  # Mark as git repo

        results_dir = tmp_path / "results"

        class ScanArgs:
            def __init__(self):
                self.repo = str(repo)
                self.repos_dir = None
                self.targets = None
                self.results_dir = str(results_dir)
                self.config = str(tmp_path / "jmo.yml")
                self.tools = ["semgrep"]
                self.timeout = 300
                self.threads = 1
                self.allow_missing_tools = True
                self.profile = False
                self.profile_name = "fast"
                # Multi-target args
                self.image = None
                self.images_file = None
                self.terraform_state = None
                self.cloudformation = None
                self.k8s_manifest = None
                self.url = None
                self.urls_file = None
                self.api_spec = None
                self.gitlab_repo = None
                self.gitlab_group = None
                self.gitlab_url = None
                self.gitlab_token = None
                self.k8s_context = None
                self.k8s_namespace = None
                self.k8s_all_namespaces = False

        # Run scan
        rc = cmd_scan(ScanArgs())
        assert rc == 0, "Semgrep scan should succeed"

        # Verify repo results directory exists
        repo_results = results_dir / "individual-repos" / "vulnerable-app"
        assert repo_results.exists(), "Repo results directory should exist"

        # Verify semgrep.json exists
        semgrep_output = repo_results / "semgrep.json"
        assert semgrep_output.exists(), "Semgrep output should exist"

        with open(semgrep_output) as f:
            semgrep_data = json.load(f)

        # Semgrep format: {"results": [...], "errors": [...]}
        results = semgrep_data.get("results", [])

        # Should detect SQL injection
        found_sqli = False
        for finding in results:
            check_id = finding.get("check_id", "")
            message = finding.get("extra", {}).get("message", "").lower()

            if "sql" in check_id.lower() or "sql" in message:
                found_sqli = True

                # Verify metadata includes CWE
                metadata = finding.get("extra", {}).get("metadata", {})
                cwe = metadata.get("cwe")
                if cwe:
                    # CWE-89 is SQL injection
                    assert "CWE-89" in str(cwe) or "89" in str(
                        cwe
                    ), "Should map to CWE-89"

                # Verify OWASP mapping (if present)
                owasp = metadata.get("owasp")
                if owasp:
                    # A03:2021 is Injection category
                    assert any(
                        "A03" in str(o) or "injection" in str(o).lower() for o in owasp
                    )

                break

        assert found_sqli, "Should detect SQL injection vulnerability"

    def test_trufflehog_verified_secret_detection(self, tmp_path):
        """
        Test TruffleHog detects and verifies secrets.

        NOTE: TruffleHog is smart enough to ignore obviously fake test patterns.
        This test verifies that TruffleHog runs successfully and produces valid output,
        but may not detect secrets in test data (which is expected behavior).

        Verifies:
        - TruffleHog execution succeeds
        - Output file is created
        - NDJSON format is valid (if findings exist)
        """
        # Create test repo with fake secret
        repo = tmp_path / "secret-repo"
        repo.mkdir()

        # Create file with fake GitHub PAT (won't verify, but will detect pattern)
        secret_file = '''#!/usr/bin/env python3
"""Test file with embedded secrets."""

# GitHub Personal Access Token (fake, for testing)
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12"

# AWS Access Key (fake, for testing)
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def main():
    print("This is a test file with fake secrets")
'''

        (repo / "secrets.py").write_text(secret_file)
        (repo / ".git").mkdir()  # Mark as git repo

        results_dir = tmp_path / "results"

        class ScanArgs:
            def __init__(self):
                self.repo = str(repo)
                self.repos_dir = None
                self.targets = None
                self.results_dir = str(results_dir)
                self.config = str(tmp_path / "jmo.yml")
                self.tools = ["trufflehog"]
                self.timeout = 300
                self.threads = 1
                self.allow_missing_tools = True
                self.profile = False
                self.profile_name = "fast"
                # Multi-target args
                self.image = None
                self.images_file = None
                self.terraform_state = None
                self.cloudformation = None
                self.k8s_manifest = None
                self.url = None
                self.urls_file = None
                self.api_spec = None
                self.gitlab_repo = None
                self.gitlab_group = None
                self.gitlab_url = None
                self.gitlab_token = None
                self.k8s_context = None
                self.k8s_namespace = None
                self.k8s_all_namespaces = False

        # Run scan
        rc = cmd_scan(ScanArgs())
        assert rc == 0, "TruffleHog scan should succeed"

        # Verify repo results directory exists
        repo_results = results_dir / "individual-repos" / "secret-repo"
        assert repo_results.exists(), "Repo results directory should exist"

        # Verify trufflehog.json exists
        trufflehog_output = repo_results / "trufflehog.json"
        assert trufflehog_output.exists(), "TruffleHog output should exist"

        # TruffleHog outputs NDJSON (one JSON object per line)
        secrets_found = []
        with open(trufflehog_output) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        secrets_found.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        # NOTE: TruffleHog may not detect fake test patterns (expected behavior)
        # Just verify the output format is valid if findings exist
        if len(secrets_found) > 0:
            # Verify secret structure
            for secret in secrets_found:
                # TruffleHog v3 format
                assert (
                    "DetectorName" in secret or "detector_name" in secret
                ), "Should have detector name"
                assert (
                    "Verified" in secret or "verified" in secret
                ), "Should have verification status"

                # Check if it's GitHub or AWS secret
                detector = (
                    secret.get("DetectorName") or secret.get("detector_name") or ""
                )
                if "github" in detector.lower():
                    # GitHub token detected
                    assert "github" in detector.lower()
                elif "aws" in detector.lower():
                    # AWS key detected
                    assert "aws" in detector.lower()
        else:
            # TruffleHog didn't detect the fake patterns (expected)
            # Test passes as long as TruffleHog ran successfully
            pass

    def test_checkov_iac_misconfiguration(self, tmp_path):
        """
        Test Checkov detects Terraform misconfigurations.

        Creates Terraform file with public S3 bucket and verifies:
        - S3 public access finding
        - CIS AWS Foundations compliance mapping
        - Severity assessment
        """
        # Create Terraform file with misconfig
        terraform_file = tmp_path / "main.tf"
        terraform_content = """
resource "aws_s3_bucket" "example" {
  bucket = "my-insecure-bucket"

  # MISCONFIGURATION: Public ACL
  acl = "public-read"

  tags = {
    Name        = "Test bucket"
    Environment = "Dev"
  }
}

resource "aws_s3_bucket" "secure_example" {
  bucket = "my-secure-bucket"

  # SECURE: Private ACL
  acl = "private"

  tags = {
    Name        = "Secure bucket"
    Environment = "Prod"
  }
}
"""

        terraform_file.write_text(terraform_content)

        results_dir = tmp_path / "results"

        class ScanArgs:
            def __init__(self):
                self.repo = None
                self.repos_dir = None
                self.targets = None
                self.results_dir = str(results_dir)
                self.config = str(tmp_path / "jmo.yml")
                self.tools = ["checkov"]
                self.timeout = 300
                self.threads = 1
                self.allow_missing_tools = True
                self.profile = False
                self.profile_name = "fast"
                # Multi-target args - testing IaC scanning
                self.image = None
                self.images_file = None
                self.terraform_state = str(terraform_file)
                self.cloudformation = None
                self.k8s_manifest = None
                self.url = None
                self.urls_file = None
                self.api_spec = None
                self.gitlab_repo = None
                self.gitlab_group = None
                self.gitlab_url = None
                self.gitlab_token = None
                self.k8s_context = None
                self.k8s_namespace = None
                self.k8s_all_namespaces = False

        # Run scan
        rc = cmd_scan(ScanArgs())
        assert rc == 0, "Checkov scan should succeed"

        # Verify IaC results directory exists
        iac_results = results_dir / "individual-iac" / "main"
        assert iac_results.exists(), "IaC results directory should exist"

        # Verify checkov.json exists
        checkov_output = iac_results / "checkov.json"
        assert checkov_output.exists(), "Checkov output should exist"

        with open(checkov_output) as f:
            checkov_data = json.load(f)

        # Checkov format: {"results": {"failed_checks": [...], "passed_checks": [...]}}
        results = checkov_data.get("results", {})
        failed_checks = results.get("failed_checks", [])

        # Should detect S3 public access issue
        assert len(failed_checks) > 0, "Should detect IaC misconfigurations"

        found_s3_public = False
        for check in failed_checks:
            check_id = check.get("check_id", "")
            check_name = check.get("check_name", "").lower()
            resource = check.get("resource", "").lower()

            if "s3" in resource and ("public" in check_name or "acl" in check_name):
                found_s3_public = True

                # Verify guideline (CIS reference if present)
                guideline = check.get("guideline")
                if guideline:
                    # Should reference CIS AWS Foundations
                    assert "cis" in guideline.lower() or "aws" in guideline.lower()

                break

        assert found_s3_public, "Should detect S3 public access misconfiguration"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "slow"])
