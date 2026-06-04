#!/usr/bin/env python3
"""
Secrets Management Audit Tests for JMo Security.

Tests that the codebase follows security best practices for secrets management:
- No hardcoded API keys, tokens, or credentials
- Environment variable usage for sensitive data
- .gitignore coverage for sensitive files
- Pre-commit hooks prevent secret commits
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest


@pytest.mark.timeout(300)  # These tests scan the codebase and can be slow
class TestSecretsManagement:
    """Test secrets management and credential handling."""

    def test_no_hardcoded_api_keys_in_python(self):
        """Test that Python files don't contain hardcoded API keys.

        Scans for common patterns indicating hardcoded credentials.
        """
        # Patterns indicating hardcoded secrets
        secret_patterns = [
            r'api_key\s*=\s*["\'][A-Za-z0-9_\-]{20,}["\']',  # API key assignment
            r'secret_key\s*=\s*["\'][A-Za-z0-9_\-]{20,}["\']',  # Secret key assignment
            r'password\s*=\s*["\'].+["\']',  # Password assignment (literal)
            r'token\s*=\s*["\'][A-Za-z0-9_\-]{20,}["\']',  # Token assignment
            r"bearer\s+[A-Za-z0-9_\-]{20,}",  # Bearer token
            r'Authorization:\s*["\']Bearer\s+[A-Za-z0-9_\-]{20,}["\']',  # Auth header
        ]

        # Directories to scan
        scan_dirs = [
            Path("scripts/cli"),
            Path("scripts/core"),
            Path("scripts/dev"),
        ]

        findings = []

        for scan_dir in scan_dirs:
            if not scan_dir.exists():
                continue

            for py_file in scan_dir.rglob("*.py"):
                # Skip __pycache__ and test files
                if "__pycache__" in str(py_file) or "test_" in py_file.name:
                    continue

                content = py_file.read_text()
                lines = content.split("\n")

                for line_num, line in enumerate(lines, 1):
                    # Skip comments and docstrings
                    if line.strip().startswith("#") or '"""' in line or "'''" in line:
                        continue

                    for pattern in secret_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            findings.append(
                                f"{py_file}:{line_num} | {line.strip()[:80]}"
                            )

        # Should find no hardcoded secrets
        assert (
            len(findings) == 0
        ), f"Found {len(findings)} potential hardcoded secrets:\n" + "\n".join(
            findings[:5]
        )  # Show first 5 findings

    def test_environment_variable_usage_for_tokens(self):
        """Test that code uses environment variables for sensitive data.

        Validates that os.environ or os.getenv is used for tokens/keys.
        """
        # Files that should use environment variables
        sensitive_modules = [
            Path("scripts/core/email_service.py"),  # Email API keys
            Path("scripts/cli/scan_jobs/gitlab_scanner.py"),  # GitLab tokens
        ]

        for module in sensitive_modules:
            if not module.exists():
                # Module doesn't exist, skip
                continue

            content = module.read_text()

            # Should use os.environ or os.getenv for sensitive data
            uses_env_vars = (
                "os.environ" in content
                or "os.getenv" in content
                or "${" in content  # Shell-style env var
            )

            assert (
                uses_env_vars
            ), f"{module} should use environment variables for sensitive data"

    def test_gitignore_covers_sensitive_files(self):
        """Test that .gitignore covers common sensitive file patterns.

        Validates that credentials, secrets, and sensitive files are gitignored.
        """
        gitignore_path = Path(".gitignore")
        assert gitignore_path.exists(), ".gitignore must exist"

        gitignore_content = gitignore_path.read_text()

        # Critical patterns that MUST be gitignored
        required_patterns = [
            ".env",  # Environment variable files
            "*.pem",  # Private keys
            "*.key",  # Key files
            "*secret*",  # Files containing "secret"
            "*credentials*",  # Credentials files
        ]

        for pattern in required_patterns:
            assert (
                pattern in gitignore_content
                or pattern.replace("*", "") in gitignore_content
            ), f".gitignore must include pattern: {pattern}"

    def test_pre_commit_hooks_prevent_secrets(self):
        """Test that pre-commit hooks include secret detection.

        Validates that pre-commit config includes detect-private-key hook.
        """
        pre_commit_config = Path(".pre-commit-config.yaml")
        assert pre_commit_config.exists(), ".pre-commit-config.yaml must exist"

        config_content = pre_commit_config.read_text()

        # Should include detect-private-key hook
        assert (
            "detect-private-key" in config_content
        ), "pre-commit config must include detect-private-key hook"

    def test_trufflehog_scan_no_verified_secrets(self):
        """Test that TruffleHog doesn't find verified secrets in production code.

        Runs TruffleHog scanner and validates no verified secrets detected.
        """
        # Scan production directories only
        scan_dirs = ["scripts/", "tests/", ".github/"]

        try:
            result = subprocess.run(
                ["trufflehog", "filesystem"] + scan_dirs + ["--json", "--no-update"],
                capture_output=True,
                text=True,
                timeout=60,
            )

            # Parse findings
            findings = []
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue

                try:
                    finding = json.loads(line)
                    file_path = (
                        finding.get("SourceMetadata", {})
                        .get("Data", {})
                        .get("Filesystem", {})
                        .get("file", "")
                    )

                    # Skip non-Python files and dependencies
                    if (
                        "node_modules" in file_path
                        or ".git/" in file_path
                        or not file_path.endswith(".py")
                    ):
                        continue

                    # Check if verified (real secret)
                    if finding.get("Verified", False):
                        findings.append(
                            {
                                "file": file_path,
                                "detector": finding.get("DetectorName", "Unknown"),
                                "line": finding.get("SourceMetadata", {})
                                .get("Data", {})
                                .get("Filesystem", {})
                                .get("line", 0),
                            }
                        )
                except json.JSONDecodeError:
                    continue

            # Should find no verified secrets
            assert len(findings) == 0, (
                f"TruffleHog found {len(findings)} verified secrets in production code:\n"
                + "\n".join(str(f) for f in findings)
            )

        except FileNotFoundError:
            pytest.skip("TruffleHog not installed (optional security tool)")
        except subprocess.TimeoutExpired:
            pytest.fail("TruffleHog scan timed out after 60 seconds")

    def test_no_aws_credentials_in_code(self):
        """Test that AWS credentials are not hardcoded in code.

        Validates no AWS access keys, secret keys, or session tokens in code.
        """
        # AWS credential patterns
        aws_patterns = [
            r"AKIA[0-9A-Z]{16}",  # AWS Access Key ID
            r"aws_access_key_id\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]",  # Access key
            r"aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]",  # Secret
        ]

        scan_dirs = [
            Path("scripts"),
            Path(".github"),
        ]

        findings = []

        for scan_dir in scan_dirs:
            if not scan_dir.exists():
                continue

            for file in scan_dir.rglob("*"):
                # Skip binary files, cache, dependencies, and test fixtures
                if (
                    file.is_dir()
                    or "__pycache__" in str(file)
                    or "node_modules" in str(file)
                    or "/tests/" in str(file)  # Skip ALL test files and fixtures
                    or file.suffix in [".pyc", ".pyo", ".so", ".whl", ".sh"]
                ):
                    continue

                try:
                    content = file.read_text()
                except (UnicodeDecodeError, PermissionError):
                    continue

                lines = content.split("\n")
                for line_num, line in enumerate(lines, 1):
                    for pattern in aws_patterns:
                        if re.search(pattern, line):
                            findings.append(f"{file}:{line_num} | {line.strip()[:80]}")

        # Should find no AWS credentials
        assert (
            len(findings) == 0
        ), f"Found {len(findings)} potential AWS credentials:\n" + "\n".join(
            findings[:5]
        )

    def test_no_github_tokens_in_code(self):
        """Test that GitHub Personal Access Tokens are not hardcoded.

        Validates no GitHub tokens (ghp_, gho_, ghs_, ghr_) in code.
        """
        # GitHub token patterns
        github_patterns = [
            r"ghp_[A-Za-z0-9]{36}",  # Personal Access Token
            r"gho_[A-Za-z0-9]{36}",  # OAuth Access Token
            r"ghs_[A-Za-z0-9]{36}",  # Server-to-Server Token
            r"ghr_[A-Za-z0-9]{36}",  # Refresh Token
        ]

        scan_dirs = [
            Path("scripts"),
            Path(".github"),
        ]

        findings = []

        for scan_dir in scan_dirs:
            if not scan_dir.exists():
                continue

            for file in scan_dir.rglob("*"):
                if (
                    file.is_dir()
                    or "__pycache__" in str(file)
                    or file.suffix in [".pyc", ".pyo"]
                ):
                    continue

                try:
                    content = file.read_text()
                except (UnicodeDecodeError, PermissionError):
                    continue

                lines = content.split("\n")
                for line_num, line in enumerate(lines, 1):
                    for pattern in github_patterns:
                        if re.search(pattern, line):
                            findings.append(f"{file}:{line_num} | {line.strip()[:80]}")

        # Should find no GitHub tokens
        assert (
            len(findings) == 0
        ), f"Found {len(findings)} potential GitHub tokens:\n" + "\n".join(findings[:5])

    def test_no_database_connection_strings_in_code(self):
        """Test that database connection strings don't include credentials.

        Validates no hardcoded DB passwords in connection strings.
        """
        # Database connection patterns with embedded credentials
        db_patterns = [
            r"postgresql://[^:]+:[^@]+@",  # postgres://user:pass@host
            r"mysql://[^:]+:[^@]+@",  # mysql://user:pass@host
            r"mongodb://[^:]+:[^@]+@",  # mongodb://user:pass@host
            r"redis://[^:]+:[^@]+@",  # redis://user:pass@host
        ]

        scan_dirs = [Path("scripts")]

        findings = []

        for scan_dir in scan_dirs:
            if not scan_dir.exists():
                continue

            for py_file in scan_dir.rglob("*.py"):
                if "__pycache__" in str(py_file) or "test_secrets_management.py" in str(
                    py_file
                ):  # Skip self
                    continue

                content = py_file.read_text()
                lines = content.split("\n")

                for line_num, line in enumerate(lines, 1):
                    # Skip comments and regex pattern definitions
                    if (
                        line.strip().startswith("#")
                        or 'r"' in line  # Skip raw string definitions (regex patterns)
                        or "# Skip" in line
                    ):
                        continue

                    for pattern in db_patterns:
                        if re.search(pattern, line):
                            findings.append(
                                f"{py_file}:{line_num} | {line.strip()[:80]}"
                            )

        # Should find no hardcoded DB credentials
        assert len(findings) == 0, (
            f"Found {len(findings)} potential DB connection strings with credentials:\n"
            + "\n".join(findings[:5])
        )


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v", "--tb=short"])
