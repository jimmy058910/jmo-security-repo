"""
Pytest fixtures for MCP server tests.

Provides sample findings data, temporary directories, and mock utilities.
"""

import json
from pathlib import Path
from typing import Dict, Any, List
import pytest


@pytest.fixture
def sample_findings() -> List[Dict[str, Any]]:
    """Sample findings data for testing (CommonFinding schema v1.2.0)."""
    return [
        {
            "schemaVersion": "1.2.0",
            "id": "fingerprint-abc123",
            "ruleId": "CWE-79",
            "severity": "HIGH",
            "tool": {"name": "semgrep", "version": "1.45.0"},
            "location": {
                "path": "src/app.js",
                "startLine": 42,
                "endLine": 42,
            },
            "message": "Potential XSS vulnerability in user input",
            "title": "Cross-Site Scripting (XSS)",
            "description": "User input is rendered without sanitization",
            "remediation": {
                "description": "Use a sanitization library like DOMPurify",
                "references": [
                    "https://owasp.org/www-community/attacks/xss/",
                    "https://cwe.mitre.org/data/definitions/79.html",
                ],
            },
            "risk": {
                "cwe": ["CWE-79"],
                "confidence": "HIGH",
                "likelihood": "MEDIUM",
                "impact": "HIGH",
            },
            "compliance": {
                "owaspTop10_2021": ["A03:2021"],
                "cweTop25_2024": [
                    {"id": "CWE-79", "rank": 2, "category": "Injection"}
                ],
            },
        },
        {
            "schemaVersion": "1.2.0",
            "id": "fingerprint-def456",
            "ruleId": "CWE-89",
            "severity": "CRITICAL",
            "tool": {"name": "semgrep", "version": "1.45.0"},
            "location": {
                "path": "src/db.py",
                "startLine": 120,
                "endLine": 122,
            },
            "message": "SQL injection vulnerability",
            "title": "SQL Injection",
            "description": "User input concatenated into SQL query",
            "remediation": {
                "description": "Use parameterized queries",
                "references": [
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                ],
            },
            "risk": {
                "cwe": ["CWE-89"],
                "confidence": "HIGH",
                "likelihood": "HIGH",
                "impact": "CRITICAL",
            },
            "compliance": {
                "owaspTop10_2021": ["A03:2021"],
                "cweTop25_2024": [
                    {"id": "CWE-89", "rank": 3, "category": "Injection"}
                ],
            },
        },
        {
            "schemaVersion": "1.2.0",
            "id": "fingerprint-ghi789",
            "ruleId": "secret-aws-key",
            "severity": "CRITICAL",
            "tool": {"name": "trufflehog", "version": "3.63.0"},
            "location": {
                "path": "config/settings.py",
                "startLine": 10,
                "endLine": 10,
            },
            "message": "AWS Access Key detected",
            "title": "Hardcoded AWS Credentials",
            "description": "AWS access key found in source code",
            "remediation": {
                "description": "Remove credentials and use environment variables or AWS IAM roles",
                "references": [
                    "https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html",
                ],
            },
            "risk": {
                "cwe": ["CWE-798"],
                "confidence": "HIGH",
                "likelihood": "HIGH",
                "impact": "CRITICAL",
            },
        },
        {
            "schemaVersion": "1.2.0",
            "id": "fingerprint-jkl012",
            "ruleId": "CVE-2023-12345",
            "severity": "MEDIUM",
            "tool": {"name": "trivy", "version": "0.48.0"},
            "location": {
                "path": "package.json",
                "startLine": 15,
                "endLine": 15,
            },
            "message": "Vulnerable dependency: lodash@4.17.19",
            "title": "Known Vulnerability in lodash",
            "description": "Prototype pollution vulnerability in lodash",
            "remediation": {
                "description": "Update lodash to version 4.17.21 or later",
                "references": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-12345",
                ],
            },
            "risk": {
                "cwe": ["CWE-1321"],
                "confidence": "HIGH",
                "likelihood": "MEDIUM",
                "impact": "MEDIUM",
            },
        },
        {
            "schemaVersion": "1.2.0",
            "id": "fingerprint-mno345",
            "ruleId": "bandit-B201",
            "severity": "LOW",
            "tool": {"name": "bandit", "version": "1.7.5"},
            "location": {
                "path": "tests/test_app.py",
                "startLine": 55,
                "endLine": 55,
            },
            "message": "Use of assert detected",
            "title": "Assert Statement Used",
            "description": "Assert statements are removed when Python is run with -O flag",
            "remediation": {
                "description": "Use proper exception handling instead of assert",
                "references": [],
            },
            "risk": {
                "cwe": [],
                "confidence": "MEDIUM",
                "likelihood": "LOW",
                "impact": "LOW",
            },
        },
    ]


@pytest.fixture
def results_dir_with_findings(tmp_path: Path, sample_findings: List[Dict[str, Any]]) -> Path:
    """Create a temporary results directory with findings.json."""
    results_dir = tmp_path / "results"
    summaries_dir = results_dir / "summaries"
    summaries_dir.mkdir(parents=True)

    # Write findings.json
    findings_file = summaries_dir / "findings.json"
    findings_file.write_text(json.dumps(sample_findings, indent=2))

    return results_dir


@pytest.fixture
def results_dir_empty(tmp_path: Path) -> Path:
    """Create a temporary results directory without findings.json."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    return results_dir


@pytest.fixture
def repo_root_with_files(tmp_path: Path) -> Path:
    """Create a temporary repository with source files."""
    repo_root = tmp_path / "repo"
    repo_root.mkdir()

    # Create sample source files
    src_dir = repo_root / "src"
    src_dir.mkdir()

    # Python file
    (src_dir / "app.py").write_text(
        """#!/usr/bin/env python3
import os

def hello(name):
    print(f"Hello, {name}!")

def vulnerable_function(user_input):
    # This is the vulnerable line (line 9)
    eval(user_input)  # CWE-95: Code injection

if __name__ == "__main__":
    hello("World")
"""
    )

    # JavaScript file
    (src_dir / "app.js").write_text(
        """const express = require('express');
const app = express();

app.get('/user', (req, res) => {
  const userInput = req.query.name;
  // Vulnerable line (line 6)
  res.send(`<h1>Hello, ${userInput}!</h1>`);  // CWE-79: XSS
});

app.listen(3000);
"""
    )

    # Config file
    config_dir = repo_root / "config"
    config_dir.mkdir()
    (config_dir / "settings.py").write_text(
        """import os

# Database configuration
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_PORT = int(os.getenv('DB_PORT', 5432))

# AWS Configuration (VULNERABLE - line 8)
AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'  # CWE-798: Hardcoded credentials
AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
"""
    )

    # Dockerfile
    (repo_root / "Dockerfile").write_text(
        """FROM python:3.11-slim

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "src/app.py"]
"""
    )

    # Binary file (should not be readable as text)
    binary_file = repo_root / "binary.bin"
    binary_file.write_bytes(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09")

    return repo_root


@pytest.fixture
def mock_mcp_server():
    """Mock FastMCP server for testing tools/resources."""
    # This will be used for integration tests when we mock the MCP framework
    pass
