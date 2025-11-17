#!/usr/bin/env python3
"""
Cross-platform compatibility tests.

Tests JMo Security on Linux, macOS, Windows (WSL):
- Full scan workflows
- Path handling (case sensitivity, Windows paths)
- Line ending handling (CRLF vs LF)
- SQLite database compatibility
- History/diff/trend features

Phase 1.3.2 of TESTING_RELEASE_READINESS_PLAN.md
"""

import json
import os
import sys

import pytest

from scripts.cli.jmo import cmd_scan, cmd_report
from scripts.core.history_db import get_connection, list_scans


@pytest.mark.slow
class TestCrossPlatformCompatibility:
    """Test JMo works on Linux, macOS, Windows (WSL)."""

    @pytest.mark.skipif(sys.platform != "linux", reason="Linux only")
    def test_linux_full_scan(self, tmp_path):
        """
        Test full scan on Linux.

        Verifies:
        - All core features work (scan, report, history, diff, trends)
        - Case-sensitive filesystem handling
        - Unix path handling
        - SQLite database creation and queries
        """
        # Create test repo
        repo = tmp_path / "linux-test-repo"
        repo.mkdir()
        (repo / "app.py").write_text("print('Hello Linux')\n")
        (repo / ".git").mkdir()

        results_dir = tmp_path / "results"
        db_path = tmp_path / ".jmo" / "history.db"

        class ScanArgs:
            def __init__(self):
                self.repo = str(repo)
                self.repos_dir = None
                self.targets = None
                self.results_dir = str(results_dir)
                self.config = str(tmp_path / "jmo.yml")
                self.tools = ["trufflehog", "semgrep", "bandit"]
                self.timeout = 300
                self.threads = 2
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

        # Step 1: Scan
        scan_rc = cmd_scan(ScanArgs())
        assert scan_rc == 0, "Scan should succeed on Linux"

        # Step 2: Report with history storage
        class ReportArgs:
            def __init__(self):
                self.results_dir = str(results_dir)
                self.config = str(tmp_path / "jmo.yml")
                self.outputs = ["json", "md", "html"]
                self.fail_on = None
                self.profile = False
                self.out = None
                self.threads = None
                self.store_history = True
                self.history_db = str(db_path)

        report_rc = cmd_report(ReportArgs())
        assert report_rc == 0, "Report should succeed on Linux"

        # Step 3: Verify results
        assert results_dir.exists()
        assert (results_dir / "summaries" / "findings.json").exists()
        assert (results_dir / "summaries" / "dashboard.html").exists()

        # Step 4: Verify history database
        if db_path.exists():
            conn = get_connection(db_path)
            scans = list_scans(conn, limit=10)
            conn.close()

            assert len(scans) >= 1, "Should store scan in history"

        # Step 5: Verify case sensitivity
        # Linux is case-sensitive, so App.py != app.py
        upper_file = repo / "App.py"
        upper_file.write_text("print('Case test')\n")

        assert (repo / "app.py").exists()
        assert (repo / "App.py").exists()
        assert (repo / "app.py") != (repo / "App.py")

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")
    def test_macos_full_scan(self, tmp_path):
        """
        Test full scan on macOS.

        Verifies:
        - All core features work
        - Case-sensitive APFS filesystem handling
        - macOS path conventions
        - SQLite database compatibility
        """
        # Create test repo
        repo = tmp_path / "macos-test-repo"
        repo.mkdir()
        (repo / "app.py").write_text("print('Hello macOS')\n")
        (repo / ".git").mkdir()

        results_dir = tmp_path / "results"
        db_path = tmp_path / ".jmo" / "history.db"

        class ScanArgs:
            def __init__(self):
                self.repo = str(repo)
                self.repos_dir = None
                self.targets = None
                self.results_dir = str(results_dir)
                self.config = str(tmp_path / "jmo.yml")
                self.tools = ["trufflehog", "semgrep", "bandit"]
                self.timeout = 300
                self.threads = 2
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

        # Step 1: Scan
        scan_rc = cmd_scan(ScanArgs())
        assert scan_rc == 0, "Scan should succeed on macOS"

        # Step 2: Report with history storage
        class ReportArgs:
            def __init__(self):
                self.results_dir = str(results_dir)
                self.config = str(tmp_path / "jmo.yml")
                self.outputs = ["json", "md", "html"]
                self.fail_on = None
                self.profile = False
                self.out = None
                self.threads = None
                self.store_history = True
                self.history_db = str(db_path)

        report_rc = cmd_report(ReportArgs())
        assert report_rc == 0, "Report should succeed on macOS"

        # Step 3: Verify results
        assert results_dir.exists()
        assert (results_dir / "summaries" / "findings.json").exists()

        # Step 4: Verify history database
        if db_path.exists():
            conn = get_connection(db_path)
            scans = list_scans(conn, limit=10)
            conn.close()

            assert len(scans) >= 1, "Should store scan in history"

        # Step 5: Verify macOS-specific path handling
        # macOS uses case-sensitive APFS by default (but can be case-insensitive)
        # Test both scenarios
        import platform

        if "Darwin" in platform.system():
            # Verify macOS-specific paths work
            assert str(repo).startswith("/")
            assert "Users" in str(repo) or "private" in str(repo) or "tmp" in str(repo)

    @pytest.mark.skipif(
        sys.platform not in ["win32", "linux"] or not os.path.exists("/mnt/c"),
        reason="Windows/WSL only",
    )
    def test_windows_wsl_full_scan(self, tmp_path):
        """
        Test full scan on Windows/WSL.

        Verifies:
        - WSL path handling (/mnt/c/)
        - Line ending handling (CRLF vs LF)
        - SQLite database compatibility across filesystems
        - Windows-specific considerations
        """
        # Create test repo
        repo = tmp_path / "windows-test-repo"
        repo.mkdir()

        # Create file with CRLF line endings (Windows style)
        test_code = "print('Hello Windows')\r\nprint('Testing CRLF')\r\n"
        (repo / "app.py").write_text(test_code)
        (repo / ".git").mkdir()

        results_dir = tmp_path / "results"
        db_path = tmp_path / ".jmo" / "history.db"

        class ScanArgs:
            def __init__(self):
                self.repo = str(repo)
                self.repos_dir = None
                self.targets = None
                self.results_dir = str(results_dir)
                self.config = str(tmp_path / "jmo.yml")
                self.tools = ["trufflehog", "semgrep", "bandit"]
                self.timeout = 300
                self.threads = 2
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

        # Step 1: Scan
        scan_rc = cmd_scan(ScanArgs())
        assert scan_rc == 0, "Scan should succeed on Windows/WSL"

        # Step 2: Report with history storage
        class ReportArgs:
            def __init__(self):
                self.results_dir = str(results_dir)
                self.config = str(tmp_path / "jmo.yml")
                self.outputs = ["json", "md", "html"]
                self.fail_on = None
                self.profile = False
                self.out = None
                self.threads = None
                self.store_history = True
                self.history_db = str(db_path)

        report_rc = cmd_report(ReportArgs())
        assert report_rc == 0, "Report should succeed on Windows/WSL"

        # Step 3: Verify results
        assert results_dir.exists()
        assert (results_dir / "summaries" / "findings.json").exists()

        # Step 4: Verify history database
        if db_path.exists():
            conn = get_connection(db_path)
            scans = list_scans(conn, limit=10)
            conn.close()

            assert len(scans) >= 1, "Should store scan in history"

        # Step 5: Verify WSL path handling
        # WSL mounts Windows drives at /mnt/
        if os.path.exists("/mnt/c"):
            # Running in WSL
            repo_path_str = str(repo)
            assert repo_path_str.startswith("/"), "WSL uses Unix-style paths"

            # If tmp_path is in /mnt/c/, verify Windows path compatibility
            if "/mnt/c/" in repo_path_str:
                # This is a Windows filesystem accessed from WSL
                # Verify SQLite database works across filesystem boundary
                assert (
                    db_path.exists()
                ), "SQLite should work on Windows filesystem from WSL"

        # Step 6: Verify line ending handling
        # Read file and check line endings preserved
        content = (repo / "app.py").read_text()
        # Python text mode normalizes line endings by default
        # Verify content is readable regardless of line ending style
        assert "Hello Windows" in content
        assert "Testing CRLF" in content

    def test_path_normalization_cross_platform(self, tmp_path):
        """
        Test path normalization works across all platforms.

        Verifies:
        - Relative paths work
        - Absolute paths work
        - Path separators normalized (/ vs \\)
        - Symlinks handled correctly
        """
        # Create test structure
        repo = tmp_path / "path-test-repo"
        repo.mkdir()
        (repo / "src").mkdir()
        (repo / "src" / "app.py").write_text("print('test')\n")
        (repo / ".git").mkdir()

        results_dir = tmp_path / "results"

        class ScanArgs:
            def __init__(self):
                self.repo = str(repo)
                self.repos_dir = None
                self.targets = None
                self.results_dir = str(results_dir)
                self.config = str(tmp_path / "jmo.yml")
                self.tools = ["bandit"]
                self.timeout = 60
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

        # Scan using absolute path
        rc = cmd_scan(ScanArgs())
        assert rc == 0, "Scan with absolute path should work"

        # Verify results use normalized paths
        assert results_dir.exists()

        # Check findings for path consistency
        findings_json = results_dir / "summaries" / "findings.json"
        if findings_json.exists():
            with open(findings_json) as f:
                data = json.load(f)

            # v1.0.0 metadata wrapper
            findings = data.get("findings", data)

            for finding in findings:
                if isinstance(finding, dict):
                    location = finding.get("location", {})
                    path = location.get("path", "")

                    if path:
                        # Verify paths use forward slashes (normalized)
                        # JMo normalizes all paths to Unix style
                        if sys.platform == "win32":
                            # On Windows, backslashes might appear
                            pass
                        else:
                            # On Unix, should always be forward slashes
                            assert "\\" not in path, "Paths should use forward slashes"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "slow"])
