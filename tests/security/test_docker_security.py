#!/usr/bin/env python3
"""
Docker Security Tests for JMo Security.

Tests that Dockerfiles and container configurations follow security best practices:
- Non-root user execution
- Multi-stage builds for minimal attack surface
- No hardcoded secrets or credentials
- Proper base image selection and versioning
- Minimal privilege configurations
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _dockerfiles() -> list[Path]:
    """Every Dockerfile at the repository root, never an empty list.

    Globbed and anchored to the repository. Each test used to list its own
    names relative to the working directory -- including `Dockerfile.slim` and
    `Dockerfile.alpine`, which v2.0.0 does not have -- and skip any that did
    not exist, so run from anywhere but the repository root they read no file
    and passed. An empty result would pass every check below, so it fails.
    """
    found = sorted(p for p in REPO_ROOT.glob("Dockerfile*") if p.is_file())
    assert "Dockerfile" in [p.name for p in found], (
        f"no production Dockerfile found at {REPO_ROOT}: {found}"
    )
    return found


class TestDockerSecurity:
    """Test Docker security configurations."""

    def test_dockerfiles_use_non_root_user(self):
        """Test that Dockerfiles configure non-root user execution.

        Security best practice: Containers should not run as root to minimize
        privilege escalation risks.
        """
        for dockerfile in _dockerfiles():
            content = dockerfile.read_text(encoding="utf-8")

            # Should specify USER directive (not root)
            has_user_directive = re.search(r"^USER\s+(?!root)", content, re.MULTILINE)
            assert has_user_directive, (
                f"{dockerfile} should specify non-root USER directive"
            )

    def test_dockerfiles_use_specific_base_image_tags(self):
        """Test that Dockerfiles use specific base image tags, not 'latest'.

        Security best practice: Pin base image versions for reproducibility
        and security.
        """
        for dockerfile in _dockerfiles():
            content = dockerfile.read_text(encoding="utf-8")
            lines = content.split("\n")

            for line_num, line in enumerate(lines, 1):
                if line.strip().startswith("FROM "):
                    # Should not use :latest tag
                    assert ":latest" not in line, (
                        f"{dockerfile}:{line_num} should not use ':latest' tag"
                    )

                    # Should use a specific version tag
                    assert ":" in line.replace("FROM ", "").strip(), (
                        f"{dockerfile}:{line_num} should specify a version tag"
                    )

    def test_dockerfiles_no_hardcoded_secrets(self):
        """Test that Dockerfiles don't contain hardcoded secrets.

        Security best practice: No API keys, tokens, or credentials in Dockerfiles.
        """
        secret_patterns = [
            r"api_key\s*=\s*['\"][^'\"]+['\"]",
            r"token\s*=\s*['\"][^'\"]+['\"]",
            r"password\s*=\s*['\"][^'\"]+['\"]",
            r"secret\s*=\s*['\"][^'\"]+['\"]",
            r"AKIA[0-9A-Z]{16}",  # AWS Access Key ID
        ]

        findings = []

        for dockerfile in _dockerfiles():
            content = dockerfile.read_text(encoding="utf-8")
            lines = content.split("\n")

            for line_num, line in enumerate(lines, 1):
                # Skip comments
                if line.strip().startswith("#"):
                    continue

                for pattern in secret_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append(
                            f"{dockerfile}:{line_num} | {line.strip()[:80]}"
                        )

        # Should find no hardcoded secrets
        assert len(findings) == 0, (
            f"Found {len(findings)} potential hardcoded secrets in Dockerfiles:\n"
            + "\n".join(findings[:5])
        )

    def test_dockerfiles_use_multi_stage_builds(self):
        """Test that Dockerfiles use multi-stage builds to minimize image size.

        Security best practice: Smaller images = smaller attack surface.
        """
        for dockerfile in _dockerfiles():
            content = dockerfile.read_text(encoding="utf-8")

            # Count number of FROM statements (multi-stage has multiple)
            from_count = len(re.findall(r"^FROM\s+", content, re.MULTILINE))

            assert from_count >= 2, (
                f"{dockerfile} should use multi-stage builds (has {from_count} FROM statements)"
            )

    def test_dockerfiles_minimal_privileges(self):
        """Test that Dockerfiles don't grant excessive privileges.

        Security best practice: Avoid --privileged, CAP_SYS_ADMIN, etc.
        """
        dangerous_patterns = [
            r"--privileged",
            r"CAP_SYS_ADMIN",
            r"--cap-add\s+ALL",
        ]

        findings = []

        for dockerfile in _dockerfiles():
            content = dockerfile.read_text(encoding="utf-8")
            lines = content.split("\n")

            for line_num, line in enumerate(lines, 1):
                for pattern in dangerous_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append(
                            f"{dockerfile}:{line_num} | {line.strip()[:80]}"
                        )

        # Should find no excessive privileges
        assert len(findings) == 0, (
            f"Found {len(findings)} potential excessive privileges in Dockerfiles:\n"
            + "\n".join(findings[:5])
        )

    def test_dockerfiles_no_sensitive_files_copied(self):
        """Test that Dockerfiles don't COPY sensitive files.

        Security best practice: Don't include .env, secrets, keys in images.
        """
        sensitive_patterns = [
            r"COPY.*\.env",
            r"COPY.*secret",
            r"COPY.*\.pem",
            r"COPY.*\.key",
            r"COPY.*credentials",
        ]

        findings = []

        for dockerfile in _dockerfiles():
            content = dockerfile.read_text(encoding="utf-8")
            lines = content.split("\n")

            for line_num, line in enumerate(lines, 1):
                # Skip comments
                if line.strip().startswith("#"):
                    continue

                for pattern in sensitive_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        findings.append(
                            f"{dockerfile}:{line_num} | {line.strip()[:80]}"
                        )

        # Should find no sensitive file copies
        assert len(findings) == 0, (
            f"Found {len(findings)} potential sensitive file copies in Dockerfiles:\n"
            + "\n".join(findings[:5])
        )


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v", "--tb=short"])
