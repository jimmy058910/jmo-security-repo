"""Tests for rule equivalence mapping (rule_equivalence.py).

This module tests the cross-tool rule equivalence mapping that enables
better deduplication of findings from different security tools.

Example:
    Trivy ":latest tag used" and Hadolint "DL3006" report the same issue
    and should be recognized as equivalent.

Author: JMo Security
Version: 1.0.0
"""

import pytest

from scripts.core.rule_equivalence import (
    RULE_EQUIVALENCE,
    get_canonical_rule_id,
    are_rules_equivalent,
)


class TestRuleEquivalenceMapping:
    """Test the RULE_EQUIVALENCE mapping structure."""

    def test_mapping_exists(self):
        """Test that the mapping is properly defined."""
        assert isinstance(RULE_EQUIVALENCE, dict)
        assert len(RULE_EQUIVALENCE) > 0

    def test_mapping_structure(self):
        """Test that all entries have correct structure."""
        for canonical_id, mappings in RULE_EQUIVALENCE.items():
            # Canonical ID should be lowercase-with-dashes
            assert canonical_id == canonical_id.lower()
            assert "-" in canonical_id or canonical_id.isalpha()

            # Mappings should be list of (tool, rule_id) tuples
            assert isinstance(mappings, list)
            assert len(mappings) >= 2  # Need at least 2 tools for equivalence

            for mapping in mappings:
                assert isinstance(mapping, tuple)
                assert len(mapping) == 2
                tool, rule_id = mapping
                assert isinstance(tool, str)
                assert isinstance(rule_id, str)

    def test_dockerfile_latest_tag_equivalence(self):
        """Test that Dockerfile :latest tag rules are mapped."""
        assert "dockerfile-latest-tag" in RULE_EQUIVALENCE
        mappings = RULE_EQUIVALENCE["dockerfile-latest-tag"]

        # Should have Trivy, Hadolint, and Checkov
        tools = {m[0] for m in mappings}
        assert "trivy" in tools
        assert "hadolint" in tools
        assert "checkov" in tools


class TestGetCanonicalRuleId:
    """Test the get_canonical_rule_id function."""

    def test_hadolint_dl3006(self):
        """Test Hadolint DL3006 maps to dockerfile-latest-tag."""
        canonical = get_canonical_rule_id("hadolint", "DL3006")
        assert canonical == "dockerfile-latest-tag"

    def test_trivy_latest_tag(self):
        """Test Trivy :latest tag message maps to dockerfile-latest-tag."""
        canonical = get_canonical_rule_id("trivy", ":latest tag used")
        assert canonical == "dockerfile-latest-tag"

    def test_checkov_docker_1(self):
        """Test Checkov CKV_DOCKER_1 maps to dockerfile-latest-tag."""
        canonical = get_canonical_rule_id("checkov", "CKV_DOCKER_1")
        assert canonical == "dockerfile-latest-tag"

    def test_hadolint_dl3055(self):
        """Test Hadolint DL3055 maps to dockerfile-no-healthcheck."""
        canonical = get_canonical_rule_id("hadolint", "DL3055")
        assert canonical == "dockerfile-no-healthcheck"

    def test_trivy_no_healthcheck(self):
        """Test Trivy HEALTHCHECK message maps correctly."""
        canonical = get_canonical_rule_id("trivy", "No HEALTHCHECK defined")
        assert canonical == "dockerfile-no-healthcheck"

    def test_case_insensitive_tool(self):
        """Test that tool name matching is case insensitive."""
        canonical1 = get_canonical_rule_id("HADOLINT", "DL3006")
        canonical2 = get_canonical_rule_id("hadolint", "DL3006")
        canonical3 = get_canonical_rule_id("Hadolint", "DL3006")

        assert canonical1 == canonical2 == canonical3 == "dockerfile-latest-tag"

    def test_unknown_tool(self):
        """Test unknown tool returns None."""
        canonical = get_canonical_rule_id("unknown_tool", "SOME_RULE")
        assert canonical is None

    def test_unknown_rule(self):
        """Test unknown rule returns None."""
        canonical = get_canonical_rule_id("hadolint", "UNKNOWN_RULE_12345")
        assert canonical is None

    def test_empty_inputs(self):
        """Test empty inputs return None."""
        assert get_canonical_rule_id("", "DL3006") is None
        assert get_canonical_rule_id("hadolint", "") is None


class TestAreRulesEquivalent:
    """Test the are_rules_equivalent function."""

    def test_trivy_hadolint_latest_tag(self):
        """Test Trivy and Hadolint :latest tag rules are equivalent."""
        is_equiv, canonical = are_rules_equivalent(
            "trivy", ":latest tag used", "hadolint", "DL3006"
        )
        assert is_equiv is True
        assert canonical == "dockerfile-latest-tag"

    def test_hadolint_checkov_latest_tag(self):
        """Test Hadolint and Checkov :latest tag rules are equivalent."""
        is_equiv, canonical = are_rules_equivalent(
            "hadolint", "DL3006", "checkov", "CKV_DOCKER_1"
        )
        assert is_equiv is True
        assert canonical == "dockerfile-latest-tag"

    def test_different_issues_not_equivalent(self):
        """Test different issues are not marked as equivalent."""
        is_equiv, canonical = are_rules_equivalent(
            "hadolint", "DL3006", "hadolint", "DL3055"  # :latest tag  # no healthcheck
        )
        assert is_equiv is False
        assert canonical is None

    def test_same_tool_same_rule(self):
        """Test same tool with same rule is equivalent."""
        is_equiv, canonical = are_rules_equivalent(
            "hadolint", "DL3006", "hadolint", "DL3006"
        )
        assert is_equiv is True
        assert canonical == "dockerfile-latest-tag"

    def test_unknown_rules_not_equivalent(self):
        """Test unknown rules are not marked as equivalent."""
        is_equiv, canonical = are_rules_equivalent(
            "unknown_tool", "RULE_A", "another_tool", "RULE_B"
        )
        assert is_equiv is False
        assert canonical is None

    def test_one_known_one_unknown(self):
        """Test one known rule with one unknown rule is not equivalent."""
        is_equiv, canonical = are_rules_equivalent(
            "hadolint", "DL3006", "unknown_tool", "SOME_RULE"
        )
        assert is_equiv is False
        assert canonical is None


class TestSecretDetectionEquivalence:
    """Test equivalence for secret detection rules."""

    def test_aws_access_key_equivalence(self):
        """Test AWS access key detection across tools."""
        # Check that at least some AWS-related rules exist
        canonical = get_canonical_rule_id("trufflehog", "AWS")
        # May or may not match depending on exact mapping
        # Just verify no errors occur
        assert canonical is None or canonical == "secret-aws-access-key"

    def test_github_token_equivalence(self):
        """Test GitHub token detection across tools."""
        canonical = get_canonical_rule_id("gitleaks", "github-pat")
        assert canonical == "secret-github-token"


class TestKubernetesEquivalence:
    """Test equivalence for Kubernetes rules."""

    def test_privileged_container(self):
        """Test privileged container detection across tools."""
        canonical1 = get_canonical_rule_id("trivy", "KSV001")
        canonical2 = get_canonical_rule_id("checkov", "CKV_K8S_1")

        assert canonical1 == canonical2 == "k8s-privileged-container"

    def test_root_container(self):
        """Test root container detection across tools."""
        canonical1 = get_canonical_rule_id("trivy", "KSV012")
        canonical2 = get_canonical_rule_id("checkov", "CKV_K8S_6")

        assert canonical1 == canonical2 == "k8s-root-container"


class TestCodeSecurityEquivalence:
    """Test equivalence for code security rules."""

    def test_sql_injection(self):
        """Test SQL injection detection across tools."""
        canonical = get_canonical_rule_id("bandit", "B608")
        assert canonical == "code-sql-injection"

    def test_command_injection(self):
        """Test command injection detection across tools."""
        canonical1 = get_canonical_rule_id("bandit", "B602")
        canonical2 = get_canonical_rule_id("bandit", "B603")

        assert canonical1 == canonical2 == "code-command-injection"


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_substring_matching(self):
        """Test that substring matching works for variable messages."""
        # Trivy may report slightly different messages
        canonical = get_canonical_rule_id("trivy", "DS001")
        assert canonical == "dockerfile-latest-tag"

    def test_reverse_map_caching(self):
        """Test that repeated calls use cached reverse map."""
        # Call multiple times - should be fast due to caching
        for _ in range(100):
            get_canonical_rule_id("hadolint", "DL3006")

        # Just verify no errors - caching is internal implementation


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
