"""Tests for rule equivalence mapping (rule_equivalence.py).

This module tests the cross-tool rule equivalence mapping that enables
better deduplication of findings from different security tools.

Example:
    Trivy "DS-0001" ("':latest' tag used") and Hadolint "DL3006" report the
    same issue and should be recognized as equivalent.

Author: JMo Security
Version: 1.0.0
"""

from pathlib import Path

import pytest

from scripts.core.rule_equivalence import (
    RULE_EQUIVALENCE,
    are_rules_equivalent,
    get_canonical_rule_id,
)

# trivy 0.74.0's own output; how it was recorded is in the docstring of
# tests/adapters/test_trivy_adapter.py.
RECORDED_TRIVY_074 = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "samples"
    / "trivy"
    / "misconfig-0.74.json"
)


def _trivy_074_findings():
    """The recorded output, through the real adapter (47 misconfigurations)."""
    from scripts.core.adapters.trivy_adapter import TrivyAdapter

    findings = TrivyAdapter().parse(RECORDED_TRIVY_074)
    assert len(findings) == 47, len(findings)
    return findings


class TestRuleEquivalenceMapping:
    """Test the RULE_EQUIVALENCE mapping structure."""

    def test_maps_the_documented_cross_tool_equivalence(self):
        """The module docstring's own example, asserted.

        ``test_mapping_structure`` below is a ``for ... in RULE_EQUIVALENCE``
        loop, so an emptied mapping passes it vacuously; the replaced
        ``isinstance``/``len > 0`` pair was the only guard, and it could not
        notice a canonical id losing the very tools it exists to equate.
        """
        latest_tag = RULE_EQUIVALENCE["dockerfile-latest-tag"]
        assert ("trivy", "DS-0001") in latest_tag
        assert ("hadolint", "DL3006") in latest_tag
        # An equivalence naming one tool cannot dedupe anything across tools.
        assert len({tool for tool, _ in latest_tag}) >= 2

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
        """Test Trivy's :latest tag check (DS-0001) maps to dockerfile-latest-tag."""
        canonical = get_canonical_rule_id("trivy", "DS-0001")
        assert canonical == "dockerfile-latest-tag"

    def test_checkov_docker_7(self):
        """Checkov CKV_DOCKER_7 is its latest-tag check.

        CKV_DOCKER_1 stood here until #1221; checkov's own name for it is
        "Ensure port 22 is not exposed".
        """
        assert get_canonical_rule_id("checkov", "CKV_DOCKER_7") == (
            "dockerfile-latest-tag"
        )
        assert get_canonical_rule_id("checkov", "CKV_DOCKER_1") == (
            "dockerfile-port-22-exposed"
        )

    def test_hadolint_dl3057(self):
        """Hadolint's missing-HEALTHCHECK rule is DL3057, not DL3055.

        hadolint 2.14.0's own messages: DL3057 "`HEALTHCHECK` instruction
        missing.", DL3055 "Label `commit` is not a valid git hash."
        """
        assert get_canonical_rule_id("hadolint", "DL3057") == (
            "dockerfile-no-healthcheck"
        )
        assert get_canonical_rule_id("hadolint", "DL3055") is None

    def test_trivy_no_healthcheck(self):
        """Test Trivy's HEALTHCHECK check (DS-0026) maps correctly."""
        canonical = get_canonical_rule_id("trivy", "DS-0026")
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
            "trivy", "DS-0001", "hadolint", "DL3006"
        )
        assert is_equiv is True
        assert canonical == "dockerfile-latest-tag"

    def test_hadolint_checkov_latest_tag(self):
        """Test Hadolint and Checkov :latest tag rules are equivalent."""
        is_equiv, canonical = are_rules_equivalent(
            "hadolint", "DL3006", "checkov", "CKV_DOCKER_7"
        )
        assert is_equiv is True
        assert canonical == "dockerfile-latest-tag"

    def test_different_issues_not_equivalent(self):
        """Test different issues are not marked as equivalent."""
        is_equiv, canonical = are_rules_equivalent(
            "hadolint",
            "DL3006",
            "hadolint",
            "DL3057",  # :latest tag  # no healthcheck
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
        """Test GitHub token detection across tools.

        Used to assert on `("gitleaks", "github-pat")`. gitleaks has no
        adapter, is absent from `PROFILE_TOOLS` and from `versions.yaml`, and
        appeared nowhere in the product except `RULE_EQUIVALENCE` - so this
        pinned an entry that could never match a real finding. Its six tuples
        were removed in #846; the assertion now uses two tools that exist, and
        checks they agree, which is what a cross-tool equivalence test is for.
        """
        canonical1 = get_canonical_rule_id("trufflehog", "github-pat")
        canonical2 = get_canonical_rule_id(
            "semgrep", "generic.secrets.security.detected-github-pat"
        )

        assert canonical1 == canonical2 == "secret-github-token"


class TestKubernetesEquivalence:
    """Test equivalence for Kubernetes rules."""

    def test_privileged_container(self):
        """Test privileged container detection across tools."""
        canonical1 = get_canonical_rule_id("trivy", "KSV-0017")
        canonical2 = get_canonical_rule_id("checkov", "CKV_K8S_16")

        assert canonical1 == canonical2 == "k8s-privileged-container"
        # CKV_K8S_1 stood here until #1221: a PodSecurityPolicy's host PID.
        assert get_canonical_rule_id("checkov", "CKV_K8S_1") == "k8s-host-pid"
        # KSV-0001 is "Can elevate its own privileges", a different control;
        # the table listed its old id, KSV001, here until #1221.
        assert get_canonical_rule_id("trivy", "KSV-0001") == "k8s-privilege-escalation"

    def test_root_container(self):
        """Test root container detection across tools."""
        canonical1 = get_canonical_rule_id("trivy", "KSV-0012")
        canonical2 = get_canonical_rule_id("checkov", "CKV_K8S_6")

        assert canonical1 == canonical2 == "k8s-root-container"


class TestTrivyKeysAreWhatTrivyPrints:
    """The trivy keys, checked against trivy 0.74.0's recorded output.

    Until #1221 the adapter made a misconfiguration's ``Title`` its rule id,
    so the table keyed trivy by Titles and by old ids (``DS001``,
    ``KSV001``). 0.74.0 prints ``DS-0001``: measured on the recorded output,
    no old id and only three Titles still matched anything, and eight old ids
    named a different check than their group (``DS031`` sat in the open
    security-group group; it is the Dockerfile secrets check).
    """

    def test_hadolint_dl3006_and_trivys_latest_tag_finding_are_one_issue(self):
        latest = [f for f in _trivy_074_findings() if f.title == "':latest' tag used"]
        # Both FROM lines of the recorded Dockerfile.
        assert [f.location["startLine"] for f in latest] == [1, 5]
        for f in latest:
            assert are_rules_equivalent("hadolint", "DL3006", "trivy", f.ruleId) == (
                True,
                "dockerfile-latest-tag",
            )

    def test_every_trivy_key_is_an_id_trivy_prints(self):
        """Derived from the recorded output, so a Title or old-form key fails."""
        printed = {f.ruleId for f in _trivy_074_findings()}
        keys = {
            rule
            for members in RULE_EQUIVALENCE.values()
            for tool, rule in members
            if tool == "trivy"
        }
        assert len(keys) >= 10, sorted(keys)
        assert keys <= printed, f"no 0.74.0 finding carries {sorted(keys - printed)}"

    def test_what_matched_by_title_still_matches_by_id(self):
        """Measured before the fix: ruleId = Title reached exactly three groups."""
        canonical = {
            f.ruleId: get_canonical_rule_id("trivy", f.ruleId)
            for f in _trivy_074_findings()
        }
        assert canonical["DS-0002"] == "dockerfile-no-user"
        assert canonical["DS-0026"] == "dockerfile-no-healthcheck"
        assert canonical["KSV-0017"] == "k8s-privileged-container"

    def test_no_recorded_id_reaches_a_group_it_is_not_listed_in(self):
        """The substring fallback must not carry one id into another's group."""
        for f in _trivy_074_findings():
            got = get_canonical_rule_id("trivy", f.ruleId)
            if got is not None:
                assert ("trivy", f.ruleId) in RULE_EQUIVALENCE[got], (f.ruleId, got)


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_substring_matching(self):
        """A delimited id carrying a mapped id still resolves.

        trivy's ``AVD-DS-0001`` spelling (its ``aliases``) holds ``DS-0001``
        between delimiters, so the boundary fallback reaches the same group.
        """
        canonical = get_canonical_rule_id("trivy", "AVD-DS-0001")
        assert canonical == "dockerfile-latest-tag"

    def test_reverse_map_caching(self):
        """Test that repeated calls use cached reverse map."""
        # Call multiple times - should be fast due to caching
        for _ in range(100):
            get_canonical_rule_id("hadolint", "DL3006")

        # Just verify no errors - caching is internal implementation


class TestSubstringFallbackBoundaries:
    """The substring fallback must not prefix-match structured rule IDs.

    `get_canonical_rule_id` falls back to substring matching so a rule ID that
    carries a suffix still resolves -- semgrep reports a registry rule as
    `<path>.<rule>`, e.g. `...detected-github-pat.detected-github-pat` for the
    rule mapped here as `...detected-github-pat`. Plain containment made that
    fallback fire on the trailing number of every structured ID as well.
    """

    def test_numeric_suffix_does_not_prefix_match(self):
        """CKV_K8S_1 is a substring of CKV_K8S_14 but a different rule.

        CKV_K8S_16 and CKV_K8S_17 are listed in groups of their own since
        #1221, so each must reach its own group, never CKV_K8S_1's.
        """
        host_pid = get_canonical_rule_id("checkov", "CKV_K8S_1")
        assert host_pid == "k8s-host-pid"
        for unrelated in (
            "CKV_K8S_10",
            "CKV_K8S_14",
            "CKV_K8S_15",
            "CKV_K8S_16",
            "CKV_K8S_17",
            "CKV_K8S_18",
        ):
            got = get_canonical_rule_id("checkov", unrelated)
            assert got is None or ("checkov", unrelated) in RULE_EQUIVALENCE[got], (
                f"{unrelated} resolved to {got}, a group it is not listed in"
            )
        # CKV_K8S_17 is listed in k8s-host-pid itself; the other five are not.
        for unrelated in (
            "CKV_K8S_10",
            "CKV_K8S_14",
            "CKV_K8S_15",
            "CKV_K8S_16",
            "CKV_K8S_18",
        ):
            assert get_canonical_rule_id("checkov", unrelated) != host_pid

    def test_shorter_id_is_not_captured_by_a_longer_mapped_one(self):
        """The reverse direction was broken too: CKV_AWS_1 inside CKV_AWS_19."""
        assert get_canonical_rule_id("checkov", "CKV_AWS_1") is None
        assert get_canonical_rule_id("checkov", "CKV_AWS_2") is None

    def test_three_digit_ids_are_not_captured_by_single_digit_ones(self):
        """CKV_AWS_3 (mapped) must not swallow every CKV_AWS_3xx rule."""
        assert (
            get_canonical_rule_id("checkov", "CKV_AWS_3") == "iac-unencrypted-storage"
        )
        for unrelated in (
            "CKV_AWS_30",
            "CKV_AWS_35",
            "CKV_AWS_300",
            "CKV_AWS_353",
            "CKV_AWS_355",
            "CKV_AWS_382",
        ):
            assert get_canonical_rule_id("checkov", unrelated) is None, (
                f"{unrelated} must not resolve to CKV_AWS_3's canonical id"
            )

    def test_unrelated_checkov_rules_are_not_equivalent(self):
        """The measured regression: two different k8s controls scored 1.0 metadata."""
        equivalent, canonical = are_rules_equivalent(
            "checkov", "CKV_K8S_14", "checkov", "CKV_K8S_16"
        )
        assert equivalent is False, (
            f"'Image Tag should be fixed' and 'Container should not be "
            f"privileged' are different controls, got canonical={canonical}"
        )

    def test_separator_delimited_suffix_still_matches(self):
        """The case the fallback exists for must keep working.

        This drives a real cross-tool cluster (semgrep + trufflehog on one
        secret); tightening the fallback must not disable it.
        """
        semgrep_reported = (
            "generic.secrets.security.detected-github-pat.detected-github-pat"
        )
        assert get_canonical_rule_id("semgrep", semgrep_reported) == (
            "secret-github-token"
        )
        equivalent, canonical = are_rules_equivalent(
            "semgrep", semgrep_reported, "trufflehog", "github-pat"
        )
        assert equivalent is True
        assert canonical == "secret-github-token"

    def test_exact_table_entries_are_untouched(self):
        """Every (tool, rule) pair the table declares must still resolve."""
        for canonical, members in RULE_EQUIVALENCE.items():
            for tool, rule in members:
                assert get_canonical_rule_id(tool, rule) is not None, (
                    f"({tool}, {rule}) is in the table but no longer resolves"
                )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
