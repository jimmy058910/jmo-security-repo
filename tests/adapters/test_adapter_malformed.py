#!/usr/bin/env python3
"""
Comprehensive Adapter Malformed Input Tests.

Tests all adapters' handling of malformed, invalid, and edge-case inputs.
Each adapter should gracefully handle bad input without crashing.

Usage:
    pytest tests/adapters/test_adapter_malformed.py -v
    pytest tests/adapters/test_adapter_malformed.py -v -k "semgrep"
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# Import all adapters for comprehensive testing
from scripts.core.adapters.aflplusplus_adapter import AFLPlusPlusAdapter
from scripts.core.adapters.akto_adapter import AktoAdapter
from scripts.core.adapters.bandit_adapter import BanditAdapter
from scripts.core.adapters.bearer_adapter import BearerAdapter
from scripts.core.adapters.cdxgen_adapter import CdxgenAdapter
from scripts.core.adapters.checkov_adapter import CheckovAdapter
from scripts.core.adapters.dependency_check_adapter import DependencyCheckAdapter
from scripts.core.adapters.falco_adapter import FalcoAdapter
from scripts.core.adapters.gosec_adapter import GosecAdapter
from scripts.core.adapters.grype_adapter import GrypeAdapter
from scripts.core.adapters.hadolint_adapter import HadolintAdapter
from scripts.core.adapters.horusec_adapter import HorusecAdapter
from scripts.core.adapters.kubescape_adapter import KubescapeAdapter
from scripts.core.adapters.lynis_adapter import LynisAdapter
from scripts.core.adapters.mobsf_adapter import MobsfAdapter
from scripts.core.adapters.noseyparker_adapter import NoseyParkerAdapter
from scripts.core.adapters.nuclei_adapter import NucleiAdapter
from scripts.core.adapters.prowler_adapter import ProwlerAdapter
from scripts.core.adapters.scancode_adapter import ScancodeAdapter
from scripts.core.adapters.semgrep_adapter import SemgrepAdapter
from scripts.core.adapters.semgrep_secrets_adapter import SemgrepSecretsAdapter
from scripts.core.adapters.shellcheck_adapter import ShellCheckAdapter
from scripts.core.adapters.syft_adapter import SyftAdapter
from scripts.core.adapters.trivy_adapter import TrivyAdapter
from scripts.core.adapters.trivy_rbac_adapter import TrivyRbacAdapter
from scripts.core.adapters.trufflehog_adapter import TruffleHogAdapter
from scripts.core.adapters.yara_adapter import YaraAdapter
from scripts.core.adapters.zap_adapter import ZapAdapter

# ============================================================================
# Adapter Registry
# ============================================================================

ALL_ADAPTERS = [
    ("aflplusplus", AFLPlusPlusAdapter),
    ("akto", AktoAdapter),
    ("bandit", BanditAdapter),
    ("bearer", BearerAdapter),
    ("cdxgen", CdxgenAdapter),
    ("checkov", CheckovAdapter),
    ("dependency_check", DependencyCheckAdapter),
    ("falco", FalcoAdapter),
    ("gosec", GosecAdapter),
    ("grype", GrypeAdapter),
    ("hadolint", HadolintAdapter),
    ("horusec", HorusecAdapter),
    ("kubescape", KubescapeAdapter),
    ("lynis", LynisAdapter),
    ("mobsf", MobsfAdapter),
    ("noseyparker", NoseyParkerAdapter),
    ("nuclei", NucleiAdapter),
    ("prowler", ProwlerAdapter),
    ("scancode", ScancodeAdapter),
    ("semgrep", SemgrepAdapter),
    ("semgrep_secrets", SemgrepSecretsAdapter),
    ("shellcheck", ShellCheckAdapter),
    ("syft", SyftAdapter),
    ("trivy", TrivyAdapter),
    ("trivy_rbac", TrivyRbacAdapter),
    ("trufflehog", TruffleHogAdapter),
    ("yara", YaraAdapter),
    ("zap", ZapAdapter),
]


# ============================================================================
# Malformed Input Test Cases
# ============================================================================

MALFORMED_INPUTS = [
    ("empty_string", ""),
    ("invalid_json_syntax", "{not valid json}"),
    ("unclosed_brace", '{"key": "value"'),
    ("unclosed_bracket", '["item1", "item2"'),
    ("null_literal", "null"),
    ("boolean_true", "true"),
    ("boolean_false", "false"),
    ("number_literal", "42"),
    ("string_literal", '"just a string"'),
    ("empty_object", "{}"),
    ("empty_array", "[]"),
    ("nested_empty", '{"results": {}, "findings": []}'),
    ("array_of_nulls", "[null, null, null]"),
    ("array_of_numbers", "[1, 2, 3]"),
    ("array_of_strings", '["a", "b", "c"]'),
    ("deeply_nested_empty", '{"a": {"b": {"c": {"d": {}}}}}'),
]

MISSING_FIELD_INPUTS = [
    ("missing_severity", '{"findings": [{"message": "test", "path": "file.py"}]}'),
    ("missing_message", '{"findings": [{"severity": "HIGH", "path": "file.py"}]}'),
    ("missing_path", '{"findings": [{"severity": "HIGH", "message": "test"}]}'),
    ("null_severity", '{"findings": [{"severity": null, "message": "test"}]}'),
    ("null_message", '{"findings": [{"severity": "HIGH", "message": null}]}'),
    ("empty_severity", '{"findings": [{"severity": "", "message": "test"}]}'),
    ("empty_message", '{"findings": [{"severity": "HIGH", "message": ""}]}'),
]

UNICODE_EDGE_CASES = [
    ("null_byte", '{"message": "test\\u0000injection"}'),
    ("zero_width_space", '{"message": "invisible\\u200bspace"}'),
    ("rtl_override", '{"message": "\\u202eevil"}'),
    ("emoji", '{"message": "emoji: 🔒🔑🛡️"}'),
    ("chinese", '{"message": "中文测试"}'),
    ("arabic", '{"message": "اختبار عربي"}'),
    ("mixed_unicode", '{"message": "Mixed: Héllo 世界 مرحبا"}'),
    ("control_chars", '{"message": "control\\x1b[31mred\\x1b[0m"}'),
    ("max_unicode", '{"message": "\\uffff"}'),
]

TYPE_MISMATCH_INPUTS = [
    ("findings_as_object", '{"findings": {"not": "an array"}}'),
    ("findings_as_string", '{"findings": "not an array"}'),
    ("findings_as_number", '{"findings": 42}'),
    ("findings_as_null", '{"findings": null}'),
    ("results_as_array", '{"results": ["not", "an", "object"]}'),
    ("results_as_string", '{"results": "not an object"}'),
    ("severity_as_number", '{"findings": [{"severity": 1}]}'),
    ("severity_as_array", '{"findings": [{"severity": ["HIGH"]}]}'),
    ("line_as_string", '{"findings": [{"line": "not a number"}]}'),
]


# ============================================================================
# Parametrized Tests
# ============================================================================


class TestAdapterMalformedJSON:
    """Test all adapters handle malformed JSON gracefully."""

    @pytest.mark.parametrize("adapter_name,adapter_class", ALL_ADAPTERS)
    @pytest.mark.parametrize("case_name,malformed_content", MALFORMED_INPUTS)
    def test_adapter_handles_malformed_json(
        self,
        tmp_path: Path,
        adapter_name: str,
        adapter_class: type,
        case_name: str,
        malformed_content: str,
    ):
        """Adapter should not crash on malformed JSON."""
        test_file = tmp_path / f"{adapter_name}.json"
        test_file.write_text(malformed_content, encoding="utf-8")

        adapter = adapter_class()
        result = adapter.parse(test_file)

        # Should return a list, not crash
        assert isinstance(result, list), f"{adapter_name} returned {type(result)}"
        # Should be empty or have valid findings
        assert all(hasattr(f, "severity") for f in result if result)


class TestAdapterMissingFields:
    """Test all adapters handle missing required fields."""

    @pytest.mark.parametrize("adapter_name,adapter_class", ALL_ADAPTERS)
    @pytest.mark.parametrize("case_name,content", MISSING_FIELD_INPUTS)
    def test_adapter_handles_missing_fields(
        self,
        tmp_path: Path,
        adapter_name: str,
        adapter_class: type,
        case_name: str,
        content: str,
    ):
        """Adapter should handle missing fields without crashing."""
        test_file = tmp_path / f"{adapter_name}.json"
        test_file.write_text(content, encoding="utf-8")

        adapter = adapter_class()
        result = adapter.parse(test_file)

        assert isinstance(result, list)


class TestAdapterUnicodeEdgeCases:
    """Test all adapters handle Unicode edge cases."""

    @pytest.mark.parametrize("adapter_name,adapter_class", ALL_ADAPTERS)
    @pytest.mark.parametrize("case_name,content", UNICODE_EDGE_CASES)
    def test_adapter_handles_unicode(
        self,
        tmp_path: Path,
        adapter_name: str,
        adapter_class: type,
        case_name: str,
        content: str,
    ):
        """Adapter should handle Unicode content without crashing."""
        test_file = tmp_path / f"{adapter_name}.json"
        test_file.write_text(content, encoding="utf-8")

        adapter = adapter_class()
        result = adapter.parse(test_file)

        assert isinstance(result, list)


class TestAdapterTypeMismatches:
    """Test all adapters handle type mismatches."""

    @pytest.mark.parametrize("adapter_name,adapter_class", ALL_ADAPTERS)
    @pytest.mark.parametrize("case_name,content", TYPE_MISMATCH_INPUTS)
    def test_adapter_handles_type_mismatch(
        self,
        tmp_path: Path,
        adapter_name: str,
        adapter_class: type,
        case_name: str,
        content: str,
    ):
        """Adapter should handle type mismatches without crashing."""
        test_file = tmp_path / f"{adapter_name}.json"
        test_file.write_text(content, encoding="utf-8")

        adapter = adapter_class()
        result = adapter.parse(test_file)

        assert isinstance(result, list)


# ============================================================================
# File System Edge Cases
# ============================================================================


class TestAdapterFileSystemEdgeCases:
    """Test adapter handling of file system edge cases."""

    @pytest.mark.parametrize("adapter_name,adapter_class", ALL_ADAPTERS)
    def test_adapter_handles_missing_file(
        self,
        tmp_path: Path,
        adapter_name: str,
        adapter_class: type,
    ):
        """Adapter should handle missing files gracefully."""
        missing_file = tmp_path / "nonexistent.json"

        adapter = adapter_class()
        result = adapter.parse(missing_file)

        assert isinstance(result, list)
        assert len(result) == 0

    @pytest.mark.parametrize("adapter_name,adapter_class", ALL_ADAPTERS)
    def test_adapter_handles_empty_file(
        self,
        tmp_path: Path,
        adapter_name: str,
        adapter_class: type,
    ):
        """Adapter should handle empty files gracefully."""
        empty_file = tmp_path / f"{adapter_name}_empty.json"
        empty_file.write_text("", encoding="utf-8")

        adapter = adapter_class()
        result = adapter.parse(empty_file)

        assert isinstance(result, list)
        assert len(result) == 0

    @pytest.mark.parametrize("adapter_name,adapter_class", ALL_ADAPTERS)
    def test_adapter_handles_binary_file(
        self,
        tmp_path: Path,
        adapter_name: str,
        adapter_class: type,
    ):
        """Adapter should handle binary files gracefully."""
        binary_file = tmp_path / f"{adapter_name}_binary.json"
        # PNG header bytes
        binary_file.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")

        adapter = adapter_class()
        result = adapter.parse(binary_file)

        assert isinstance(result, list)

    @pytest.mark.parametrize("adapter_name,adapter_class", ALL_ADAPTERS)
    def test_adapter_handles_whitespace_only(
        self,
        tmp_path: Path,
        adapter_name: str,
        adapter_class: type,
    ):
        """Adapter should handle whitespace-only files gracefully."""
        whitespace_file = tmp_path / f"{adapter_name}_whitespace.json"
        whitespace_file.write_text("   \n\t\r\n   ", encoding="utf-8")

        adapter = adapter_class()
        result = adapter.parse(whitespace_file)

        assert isinstance(result, list)


# ============================================================================
# Large Input Tests
# ============================================================================


class TestAdapterLargeInputs:
    """Test adapter handling of large inputs."""

    @pytest.mark.parametrize("adapter_name,adapter_class", ALL_ADAPTERS)
    def test_adapter_handles_large_string(
        self,
        tmp_path: Path,
        adapter_name: str,
        adapter_class: type,
    ):
        """Adapter should handle very long strings."""
        # 100KB string
        large_string = "A" * 100_000
        content = json.dumps({"message": large_string, "description": large_string})

        large_file = tmp_path / f"{adapter_name}_large.json"
        large_file.write_text(content, encoding="utf-8")

        adapter = adapter_class()
        result = adapter.parse(large_file)

        assert isinstance(result, list)

    @pytest.mark.parametrize(
        "adapter_name,adapter_class", ALL_ADAPTERS[:5]
    )  # Subset for performance
    def test_adapter_handles_many_findings(
        self,
        tmp_path: Path,
        adapter_name: str,
        adapter_class: type,
    ):
        """Adapter should handle many findings."""
        # Generate 1000 items
        items = [
            {"id": i, "message": f"Finding {i}", "severity": "LOW"} for i in range(1000)
        ]
        content = json.dumps(items)

        many_file = tmp_path / f"{adapter_name}_many.json"
        many_file.write_text(content, encoding="utf-8")

        adapter = adapter_class()
        result = adapter.parse(many_file)

        assert isinstance(result, list)


# ============================================================================
# Tool-Specific Malformed Inputs
# ============================================================================


class TestSemgrepMalformed:
    """Semgrep-specific malformed input tests."""

    def test_semgrep_missing_results_key(self, tmp_path: Path):
        """Semgrep should handle missing 'results' key."""
        content = '{"version": "1.0.0", "errors": []}'
        test_file = tmp_path / "semgrep.json"
        test_file.write_text(content, encoding="utf-8")

        adapter = SemgrepAdapter()
        result = adapter.parse(test_file)

        assert isinstance(result, list)
        assert len(result) == 0

    def test_semgrep_results_not_array(self, tmp_path: Path):
        """Semgrep should handle results not being an array."""
        content = '{"results": {"not": "an array"}, "version": "1.0.0"}'
        test_file = tmp_path / "semgrep.json"
        test_file.write_text(content, encoding="utf-8")

        adapter = SemgrepAdapter()
        result = adapter.parse(test_file)

        assert isinstance(result, list)

    def test_semgrep_result_missing_check_id(self, tmp_path: Path):
        """Semgrep should handle result missing check_id."""
        content = json.dumps(
            {
                "results": [
                    {
                        "path": "test.py",
                        "start": {"line": 1},
                        "extra": {"message": "test"},
                    }
                ],
                "version": "1.0.0",
            }
        )
        test_file = tmp_path / "semgrep.json"
        test_file.write_text(content, encoding="utf-8")

        adapter = SemgrepAdapter()
        result = adapter.parse(test_file)

        assert isinstance(result, list)


class TestTrivyMalformed:
    """Trivy-specific malformed input tests."""

    def test_trivy_missing_results(self, tmp_path: Path):
        """Trivy should handle missing Results array."""
        content = '{"SchemaVersion": 2, "ArtifactName": "test"}'
        test_file = tmp_path / "trivy.json"
        test_file.write_text(content, encoding="utf-8")

        adapter = TrivyAdapter()
        result = adapter.parse(test_file)

        assert isinstance(result, list)

    def test_trivy_null_vulnerabilities(self, tmp_path: Path):
        """Trivy should handle null Vulnerabilities."""
        content = json.dumps(
            {
                "SchemaVersion": 2,
                "Results": [{"Target": "test", "Vulnerabilities": None}],
            }
        )
        test_file = tmp_path / "trivy.json"
        test_file.write_text(content, encoding="utf-8")

        adapter = TrivyAdapter()
        result = adapter.parse(test_file)

        assert isinstance(result, list)


class TestBanditMalformed:
    """Bandit-specific malformed input tests."""

    def test_bandit_missing_results(self, tmp_path: Path):
        """Bandit should handle missing 'results' key."""
        content = '{"metrics": {}, "errors": []}'
        test_file = tmp_path / "bandit.json"
        test_file.write_text(content, encoding="utf-8")

        adapter = BanditAdapter()
        result = adapter.parse(test_file)

        assert isinstance(result, list)

    def test_bandit_null_results(self, tmp_path: Path):
        """Bandit should handle null results."""
        content = '{"results": null}'
        test_file = tmp_path / "bandit.json"
        test_file.write_text(content, encoding="utf-8")

        adapter = BanditAdapter()
        result = adapter.parse(test_file)

        assert isinstance(result, list)


class TestCheckovMalformed:
    """Checkov-specific malformed input tests."""

    def test_checkov_missing_failed_checks(self, tmp_path: Path):
        """Checkov should handle missing failed_checks."""
        content = json.dumps({"results": {"passed_checks": []}})
        test_file = tmp_path / "checkov.json"
        test_file.write_text(content, encoding="utf-8")

        adapter = CheckovAdapter()
        result = adapter.parse(test_file)

        assert isinstance(result, list)

    def test_checkov_array_format(self, tmp_path: Path):
        """Checkov should handle array format (multi-framework)."""
        content = json.dumps(
            [
                {"check_type": "terraform", "results": {"failed_checks": []}},
                {"check_type": "kubernetes", "results": {"failed_checks": []}},
            ]
        )
        test_file = tmp_path / "checkov.json"
        test_file.write_text(content, encoding="utf-8")

        adapter = CheckovAdapter()
        result = adapter.parse(test_file)

        assert isinstance(result, list)


class TestTrufflehogMalformed:
    """Trufflehog-specific malformed input tests."""

    def test_trufflehog_newline_delimited(self, tmp_path: Path):
        """Trufflehog should handle newline-delimited JSON."""
        content = '{"SourceMetadata":{}}\n{"SourceMetadata":{}}\n'
        test_file = tmp_path / "trufflehog.json"
        test_file.write_text(content, encoding="utf-8")

        adapter = TruffleHogAdapter()
        result = adapter.parse(test_file)

        assert isinstance(result, list)

    def test_trufflehog_mixed_valid_invalid_lines(self, tmp_path: Path):
        """Trufflehog should handle mix of valid and invalid lines."""
        content = '{"SourceMetadata":{}}\ninvalid line\n{"SourceMetadata":{}}\n'
        test_file = tmp_path / "trufflehog.json"
        test_file.write_text(content, encoding="utf-8")

        adapter = TruffleHogAdapter()
        result = adapter.parse(test_file)

        assert isinstance(result, list)


class TestGrypeMalformed:
    """Grype-specific malformed input tests."""

    def test_grype_missing_matches(self, tmp_path: Path):
        """Grype should handle missing matches array."""
        content = '{"source": {}, "distro": {}}'
        test_file = tmp_path / "grype.json"
        test_file.write_text(content, encoding="utf-8")

        adapter = GrypeAdapter()
        result = adapter.parse(test_file)

        assert isinstance(result, list)


class TestHadolintMalformed:
    """Hadolint-specific malformed input tests."""

    def test_hadolint_non_array_root(self, tmp_path: Path):
        """Hadolint should handle non-array root."""
        content = '{"error": "unexpected format"}'
        test_file = tmp_path / "hadolint.json"
        test_file.write_text(content, encoding="utf-8")

        adapter = HadolintAdapter()
        result = adapter.parse(test_file)

        assert isinstance(result, list)

    def test_hadolint_missing_code(self, tmp_path: Path):
        """Hadolint should handle items missing 'code' field."""
        content = '[{"file": "Dockerfile", "line": 1, "level": "error"}]'
        test_file = tmp_path / "hadolint.json"
        test_file.write_text(content, encoding="utf-8")

        adapter = HadolintAdapter()
        result = adapter.parse(test_file)

        assert isinstance(result, list)


# ============================================================================
# Concurrent Processing Tests
# ============================================================================


class TestAdapterConcurrentFailures:
    """Test handling of concurrent adapter failures."""

    def test_multiple_adapters_fail_gracefully(self, tmp_path: Path):
        """All adapters failing should not crash aggregation."""
        from scripts.core.normalize_and_report import gather_results

        # Create results dir with malformed files for multiple tools
        indiv = tmp_path / "individual-repos" / "test-repo"
        indiv.mkdir(parents=True)

        for tool in ["semgrep", "trivy", "bandit", "checkov", "hadolint"]:
            (indiv / f"{tool}.json").write_text("INVALID{JSON", encoding="utf-8")

        findings = gather_results(tmp_path)

        assert isinstance(findings, list)
        assert len(findings) == 0


# ============================================================================
# Encoding Edge Cases
# ============================================================================


class TestAdapterEncodingEdgeCases:
    """Test adapter handling of encoding edge cases."""

    @pytest.mark.parametrize("adapter_name,adapter_class", ALL_ADAPTERS[:10])  # Subset
    def test_adapter_handles_utf16(
        self,
        tmp_path: Path,
        adapter_name: str,
        adapter_class: type,
    ):
        """Adapter should handle UTF-16 encoded file."""
        content = '{"message": "test"}'
        utf16_file = tmp_path / f"{adapter_name}_utf16.json"
        utf16_file.write_text(content, encoding="utf-16")

        adapter = adapter_class()
        # May fail to parse but should not crash
        try:
            result = adapter.parse(utf16_file)
            assert isinstance(result, list)
        except UnicodeDecodeError:
            # Expected for adapters that assume UTF-8
            pass

    @pytest.mark.parametrize("adapter_name,adapter_class", ALL_ADAPTERS[:10])
    def test_adapter_handles_latin1(
        self,
        tmp_path: Path,
        adapter_name: str,
        adapter_class: type,
    ):
        """Adapter should handle Latin-1 encoded file."""
        # Write with latin-1 but the adapter will try utf-8
        latin1_file = tmp_path / f"{adapter_name}_latin1.json"
        latin1_file.write_bytes(b'{"message": "\xe9"}')  # é in latin-1

        adapter = adapter_class()
        try:
            result = adapter.parse(latin1_file)
            assert isinstance(result, list)
        except UnicodeDecodeError:
            # Expected for strict UTF-8 handling
            pass
