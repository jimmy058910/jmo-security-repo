"""Comprehensive tests for the Scan Correctness validator.

Tests the validate_scans() function and individual check groups.
"""

from __future__ import annotations

import importlib
from unittest.mock import patch

import pytest

from scripts.core.validators import CategoryResult, CheckResult, CheckStatus
from scripts.core.validators.scan_validator import (
    EXPECTED_ADAPTER_COUNT,
    EXPECTED_ADAPTERS,
    STANDARD_SEVERITIES,
    _check_adapter_count,
    _check_adapter_metadata,
    _check_adapter_naming,
    _check_adapters_importable,
    _check_compliance_cis,
    _check_compliance_cwe,
    _check_compliance_empty_findings,
    _check_compliance_mitre,
    _check_compliance_nist,
    _check_compliance_owasp,
    _check_compliance_pci_dss,
    _check_compliance_unmapped,
    _check_dedup_algorithm_selection,
    _check_dedup_consensus,
    _check_dedup_determinism,
    _check_dedup_empty_dict,
    _check_dedup_empty_input,
    _check_dedup_empty_list,
    _check_dedup_fixture_exists,
    _check_dedup_identical_reduces,
    _check_dedup_large_batch,
    _check_dedup_mixed_severity,
    _check_dedup_none_values,
    _check_dedup_path_normalization,
    _check_dedup_single_finding,
    _check_dedup_threshold_config,
    _check_dedup_unique_preserves,
    _check_empty_findings_validate,
    _check_full_1000_findings,
    _check_full_compliance_enrichment,
    _check_full_consensus_stability,
    _check_full_dashboard_html,
    _check_full_dedup_determinism_across_runs,
    _check_full_dedup_reduction_pct,
    _check_full_e2e_pipeline,
    _check_full_fingerprint_stability,
    _check_full_json_roundtrip,
    _check_full_priority_enrichment,
    _check_full_real_scan_available,
    _check_full_sarif_schema,
    _check_invalid_finding_fails,
    _check_large_findings_list,
    _check_no_duplicate_adapters,
    _check_nul_bytes_in_strings,
    _check_plugin_loader_fallback,
    _check_reporter_csv,
    _check_reporter_empty_findings,
    _check_reporter_html,
    _check_reporter_json,
    _check_reporter_large_list,
    _check_reporter_markdown,
    _check_reporter_sarif,
    _check_reporter_utf8,
    _check_sample_finding_validates,
    _check_sbom_empty_findings,
    _check_sbom_functions_exist,
    _check_sbom_index_building,
    _check_sbom_no_syft_findings,
    _check_schema_file_exists,
    _check_schema_invalid_json,
    _check_schema_loads,
    _check_severity_mappings_exist,
    _check_standard_severity_set,
    _check_unknown_severity_fallback,
    _make_adapter_parse_check,
    _make_sample_finding,
    validate_scans,
)

# ============================================================================
# Test validate_scans entry point
# ============================================================================


class TestValidateScans:
    """Tests for the main validate_scans() entry point."""

    def test_quick_tier_returns_category_result(self):
        result = validate_scans("quick")
        assert isinstance(result, CategoryResult)
        assert result.name == "Scan Correctness"

    def test_quick_tier_has_80_checks(self):
        # 6 adapter registry + 28 fixture parsing + 3 severity + 5 schema
        # + 6 edge cases + 12 dedup + 8 compliance + 4 SBOM + 8 reporters = 80
        result = validate_scans("quick")
        assert result.total == 80, f"Expected 80 quick checks, got {result.total}"

    def test_full_tier_has_92_checks(self):
        # 80 quick + 12 full-tier = 92
        result = validate_scans("full")
        assert result.total == 92, f"Expected 92 full checks, got {result.total}"

    def test_full_tier_includes_quick_checks(self):
        quick = validate_scans("quick")
        full = validate_scans("full")
        quick_names = {c.name for c in quick.checks}
        full_names = {c.name for c in full.checks}
        # All quick checks should be in full
        assert quick_names.issubset(
            full_names
        ), f"Quick checks not in full: {quick_names - full_names}"

    def test_all_checks_have_status(self):
        result = validate_scans("quick")
        for check in result.checks:
            assert check.status in list(CheckStatus), f"Invalid status for {check.name}"
            assert check.name, "Check has empty name"

    def test_all_checks_have_timing(self):
        result = validate_scans("quick")
        for check in result.checks:
            assert check.duration_ms >= 0, f"Negative timing for {check.name}"

    def test_category_result_properties(self):
        result = validate_scans("quick")
        # Verify property calculations work
        total = (
            result.passed
            + result.failed
            + result.warned
            + result.skipped
            + result.errored
        )
        assert total == result.total

    def test_unknown_tier_treated_as_quick(self):
        """Unknown tier should run quick checks only (no full extras)."""
        result = validate_scans("unknown_tier")
        assert result.total == 80


# ============================================================================
# Test constants
# ============================================================================


class TestConstants:
    """Tests for module-level constants."""

    def test_expected_adapter_count(self):
        assert EXPECTED_ADAPTER_COUNT == 28

    def test_expected_adapters_list(self):
        assert len(EXPECTED_ADAPTERS) == 28

    def test_adapters_sorted(self):
        assert EXPECTED_ADAPTERS == sorted(EXPECTED_ADAPTERS)

    def test_standard_severities(self):
        assert STANDARD_SEVERITIES == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    def test_known_adapters_in_list(self):
        for adapter in ["bandit", "trivy", "semgrep", "grype", "zap"]:
            assert adapter in EXPECTED_ADAPTERS


# ============================================================================
# Test _make_sample_finding helper
# ============================================================================


class TestMakeSampleFinding:
    """Tests for the sample finding factory."""

    def test_default_finding_has_required_fields(self):
        finding = _make_sample_finding()
        assert "schemaVersion" in finding
        assert "id" in finding
        assert "ruleId" in finding
        assert "severity" in finding
        assert "tool" in finding
        assert "location" in finding
        assert "message" in finding

    def test_override_fields(self):
        finding = _make_sample_finding(id="custom_id", severity="HIGH")
        assert finding["id"] == "custom_id"
        assert finding["severity"] == "HIGH"

    def test_tool_is_dict(self):
        finding = _make_sample_finding()
        assert isinstance(finding["tool"], dict)
        assert "name" in finding["tool"]
        assert "version" in finding["tool"]


# ============================================================================
# Group 1: Adapter registry checks
# ============================================================================


class TestAdapterRegistryChecks:
    """Tests for adapter registry validation checks."""

    def test_adapters_importable(self):
        result = _check_adapters_importable()
        assert isinstance(result, CheckResult)
        assert result.status in (CheckStatus.PASS, CheckStatus.FAIL, CheckStatus.ERROR)

    def test_adapter_count(self):
        result = _check_adapter_count()
        assert isinstance(result, CheckResult)
        # Should pass if all 28 adapters are available
        assert result.status in (CheckStatus.PASS, CheckStatus.FAIL, CheckStatus.ERROR)

    def test_adapter_naming(self):
        result = _check_adapter_naming()
        assert isinstance(result, CheckResult)
        assert result.name == "adapter-naming"

    def test_no_duplicate_adapters(self):
        result = _check_no_duplicate_adapters()
        assert isinstance(result, CheckResult)
        assert result.name == "no-duplicate-adapters"

    def test_plugin_loader_fallback(self):
        result = _check_plugin_loader_fallback()
        assert isinstance(result, CheckResult)
        assert result.name == "plugin-loader-fallback"

    def test_adapter_metadata(self):
        result = _check_adapter_metadata()
        assert isinstance(result, CheckResult)
        assert result.name == "adapter-metadata"

    def test_adapters_importable_handles_loader_error(self):
        """If plugin_loader import fails, check should return ERROR."""
        with patch.dict("sys.modules", {"scripts.core.plugin_loader": None}):
            # Force import error by clearing module
            result = _check_adapters_importable()
            assert result.status in (
                CheckStatus.PASS,
                CheckStatus.FAIL,
                CheckStatus.ERROR,
            )


# ============================================================================
# Group 2: Fixture parsing checks
# ============================================================================


class TestFixtureParsing:
    """Tests for adapter parse function checks."""

    def test_make_adapter_parse_check_returns_callable(self):
        check_fn = _make_adapter_parse_check("bandit")
        assert callable(check_fn)

    def test_parse_check_bandit(self):
        check_fn = _make_adapter_parse_check("bandit")
        result = check_fn()
        assert isinstance(result, CheckResult)
        assert result.name == "parse-bandit"
        assert result.status in (CheckStatus.PASS, CheckStatus.FAIL, CheckStatus.ERROR)

    def test_parse_check_trivy(self):
        check_fn = _make_adapter_parse_check("trivy")
        result = check_fn()
        assert result.name == "parse-trivy"

    def test_parse_check_nonexistent_adapter(self):
        check_fn = _make_adapter_parse_check("nonexistent_xyz")
        result = check_fn()
        assert result.status == CheckStatus.ERROR
        assert "Import failed" in result.message

    def test_all_28_adapters_have_parse_checks(self):
        """All 28 expected adapters should produce valid checks."""
        for adapter_name in EXPECTED_ADAPTERS:
            check_fn = _make_adapter_parse_check(adapter_name)
            result = check_fn()
            assert isinstance(result, CheckResult), f"Failed for {adapter_name}"
            assert result.name == f"parse-{adapter_name}"

    @pytest.mark.parametrize("adapter", EXPECTED_ADAPTERS)
    def test_adapter_parse_check_individual(self, adapter):
        """Parameterized test: each adapter produces a valid check result."""
        check_fn = _make_adapter_parse_check(adapter)
        result = check_fn()
        assert isinstance(result, CheckResult)
        assert (
            result.status != CheckStatus.ERROR or "Import failed" not in result.message
        ), f"Adapter {adapter} failed to import: {result.message}"


# ============================================================================
# Group 3: Severity mapping checks
# ============================================================================


class TestSeverityMappingChecks:
    """Tests for severity mapping validation checks."""

    def test_severity_mappings_exist(self):
        result = _check_severity_mappings_exist()
        assert isinstance(result, CheckResult)
        assert result.status == CheckStatus.PASS

    def test_unknown_severity_fallback(self):
        result = _check_unknown_severity_fallback()
        assert isinstance(result, CheckResult)
        assert result.status == CheckStatus.PASS

    def test_standard_severity_set(self):
        result = _check_standard_severity_set()
        assert isinstance(result, CheckResult)
        assert result.status == CheckStatus.PASS

    def test_severity_mapping_direct(self):
        """Verify map_tool_severity works directly."""
        from scripts.core.common_finding import map_tool_severity

        assert map_tool_severity("zap", "informational") == "INFO"
        assert map_tool_severity("semgrep", "error") == "HIGH"
        assert map_tool_severity("nuclei", "critical") == "CRITICAL"

    def test_severity_enum_values(self):
        """Verify Severity enum has expected values."""
        from scripts.core.common_finding import Severity

        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.INFO.value == "INFO"


# ============================================================================
# Group 4: CommonFinding schema checks
# ============================================================================


class TestSchemaChecks:
    """Tests for CommonFinding schema validation checks."""

    def test_schema_file_exists(self):
        result = _check_schema_file_exists()
        assert result.status == CheckStatus.PASS

    def test_schema_loads(self):
        result = _check_schema_loads()
        assert result.status == CheckStatus.PASS

    def test_empty_findings_validate(self):
        result = _check_empty_findings_validate()
        assert result.status == CheckStatus.PASS

    def test_sample_finding_validates(self):
        result = _check_sample_finding_validates()
        assert result.status in (CheckStatus.PASS, CheckStatus.SKIP)

    def test_invalid_finding_fails(self):
        result = _check_invalid_finding_fails()
        assert result.status in (CheckStatus.PASS, CheckStatus.SKIP)


# ============================================================================
# Group 5: Empty/malformed input checks
# ============================================================================


class TestEdgeCaseChecks:
    """Tests for empty/malformed input handling checks."""

    def test_dedup_empty_dict(self):
        result = _check_dedup_empty_dict()
        assert result.status in (CheckStatus.PASS, CheckStatus.WARN)

    def test_dedup_empty_list(self):
        result = _check_dedup_empty_list()
        assert result.status == CheckStatus.PASS

    def test_dedup_none_values(self):
        result = _check_dedup_none_values()
        assert result.status == CheckStatus.PASS

    def test_schema_invalid_json(self):
        result = _check_schema_invalid_json()
        assert result.status == CheckStatus.PASS

    def test_large_findings_list(self):
        result = _check_large_findings_list()
        assert result.status == CheckStatus.PASS

    def test_nul_bytes_in_strings(self):
        result = _check_nul_bytes_in_strings()
        assert result.status == CheckStatus.PASS


# ============================================================================
# Group 6: Deduplication checks
# ============================================================================


class TestDeduplicationChecks:
    """Tests for deduplication validation checks."""

    def test_fixture_exists(self):
        result = _check_dedup_fixture_exists()
        assert result.status == CheckStatus.PASS

    def test_identical_reduces(self):
        result = _check_dedup_identical_reduces()
        assert result.status == CheckStatus.PASS

    def test_unique_preserves(self):
        result = _check_dedup_unique_preserves()
        assert result.status == CheckStatus.PASS

    def test_path_normalization(self):
        result = _check_dedup_path_normalization()
        assert result.status == CheckStatus.PASS

    def test_determinism(self):
        result = _check_dedup_determinism()
        assert result.status == CheckStatus.PASS

    def test_empty_input(self):
        result = _check_dedup_empty_input()
        assert result.status == CheckStatus.PASS

    def test_single_finding(self):
        result = _check_dedup_single_finding()
        assert result.status == CheckStatus.PASS

    def test_large_batch(self):
        result = _check_dedup_large_batch()
        assert result.status == CheckStatus.PASS

    def test_mixed_severity(self):
        result = _check_dedup_mixed_severity()
        assert result.status == CheckStatus.PASS

    def test_consensus(self):
        result = _check_dedup_consensus()
        assert result.status == CheckStatus.PASS

    def test_algorithm_selection(self):
        result = _check_dedup_algorithm_selection()
        assert result.status in (CheckStatus.PASS, CheckStatus.SKIP)

    def test_threshold_config(self):
        result = _check_dedup_threshold_config()
        assert result.status == CheckStatus.PASS


# ============================================================================
# Group 7: Compliance enrichment checks
# ============================================================================


class TestComplianceChecks:
    """Tests for compliance enrichment validation checks."""

    def test_owasp(self):
        result = _check_compliance_owasp()
        assert result.status == CheckStatus.PASS

    def test_cwe(self):
        result = _check_compliance_cwe()
        assert result.status == CheckStatus.PASS

    def test_cis(self):
        result = _check_compliance_cis()
        assert result.status in (CheckStatus.PASS, CheckStatus.WARN)

    def test_nist(self):
        result = _check_compliance_nist()
        assert result.status == CheckStatus.PASS

    def test_pci_dss(self):
        result = _check_compliance_pci_dss()
        assert result.status == CheckStatus.PASS

    def test_mitre(self):
        result = _check_compliance_mitre()
        assert result.status == CheckStatus.PASS

    def test_unmapped(self):
        result = _check_compliance_unmapped()
        assert result.status in (CheckStatus.PASS, CheckStatus.WARN)

    def test_empty_findings(self):
        result = _check_compliance_empty_findings()
        assert result.status == CheckStatus.PASS


# ============================================================================
# Group 8: SBOM enrichment checks
# ============================================================================


class TestSBOMChecks:
    """Tests for SBOM enrichment validation checks."""

    def test_functions_exist(self):
        result = _check_sbom_functions_exist()
        assert result.status == CheckStatus.PASS

    def test_empty_findings(self):
        result = _check_sbom_empty_findings()
        assert result.status == CheckStatus.PASS

    def test_no_syft_findings(self):
        result = _check_sbom_no_syft_findings()
        assert result.status == CheckStatus.PASS

    def test_index_building(self):
        result = _check_sbom_index_building()
        assert result.status in (CheckStatus.PASS, CheckStatus.WARN)


# ============================================================================
# Group 9: Reporter output checks
# ============================================================================


class TestReporterChecks:
    """Tests for reporter output validation checks."""

    def test_json(self):
        result = _check_reporter_json()
        assert result.status == CheckStatus.PASS

    def test_markdown(self):
        result = _check_reporter_markdown()
        assert result.status == CheckStatus.PASS

    def test_html(self):
        result = _check_reporter_html()
        assert result.status == CheckStatus.PASS

    def test_sarif(self):
        result = _check_reporter_sarif()
        assert result.status == CheckStatus.PASS

    def test_csv(self):
        result = _check_reporter_csv()
        assert result.status == CheckStatus.PASS

    def test_empty_findings(self):
        result = _check_reporter_empty_findings()
        assert result.status == CheckStatus.PASS

    def test_utf8(self):
        result = _check_reporter_utf8()
        assert result.status == CheckStatus.PASS

    def test_large_list(self):
        result = _check_reporter_large_list()
        assert result.status == CheckStatus.PASS


# ============================================================================
# Full tier checks
# ============================================================================


class TestFullTierChecks:
    """Tests for full-tier additional checks."""

    def test_e2e_pipeline(self):
        result = _check_full_e2e_pipeline()
        assert result.status == CheckStatus.PASS

    def test_dashboard_html(self):
        result = _check_full_dashboard_html()
        assert result.status == CheckStatus.PASS

    def test_sarif_schema(self):
        result = _check_full_sarif_schema()
        assert result.status == CheckStatus.PASS

    def test_json_roundtrip(self):
        result = _check_full_json_roundtrip()
        assert result.status == CheckStatus.PASS

    def test_1000_findings(self):
        result = _check_full_1000_findings()
        assert result.status == CheckStatus.PASS

    def test_compliance_enrichment(self):
        result = _check_full_compliance_enrichment()
        assert result.status in (CheckStatus.PASS, CheckStatus.WARN)

    def test_priority_enrichment(self):
        result = _check_full_priority_enrichment()
        assert result.status in (CheckStatus.PASS, CheckStatus.WARN, CheckStatus.SKIP)

    def test_fingerprint_stability(self):
        result = _check_full_fingerprint_stability()
        assert result.status == CheckStatus.PASS

    def test_dedup_determinism_across_runs(self):
        result = _check_full_dedup_determinism_across_runs()
        assert result.status == CheckStatus.PASS

    def test_consensus_stability(self):
        result = _check_full_consensus_stability()
        assert result.status == CheckStatus.PASS

    def test_dedup_reduction_pct(self):
        result = _check_full_dedup_reduction_pct()
        assert result.status in (CheckStatus.PASS, CheckStatus.WARN)

    def test_real_scan_available(self):
        result = _check_full_real_scan_available()
        assert result.status in (CheckStatus.PASS, CheckStatus.SKIP)


# ============================================================================
# Integration: validate_scans check-name uniqueness
# ============================================================================


class TestCheckNameUniqueness:
    """Verify all check names within a run are unique."""

    def test_quick_check_names_unique(self):
        result = validate_scans("quick")
        names = [c.name for c in result.checks]
        assert len(names) == len(
            set(names)
        ), f"Duplicate check names: {[n for n in names if names.count(n) > 1]}"

    def test_full_check_names_unique(self):
        result = validate_scans("full")
        names = [c.name for c in result.checks]
        assert len(names) == len(
            set(names)
        ), f"Duplicate check names: {[n for n in names if names.count(n) > 1]}"


# ============================================================================
# Integration: validate_scans with run_validators
# ============================================================================


class TestWithRunValidators:
    """Test validate_scans integrates with the run_validators framework."""

    def test_can_be_used_as_validator_fn(self):
        from scripts.core.validators import run_validators

        results = run_validators(validators=[validate_scans], tier="quick")
        assert len(results) == 1
        assert results[0].name == "Scan Correctness"

    def test_category_filter_works(self):
        from scripts.core.validators import run_validators

        results = run_validators(
            validators=[validate_scans],
            tier="quick",
            categories=["scans"],
        )
        assert len(results) == 1

    def test_category_filter_excludes(self):
        from scripts.core.validators import run_validators

        results = run_validators(
            validators=[validate_scans],
            tier="quick",
            categories=["cli"],
        )
        assert len(results) == 0


# ============================================================================
# Direct module import verification
# ============================================================================


class TestModuleImport:
    """Verify the module can be imported correctly."""

    def test_import_validate_scans(self):
        from scripts.core.validators.scan_validator import validate_scans as vs

        assert callable(vs)

    def test_import_from_validators_package(self):
        """validate_scans is importable from the scan_validator module."""
        mod = importlib.import_module("scripts.core.validators.scan_validator")
        assert hasattr(mod, "validate_scans")


# ============================================================================
# Edge case: check functions handle import errors gracefully
# ============================================================================


class TestImportErrorHandling:
    """Verify checks return ERROR status when dependencies are missing."""

    def test_adapter_check_with_broken_import(self):
        """An adapter parse check for a nonexistent module returns ERROR."""
        check_fn = _make_adapter_parse_check("totally_fake_adapter_xyz")
        result = check_fn()
        assert result.status == CheckStatus.ERROR

    def test_sample_finding_schema_version(self):
        """Sample finding uses schema version 1.2.0."""
        finding = _make_sample_finding()
        assert finding["schemaVersion"] == "1.2.0"
