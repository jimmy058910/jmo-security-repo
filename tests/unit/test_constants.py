"""
Tests for Constants Module

Verifies that all constants are properly defined and accessible.
"""

import pytest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from scripts.core import constants


class TestConstants:
    """Test constants module"""

    def test_schema_versions_defined(self):
        """Test schema version constants are defined"""
        assert constants.SCHEMA_VERSION_CURRENT == "1.2.0"
        assert constants.SCHEMA_VERSION_V1_0 == "1.0.0"
        assert constants.SCHEMA_VERSION_V1_1 == "1.1.0"

    def test_timeouts_defined(self):
        """Test timeout constants are defined"""
        assert constants.TIMEOUT_DEFAULT == 600
        assert constants.TIMEOUT_FAST == 300
        assert constants.TIMEOUT_DEEP == 900
        assert constants.TIMEOUT_NOSEYPARKER == 1200
        assert constants.TIMEOUT_AFLPLUSPLUS == 1800

    def test_threads_defined(self):
        """Test thread constants are defined"""
        assert constants.THREADS_FAST == 8
        assert constants.THREADS_BALANCED == 4
        assert constants.THREADS_DEEP == 2
        assert constants.THREADS_MIN == 1
        assert constants.THREADS_MAX == 128

    def test_tool_names_defined(self):
        """Test tool name constants are defined"""
        assert constants.TOOL_TRUFFLEHOG == "trufflehog"
        assert constants.TOOL_SEMGREP == "semgrep"
        assert constants.TOOL_TRIVY == "trivy"
        assert len(constants.ALL_TOOLS) == 14

    def test_severity_levels_defined(self):
        """Test severity constants are defined"""
        assert constants.SEVERITY_CRITICAL == "CRITICAL"
        assert constants.SEVERITY_HIGH == "HIGH"
        assert constants.SEVERITY_MEDIUM == "MEDIUM"
        assert constants.SEVERITY_LOW == "LOW"
        assert constants.SEVERITY_INFO == "INFO"
        assert len(constants.SEVERITY_ORDER) == 5

    def test_profile_names_defined(self):
        """Test profile constants are defined"""
        assert constants.PROFILE_FAST == "fast"
        assert constants.PROFILE_BALANCED == "balanced"
        assert constants.PROFILE_DEEP == "deep"

    def test_profile_tools_defined(self):
        """Test profile tool lists are defined"""
        assert len(constants.PROFILE_FAST_TOOLS) == 3
        assert len(constants.PROFILE_BALANCED_TOOLS) == 7
        assert len(constants.PROFILE_DEEP_TOOLS) == 11

    def test_output_formats_defined(self):
        """Test output format constants are defined"""
        assert constants.OUTPUT_JSON == "json"
        assert constants.OUTPUT_MARKDOWN == "md"
        assert constants.OUTPUT_HTML == "html"
        assert constants.OUTPUT_SARIF == "sarif"
        assert len(constants.ALL_OUTPUT_FORMATS) == 5

    def test_directory_constants_defined(self):
        """Test directory structure constants are defined"""
        assert constants.DIR_INDIVIDUAL_REPOS == "individual-repos"
        assert constants.DIR_INDIVIDUAL_IMAGES == "individual-images"
        assert constants.DIR_SUMMARIES == "summaries"
        assert len(constants.ALL_TARGET_DIRS) == 6

    def test_compliance_frameworks_defined(self):
        """Test compliance framework constants are defined"""
        assert constants.COMPLIANCE_OWASP_TOP10 == "owaspTop10_2021"
        assert constants.COMPLIANCE_CWE_TOP25 == "cweTop25_2024"
        assert len(constants.ALL_COMPLIANCE_FRAMEWORKS) == 6

    def test_exit_codes_defined(self):
        """Test exit code constants are defined"""
        assert constants.EXIT_SUCCESS == 0
        assert constants.EXIT_GENERAL_ERROR == 1
        assert constants.EXIT_CONFIG_ERROR == 2

    def test_log_levels_defined(self):
        """Test log level constants are defined"""
        assert constants.LOG_LEVEL_DEBUG == "DEBUG"
        assert constants.LOG_LEVEL_INFO == "INFO"
        assert len(constants.ALL_LOG_LEVELS) == 4


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
