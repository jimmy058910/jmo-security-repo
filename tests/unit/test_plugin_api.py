"""Unit tests for plugin API (plugin_api.py)."""

import pytest
from pathlib import Path

from scripts.core.plugin_api import (
    Finding,
    PluginMetadata,
    AdapterPlugin,
    adapter_plugin,
)


class TestFinding:
    """Test Finding dataclass."""

    def test_finding_defaults(self):
        """Test Finding with default values."""
        finding = Finding()
        assert finding.schemaVersion == "1.2.0"
        assert finding.id == ""
        assert finding.ruleId == ""
        assert finding.severity == ""
        assert finding.tool == {}
        assert finding.location == {}
        assert finding.message == ""
        assert finding.title is None
        assert finding.description is None
        assert finding.remediation is None
        assert finding.references == []
        assert finding.tags == []
        assert finding.cvss is None
        assert finding.risk is None
        assert finding.compliance is None
        assert finding.context is None
        assert finding.raw is None

    def test_finding_custom_values(self):
        """Test Finding with custom values."""
        finding = Finding(
            id="test-001",
            ruleId="RULE-123",
            severity="HIGH",
            tool={"name": "test-tool", "version": "1.0.0"},
            location={"path": "test.py", "startLine": 42, "endLine": 45},
            message="Test finding message",
            title="Test Title",
            description="Test Description",
            remediation="Test Remediation",
            references=["https://example.com"],
            tags=["security", "test"],
            cvss={"score": 7.5, "vector": "CVSS:3.1/AV:N"},
            risk={"cwe": "CWE-79", "confidence": "HIGH"},
            compliance={"owasp": ["A03:2021"]},
            context={"line": "password = 'secret'"},
            raw={"original": "data"},
        )

        assert finding.id == "test-001"
        assert finding.ruleId == "RULE-123"
        assert finding.severity == "HIGH"
        assert finding.tool == {"name": "test-tool", "version": "1.0.0"}
        assert finding.location == {"path": "test.py", "startLine": 42, "endLine": 45}
        assert finding.message == "Test finding message"
        assert finding.title == "Test Title"
        assert finding.description == "Test Description"
        assert finding.remediation == "Test Remediation"
        assert finding.references == ["https://example.com"]
        assert finding.tags == ["security", "test"]
        assert finding.cvss == {"score": 7.5, "vector": "CVSS:3.1/AV:N"}
        assert finding.risk == {"cwe": "CWE-79", "confidence": "HIGH"}
        assert finding.compliance == {"owasp": ["A03:2021"]}
        assert finding.context == {"line": "password = 'secret'"}
        assert finding.raw == {"original": "data"}


class TestPluginMetadata:
    """Test PluginMetadata dataclass."""

    def test_metadata_defaults(self):
        """Test PluginMetadata with default values."""
        metadata = PluginMetadata(name="test-plugin", version="1.0.0")
        assert metadata.name == "test-plugin"
        assert metadata.version == "1.0.0"
        assert metadata.author == "JMo Security"
        assert metadata.description == ""
        assert metadata.tool_name == ""
        assert metadata.tool_version is None
        assert metadata.schema_version == "1.2.0"
        assert metadata.output_format == "json"
        assert metadata.exit_codes == {}

    def test_metadata_custom_values(self):
        """Test PluginMetadata with custom values."""
        metadata = PluginMetadata(
            name="trivy",
            version="1.0.0",
            author="Custom Author",
            description="Trivy adapter",
            tool_name="trivy",
            tool_version="0.68.0",
            schema_version="1.2.0",
            output_format="json",
            exit_codes={0: "clean", 1: "findings", 2: "error"},
        )

        assert metadata.name == "trivy"
        assert metadata.version == "1.0.0"
        assert metadata.author == "Custom Author"
        assert metadata.description == "Trivy adapter"
        assert metadata.tool_name == "trivy"
        assert metadata.tool_version == "0.68.0"
        assert metadata.schema_version == "1.2.0"
        assert metadata.output_format == "json"
        assert metadata.exit_codes == {0: "clean", 1: "findings", 2: "error"}


class TestAdapterPlugin:
    """Test AdapterPlugin base class."""

    def test_cannot_instantiate_abstract_class(self):
        """Test that AdapterPlugin cannot be instantiated directly."""
        with pytest.raises(TypeError):
            AdapterPlugin()

    def test_concrete_implementation(self):
        """Test concrete AdapterPlugin implementation."""

        class TestAdapter(AdapterPlugin):
            @property
            def metadata(self):
                return PluginMetadata(
                    name="test", version="1.0.0", tool_name="test-tool"
                )

            def parse(self, output_path: Path):
                return []

        adapter = TestAdapter()
        assert adapter.metadata.name == "test"
        assert adapter.parse(Path("/tmp/test.json")) == []

    def test_validate_success(self, tmp_path):
        """Test validate() with valid output."""

        class TestAdapter(AdapterPlugin):
            @property
            def metadata(self):
                return PluginMetadata(name="test", version="1.0.0")

            def parse(self, output_path: Path):
                return [
                    Finding(
                        id="test-001", ruleId="TEST", severity="HIGH", message="Test"
                    )
                ]

        adapter = TestAdapter()

        # Create test file
        test_file = tmp_path / "test.json"
        test_file.write_text('{"test": "data"}')

        assert adapter.validate(test_file) is True

    def test_validate_missing_file(self):
        """Test validate() with missing file."""

        class TestAdapter(AdapterPlugin):
            @property
            def metadata(self):
                return PluginMetadata(name="test", version="1.0.0")

            def parse(self, output_path: Path):
                return []

        adapter = TestAdapter()
        assert adapter.validate(Path("/nonexistent/file.json")) is False

    def test_validate_parse_error(self, tmp_path):
        """Test validate() with parse error."""

        class TestAdapter(AdapterPlugin):
            @property
            def metadata(self):
                return PluginMetadata(name="test", version="1.0.0")

            def parse(self, output_path: Path):
                raise ValueError("Parse error")

        adapter = TestAdapter()

        # Create test file
        test_file = tmp_path / "test.json"
        test_file.write_text('{"test": "data"}')

        assert adapter.validate(test_file) is False

    def test_get_fingerprint_default(self):
        """Test default get_fingerprint() implementation."""

        class TestAdapter(AdapterPlugin):
            @property
            def metadata(self):
                return PluginMetadata(name="test", version="1.0.0")

            def parse(self, output_path: Path):
                return []

        adapter = TestAdapter()

        finding = Finding(
            ruleId="RULE-123",
            severity="HIGH",
            tool={"name": "test-tool", "version": "1.0.0"},
            location={"path": "test.py", "startLine": 42},
            message="Test finding message",
        )

        fingerprint = adapter.get_fingerprint(finding)

        assert isinstance(fingerprint, str)
        assert len(fingerprint) == 16  # 16 hex characters

        # Verify deterministic (same input = same output)
        fingerprint2 = adapter.get_fingerprint(finding)
        assert fingerprint == fingerprint2

    def test_get_fingerprint_different_findings(self):
        """Test that different findings produce different fingerprints."""

        class TestAdapter(AdapterPlugin):
            @property
            def metadata(self):
                return PluginMetadata(name="test", version="1.0.0")

            def parse(self, output_path: Path):
                return []

        adapter = TestAdapter()

        finding1 = Finding(
            ruleId="RULE-123",
            severity="HIGH",
            tool={"name": "test-tool"},
            location={"path": "test.py", "startLine": 42},
            message="Test message 1",
        )

        finding2 = Finding(
            ruleId="RULE-456",
            severity="MEDIUM",
            tool={"name": "test-tool"},
            location={"path": "test2.py", "startLine": 100},
            message="Test message 2",
        )

        fingerprint1 = adapter.get_fingerprint(finding1)
        fingerprint2 = adapter.get_fingerprint(finding2)

        assert fingerprint1 != fingerprint2

    def test_get_fingerprint_custom_override(self):
        """Test custom get_fingerprint() override."""

        class TestAdapter(AdapterPlugin):
            @property
            def metadata(self):
                return PluginMetadata(name="test", version="1.0.0")

            def parse(self, output_path: Path):
                return []

            def get_fingerprint(self, finding: Finding) -> str:
                # Custom fingerprinting logic
                return f"custom-{finding.ruleId}"

        adapter = TestAdapter()

        finding = Finding(
            ruleId="RULE-123",
            severity="HIGH",
            tool={"name": "test-tool"},
            location={"path": "test.py", "startLine": 42},
            message="Test message",
        )

        fingerprint = adapter.get_fingerprint(finding)
        assert fingerprint == "custom-RULE-123"


class TestAdapterPluginDecorator:
    """Test @adapter_plugin decorator."""

    def test_decorator_attaches_metadata(self):
        """Test that decorator attaches metadata to class."""

        @adapter_plugin(
            PluginMetadata(name="test-plugin", version="1.0.0", tool_name="test-tool")
        )
        class TestAdapter(AdapterPlugin):
            @property
            def metadata(self):
                return self.__class__._plugin_metadata

            def parse(self, output_path: Path):
                return []

        assert hasattr(TestAdapter, "_plugin_metadata")
        assert TestAdapter._plugin_metadata.name == "test-plugin"
        assert TestAdapter._plugin_metadata.version == "1.0.0"
        assert TestAdapter._plugin_metadata.tool_name == "test-tool"

        # Verify instance can access metadata
        adapter = TestAdapter()
        assert adapter.metadata.name == "test-plugin"

    def test_decorator_multiple_plugins(self):
        """Test decorator with multiple plugin classes."""

        @adapter_plugin(PluginMetadata(name="plugin-1", version="1.0.0"))
        class Plugin1(AdapterPlugin):
            @property
            def metadata(self):
                return self.__class__._plugin_metadata

            def parse(self, output_path: Path):
                return []

        @adapter_plugin(PluginMetadata(name="plugin-2", version="2.0.0"))
        class Plugin2(AdapterPlugin):
            @property
            def metadata(self):
                return self.__class__._plugin_metadata

            def parse(self, output_path: Path):
                return []

        assert Plugin1._plugin_metadata.name == "plugin-1"
        assert Plugin1._plugin_metadata.version == "1.0.0"
        assert Plugin2._plugin_metadata.name == "plugin-2"
        assert Plugin2._plugin_metadata.version == "2.0.0"
