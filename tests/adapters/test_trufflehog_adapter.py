"""Comprehensive tests for TruffleHog adapter.

Tests cover:
- Basic parsing of TruffleHog JSON/NDJSON output
- Verified vs unverified secret handling
- Multiple input formats (array, ndjson, single object, nested)
- File path extraction from various SourceMetadata structures
- Line number extraction
- Edge cases (empty, malformed, missing fields)
- Schema version and compliance enrichment
- Fingerprint generation
"""

import json
from pathlib import Path


from scripts.core.adapters.trufflehog_adapter import TruffleHogAdapter


def write_tmp(tmp_path: Path, name: str, content: str) -> Path:
    """Write content to a temporary file."""
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


class TestTruffleHogBasicParsing:
    """Tests for basic TruffleHog output parsing."""

    def test_basic_array_format(self, tmp_path: Path):
        """Test parsing JSON array format."""
        sample = [
            {
                "DetectorName": "AWS",
                "Verified": True,
                "SourceMetadata": {"Data": {"Filesystem": {"file": "config/aws.yaml"}}},
                "StartLine": 7,
            }
        ]
        path = write_tmp(tmp_path, "th.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        item = findings[0]
        assert item.severity == "HIGH"
        assert item.location["path"] == "config/aws.yaml"
        assert item.location["startLine"] == 7

    def test_ndjson_format(self, tmp_path: Path):
        """Test parsing NDJSON format (one JSON per line)."""
        ndjson = "\n".join(
            [
                json.dumps(
                    {
                        "DetectorName": "Slack",
                        "Verified": True,
                        "SourceMetadata": {
                            "Data": {"Filesystem": {"file": "webhooks.js"}}
                        },
                    }
                ),
                json.dumps(
                    {
                        "DetectorName": "GitHub",
                        "Verified": False,
                        "SourceMetadata": {
                            "Data": {"Filesystem": {"file": "tokens.py"}}
                        },
                    }
                ),
            ]
        )
        path = write_tmp(tmp_path, "th.ndjson", ndjson)
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 2

    def test_single_object_format(self, tmp_path: Path):
        """Test parsing single JSON object format."""
        sample = {"DetectorName": "JWT", "Verified": True, "Line": 12}
        path = write_tmp(tmp_path, "single.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].ruleId == "JWT"

    def test_nested_array_format(self, tmp_path: Path):
        """Test parsing nested array format [[{...}]]."""
        sample = [[{"DetectorName": "Nested", "Verified": False}]]
        path = write_tmp(tmp_path, "nested.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].ruleId == "Nested"

    def test_metadata_property(self, tmp_path: Path):
        """Test adapter metadata property."""
        adapter = TruffleHogAdapter()
        metadata = adapter.metadata
        assert metadata.name == "trufflehog"
        assert metadata.tool_name == "trufflehog"
        assert metadata.schema_version == "1.2.0"


class TestTruffleHogVerification:
    """Tests for verified vs unverified secret handling."""

    def test_verified_secret_high_severity(self, tmp_path: Path):
        """Test verified secrets have HIGH severity."""
        sample = [
            {
                "DetectorName": "GitHub",
                "Verified": True,
                "SourceMetadata": {"Data": {"Filesystem": {"file": "config.yml"}}},
                "Raw": "ghp_verifiedtoken123",
            }
        ]
        path = write_tmp(tmp_path, "verified.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].severity == "HIGH"
        assert "verified" in findings[0].tags

    def test_unverified_secret_medium_severity(self, tmp_path: Path):
        """Test unverified secrets have MEDIUM severity."""
        sample = [
            {
                "DetectorName": "AWS",
                "Verified": False,
                "SourceMetadata": {"Data": {"Filesystem": {"file": "secrets.txt"}}},
                "Raw": "AKIAIOSFODNN7EXAMPLE",
            }
        ]
        path = write_tmp(tmp_path, "unverified.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].severity == "MEDIUM"
        assert "unverified" in findings[0].tags

    def test_mixed_verification_status(self, tmp_path: Path):
        """Test handling of mixed verified/unverified secrets."""
        sample = [
            {
                "DetectorName": "Stripe",
                "Verified": True,
                "SourceMetadata": {"Data": {"Filesystem": {"file": "payments.py"}}},
            },
            {
                "DetectorName": "Twilio",
                "Verified": False,
                "SourceMetadata": {"Data": {"Filesystem": {"file": "sms.js"}}},
            },
        ]
        path = write_tmp(tmp_path, "mixed.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 2
        verified_count = sum(1 for f in findings if f.severity == "HIGH")
        unverified_count = sum(1 for f in findings if f.severity == "MEDIUM")
        assert verified_count == 1
        assert unverified_count == 1

    def test_verification_metadata_preserved(self, tmp_path: Path):
        """Test verification metadata is preserved in raw field."""
        sample = [
            {
                "DetectorName": "GitLab",
                "Verified": True,
                "SourceMetadata": {
                    "Data": {"Filesystem": {"file": "gitlab_token.txt"}}
                },
                "ExtraData": {"account": "testuser"},
            }
        ]
        path = write_tmp(tmp_path, "metadata.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].raw is not None
        assert "ExtraData" in findings[0].raw


class TestTruffleHogFilePath:
    """Tests for file path extraction."""

    def test_filesystem_path(self, tmp_path: Path):
        """Test path from SourceMetadata.Data.Filesystem.file."""
        sample = [
            {
                "DetectorName": "AWS",
                "Verified": False,
                "SourceMetadata": {"Data": {"Filesystem": {"file": "config/aws.yaml"}}},
            }
        ]
        path = write_tmp(tmp_path, "fs.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert findings[0].location["path"] == "config/aws.yaml"

    def test_filesystem_path_alternative(self, tmp_path: Path):
        """Test path from SourceMetadata.Data.Filesystem.path."""
        sample = [
            {
                "DetectorName": "AWS",
                "Verified": False,
                "SourceMetadata": {"Data": {"Filesystem": {"path": "alt/path.txt"}}},
            }
        ]
        path = write_tmp(tmp_path, "alt.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert findings[0].location["path"] == "alt/path.txt"

    def test_filename_field(self, tmp_path: Path):
        """Test path from Filename field."""
        sample = [{"DetectorName": "Token", "Verified": False, "Filename": "direct.py"}]
        path = write_tmp(tmp_path, "filename.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert findings[0].location["path"] == "direct.py"

    def test_path_field(self, tmp_path: Path):
        """Test path from Path field."""
        sample = [{"DetectorName": "Token", "Verified": False, "Path": "path/field.js"}]
        path = write_tmp(tmp_path, "pathfield.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert findings[0].location["path"] == "path/field.js"


class TestTruffleHogLineNumber:
    """Tests for line number extraction."""

    def test_start_line(self, tmp_path: Path):
        """Test StartLine field extraction."""
        sample = [{"DetectorName": "AWS", "Verified": False, "StartLine": 42}]
        path = write_tmp(tmp_path, "startline.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert findings[0].location["startLine"] == 42

    def test_line_field(self, tmp_path: Path):
        """Test Line field extraction."""
        sample = [{"DetectorName": "AWS", "Verified": False, "Line": 100}]
        path = write_tmp(tmp_path, "line.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert findings[0].location["startLine"] == 100

    def test_missing_line_defaults_to_zero(self, tmp_path: Path):
        """Test missing line number defaults to 0."""
        sample = [{"DetectorName": "AWS", "Verified": False}]
        path = write_tmp(tmp_path, "noline.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert findings[0].location["startLine"] == 0


class TestTruffleHogEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_file(self, tmp_path: Path):
        """Test parsing empty file."""
        path = write_tmp(tmp_path, "empty.json", "")
        adapter = TruffleHogAdapter()
        assert adapter.parse(path) == []

    def test_nonexistent_file(self, tmp_path: Path):
        """Test parsing nonexistent file."""
        adapter = TruffleHogAdapter()
        assert adapter.parse(tmp_path / "nonexistent.json") == []

    def test_malformed_json(self, tmp_path: Path):
        """Test parsing malformed JSON."""
        path = write_tmp(tmp_path, "bad.json", "{not valid json}")
        adapter = TruffleHogAdapter()
        assert adapter.parse(path) == []

    def test_empty_array(self, tmp_path: Path):
        """Test parsing empty array."""
        path = write_tmp(tmp_path, "empty_array.json", "[]")
        adapter = TruffleHogAdapter()
        assert adapter.parse(path) == []

    def test_detector_name_alternatives(self, tmp_path: Path):
        """Test Detector field as alternative to DetectorName."""
        sample = [{"Detector": "AltDetector", "Verified": False}]
        path = write_tmp(tmp_path, "alt_detector.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].ruleId == "AltDetector"

    def test_missing_detector_defaults_to_unknown(self, tmp_path: Path):
        """Test missing detector defaults to Unknown."""
        sample = [{"Verified": False}]
        path = write_tmp(tmp_path, "no_detector.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].ruleId == "Unknown"


class TestTruffleHogCompliance:
    """Tests for compliance enrichment and metadata."""

    def test_schema_version(self, tmp_path: Path):
        """Test schema version is set correctly."""
        sample = [{"DetectorName": "AWS", "Verified": False}]
        path = write_tmp(tmp_path, "schema.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert findings[0].schemaVersion == "1.2.0"

    def test_tool_name(self, tmp_path: Path):
        """Test tool name is correct."""
        sample = [{"DetectorName": "AWS", "Verified": False}]
        path = write_tmp(tmp_path, "tool.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert findings[0].tool["name"] == "trufflehog"

    def test_cwe_798_tag(self, tmp_path: Path):
        """Test CWE-798 is included in risk for hardcoded credentials."""
        sample = [{"DetectorName": "AWS", "Verified": True}]
        path = write_tmp(tmp_path, "cwe.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert findings[0].risk is not None
        assert "CWE-798" in findings[0].risk["cwe"]

    def test_remediation_message(self, tmp_path: Path):
        """Test remediation message is present."""
        sample = [{"DetectorName": "AWS", "Verified": False}]
        path = write_tmp(tmp_path, "remediation.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert "Rotate" in findings[0].remediation

    def test_secrets_tag(self, tmp_path: Path):
        """Test secrets tag is present."""
        sample = [{"DetectorName": "AWS", "Verified": False}]
        path = write_tmp(tmp_path, "tags.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert "secrets" in findings[0].tags


class TestTruffleHogFingerprinting:
    """Tests for finding fingerprint generation."""

    def test_unique_fingerprints(self, tmp_path: Path):
        """Test that different findings get unique fingerprints."""
        sample = [
            {"DetectorName": "AWS", "Verified": False, "Filename": "file1.py"},
            {"DetectorName": "AWS", "Verified": False, "Filename": "file2.py"},
        ]
        path = write_tmp(tmp_path, "fingerprint.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 2
        assert findings[0].id != findings[1].id

    def test_consistent_fingerprints(self, tmp_path: Path):
        """Test that same input produces same fingerprint."""
        sample = [
            {"DetectorName": "GitHub", "Verified": True, "Filename": "tokens.txt"}
        ]
        path = write_tmp(tmp_path, "consistent.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings1 = adapter.parse(path)
        findings2 = adapter.parse(path)
        assert findings1[0].id == findings2[0].id


class TestTruffleHogRawMessage:
    """Tests for raw/redacted message handling."""

    def test_raw_field_in_message(self, tmp_path: Path):
        """Test Raw field is used in message."""
        sample = [
            {
                "DetectorName": "AWS",
                "Verified": False,
                "Raw": "AKIAIOSFODNN7EXAMPLE",
            }
        ]
        path = write_tmp(tmp_path, "raw.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert "AKIAIOSFODNN7EXAMPLE" in findings[0].message

    def test_redacted_field_in_message(self, tmp_path: Path):
        """Test Redacted field is used in message when Raw is missing."""
        sample = [
            {
                "DetectorName": "Stripe",
                "Verified": True,
                "Redacted": "sk_live_****redacted****",
            }
        ]
        path = write_tmp(tmp_path, "redacted.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert "redacted" in findings[0].message

    def test_detector_name_fallback_in_message(self, tmp_path: Path):
        """Test detector name is used as fallback message."""
        sample = [{"DetectorName": "FallbackDetector", "Verified": False}]
        path = write_tmp(tmp_path, "fallback.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert "FallbackDetector" in findings[0].message


class TestTruffleHogUnicode:
    """Tests for Unicode handling."""

    def test_unicode_in_path(self, tmp_path: Path):
        """Test Unicode in file path."""
        sample = [
            {
                "DetectorName": "Token",
                "Verified": False,
                "Filename": "configs/日本語/secrets.txt",
            }
        ]
        path = write_tmp(tmp_path, "unicode.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert "日本語" in findings[0].location["path"]

    def test_unicode_in_raw(self, tmp_path: Path):
        """Test Unicode in raw content."""
        sample = [
            {
                "DetectorName": "Token",
                "Verified": False,
                "Raw": "密码=secret123",
            }
        ]
        path = write_tmp(tmp_path, "unicode_raw.json", json.dumps(sample))
        adapter = TruffleHogAdapter()
        findings = adapter.parse(path)
        assert "密码" in findings[0].message
