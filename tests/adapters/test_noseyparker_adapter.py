"""Comprehensive tests for NoseyParker adapter.

Tests cover:
- Basic parsing of NoseyParker JSON output
- Multiple detector types (AWS, GitHub, etc.)
- Alternative field naming conventions
- Edge cases (empty input, malformed JSON, missing fields)
- Unicode handling in secret content
- Multiple findings in single scan
"""

import json
from pathlib import Path


from scripts.core.adapters.noseyparker_adapter import NoseyParkerAdapter


def write_tmp(tmp_path: Path, name: str, content: str) -> Path:
    """Write content to a temporary file."""
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


class TestNoseyParkerBasicParsing:
    """Tests for basic NoseyParker output parsing."""

    def test_basic_single_match(self, tmp_path: Path):
        """Test parsing a single secret match."""
        sample = {
            "version": "0.16.0",
            "matches": [
                {
                    "signature": "AWS",
                    "path": "a/b.txt",
                    "line_number": 5,
                    "match": "AKIA...",
                }
            ],
        }
        path = write_tmp(tmp_path, "np.json", json.dumps(sample))
        adapter = NoseyParkerAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        item = findings[0]
        assert item.ruleId == "AWS"
        assert item.location["path"] == "a/b.txt"
        assert item.location["startLine"] == 5
        assert item.tool["name"] == "noseyparker"
        assert item.tool["version"] == "0.16.0"
        assert item.severity == "MEDIUM"
        assert "secrets" in item.tags

    def test_multiple_matches(self, tmp_path: Path):
        """Test parsing multiple secret matches."""
        sample = {
            "version": "0.17.0",
            "matches": [
                {
                    "signature": "AWS Access Key",
                    "path": "config/aws.yml",
                    "line_number": 10,
                    "match": "AKIAIOSFODNN7EXAMPLE",
                },
                {
                    "signature": "GitHub Token",
                    "path": ".env",
                    "line_number": 3,
                    "match": "ghp_xxxxxxxxxxxx",
                },
                {
                    "signature": "Private Key",
                    "path": "keys/private.pem",
                    "line_number": 1,
                    "match": "-----BEGIN RSA PRIVATE KEY-----",
                },
            ],
        }
        path = write_tmp(tmp_path, "np.json", json.dumps(sample))
        adapter = NoseyParkerAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 3
        rule_ids = {f.ruleId for f in findings}
        assert rule_ids == {"AWS Access Key", "GitHub Token", "Private Key"}

    def test_metadata_property(self, tmp_path: Path):
        """Test adapter metadata property."""
        adapter = NoseyParkerAdapter()
        metadata = adapter.metadata
        assert metadata.name == "noseyparker"
        assert metadata.tool_name == "noseyparker"
        assert metadata.schema_version == "1.2.0"


class TestNoseyParkerAlternativeFieldNames:
    """Tests for alternative field naming conventions."""

    def test_detector_name_field(self, tmp_path: Path):
        """Test parsing with DetectorName field instead of signature."""
        sample = {
            "version": "0.18.0",
            "matches": [
                {
                    "DetectorName": "AWS Secret Access Key",
                    "path": "src/config.py",
                    "line_number": 25,
                    "match": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                }
            ],
        }
        path = write_tmp(tmp_path, "np.json", json.dumps(sample))
        adapter = NoseyParkerAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].ruleId == "AWS Secret Access Key"

    def test_location_object_field(self, tmp_path: Path):
        """Test parsing with location object structure."""
        sample = {
            "version": "0.18.0",
            "matches": [
                {
                    "signature": "Slack Token",
                    "location": {"path": "scripts/notify.sh", "startLine": 15},
                    "match": "xoxb-xxxx-xxxx-xxxx",
                }
            ],
        }
        path = write_tmp(tmp_path, "np.json", json.dumps(sample))
        adapter = NoseyParkerAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].location["path"] == "scripts/notify.sh"
        assert findings[0].location["startLine"] == 15

    def test_context_field_instead_of_match(self, tmp_path: Path):
        """Test parsing with context field instead of match."""
        sample = {
            "version": "0.16.0",
            "matches": [
                {
                    "signature": "SSH Private Key",
                    "path": ".ssh/id_rsa",
                    "line_number": 1,
                    "context": "Passphrase protected SSH key",
                }
            ],
        }
        path = write_tmp(tmp_path, "np.json", json.dumps(sample))
        adapter = NoseyParkerAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert "Passphrase protected SSH key" in findings[0].message


class TestNoseyParkerEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_file(self, tmp_path: Path):
        """Test parsing empty file."""
        path = write_tmp(tmp_path, "empty.json", "")
        adapter = NoseyParkerAdapter()
        assert adapter.parse(path) == []

    def test_malformed_json(self, tmp_path: Path):
        """Test parsing malformed JSON."""
        path = write_tmp(tmp_path, "bad.json", "{not valid json}")
        adapter = NoseyParkerAdapter()
        assert adapter.parse(path) == []

    def test_matches_not_list(self, tmp_path: Path):
        """Test parsing when matches is not a list."""
        sample = {"matches": {}}
        path = write_tmp(tmp_path, "dict_matches.json", json.dumps(sample))
        adapter = NoseyParkerAdapter()
        assert adapter.parse(path) == []

    def test_matches_missing(self, tmp_path: Path):
        """Test parsing when matches key is missing."""
        sample = {"version": "0.16.0"}
        path = write_tmp(tmp_path, "no_matches.json", json.dumps(sample))
        adapter = NoseyParkerAdapter()
        assert adapter.parse(path) == []

    def test_nonexistent_file(self, tmp_path: Path):
        """Test parsing nonexistent file."""
        adapter = NoseyParkerAdapter()
        assert adapter.parse(tmp_path / "nonexistent.json") == []

    def test_match_item_not_dict(self, tmp_path: Path):
        """Test parsing when match item is not a dictionary."""
        sample = {"matches": ["string_not_dict", 123, None]}
        path = write_tmp(tmp_path, "bad_items.json", json.dumps(sample))
        adapter = NoseyParkerAdapter()
        assert adapter.parse(path) == []

    def test_missing_line_number(self, tmp_path: Path):
        """Test parsing without line number defaults to 0."""
        sample = {
            "matches": [
                {"signature": "API Key", "path": "config.txt", "match": "key123"}
            ]
        }
        path = write_tmp(tmp_path, "no_line.json", json.dumps(sample))
        adapter = NoseyParkerAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].location["startLine"] == 0


class TestNoseyParkerUnicodeHandling:
    """Tests for Unicode and encoding edge cases."""

    def test_unicode_in_path(self, tmp_path: Path):
        """Test parsing with Unicode characters in file path."""
        sample = {
            "matches": [
                {
                    "signature": "Password",
                    "path": "configs/\u65e5\u672c\u8a9e/secrets.txt",
                    "line_number": 1,
                    "match": "password123",
                }
            ]
        }
        path = write_tmp(tmp_path, "unicode.json", json.dumps(sample))
        adapter = NoseyParkerAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert "\u65e5\u672c\u8a9e" in findings[0].location["path"]

    def test_unicode_in_match_content(self, tmp_path: Path):
        """Test parsing with Unicode in secret content."""
        sample = {
            "matches": [
                {
                    "signature": "API Key",
                    "path": "api.conf",
                    "line_number": 5,
                    "match": "key=\u5bc6\u7801123\ud83d\udd11",
                }
            ]
        }
        path = write_tmp(tmp_path, "unicode_match.json", json.dumps(sample))
        adapter = NoseyParkerAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert "\u5bc6\u7801" in findings[0].message


class TestNoseyParkerCompliance:
    """Tests for compliance enrichment and metadata."""

    def test_cwe_tag_present(self, tmp_path: Path):
        """Test that CWE-798 tag is added for secrets."""
        sample = {
            "matches": [
                {
                    "signature": "Hardcoded Password",
                    "path": "app.py",
                    "line_number": 10,
                    "match": "password='secret123'",
                }
            ]
        }
        path = write_tmp(tmp_path, "cwe.json", json.dumps(sample))
        adapter = NoseyParkerAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].risk is not None
        assert "CWE-798" in findings[0].risk.get("cwe", [])

    def test_schema_version(self, tmp_path: Path):
        """Test schema version is set correctly."""
        sample = {
            "matches": [
                {
                    "signature": "Token",
                    "path": "test.txt",
                    "line_number": 1,
                    "match": "tok",
                }
            ]
        }
        path = write_tmp(tmp_path, "schema.json", json.dumps(sample))
        adapter = NoseyParkerAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].schemaVersion == "1.2.0"

    def test_remediation_message(self, tmp_path: Path):
        """Test remediation message is present."""
        sample = {
            "matches": [
                {
                    "signature": "Key",
                    "path": "test.txt",
                    "line_number": 1,
                    "match": "key",
                }
            ]
        }
        path = write_tmp(tmp_path, "remediation.json", json.dumps(sample))
        adapter = NoseyParkerAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert "Rotate" in findings[0].remediation


class TestNoseyParkerFingerprinting:
    """Tests for finding fingerprint generation."""

    def test_unique_fingerprints(self, tmp_path: Path):
        """Test that different findings get unique fingerprints."""
        sample = {
            "matches": [
                {
                    "signature": "AWS",
                    "path": "file1.txt",
                    "line_number": 1,
                    "match": "key1",
                },
                {
                    "signature": "AWS",
                    "path": "file2.txt",
                    "line_number": 1,
                    "match": "key2",
                },
            ]
        }
        path = write_tmp(tmp_path, "fingerprint.json", json.dumps(sample))
        adapter = NoseyParkerAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 2
        assert findings[0].id != findings[1].id

    def test_consistent_fingerprints(self, tmp_path: Path):
        """Test that same input produces same fingerprint."""
        sample = {
            "matches": [
                {
                    "signature": "GitHub Token",
                    "path": "src/auth.py",
                    "line_number": 50,
                    "match": "ghp_test123",
                }
            ]
        }
        path = write_tmp(tmp_path, "consistent.json", json.dumps(sample))
        adapter = NoseyParkerAdapter()
        findings1 = adapter.parse(path)
        findings2 = adapter.parse(path)
        assert findings1[0].id == findings2[0].id
