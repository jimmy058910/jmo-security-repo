"""Comprehensive tests for Bearer adapter.

Tests cover:
- Data flow detection parsing (data_types)
- Security finding parsing (findings)
- Multiple data types and locations
- Edge cases (empty, malformed, missing fields)
- Schema version and compliance enrichment
- Fingerprint generation
"""

import json
from pathlib import Path


from scripts.core.adapters.bearer_adapter import BearerAdapter


def write(p: Path, obj):
    """Write JSON object to a file."""
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


class TestBearerDataflowDetection:
    """Tests for Bearer dataflow detection parsing."""

    def test_basic_dataflow_detection(self, tmp_path: Path):
        """Test Bearer adapter with data flow detection."""
        data = {
            "data_types": [
                {
                    "name": "EmailAddress",
                    "detectors": [
                        {
                            "name": "ruby",
                            "locations": [
                                {
                                    "filename": "app/models/user.rb",
                                    "line_number": 15,
                                    "field_name": "email",
                                    "subject_name": "User",
                                }
                            ],
                        }
                    ],
                }
            ]
        }
        f = tmp_path / "bearer.json"
        write(f, data)
        adapter = BearerAdapter()
        items = adapter.parse(f)

        assert len(items) == 1
        assert items[0].ruleId == "DATA.EmailAddress"
        assert items[0].severity == "MEDIUM"
        assert "data-privacy" in items[0].tags
        assert "sensitive-data" in items[0].tags
        assert items[0].context["data_type"] == "EmailAddress"
        assert items[0].context["subject_name"] == "User"
        assert items[0].context["field_name"] == "email"
        assert items[0].location["path"] == "app/models/user.rb"
        assert items[0].location["startLine"] == 15

    def test_multiple_data_types(self, tmp_path: Path):
        """Test Bearer adapter with multiple data types."""
        data = {
            "data_types": [
                {
                    "name": "SSN",
                    "detectors": [
                        {
                            "locations": [
                                {
                                    "filename": "app/controllers/users_controller.rb",
                                    "line_number": 42,
                                    "field_name": "social_security_number",
                                    "subject_name": "User",
                                }
                            ]
                        }
                    ],
                },
                {
                    "name": "CreditCardNumber",
                    "detectors": [
                        {
                            "locations": [
                                {
                                    "filename": "app/models/payment.rb",
                                    "line_number": 20,
                                    "field_name": "card_number",
                                    "subject_name": "Payment",
                                }
                            ]
                        }
                    ],
                },
            ]
        }
        f = tmp_path / "bearer.json"
        write(f, data)
        adapter = BearerAdapter()
        items = adapter.parse(f)

        assert len(items) == 2
        assert items[0].context["data_type"] == "SSN"
        assert items[1].context["data_type"] == "CreditCardNumber"

    def test_multiple_locations_same_type(self, tmp_path: Path):
        """Test Bearer adapter with multiple locations for same data type."""
        data = {
            "data_types": [
                {
                    "name": "PhoneNumber",
                    "detectors": [
                        {
                            "locations": [
                                {
                                    "filename": "app/models/user.rb",
                                    "line_number": 10,
                                    "field_name": "phone",
                                    "subject_name": "User",
                                },
                                {
                                    "filename": "app/models/contact.rb",
                                    "line_number": 8,
                                    "field_name": "mobile",
                                    "subject_name": "Contact",
                                },
                            ]
                        }
                    ],
                }
            ]
        }
        f = tmp_path / "bearer.json"
        write(f, data)
        adapter = BearerAdapter()
        items = adapter.parse(f)

        assert len(items) == 2
        assert items[0].location["path"] == "app/models/user.rb"
        assert items[1].location["path"] == "app/models/contact.rb"


class TestBearerSecurityFinding:
    """Tests for Bearer security finding parsing."""

    def test_basic_security_finding(self, tmp_path: Path):
        """Test Bearer adapter with security finding."""
        data = {
            "findings": [
                {
                    "rule_id": "javascript_lang_session",
                    "severity": "HIGH",
                    "filename": "frontend/src/app/login/login.component.ts",
                    "line_number": 102,
                    "description": "Insecure session handling detected",
                }
            ]
        }
        f = tmp_path / "bearer.json"
        write(f, data)
        adapter = BearerAdapter()
        items = adapter.parse(f)

        assert len(items) == 1
        assert items[0].ruleId == "javascript_lang_session"
        assert items[0].severity == "HIGH"
        assert "security" in items[0].tags
        assert items[0].location["path"] == "frontend/src/app/login/login.component.ts"
        assert items[0].location["startLine"] == 102

    def test_critical_security_finding(self, tmp_path: Path):
        """Test Bearer adapter with CRITICAL severity finding."""
        data = {
            "findings": [
                {
                    "rule_id": "ruby_lang_weak_encryption",
                    "severity": "CRITICAL",
                    "filename": "app/services/encryption.rb",
                    "line_number": 15,
                    "description": "Weak encryption algorithm detected",
                }
            ]
        }
        f = tmp_path / "bearer.json"
        write(f, data)
        adapter = BearerAdapter()
        items = adapter.parse(f)

        assert len(items) == 1
        assert items[0].severity == "CRITICAL"

    def test_low_security_finding(self, tmp_path: Path):
        """Test Bearer adapter with LOW severity finding."""
        data = {
            "findings": [
                {
                    "rule_id": "info_leak",
                    "severity": "LOW",
                    "filename": "app/controllers/api.rb",
                    "line_number": 50,
                    "description": "Information disclosure",
                }
            ]
        }
        f = tmp_path / "bearer.json"
        write(f, data)
        adapter = BearerAdapter()
        items = adapter.parse(f)

        assert len(items) == 1
        assert items[0].severity == "LOW"


class TestBearerMixedFindings:
    """Tests for mixed dataflow and security findings."""

    def test_mixed_findings(self, tmp_path: Path):
        """Test Bearer adapter with both dataflow and security findings."""
        data = {
            "data_types": [
                {
                    "name": "Password",
                    "detectors": [
                        {
                            "locations": [
                                {
                                    "filename": "app/models/user.rb",
                                    "line_number": 25,
                                    "field_name": "password_digest",
                                }
                            ]
                        }
                    ],
                }
            ],
            "findings": [
                {
                    "rule_id": "ruby_lang_weak_encryption",
                    "severity": "CRITICAL",
                    "filename": "app/services/encryption.rb",
                    "line_number": 15,
                    "description": "Weak encryption algorithm detected",
                }
            ],
        }
        f = tmp_path / "bearer.json"
        write(f, data)
        adapter = BearerAdapter()
        items = adapter.parse(f)

        assert len(items) == 2
        dataflow_findings = [i for i in items if i.ruleId.startswith("DATA.")]
        security_findings = [i for i in items if not i.ruleId.startswith("DATA.")]
        assert len(dataflow_findings) == 1
        assert len(security_findings) == 1
        assert security_findings[0].severity == "CRITICAL"


class TestBearerEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_file(self, tmp_path: Path):
        """Test Bearer adapter handles empty JSON file."""
        f = tmp_path / "bearer.json"
        f.write_text("", encoding="utf-8")
        adapter = BearerAdapter()
        items = adapter.parse(f)
        assert items == []

    def test_nonexistent_file(self, tmp_path: Path):
        """Test Bearer adapter handles nonexistent file."""
        adapter = BearerAdapter()
        items = adapter.parse(tmp_path / "nonexistent.json")
        assert items == []

    def test_malformed_json(self, tmp_path: Path):
        """Test Bearer adapter handles malformed JSON."""
        f = tmp_path / "bearer.json"
        f.write_text("{not valid json}", encoding="utf-8")
        adapter = BearerAdapter()
        items = adapter.parse(f)
        assert items == []

    def test_empty_data_types(self, tmp_path: Path):
        """Test Bearer adapter with empty data_types array."""
        data = {"data_types": []}
        f = tmp_path / "bearer.json"
        write(f, data)
        adapter = BearerAdapter()
        items = adapter.parse(f)
        assert items == []

    def test_empty_findings(self, tmp_path: Path):
        """Test Bearer adapter with empty findings array."""
        data = {"findings": []}
        f = tmp_path / "bearer.json"
        write(f, data)
        adapter = BearerAdapter()
        items = adapter.parse(f)
        assert items == []

    def test_no_subject_name(self, tmp_path: Path):
        """Test Bearer adapter handles missing subject_name gracefully."""
        data = {
            "data_types": [
                {
                    "name": "IPAddress",
                    "detectors": [
                        {
                            "locations": [
                                {
                                    "filename": "app/controllers/api_controller.rb",
                                    "line_number": 30,
                                    "field_name": "client_ip",
                                }
                            ]
                        }
                    ],
                }
            ]
        }
        f = tmp_path / "bearer.json"
        write(f, data)
        adapter = BearerAdapter()
        items = adapter.parse(f)

        assert len(items) == 1
        assert items[0].context["subject_name"] is None
        assert "subject:" not in items[0].message

    def test_missing_field_name(self, tmp_path: Path):
        """Test Bearer adapter handles missing field_name gracefully."""
        data = {
            "data_types": [
                {
                    "name": "TestData",
                    "detectors": [
                        {
                            "locations": [
                                {
                                    "filename": "test.rb",
                                    "line_number": 1,
                                }
                            ]
                        }
                    ],
                }
            ]
        }
        f = tmp_path / "bearer.json"
        write(f, data)
        adapter = BearerAdapter()
        items = adapter.parse(f)

        assert len(items) == 1
        assert items[0].context["field_name"] is None

    def test_data_type_entry_not_dict(self, tmp_path: Path):
        """Test Bearer adapter skips non-dict data type entries."""
        data = {"data_types": ["not a dict", 123]}
        f = tmp_path / "bearer.json"
        write(f, data)
        adapter = BearerAdapter()
        items = adapter.parse(f)
        assert items == []

    def test_detector_not_dict(self, tmp_path: Path):
        """Test Bearer adapter skips non-dict detector entries."""
        data = {"data_types": [{"name": "Test", "detectors": ["not a dict"]}]}
        f = tmp_path / "bearer.json"
        write(f, data)
        adapter = BearerAdapter()
        items = adapter.parse(f)
        assert items == []

    def test_location_not_dict(self, tmp_path: Path):
        """Test Bearer adapter skips non-dict location entries."""
        data = {
            "data_types": [
                {"name": "Test", "detectors": [{"locations": ["not a dict"]}]}
            ]
        }
        f = tmp_path / "bearer.json"
        write(f, data)
        adapter = BearerAdapter()
        items = adapter.parse(f)
        assert items == []


class TestBearerCompliance:
    """Tests for compliance enrichment and metadata."""

    def test_compliance_enrichment(self, tmp_path: Path):
        """Test that Bearer findings are enriched with compliance mappings."""
        data = {
            "data_types": [
                {
                    "name": "PersonalData",
                    "detectors": [
                        {
                            "locations": [
                                {
                                    "filename": "app/models/profile.rb",
                                    "line_number": 12,
                                    "field_name": "full_name",
                                    "subject_name": "UserProfile",
                                }
                            ]
                        }
                    ],
                }
            ]
        }
        f = tmp_path / "bearer.json"
        write(f, data)
        adapter = BearerAdapter()
        items = adapter.parse(f)

        assert len(items) == 1
        assert hasattr(items[0], "compliance")

    def test_schema_version(self, tmp_path: Path):
        """Test schema version is correct."""
        data = {
            "data_types": [
                {
                    "name": "Test",
                    "detectors": [
                        {"locations": [{"filename": "test.rb", "line_number": 1}]}
                    ],
                }
            ]
        }
        f = tmp_path / "bearer.json"
        write(f, data)
        adapter = BearerAdapter()
        items = adapter.parse(f)

        assert len(items) == 1
        assert items[0].schemaVersion == "1.2.0"

    def test_tool_name(self, tmp_path: Path):
        """Test tool name is correct."""
        data = {
            "data_types": [
                {
                    "name": "Test",
                    "detectors": [
                        {"locations": [{"filename": "test.rb", "line_number": 1}]}
                    ],
                }
            ]
        }
        f = tmp_path / "bearer.json"
        write(f, data)
        adapter = BearerAdapter()
        items = adapter.parse(f)

        assert len(items) == 1
        assert items[0].tool["name"] == "bearer"

    def test_metadata_property(self, tmp_path: Path):
        """Test adapter metadata property."""
        adapter = BearerAdapter()
        metadata = adapter.metadata
        assert metadata.name == "bearer"
        assert metadata.tool_name == "bearer"
        assert metadata.schema_version == "1.2.0"


class TestBearerFingerprinting:
    """Tests for finding fingerprint generation."""

    def test_unique_fingerprints(self, tmp_path: Path):
        """Test that different findings get unique fingerprints."""
        data = {
            "data_types": [
                {
                    "name": "Email",
                    "detectors": [
                        {
                            "locations": [
                                {"filename": "file1.rb", "line_number": 1},
                                {"filename": "file2.rb", "line_number": 1},
                            ]
                        }
                    ],
                }
            ]
        }
        f = tmp_path / "bearer.json"
        write(f, data)
        adapter = BearerAdapter()
        items = adapter.parse(f)

        assert len(items) == 2
        assert items[0].id != items[1].id

    def test_consistent_fingerprints(self, tmp_path: Path):
        """Test that same input produces same fingerprint."""
        data = {
            "data_types": [
                {
                    "name": "Email",
                    "detectors": [
                        {"locations": [{"filename": "test.rb", "line_number": 10}]}
                    ],
                }
            ]
        }
        f = tmp_path / "bearer.json"
        write(f, data)
        adapter = BearerAdapter()
        items1 = adapter.parse(f)
        items2 = adapter.parse(f)

        assert items1[0].id == items2[0].id


class TestBearerUnicode:
    """Tests for Unicode handling."""

    def test_unicode_in_filename(self, tmp_path: Path):
        """Test Unicode in filename."""
        data = {
            "data_types": [
                {
                    "name": "Test",
                    "detectors": [
                        {
                            "locations": [
                                {"filename": "日本語/test.rb", "line_number": 1}
                            ]
                        }
                    ],
                }
            ]
        }
        f = tmp_path / "bearer.json"
        write(f, data)
        adapter = BearerAdapter()
        items = adapter.parse(f)

        assert len(items) == 1
        assert "日本語" in items[0].location["path"]

    def test_unicode_in_data_type_name(self, tmp_path: Path):
        """Test Unicode in data type name."""
        data = {
            "data_types": [
                {
                    "name": "PersonalDataé",
                    "detectors": [
                        {"locations": [{"filename": "test.rb", "line_number": 1}]}
                    ],
                }
            ]
        }
        f = tmp_path / "bearer.json"
        write(f, data)
        adapter = BearerAdapter()
        items = adapter.parse(f)

        assert len(items) == 1
        assert "é" in items[0].ruleId
