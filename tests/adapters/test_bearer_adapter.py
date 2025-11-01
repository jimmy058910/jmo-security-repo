import json
from pathlib import Path

from scripts.core.adapters.bearer_adapter import BearerAdapter


def write(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def test_bearer_adapter_dataflow_detection(tmp_path: Path):
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


def test_bearer_adapter_security_finding(tmp_path: Path):
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


def test_bearer_adapter_multiple_data_types(tmp_path: Path):
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


def test_bearer_adapter_multiple_locations(tmp_path: Path):
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

    assert len(items) == 2  # One finding per location
    assert items[0].location["path"] == "app/models/user.rb"
    assert items[1].location["path"] == "app/models/contact.rb"


def test_bearer_adapter_mixed_findings(tmp_path: Path):
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

    assert len(items) == 2  # One dataflow + one security finding
    dataflow_findings = [f for f in items if f.ruleId.startswith("DATA.")]
    security_findings = [f for f in items if not f.ruleId.startswith("DATA.")]
    assert len(dataflow_findings) == 1
    assert len(security_findings) == 1
    assert security_findings[0].severity == "CRITICAL"


def test_bearer_adapter_no_subject_name(tmp_path: Path):
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
                                # No subject_name
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


def test_bearer_adapter_empty_data_types(tmp_path: Path):
    """Test Bearer adapter with empty data_types array."""
    data = {"data_types": []}
    f = tmp_path / "bearer.json"
    write(f, data)
    adapter = BearerAdapter()
    items = adapter.parse(f)

    assert items == []


def test_bearer_adapter_empty_file(tmp_path: Path):
    """Test Bearer adapter handles empty JSON file."""
    f = tmp_path / "bearer.json"
    f.write_text("", encoding="utf-8")
    adapter = BearerAdapter()
    items = adapter.parse(f)

    assert items == []


def test_bearer_adapter_compliance_enrichment(tmp_path: Path):
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
    # Compliance field should exist (enriched by compliance_mapper)
    assert hasattr(items[0], "compliance")
