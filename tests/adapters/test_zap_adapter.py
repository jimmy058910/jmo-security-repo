import json
from pathlib import Path

from scripts.core.adapters.zap_adapter import load_zap


def write_tmp(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_zap_basic_alert(tmp_path: Path):
    """Test basic ZAP alert parsing."""
    sample = {
        "@version": "2.11.0",
        "site": [
            {
                "alerts": [
                    {
                        "alert": "SQL Injection",
                        "risk": "High",
                        "confidence": "Medium",
                        "desc": "SQL injection may be possible",
                        "solution": "Use parameterized queries",
                        "reference": "https://owasp.org/www-community/attacks/SQL_Injection",
                        "cweid": "89",
                        "wascid": "19",
                        "instances": [
                            {
                                "uri": "http://example.com/page?id=1",
                                "method": "GET",
                                "param": "id",
                                "evidence": "' OR 1=1",
                            }
                        ],
                    }
                ]
            }
        ],
    }
    path = write_tmp(tmp_path, "zap.json", json.dumps(sample))
    out = load_zap(path)
    assert len(out) == 1
    item = out[0]
    assert item["severity"] == "HIGH"
    assert item["title"] == "SQL Injection"
    assert "CWE-89" in item["tags"]
    assert item["context"]["method"] == "GET"
    assert item["context"]["param"] == "id"


def test_zap_multiple_instances(tmp_path: Path):
    """Test ZAP alert with multiple instances."""
    sample = {
        "site": [
            {
                "alerts": [
                    {
                        "alert": "Cross Site Scripting (XSS)",
                        "risk": "Medium",
                        "confidence": "High",
                        "desc": "XSS vulnerability detected",
                        "instances": [
                            {
                                "uri": "http://example.com/search?q=test",
                                "method": "GET",
                                "param": "q",
                            },
                            {
                                "uri": "http://example.com/profile?name=user",
                                "method": "GET",
                                "param": "name",
                            },
                        ],
                    }
                ]
            }
        ],
    }
    path = write_tmp(tmp_path, "zap.json", json.dumps(sample))
    out = load_zap(path)
    # Should create 2 findings (one per instance)
    assert len(out) == 2
    assert all(it["title"] == "Cross Site Scripting (XSS)" for it in out)
    assert out[0]["context"]["param"] == "q"
    assert out[1]["context"]["param"] == "name"


def test_zap_no_instances(tmp_path: Path):
    """Test ZAP alert with no instances."""
    sample = {
        "site": [
            {
                "alerts": [
                    {
                        "alert": "Missing Security Header",
                        "risk": "Low",
                        "confidence": "High",
                        "instances": [],
                    }
                ]
            }
        ],
    }
    path = write_tmp(tmp_path, "zap.json", json.dumps(sample))
    out = load_zap(path)
    # Should create 1 finding even with no instances
    assert len(out) == 1
    assert out[0]["severity"] == "LOW"


def test_zap_empty_and_nonexistent(tmp_path: Path):
    """Test empty file and nonexistent file."""
    empty = write_tmp(tmp_path, "empty.json", "")
    assert load_zap(empty) == []
    nonexistent = tmp_path / "nonexistent.json"
    assert load_zap(nonexistent) == []


def test_zap_severity_mapping(tmp_path: Path):
    """Test severity level mapping."""
    for risk, expected_severity in [
        ("Informational", "INFO"),
        ("Low", "LOW"),
        ("Medium", "MEDIUM"),
        ("High", "HIGH"),
    ]:
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": f"{risk} Alert",
                            "risk": risk,
                            "confidence": "Medium",
                            "instances": [{"uri": "http://example.com"}],
                        }
                    ]
                }
            ],
        }
        path = write_tmp(tmp_path, f"zap_{risk}.json", json.dumps(sample))
        out = load_zap(path)
        assert len(out) == 1
        assert out[0]["severity"] == expected_severity
