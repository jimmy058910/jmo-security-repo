import json
from pathlib import Path

from scripts.core.adapters.mobsf_adapter import MobsfAdapter


def write(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def test_mobsf_adapter_code_analysis_high(tmp_path: Path):
    """Test MobSF adapter with HIGH severity code analysis finding."""
    data = {
        "file_name": "app-release.apk",
        "app_name": "MyApp",
        "code_analysis": {
            "android_hardcoded_secret": {
                "metadata": {
                    "description": "Hardcoded API keys or secrets detected",
                    "severity": "high",
                    "cwe": "798",
                    "owasp-mobile": "M9",
                    "masvs": "MSTG-STORAGE-14",
                },
                "files": [
                    {
                        "file_path": "com/example/app/Config.java",
                        "match_position": [{"start": 42, "end": 80}],
                    }
                ],
            }
        },
    }
    f = tmp_path / "mobsf.json"
    write(f, data)
    adapter = MobsfAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "android_hardcoded_secret"
    assert items[0].severity == "HIGH"
    assert "mobile-security" in items[0].tags
    assert "sast" in items[0].tags
    assert "owasp-mobile" in items[0].tags
    assert "cwe-798" in items[0].tags
    assert "masvs" in items[0].tags
    assert items[0].context["cwe"] == "798"
    assert items[0].context["owasp_mobile"] == "M9"
    assert items[0].context["masvs"] == "MSTG-STORAGE-14"
    assert items[0].location["path"] == "com/example/app/Config.java"
    assert items[0].location["startLine"] == 42
    assert "https://cwe.mitre.org/data/definitions/798.html" in items[0].references


def test_mobsf_adapter_code_analysis_warning(tmp_path: Path):
    """Test MobSF adapter with WARNING severity (maps to MEDIUM)."""
    data = {
        "file_name": "app.apk",
        "app_name": "TestApp",
        "code_analysis": {
            "android_insecure_random": {
                "metadata": {
                    "description": "Insecure Random Number Generator",
                    "severity": "warning",
                    "cwe": "330",
                },
                "files": [
                    {
                        "file_path": "com/example/app/Crypto.java",
                        "match_position": [{"start": 108}],
                    }
                ],
            }
        },
    }
    f = tmp_path / "mobsf.json"
    write(f, data)
    adapter = MobsfAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].severity == "MEDIUM"  # WARNING normalized to MEDIUM
    assert items[0].location["startLine"] == 108


def test_mobsf_adapter_code_analysis_info(tmp_path: Path):
    """Test MobSF adapter with INFO severity (maps to LOW)."""
    data = {
        "file_name": "app.apk",
        "code_analysis": {
            "android_logging": {
                "metadata": {
                    "description": "Logging detected in application",
                    "severity": "info",
                },
                "files": [
                    {"file_path": "com/example/app/Logger.java", "match_position": []}
                ],
            }
        },
    }
    f = tmp_path / "mobsf.json"
    write(f, data)
    adapter = MobsfAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].severity == "LOW"  # INFO normalized to LOW


def test_mobsf_adapter_manifest_analysis(tmp_path: Path):
    """Test MobSF adapter with manifest_analysis findings."""
    data = {
        "file_name": "app.apk",
        "app_name": "MyApp",
        "manifest_analysis": {
            "android_debuggable": {
                "title": "Application is Debuggable",
                "description": "Application has android:debuggable=true which is dangerous in production",
                "severity": "high",
            },
            "android_backup_enabled": {
                "title": "Backup Enabled",
                "description": "Application has android:allowBackup=true",
                "severity": "warning",
            },
        },
    }
    f = tmp_path / "mobsf.json"
    write(f, data)
    adapter = MobsfAdapter()
    items = adapter.parse(f)

    assert len(items) == 2
    # First finding: debuggable (HIGH)
    assert items[0].ruleId == "android_debuggable"
    assert items[0].severity == "HIGH"
    assert items[0].location["path"] == "AndroidManifest.xml"
    assert (
        items[0].location["startLine"] == 0
    )  # Manifest findings don't have line numbers
    assert "manifest" in items[0].tags
    assert "configuration" in items[0].tags
    # Second finding: backup (MEDIUM)
    assert items[1].ruleId == "android_backup_enabled"
    assert items[1].severity == "MEDIUM"


def test_mobsf_adapter_manifest_skips_secure(tmp_path: Path):
    """Test MobSF adapter skips SECURE manifest findings."""
    data = {
        "file_name": "app.apk",
        "manifest_analysis": {
            "android_certificate_pinning": {
                "title": "Certificate Pinning Implemented",
                "description": "Application has certificate pinning enabled",
                "severity": "secure",
            },
            "android_root_detection": {
                "title": "Root Detection Missing",
                "description": "Application should implement root detection",
                "severity": "high",
            },
        },
    }
    f = tmp_path / "mobsf.json"
    write(f, data)
    adapter = MobsfAdapter()
    items = adapter.parse(f)

    # Only non-SECURE finding should be processed
    assert len(items) == 1
    assert items[0].ruleId == "android_root_detection"


def test_mobsf_adapter_multiple_file_locations(tmp_path: Path):
    """Test MobSF adapter creates separate findings for each file location."""
    data = {
        "file_name": "app.apk",
        "code_analysis": {
            "android_sql_injection": {
                "metadata": {
                    "description": "SQL Injection vulnerability",
                    "severity": "high",
                    "cwe": "89",
                },
                "files": [
                    {
                        "file_path": "com/example/app/DatabaseHelper.java",
                        "match_position": [{"start": 42}],
                    },
                    {
                        "file_path": "com/example/app/UserDAO.java",
                        "match_position": [{"start": 108}],
                    },
                    {
                        "file_path": "com/example/app/ProductDAO.java",
                        "match_position": [{"start": 200}],
                    },
                ],
            }
        },
    }
    f = tmp_path / "mobsf.json"
    write(f, data)
    adapter = MobsfAdapter()
    items = adapter.parse(f)

    # Should create 3 separate findings (one per file)
    assert len(items) == 3
    assert items[0].location["path"] == "com/example/app/DatabaseHelper.java"
    assert items[0].location["startLine"] == 42
    assert items[1].location["path"] == "com/example/app/UserDAO.java"
    assert items[1].location["startLine"] == 108
    assert items[2].location["path"] == "com/example/app/ProductDAO.java"
    assert items[2].location["startLine"] == 200
    # All should have same ruleId
    assert all(item.ruleId == "android_sql_injection" for item in items)


def test_mobsf_adapter_no_files_fallback(tmp_path: Path):
    """Test MobSF adapter handles findings with no file paths gracefully."""
    data = {
        "file_name": "app.apk",
        "app_name": "MyApp",
        "code_analysis": {
            "generic_finding": {
                "metadata": {
                    "description": "Generic security issue",
                    "severity": "high",
                },
                "files": [],  # No files specified
            }
        },
    }
    f = tmp_path / "mobsf.json"
    write(f, data)
    adapter = MobsfAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Should use app_name as fallback
    assert items[0].location["path"] == "MyApp"
    assert items[0].location["startLine"] == 0


def test_mobsf_adapter_combined_analysis(tmp_path: Path):
    """Test MobSF adapter with both code_analysis and manifest_analysis findings."""
    data = {
        "file_name": "app.apk",
        "app_name": "MyApp",
        "code_analysis": {
            "android_webview_ssl": {
                "metadata": {
                    "description": "WebView SSL Error Handler allows all certificates",
                    "severity": "high",
                    "cwe": "295",
                },
                "files": [
                    {
                        "file_path": "com/example/app/WebViewActivity.java",
                        "match_position": [{"start": 156}],
                    }
                ],
            }
        },
        "manifest_analysis": {
            "android_clear_text_traffic": {
                "title": "Clear Text Traffic Allowed",
                "description": "Application allows clear text HTTP traffic",
                "severity": "high",
            }
        },
    }
    f = tmp_path / "mobsf.json"
    write(f, data)
    adapter = MobsfAdapter()
    items = adapter.parse(f)

    assert len(items) == 2
    # Code analysis finding
    assert items[0].ruleId == "android_webview_ssl"
    assert "sast" in items[0].tags
    assert items[0].location["path"] == "com/example/app/WebViewActivity.java"
    # Manifest analysis finding
    assert items[1].ruleId == "android_clear_text_traffic"
    assert "manifest" in items[1].tags
    assert items[1].location["path"] == "AndroidManifest.xml"


def test_mobsf_adapter_empty_file(tmp_path: Path):
    """Test MobSF adapter handles empty JSON file."""
    f = tmp_path / "mobsf.json"
    f.write_text("", encoding="utf-8")
    adapter = MobsfAdapter()
    items = adapter.parse(f)

    assert items == []


def test_mobsf_adapter_compliance_enrichment(tmp_path: Path):
    """Test that MobSF findings are enriched with compliance mappings."""
    data = {
        "file_name": "app.apk",
        "code_analysis": {
            "test_finding": {
                "metadata": {"description": "Test security issue", "severity": "high"},
                "files": [{"file_path": "test.java", "match_position": []}],
            }
        },
    }
    f = tmp_path / "mobsf.json"
    write(f, data)
    adapter = MobsfAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Compliance field should exist (enriched by compliance_mapper)
    assert hasattr(items[0], "compliance")
