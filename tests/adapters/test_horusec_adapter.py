import json
from pathlib import Path

from scripts.core.adapters.horusec_adapter import HorusecAdapter


def write(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def test_horusec_adapter_sql_injection(tmp_path: Path):
    """Test Horusec adapter with SQL injection vulnerability."""
    data = {
        "version": "2.8.0",
        "totalVulnerabilities": 1,
        "analysisVulnerabilities": [
            {
                "vulnerabilityID": "9f1d0a72-4c8e-4b21-9a5f-2d6b1c0e7a31",
                "rule_id": "HS-JAVA-1",
                "severity": "HIGH",
                "file": "src/main/java/com/app/UserDAO.java",
                "line": 42,
                "details": "SQL Injection vulnerability detected - user input directly concatenated into SQL query",
                "securityTool": "SecurityCodeScan",
                "type": "SQL Injection",
                "code": 'String query = "SELECT * FROM users WHERE id=" + userId;',
            }
        ],
    }
    f = tmp_path / "horusec.json"
    write(f, data)
    adapter = HorusecAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "HS-JAVA-1"
    assert items[0].severity == "HIGH"
    assert "sast" in items[0].tags
    assert "horusec" in items[0].tags
    assert "sql-injection" in items[0].tags
    assert "securitycodescan" in items[0].tags
    assert items[0].context["security_tool"] == "SecurityCodeScan"
    assert items[0].context["vulnerability_type"] == "SQL Injection"
    assert items[0].location["path"] == "src/main/java/com/app/UserDAO.java"
    assert items[0].location["startLine"] == 42


def test_horusec_adapter_xss(tmp_path: Path):
    """Test Horusec adapter with XSS vulnerability."""
    data = {
        "version": "2.8.0",
        "analysisVulnerabilities": [
            {
                "vulnerabilityID": "5a2f9d14-6b03-4e88-8c7a-1d9e0f3b47c5",
                "rule_id": "HS-JS-2",
                "severity": "MEDIUM",
                "file": "public/js/app.js",
                "line": 108,
                "details": "Cross-Site Scripting (XSS) vulnerability - unescaped user input rendered in DOM",
                "securityTool": "HorusecJavascript",
                "type": "Cross-Site Scripting (XSS)",
            }
        ],
    }
    f = tmp_path / "horusec.json"
    write(f, data)
    adapter = HorusecAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].severity == "MEDIUM"
    assert "xss" in items[0].tags


def test_horusec_adapter_hardcoded_secret(tmp_path: Path):
    """Test Horusec adapter with hardcoded secret."""
    data = {
        "version": "2.8.0",
        "analysisVulnerabilities": [
            {
                "vulnerabilityID": "e71b3c05-9d42-4a16-b8f3-0c5a7e2d9614",
                "rule_id": "HS-PY-3",
                "severity": "CRITICAL",
                "file": "config/settings.py",
                "line": 15,
                "details": "Hardcoded secret detected in configuration file",
                "securityTool": "HorusecPython",
                "type": "Hardcoded Secret",
                "code": "API_KEY = 'sk_live_1234567890abcdef'",
            }
        ],
    }
    f = tmp_path / "horusec.json"
    write(f, data)
    adapter = HorusecAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].severity == "CRITICAL"
    assert "hardcoded-secret" in items[0].tags
    assert items[0].context["code_snippet"] == "API_KEY = 'sk_live_1234567890abcdef'"


def test_horusec_adapter_command_injection(tmp_path: Path):
    """Test Horusec adapter with command injection vulnerability."""
    data = {
        "version": "2.8.0",
        "analysisVulnerabilities": [
            {
                "vulnerabilityID": "2d68f4a9-0e5b-4c73-91a8-6f2c3b0d85e7",
                "rule_id": "HS-GO-4",
                "severity": "HIGH",
                "file": "api/handlers.go",
                "line": 200,
                "details": "Command injection vulnerability - user input passed to shell command",
                "securityTool": "HorusecGolang",
                "type": "Command Injection",
            }
        ],
    }
    f = tmp_path / "horusec.json"
    write(f, data)
    adapter = HorusecAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].severity == "HIGH"
    assert "injection" in items[0].tags


def test_horusec_adapter_multiple_vulnerabilities(tmp_path: Path):
    """Test Horusec adapter with multiple vulnerabilities."""
    data = {
        "version": "2.8.0",
        "totalVulnerabilities": 3,
        "analysisVulnerabilities": [
            {
                "vulnerabilityID": "9f1d0a72-4c8e-4b21-9a5f-2d6b1c0e7a31",
                "rule_id": "HS-JAVA-1",
                "severity": "CRITICAL",
                "file": "UserService.java",
                "line": 50,
                "details": "SQL Injection",
                "securityTool": "HorusecJava",
                "type": "SQL Injection",
            },
            {
                "vulnerabilityID": "3b7c5e10-8a94-4f6d-b2c1-7e0d4a9f5b82",
                "rule_id": "HS-JAVA-2",
                "severity": "HIGH",
                "file": "AuthController.java",
                "line": 75,
                "details": "CSRF vulnerability",
                "securityTool": "HorusecJava",
                "type": "CSRF",
            },
            {
                "vulnerabilityID": "c04e8b39-1f77-4a02-9d5e-6b3a8c214f60",
                "rule_id": "HS-JS-1",
                "severity": "MEDIUM",
                "file": "client.js",
                "line": 120,
                "details": "XSS vulnerability",
                "securityTool": "HorusecJavascript",
                "type": "XSS",
            },
        ],
    }
    f = tmp_path / "horusec.json"
    write(f, data)
    adapter = HorusecAdapter()
    items = adapter.parse(f)

    assert len(items) == 3
    assert items[0].severity == "CRITICAL"
    assert items[1].severity == "HIGH"
    assert items[2].severity == "MEDIUM"
    assert items[0].ruleId == "HS-JAVA-1"
    assert items[1].ruleId == "HS-JAVA-2"
    assert items[2].ruleId == "HS-JS-1"


def test_horusec_adapter_minimal_metadata(tmp_path: Path):
    """Test Horusec adapter handles minimal vulnerability metadata gracefully."""
    data = {
        "version": "2.8.0",
        "analysisVulnerabilities": [
            {
                "vulnerabilityID": "8c15e0b7-3a26-4d94-a0f5-7b1c9e64d203",
                "rule_id": "HS-TEST-1",
                "severity": "LOW",
                "file": "test.py",
                "line": 10,
            }
        ],
    }
    f = tmp_path / "horusec.json"
    write(f, data)
    adapter = HorusecAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Should use fallback values
    assert items[0].ruleId == "HS-TEST-1"
    assert items[0].message.startswith("Security vulnerability detected")
    assert items[0].context["security_tool"] is None
    assert items[0].context["vulnerability_type"] is None


def test_horusec_adapter_no_vulnerability_id(tmp_path: Path):
    """Test Horusec adapter handles missing vulnerabilityID gracefully."""
    data = {
        "version": "2.8.0",
        "analysisVulnerabilities": [
            {
                "severity": "MEDIUM",
                "file": "app.js",
                "line": 50,
                "type": "Generic Security Issue",
                "details": "Security issue detected",
            }
        ],
    }
    f = tmp_path / "horusec.json"
    write(f, data)
    adapter = HorusecAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Should use type as fallback ruleId
    assert items[0].ruleId == "Generic Security Issue"
    assert items[0].title == "Generic Security Issue"


def test_horusec_adapter_severity_normalization(tmp_path: Path):
    """Test Horusec adapter normalizes different severity levels."""
    data = {
        "version": "2.8.0",
        "analysisVulnerabilities": [
            {
                "vulnerabilityID": "1a4e7c92-0b38-4f65-9c2d-8e5b3a10f7d6",
                "rule_id": "HS-1",
                "severity": "INFO",
                "file": "test1.py",
                "line": 1,
            },
            {
                "vulnerabilityID": "6f0b3d85-2c19-4a70-b4e8-9d1a5c803e42",
                "rule_id": "HS-2",
                "severity": "LOW",
                "file": "test2.py",
                "line": 2,
            },
            {
                "vulnerabilityID": "4e9c1a06-7d53-4b28-8f60-2a5e0c3b9147",
                "rule_id": "HS-3",
                "severity": "MEDIUM",
                "file": "test3.py",
                "line": 3,
            },
        ],
    }
    f = tmp_path / "horusec.json"
    write(f, data)
    adapter = HorusecAdapter()
    items = adapter.parse(f)

    assert len(items) == 3
    assert items[0].severity == "INFO"
    assert items[1].severity == "LOW"
    assert items[2].severity == "MEDIUM"


def test_horusec_adapter_empty_vulnerabilities(tmp_path: Path):
    """Test Horusec adapter with empty vulnerabilities array."""
    data = {
        "version": "2.8.0",
        "totalVulnerabilities": 0,
        "analysisVulnerabilities": [],
    }
    f = tmp_path / "horusec.json"
    write(f, data)
    adapter = HorusecAdapter()
    items = adapter.parse(f)

    assert items == []


def test_horusec_adapter_compliance_enrichment(tmp_path: Path):
    """Test that Horusec findings are enriched with compliance mappings."""
    data = {
        "version": "2.8.0",
        "analysisVulnerabilities": [
            {
                "vulnerabilityID": "b93a2f68-5c01-4e7b-8d16-4a0f7c25e9b3",
                "rule_id": "HS-TEST",
                "severity": "HIGH",
                "file": "test.py",
                "line": 10,
                "type": "Test Vulnerability",
            }
        ],
    }
    f = tmp_path / "horusec.json"
    write(f, data)
    adapter = HorusecAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Compliance field should exist (enriched by compliance_mapper)
    assert hasattr(items[0], "compliance")


def _record(vulnerability_id: str) -> dict:
    """One realistic horusec record, parameterised only by its per-run UUID."""
    return {
        "vulnerabilityID": vulnerability_id,
        "analysisID": "a1b2c3d4-0000-4000-8000-000000000000",
        "createdAt": "2026-09-02T18:00:00Z",
        "vulnerabilities": {
            "vulnerabilityID": vulnerability_id,
            "rule_id": "HS-JAVASCRIPT-2",
            "line": "23",
            "column": "19",
            "file": "routes/captcha.ts",
            "code": "const answer = eval(expression).toString()",
            "details": (
                "(1/1) * Possible vulnerability detected: No use eval\n"
                "The eval function is dangerous."
            ),
            "securityTool": "HorusecEngine",
            "language": "JavaScript",
            "severity": "CRITICAL",
            "type": "Vulnerability",
            "vulnHash": "5ece8249d395de0eded88a244ef5396080da4396370938a401c8687dc78f",
        },
    }


def _parse_one(tmp_path: Path, name: str, vulnerability_id: str):
    f = tmp_path / name / "horusec.json"
    write(
        f,
        {
            "version": "2.8.0",
            "totalVulnerabilities": 1,
            "analysisVulnerabilities": [_record(vulnerability_id)],
        },
    )
    items = HorusecAdapter().parse(f)
    assert len(items) == 1
    return items[0]


def test_fingerprint_survives_a_regenerated_vulnerability_id(tmp_path: Path):
    """The same finding, two runs, two UUIDs -> one fingerprint.

    horusec mints a fresh `vulnerabilityID` UUID for every record on every
    run. Seeding the fingerprint from it meant no horusec finding could ever
    be recognised as the same finding twice.

    Measured across two deep scans of one unchanged juice-shop commit:
    584 findings and 493, of which 492 shared (rule_id, file, line) and
    **zero** shared an id. `jmo diff` read 1,119 new / 769 resolved / 2
    modified. horusec produced 584 of 831 total findings and 468 of 485
    CRITICALs, so diff, history trends and cross-tool dedup were all
    meaningless for the tool that dominates the numbers.

    Re-parsing the captured output with every UUID regenerated: 583 of 584
    ids preserved before/after (584 records, 583 distinct -- horusec emitted
    one finding twice, identically, and a stable fingerprint correctly
    collapses it). On the pre-fix adapter: 0 of 584.
    """
    first = _parse_one(tmp_path, "run1", "ebeefbf7-693c-4b59-a72b-7c43e0100c98")
    second = _parse_one(tmp_path, "run2", "00000000-1111-4222-8333-444444444444")

    assert first.id == second.id, (
        "the same finding got two fingerprints across two runs; the id is "
        f"still derived from the per-run UUID. {first.id} != {second.id}"
    )


def test_rule_id_is_the_horusec_rule_not_the_uuid(tmp_path: Path):
    """The dashboard RULE column showed raw UUIDs before this."""
    item = _parse_one(tmp_path, "run", "ebeefbf7-693c-4b59-a72b-7c43e0100c98")

    assert item.ruleId == "HS-JAVASCRIPT-2"
    assert "ebeefbf7" not in item.ruleId


def test_the_uuid_is_still_retained_for_traceability(tmp_path: Path):
    """Dropping it from the id must not drop it from the record."""
    uuid = "ebeefbf7-693c-4b59-a72b-7c43e0100c98"
    item = _parse_one(tmp_path, "run", uuid)

    assert item.context["vulnerability_id"] == uuid
    assert item.raw["vulnerabilityID"] == uuid


def test_title_is_the_vulnerability_name_not_the_constant_type(tmp_path: Path):
    """`type` is the literal "Vulnerability" on every horusec record.

    Measured: 584 of 584 in the juice-shop run, so the previous
    `title = type or vulnerabilityID` gave every finding in the report the
    same title. The only human-readable name horusec emits is inside
    `details`.
    """
    item = _parse_one(tmp_path, "run", "ebeefbf7-693c-4b59-a72b-7c43e0100c98")

    assert item.title == "No use eval"


def test_fingerprint_still_separates_two_different_rules(tmp_path: Path):
    """Negative control: stability must not become collapsing.

    A fingerprint that ignored everything would also be "stable". This
    proves the id still discriminates.
    """
    uuid = "ebeefbf7-693c-4b59-a72b-7c43e0100c98"
    first = _parse_one(tmp_path, "run1", uuid)

    rec = _record(uuid)
    rec["vulnerabilities"]["rule_id"] = "HS-JAVASCRIPT-99"
    f = tmp_path / "run2" / "horusec.json"
    write(
        f,
        {
            "version": "2.8.0",
            "totalVulnerabilities": 1,
            "analysisVulnerabilities": [rec],
        },
    )
    second = HorusecAdapter().parse(f)[0]

    assert first.id != second.id, (
        "two different horusec rules at the same location collapsed to one "
        "fingerprint"
    )
