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


# --- Real `noseyparker report --format json` shape (0.24.0) -------------------
#
# The adapter previously required a dict with a top-level "matches" key. That
# shape does not exist in any noseyparker release JMo ships. Measured against
# 0.24.0 on juice-shop: the real 330 KB report parsed to **0** findings from
# 116 records. It stayed invisible because the tool could never run -- the
# scanner pre-created the datastore directory noseyparker insists on creating
# itself (#1127) -- so no real output ever reached the adapter. Same shape as
# #1094, where kubescape's adapter had never parsed a real scan.
#
# The snippet below is a byte-faithful reduction of a real record, with the
# secret material replaced.

REPORT_RECORD = {
    "finding_id": "dec85501510891d385707a1db0fe09fa161f1d8e",
    "rule_name": "Generic Password",
    "rule_text_id": "np.generic.5",
    "rule_structural_id": "4742a7e5266ce68dd5633ca6c2c634a4fa706673",
    "num_matches": 1,
    "num_redundant_matches": 0,
    "matches": [
        {
            "blob_id": "8a022df2f580bf8fff7b4b009c071ff39e76dc10",
            "rule_name": "Generic Password",
            "rule_text_id": "np.generic.5",
            "structural_id": "b468b5554f93bed04fd9c28fd047c7e2faa6a179",
            "provenance": [
                {"kind": "file", "path": "frontend/src/assets/i18n/bg_BG.json"}
            ],
            "location": {
                "offset_span": {"start": 389, "end": 414},
                "source_span": {
                    "start": {"line": 10, "column": 10},
                    "end": {"line": 10, "column": 34},
                },
            },
            "snippet": {
                "before": '"TITLE_LOGIN": "x",',
                "matching": 'PASSWORD": "TOP-SECRET-VALUE"',
                "after": '"SHOW_PASSWORD_ADVICE": "y"',
            },
        }
    ],
}


def _report(tmp_path: Path, *records) -> Path:
    return write_tmp(tmp_path, "noseyparker.json", json.dumps(list(records)))


def test_parses_the_real_top_level_list_report(tmp_path: Path):
    """A top-level list is what `report --format json` actually emits."""
    findings = NoseyParkerAdapter().parse(_report(tmp_path, REPORT_RECORD))

    assert len(findings) == 1, (
        "the real noseyparker report shape parsed to nothing; the adapter is "
        "still expecting a dict with a 'matches' key"
    )
    f = findings[0]
    assert f.ruleId == "np.generic.5"
    assert f.title == "Generic Password"
    assert f.location["path"] == "frontend/src/assets/i18n/bg_BG.json"
    assert f.location["startLine"] == 10


def test_the_matched_secret_never_reaches_the_finding(tmp_path: Path):
    """`snippet.matching` IS the secret.

    The previous adapter used `m.get("match")` as the message, which is the
    defect #1128 describes for TruffleHog: the report, the SARIF file and the
    history database all end up carrying the credential. A secret scanner's
    output must say *where* the secret is, not *what* it is.
    """
    findings = NoseyParkerAdapter().parse(_report(tmp_path, REPORT_RECORD))

    # Without this, the test passes vacuously on any build that parses the
    # real shape to nothing -- which is exactly the build it is guarding.
    assert findings, "no findings parsed; the leak assertion below is vacuous"

    blob = json.dumps(
        [
            {
                "message": f.message,
                "title": f.title,
                "description": f.description,
                "raw": f.raw,
                "context": f.context,
            }
            for f in findings
        ]
    )
    assert "TOP-SECRET-VALUE" not in blob, (
        "the matched secret was copied into the finding; a report is not a "
        "place to reproduce credentials"
    )


def test_one_finding_per_match(tmp_path: Path):
    """Each match has its own file and line, so each is a finding."""
    import copy

    record = copy.deepcopy(REPORT_RECORD)
    second = copy.deepcopy(record["matches"][0])
    second["provenance"] = [{"kind": "file", "path": "other/file.json"}]
    second["location"]["source_span"]["start"]["line"] = 99
    record["matches"].append(second)
    record["num_matches"] = 2

    findings = NoseyParkerAdapter().parse(_report(tmp_path, record))

    assert len(findings) == 2
    assert {f.location["startLine"] for f in findings} == {10, 99}
    assert len({f.id for f in findings}) == 2, "two locations collapsed to one id"


def test_fingerprint_is_stable_across_runs(tmp_path: Path):
    """Nothing per-run may feed the id."""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    a = NoseyParkerAdapter().parse(_report(tmp_path / "a", REPORT_RECORD))
    b = NoseyParkerAdapter().parse(_report(tmp_path / "b", REPORT_RECORD))

    assert a, "no findings parsed; comparing two empty lists proves nothing"
    assert [f.id for f in a] == [f.id for f in b]


def test_the_legacy_dict_shape_still_parses(tmp_path: Path):
    """Control: the Docker fallback path is untouched by this change."""
    legacy = {
        "matches": [
            {"signature": "AWS", "path": "a.py", "line_number": 3, "match": "x"}
        ]
    }
    findings = NoseyParkerAdapter().parse(
        write_tmp(tmp_path, "np.json", json.dumps(legacy))
    )

    assert len(findings) == 1
    assert findings[0].ruleId == "AWS"
