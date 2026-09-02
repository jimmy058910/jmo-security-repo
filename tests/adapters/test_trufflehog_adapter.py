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
        # Provenance is kept...
        assert findings[0].raw["DetectorName"] == "GitLab"
        assert findings[0].raw["Verified"] is True
        assert "SourceMetadata" in findings[0].raw
        # ...but ExtraData is not. It is detector-defined and has carried
        # decoded JWT claims; nothing guarantees a detector will not put
        # secret-derived content there.
        assert "ExtraData" not in findings[0].raw


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


# Assembled rather than written out: a literal PEM header in a tracked file
# trips this repo's own detect-private-key hook and its TruffleHog CI scan.
KEY_HEADER = "-----BEGIN RSA " + "PRIVATE KEY-----" + chr(10)


class TestTruffleHogRawMessage:
    """The finding must say WHERE the secret is, never WHAT it is.

    This class previously asserted the opposite: that `Raw` -- the matched
    credential -- appears in the message. That contract put juice-shop's
    planted 875-character RSA private key verbatim into findings.json,
    findings.csv, findings.sarif, dashboard.html and the history database
    (stored unencrypted unless --encrypt-findings). Measured: 6 of 7 secrets
    in a juice-shop scan appeared in the findings.

    `Redacted` is not a safe substitute. Measured on the same 7 records, it is
    empty on 5, and on the PrivateKey record it is the key's first 64
    characters.
    """

    def test_the_raw_secret_never_reaches_the_message(self, tmp_path: Path):
        sample = [
            {
                "DetectorName": "AWS",
                "Verified": False,
                "Raw": "AKIAIOSFODNN7EXAMPLE",
            }
        ]
        path = write_tmp(tmp_path, "raw.json", json.dumps(sample))
        findings = TruffleHogAdapter().parse(path)

        assert findings, "no findings parsed; the assertions below are vacuous"
        assert "AKIAIOSFODNN7EXAMPLE" not in findings[0].message
        assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(findings[0].raw)
        assert (
            "AWS" in findings[0].message
        ), "the message must still identify the detector"

    def test_the_redacted_value_never_reaches_the_message_either(self, tmp_path: Path):
        """TruffleHog's Redacted is a display convenience, not a guarantee.

        For the PrivateKey detector it is the first 64 characters of the key.
        """
        sample = [
            {
                "DetectorName": "PrivateKey",
                "Verified": False,
                "Raw": KEY_HEADER + "AAAAREALKEYMATERIAL",
                "Redacted": KEY_HEADER + "AAAAREALKEY",
            }
        ]
        path = write_tmp(tmp_path, "redacted.json", json.dumps(sample))
        findings = TruffleHogAdapter().parse(path)

        assert findings
        blob = findings[0].message + json.dumps(findings[0].raw)
        assert "REALKEY" not in blob

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

    def test_unicode_in_raw_is_still_not_leaked(self, tmp_path: Path):
        """A non-ASCII secret is still a secret."""
        sample = [
            {
                "DetectorName": "Token",
                "Verified": False,
                "Raw": "密码=secret123",
            }
        ]
        path = write_tmp(tmp_path, "unicode_raw.json", json.dumps(sample))
        findings = TruffleHogAdapter().parse(path)

        assert findings
        assert "密码" not in findings[0].message
        assert "secret123" not in json.dumps(findings[0].raw)


class TestLobDetectorCollidesWithPytestNames:
    """TruffleHog's Lob detector matches `test_[A-Za-z0-9_]{35}`.

    pytest names test functions `test_<words_with_underscores>`, so the two
    collide by construction: any Python project whose test names happen to be
    35 characters long produces "verified" Lob findings. Measured on this
    repository, `tests/` alone yielded 2318 of them, 412 distinct, and every
    single one contained an underscore. A real Lob key is hex-ish and has
    none, which is what makes them separable.

    They arrive `Verified: true` because Lob's API accepts test-mode keys, so
    the adapter graded them HIGH and `zero-secrets.rego` - "blocks all
    verified secrets" - failed the build. See #724.
    """

    def test_pytest_function_name_is_not_reported_as_a_secret(self, tmp_path: Path):
        """Verbatim TruffleHog output for a real false positive."""
        payload = {
            "SourceMetadata": {
                "Data": {"Filesystem": {"file": "tests/adapters/t.py", "line": 142}}
            },
            "DetectorName": "Lob",
            "Verified": True,
            "Raw": "test_akto_adapter_non_vulnerable_skipped",
            "ExtraData": {"environment": "test"},
        }
        path = write_tmp(tmp_path, "trufflehog.json", json.dumps(payload))
        assert TruffleHogAdapter().parse(path) == []

    def test_a_real_lob_key_is_still_reported(self, tmp_path: Path):
        """The filter must not cost real detection - no underscores here.

        The body below is **34 characters on purpose**. Lob's detector matches
        exactly 35, so a fully realistic fixture would be flagged as a live
        secret in this very file - it was, on the first draft, and it is the
        only finding that survived the fix. The predicate under test does not
        look at length, so 34 exercises precisely the same path.

        Do not "correct" this to 35.
        """
        payload = {
            "SourceMetadata": {
                "Data": {"Filesystem": {"file": "src/app.py", "line": 3}}
            },
            "DetectorName": "Lob",
            "Verified": True,
            "Raw": "test_0dc8d51e0acffcb1880e0f19c79b2f5b0c",
        }
        path = write_tmp(tmp_path, "trufflehog.json", json.dumps(payload))
        findings = TruffleHogAdapter().parse(path)
        assert len(findings) == 1
        assert findings[0].severity == "HIGH"

    def test_other_detectors_are_never_filtered(self, tmp_path: Path):
        """The collision is specific to Lob; nothing else may be suppressed."""
        payload = {
            "SourceMetadata": {
                "Data": {"Filesystem": {"file": "src/app.py", "line": 3}}
            },
            "DetectorName": "AWS",
            "Verified": True,
            "Raw": "test_akto_adapter_non_vulnerable_skipped",
        }
        path = write_tmp(tmp_path, "trufflehog.json", json.dumps(payload))
        assert len(TruffleHogAdapter().parse(path)) == 1

    def test_a_lob_secret_without_the_test_prefix_is_never_filtered(
        self, tmp_path: Path
    ):
        """The prefix is load-bearing, not decoration.

        Lob issues live keys too. Without the `test_` check the predicate
        would slice the first five characters off *any* Lob secret and filter
        it whenever the remainder held an underscore - discarding a live key.
        Mutation testing found this: removing the prefix check left every
        other test in this class passing.
        """
        payload = {
            "SourceMetadata": {
                "Data": {"Filesystem": {"file": "src/app.py", "line": 3}}
            },
            "DetectorName": "Lob",
            "Verified": True,
            "Raw": "live_0dc8_d51e0acffcb1880e0f19c79b2f5b0cc",
        }
        path = write_tmp(tmp_path, "trufflehog.json", json.dumps(payload))
        findings = TruffleHogAdapter().parse(path)
        assert len(findings) == 1
        assert findings[0].severity == "HIGH"


class TestTruffleHogFilesystemLine:
    """TruffleHog puts the line in SourceMetadata, not in StartLine.

    Measured on a juice-shop filesystem scan: `StartLine` present on **0 of
    7** records, `SourceMetadata.Data.Filesystem.line` on **7 of 7**. Every
    finding was therefore reported at line 0 and the dashboard rendered
    `lib/insecurity.ts:?`.

    That was not only cosmetic. The default fingerprint is
    `tool | ruleId | path | line | message[:120]`, so with the line pinned to
    0 two distinct secrets in one file collapsed into one finding: the same
    7 records produced **5** distinct ids before the fix and **7** after.
    """

    @staticmethod
    def _record(line: int, path: str = "app/config.ts", raw: str = "s3cret"):
        return {
            "DetectorName": "JWT",
            "Verified": False,
            "Raw": raw,
            "SourceMetadata": {"Data": {"Filesystem": {"file": path, "line": line}}},
        }

    def test_line_is_read_from_source_metadata(self, tmp_path: Path):
        path = write_tmp(tmp_path, "th.json", json.dumps([self._record(23)]))
        findings = TruffleHogAdapter().parse(path)

        assert findings
        assert findings[0].location["startLine"] == 23, (
            "the line stayed 0, so the report cannot point at the secret and "
            "two secrets in one file share a fingerprint"
        )

    def test_two_secrets_in_one_file_keep_separate_identities(self, tmp_path: Path):
        path = write_tmp(
            tmp_path,
            "th.json",
            json.dumps(
                [
                    self._record(302, raw="first-secret"),
                    self._record(306, raw="second-secret"),
                ]
            ),
        )
        findings = TruffleHogAdapter().parse(path)

        assert len(findings) == 2
        assert len({f.id for f in findings}) == 2, (
            "two secrets at different lines collapsed to one fingerprint -- "
            "the line is not reaching the finding"
        )
        # Note: this assertion passes on the pre-fix adapter too, and for a
        # reason worth stating -- there, the message WAS the secret, so the
        # leak itself was doing the discriminating. Once the message stops
        # carrying the credential, the line is the only thing separating two
        # secrets in one file. That makes this a forward guard on the line
        # mapping, not a reproduction of the original defect.

    def test_an_explicit_start_line_still_wins(self, tmp_path: Path):
        """Control: the existing StartLine path is unchanged."""
        record = self._record(23)
        record["StartLine"] = 99
        path = write_tmp(tmp_path, "th.json", json.dumps([record]))
        findings = TruffleHogAdapter().parse(path)

        assert findings[0].location["startLine"] == 99
