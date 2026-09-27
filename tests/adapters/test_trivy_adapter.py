"""Comprehensive tests for Trivy adapter.

Tests cover:
- Basic parsing of Trivy JSON output
- Vulnerabilities, secrets, and misconfigurations
- Multiple severity levels (LOW, MEDIUM, HIGH, CRITICAL)
- CWE mapping for vulnerabilities
- Edge cases (empty input, malformed JSON, missing fields)
- Code context extraction for misconfigurations
- Schema version and compliance enrichment
- trivy 0.74.0's own output (``TestTrivy074RecordedOutput``), recorded below

Recorded fixture ``tests/fixtures/samples/trivy/misconfig-0.74.json``: trivy
**0.74.0**'s JSON, byte for byte, recorded 2026-09-27 on Windows by running,
from inside a scratch directory holding only the three files listed below::

    trivy fs -q -f json --scanners vuln,secret,misconfig \\
        --skip-db-update --skip-check-update . -o misconfig-0.74.json

``--scanners`` is what JMo's repository descriptor passes
(``tool_descriptors._trivy``); scanning ``.`` from inside the directory keeps
``ArtifactName`` and every ``Target`` relative, so no machine path is
recorded. ``--skip-db-update --skip-check-update`` used the vulnerability DB
and check bundle already cached. Result: 43 misconfigurations, 0
vulnerabilities, 0 secrets. To re-record, recreate the three files verbatim::

    Dockerfile
        FROM alpine:latest AS build
        RUN apk add curl
        RUN sudo apk add bash

        FROM alpine:latest
        ENV DB_PASSWORD=example
        RUN apt-get update && apt-get -y dist-upgrade
        ADD app.py /app/app.py
        RUN cd /app && make
        CMD ["python3", "/app/app.py"]

    pod.yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: insecure-pod
        spec:
          hostNetwork: true
          containers:
            - name: app
              image: nginx:latest
              securityContext:
                privileged: true
                runAsUser: 0

    main.tf
        resource "aws_s3_bucket" "public" {
          bucket = "example-public-bucket"
          acl    = "public-read"
        }

        resource "aws_ebs_volume" "data" {
          availability_zone = "us-east-1a"
          size              = 10
          encrypted         = false
        }

        resource "aws_security_group" "open" {
          name        = "open"
          description = "open ingress"

          ingress {
            description = "ssh"
            from_port   = 22
            to_port     = 22
            protocol    = "tcp"
            cidr_blocks = ["0.0.0.0/0"]
          }

          ingress {
            description = "rdp"
            from_port   = 3389
            to_port     = 3389
            protocol    = "tcp"
            cidr_blocks = ["0.0.0.0/0"]
          }
        }

The two ``FROM ...:latest`` lines and the two open ingress rules are there on
purpose: each makes trivy report one check twice in one file, which is the
case that lost its lines (#1221's line defect).
"""

import json
from pathlib import Path

from scripts.core.adapters.trivy_adapter import TrivyAdapter

RECORDED_074 = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "samples"
    / "trivy"
    / "misconfig-0.74.json"
)


def write(tmp_path: Path, name: str, content: str) -> Path:
    """Write content to a temporary file."""
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


class TestTrivyBasicParsing:
    """Tests for basic Trivy output parsing."""

    def test_vulnerability_parsing(self, tmp_path: Path):
        """Test parsing a single vulnerability."""
        sample = {
            "Version": "0.45.0",
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-1234",
                            "Title": "Remote Code Execution",
                            "Description": "A critical RCE vulnerability",
                            "Severity": "CRITICAL",
                            "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
                        }
                    ],
                }
            ],
        }
        path = write(tmp_path, "trivy.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        item = findings[0]
        assert item.ruleId == "CVE-2023-1234"
        # The advisory's Title is the title; the CVE stays the rule id.
        assert item.title == "Remote Code Execution"
        assert item.severity == "CRITICAL"
        assert item.tool["name"] == "trivy"
        assert item.tool["version"] == "0.45.0"
        assert "vulnerability" in item.tags

    def test_secret_parsing(self, tmp_path: Path):
        """Test parsing a secret finding."""
        sample = {
            "Version": "0.45.0",
            "Results": [
                {
                    "Target": "app/.env",
                    "Secrets": [
                        {
                            "Title": "Hardcoded API key",
                            "Description": "API key found in source",
                            "Severity": "HIGH",
                        }
                    ],
                }
            ],
        }
        path = write(tmp_path, "trivy.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].severity == "HIGH"
        assert "secret" in findings[0].tags

    def test_misconfiguration_parsing(self, tmp_path: Path):
        """Test parsing a misconfiguration finding."""
        sample = {
            "Version": "0.45.0",
            "Results": [
                {
                    "Target": "Dockerfile",
                    "Misconfigurations": [
                        {
                            "Title": "User not specified",
                            "RuleID": "DS002",
                            "Description": "Running as root is insecure",
                            "Severity": "MEDIUM",
                        }
                    ],
                }
            ],
        }
        path = write(tmp_path, "trivy.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        # The rule's id is the id, and its Title is the title (#1221). This
        # test used to pin the defect: Title ranked above RuleID.
        assert findings[0].ruleId == "DS002"
        assert findings[0].title == "User not specified"
        assert findings[0].severity == "MEDIUM"
        assert "misconfig" in findings[0].tags

    def test_metadata_property(self, tmp_path: Path):
        """Test adapter metadata property."""
        adapter = TrivyAdapter()
        metadata = adapter.metadata
        assert metadata.name == "trivy"
        assert metadata.tool_name == "trivy"
        assert metadata.schema_version == "1.2.0"
        assert metadata.exit_codes == {0: "clean", 1: "findings", 2: "error"}


class TestTrivyMixedResults:
    """Tests for mixed result types."""

    def test_vuln_and_secret(self, tmp_path: Path):
        """Test Trivy adapter parses vulnerabilities and secrets."""
        sample = {
            "Version": "0",
            "Results": [
                {
                    "Target": "app/Dockerfile",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-123",
                            "Title": "Something",
                            "Severity": "CRITICAL",
                        }
                    ],
                    "Secrets": [
                        {
                            "Title": "Hardcoded token",
                            "Severity": "HIGH",
                            "Target": "app/.env",
                        }
                    ],
                }
            ],
        }
        path = write(tmp_path, "trivy.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 2
        assert any(f.ruleId == "CVE-123" and f.severity == "CRITICAL" for f in findings)
        assert any(
            f.ruleId == "Hardcoded token" or f.title == "Hardcoded token"
            for f in findings
        )

    def test_multiple_targets(self, tmp_path: Path):
        """Test parsing multiple targets."""
        sample = {
            "Version": "0.45.0",
            "Results": [
                {
                    "Target": "package.json",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2022-0001",
                            "Title": "JS vuln",
                            "Severity": "HIGH",
                        }
                    ],
                },
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2022-0002",
                            "Title": "Python vuln",
                            "Severity": "MEDIUM",
                        }
                    ],
                },
            ],
        }
        path = write(tmp_path, "trivy.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 2
        targets = {f.location["path"] for f in findings}
        assert targets == {"package.json", "requirements.txt"}


class TestTrivySeverityMapping:
    """Tests for severity level mapping."""

    def test_low_severity(self, tmp_path: Path):
        """Test LOW severity."""
        sample = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [{"VulnerabilityID": "V001", "Severity": "LOW"}],
                }
            ]
        }
        path = write(tmp_path, "low.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert findings[0].severity == "LOW"

    def test_medium_severity(self, tmp_path: Path):
        """Test MEDIUM severity."""
        sample = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "V002", "Severity": "MEDIUM"}
                    ],
                }
            ]
        }
        path = write(tmp_path, "medium.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert findings[0].severity == "MEDIUM"

    def test_high_severity(self, tmp_path: Path):
        """Test HIGH severity."""
        sample = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "V003", "Severity": "HIGH"}
                    ],
                }
            ]
        }
        path = write(tmp_path, "high.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert findings[0].severity == "HIGH"

    def test_critical_severity(self, tmp_path: Path):
        """Test CRITICAL severity."""
        sample = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "V004", "Severity": "CRITICAL"}
                    ],
                }
            ]
        }
        path = write(tmp_path, "critical.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert findings[0].severity == "CRITICAL"


class TestTrivyEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_file(self, tmp_path: Path):
        """Test Trivy adapter handles empty input."""
        adapter = TrivyAdapter()
        path = write(tmp_path, "empty.json", "")
        assert adapter.parse(path) == []

    def test_malformed_json(self, tmp_path: Path):
        """Test Trivy adapter handles bad input."""
        adapter = TrivyAdapter()
        path = write(tmp_path, "bad.json", "{not json}")
        assert adapter.parse(path) == []

    def test_nonexistent_file(self, tmp_path: Path):
        """Test parsing nonexistent file."""
        adapter = TrivyAdapter()
        assert adapter.parse(tmp_path / "nonexistent.json") == []

    def test_results_not_list(self, tmp_path: Path):
        """Test parsing when Results is not a list."""
        sample = {"Version": "0.45.0", "Results": "not a list"}
        path = write(tmp_path, "not_list.json", json.dumps(sample))
        adapter = TrivyAdapter()
        assert adapter.parse(path) == []

    def test_results_missing(self, tmp_path: Path):
        """Test parsing when Results key is missing."""
        sample = {"Version": "0.45.0"}
        path = write(tmp_path, "no_results.json", json.dumps(sample))
        adapter = TrivyAdapter()
        assert adapter.parse(path) == []

    def test_empty_results_array(self, tmp_path: Path):
        """Test parsing with empty Results array."""
        sample = {"Version": "0.45.0", "Results": []}
        path = write(tmp_path, "empty_results.json", json.dumps(sample))
        adapter = TrivyAdapter()
        assert adapter.parse(path) == []

    def test_empty_vulnerabilities_array(self, tmp_path: Path):
        """Test parsing with empty Vulnerabilities array."""
        sample = {
            "Results": [
                {"Target": "test", "Vulnerabilities": []},
            ]
        }
        path = write(tmp_path, "empty_vulns.json", json.dumps(sample))
        adapter = TrivyAdapter()
        assert adapter.parse(path) == []


class TestTrivyCweMapping:
    """Tests for CWE mapping in vulnerabilities."""

    def test_single_cwe_id(self, tmp_path: Path):
        """Test vulnerability with single CWE ID."""
        sample = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-0001",
                            "Severity": "HIGH",
                            "CweIDs": ["CWE-79"],
                        }
                    ],
                }
            ]
        }
        path = write(tmp_path, "cwe.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].risk is not None
        assert "CWE-79" in findings[0].risk["cwe"]

    def test_multiple_cwe_ids(self, tmp_path: Path):
        """Test vulnerability with multiple CWE IDs."""
        sample = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-0002",
                            "Severity": "CRITICAL",
                            "CweIDs": ["CWE-79", "CWE-352", "CWE-89"],
                        }
                    ],
                }
            ]
        }
        path = write(tmp_path, "multi_cwe.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert len(findings[0].risk["cwe"]) == 3

    def test_no_cwe_ids(self, tmp_path: Path):
        """Test vulnerability without CWE IDs."""
        sample = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-2023-0003", "Severity": "LOW"}
                    ],
                }
            ]
        }
        path = write(tmp_path, "no_cwe.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].risk is None


class TestTrivyCompliance:
    """Tests for compliance enrichment and metadata."""

    def test_schema_version(self, tmp_path: Path):
        """Test schema version is set correctly."""
        sample = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "V-SCHEMA", "Severity": "LOW"}
                    ],
                }
            ]
        }
        path = write(tmp_path, "schema.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert findings[0].schemaVersion == "1.2.0"

    def test_tool_version_captured(self, tmp_path: Path):
        """Test tool version is captured from output."""
        sample = {
            "Version": "0.47.0",
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "V-VER", "Severity": "LOW"}
                    ],
                }
            ],
        }
        path = write(tmp_path, "version.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert findings[0].tool["version"] == "0.47.0"

    def test_missing_version_defaults_to_unknown(self, tmp_path: Path):
        """Test missing version defaults to unknown."""
        sample = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "V-NOVER", "Severity": "LOW"}
                    ],
                }
            ]
        }
        path = write(tmp_path, "no_ver.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert findings[0].tool["version"] == "unknown"

    def test_remediation_url(self, tmp_path: Path):
        """Test remediation uses PrimaryURL when available."""
        sample = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-URL",
                            "Severity": "HIGH",
                            "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-URL",
                        }
                    ],
                }
            ]
        }
        path = write(tmp_path, "url.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert "nvd.nist.gov" in findings[0].remediation


class TestTrivyFingerprinting:
    """Tests for finding fingerprint generation."""

    def test_unique_fingerprints(self, tmp_path: Path):
        """Test that different findings get unique fingerprints."""
        sample = {
            "Results": [
                {
                    "Target": "file1.txt",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-F1", "Severity": "LOW"}
                    ],
                },
                {
                    "Target": "file2.txt",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-F2", "Severity": "LOW"}
                    ],
                },
            ]
        }
        path = write(tmp_path, "fingerprint.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 2
        assert findings[0].id != findings[1].id

    def test_consistent_fingerprints(self, tmp_path: Path):
        """Test that same input produces same fingerprint."""
        sample = {
            "Results": [
                {
                    "Target": "test.txt",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-CONS", "Severity": "MEDIUM"}
                    ],
                }
            ]
        }
        path = write(tmp_path, "consistent.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings1 = adapter.parse(path)
        findings2 = adapter.parse(path)
        assert findings1[0].id == findings2[0].id


class TestTrivyUnicodeHandling:
    """Tests for Unicode and encoding edge cases."""

    def test_unicode_in_target(self, tmp_path: Path):
        """Test parsing with Unicode in target path."""
        sample = {
            "Results": [
                {
                    "Target": "packages/\u65e5\u672c\u8a9e/lib.js",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-UNI", "Severity": "LOW"}
                    ],
                }
            ]
        }
        path = write(tmp_path, "unicode.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert "\u65e5\u672c\u8a9e" in findings[0].location["path"]

    def test_unicode_in_title(self, tmp_path: Path):
        """Test parsing with Unicode in title."""
        sample = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-UNI2",
                            "Title": "Vuln\u00e9rabilit\u00e9 critique",
                            "Severity": "HIGH",
                        }
                    ],
                }
            ]
        }
        path = write(tmp_path, "unicode_title.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert "\u00e9" in findings[0].message


class TestTrivyMisconfigurationDetails:
    """Tests for misconfiguration-specific features."""

    def test_misconfig_with_rule_id_only(self, tmp_path: Path):
        """Test misconfiguration with only RuleID (no Title)."""
        sample = {
            "Results": [
                {
                    "Target": "Dockerfile",
                    "Misconfigurations": [
                        {
                            "RuleID": "DS001",
                            "Description": "No healthcheck defined",
                            "Severity": "LOW",
                        }
                    ],
                }
            ]
        }
        path = write(tmp_path, "misconfig.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        # Without Title, RuleID is used
        assert findings[0].ruleId == "DS001"

    def test_misconfig_fallback_to_title(self, tmp_path: Path):
        """Test misconfiguration using Title as fallback rule ID."""
        sample = {
            "Results": [
                {
                    "Target": "docker-compose.yml",
                    "Misconfigurations": [
                        {
                            "Title": "Privileged container",
                            "Severity": "HIGH",
                        }
                    ],
                }
            ]
        }
        path = write(tmp_path, "misconfig_title.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert "Privileged container" in findings[0].ruleId

    def test_secrets_not_vulnerabilities(self, tmp_path: Path):
        """Test that secrets and vulnerabilities are tagged differently."""
        sample = {
            "Results": [
                {
                    "Target": "app",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-V", "Severity": "HIGH"}
                    ],
                    "Secrets": [{"Title": "API Key", "Severity": "HIGH"}],
                }
            ]
        }
        path = write(tmp_path, "mixed_tags.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 2
        vuln_finding = [f for f in findings if "vulnerability" in f.tags][0]
        secret_finding = [f for f in findings if "secret" in f.tags][0]
        assert vuln_finding.ruleId == "CVE-V"
        assert secret_finding.ruleId == "API Key"


def _recorded_misconfigs() -> list[tuple[str, dict]]:
    """(Target, item) for every misconfiguration trivy 0.74.0 recorded."""
    data = json.loads(RECORDED_074.read_bytes())
    pairs = [
        (result["Target"], item)
        for result in data["Results"]
        for item in result.get("Misconfigurations") or []
    ]
    # Meta-guard: a fixture that silently parses to nothing satisfies every
    # "for each finding" assertion below.
    assert len(pairs) == 43, len(pairs)
    return pairs


class TestTrivy074RecordedOutput:
    """#1221 and the line defect, asserted on trivy 0.74.0's own output.

    0.74.0 names a misconfiguration's rule in ``ID`` (``DS-0001``), not
    ``RuleID`` or ``AVDID``, puts its lines in ``CauseMetadata``, not at the
    top level, and writes its version at ``Trivy.Version``, not ``Version``.
    Before this was fixed every one of the 43 findings below had its Title as
    its rule id, line 0, and tool version ``unknown`` -- and the two findings
    of one check in one file shared an id, so deduplication kept one.
    """

    def _parse(self):
        findings = TrivyAdapter().parse(RECORDED_074)
        misconfigs = [f for f in findings if "misconfig" in f.tags]
        assert len(misconfigs) == len(findings) == 43
        return misconfigs

    def test_rule_id_is_trivys_id_and_title_is_its_title(self):
        misconfigs = self._parse()
        for f in misconfigs:
            assert f.ruleId == f.raw["ID"], (f.ruleId, f.raw["ID"])
            assert f.title == f.raw["Title"], (f.title, f.raw["Title"])
        ids = {f.ruleId for f in misconfigs}
        # One id per provider family, spelled as 0.74.0 prints it.
        assert {"DS-0001", "KSV-0017", "AWS-0086"} <= ids
        assert "':latest' tag used" not in ids

    def test_lines_come_from_cause_metadata(self):
        misconfigs = self._parse()
        for f in misconfigs:
            cause = f.raw.get("CauseMetadata") or {}
            assert f.location["startLine"] == (cause.get("StartLine") or 0), f.ruleId
            assert f.location.get("endLine") == cause.get("EndLine"), f.ruleId
        lines = {
            (f.location["path"], f.ruleId, f.location["startLine"]) for f in misconfigs
        }
        assert ("Dockerfile", "DS-0001", 1) in lines
        assert ("Dockerfile", "DS-0001", 5) in lines
        assert ("main.tf", "AWS-0107", 21) in lines
        assert ("main.tf", "AWS-0107", 29) in lines
        # Whole-file checks carry no line in 0.74.0 and stay at 0.
        assert ("Dockerfile", "DS-0026", 0) in lines

    def test_one_check_twice_in_one_file_keeps_two_ids(self):
        """The juice-shop loss: same-rule findings in one file shared an id."""
        misconfigs = self._parse()
        by_id: dict[str, list] = {}
        for f in misconfigs:
            by_id.setdefault(f.id, []).append((f.ruleId, f.location["startLine"]))
        shared = {k: v for k, v in by_id.items() if len(v) > 1}
        assert not shared, shared
        assert len(by_id) == 43

    def test_tool_version_is_trivy_version(self):
        misconfigs = self._parse()
        assert {f.tool["version"] for f in misconfigs} == {"0.74.0"}


class TestTrivyRuleIdLineAndVersionChain:
    """The fallbacks behind the 0.74.0 shape, on hand-built input.

    Secrets are hand-built on purpose: a recorded secret finding would commit
    a token-shaped string. ``Match`` below is the masked form trivy writes.
    """

    def test_secret_rule_id_is_rule_id_not_title(self, tmp_path: Path):
        sample = {
            "Trivy": {"Version": "0.74.0"},
            "Results": [
                {
                    "Target": "app/config.py",
                    "Class": "secret",
                    "Secrets": [
                        {
                            "RuleID": "github-pat",
                            "Category": "GitHub",
                            "Severity": "CRITICAL",
                            "Title": "GitHub Personal Access Token",
                            "StartLine": 4,
                            "EndLine": 4,
                            "Match": "TOKEN = ****************",
                        }
                    ],
                }
            ],
        }
        findings = TrivyAdapter().parse(
            write(tmp_path, "trivy.json", json.dumps(sample))
        )
        assert len(findings) == 1
        f = findings[0]
        assert f.ruleId == "github-pat"
        assert f.title == "GitHub Personal Access Token"
        # Secrets keep their lines at the top level; nothing to fall back past.
        assert f.location["startLine"] == 4
        assert f.location["endLine"] == 4

    def test_cause_metadata_line_wins_over_top_level(self, tmp_path: Path):
        sample = {
            "Results": [
                {
                    "Target": "Dockerfile",
                    "Misconfigurations": [
                        {
                            "ID": "DS-0001",
                            "Title": "':latest' tag used",
                            "Severity": "MEDIUM",
                            "StartLine": 3,
                            "EndLine": 3,
                            "CauseMetadata": {"StartLine": 7, "EndLine": 8},
                        }
                    ],
                }
            ]
        }
        f = TrivyAdapter().parse(write(tmp_path, "t.json", json.dumps(sample)))[0]
        assert (f.location["startLine"], f.location["endLine"]) == (7, 8)

    def test_top_level_line_when_cause_metadata_has_none(self, tmp_path: Path):
        """Older trivy wrote the line at the top level; keep reading it there."""
        sample = {
            "Results": [
                {
                    "Target": "Dockerfile",
                    "Misconfigurations": [
                        {
                            "ID": "DS002",
                            "Title": "Image user should not be 'root'",
                            "Severity": "HIGH",
                            "StartLine": 12,
                            "EndLine": 14,
                            "CauseMetadata": {"Provider": "Dockerfile"},
                        }
                    ],
                }
            ]
        }
        f = TrivyAdapter().parse(write(tmp_path, "t.json", json.dumps(sample)))[0]
        assert f.ruleId == "DS002"
        assert (f.location["startLine"], f.location["endLine"]) == (12, 14)

    def test_context_is_read_under_the_scanned_root_not_the_cwd(
        self, tmp_path: Path, monkeypatch
    ):
        """``Target`` is relative to ``ArtifactName``, the directory trivy scanned.

        A real line makes the adapter read code context, and ``jmo scan`` runs
        trivy on an absolute target from some other working directory. Read
        relative to the cwd, a juice-shop ``Dockerfile`` finding would carry
        the lines of whatever ``Dockerfile`` the cwd happens to hold.
        """
        scanned = tmp_path / "scanned"
        scanned.mkdir()
        (scanned / "Dockerfile").write_bytes(b"# scanned\nFROM alpine:latest\n")
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "Dockerfile").write_bytes(b"# decoy\nFROM decoy:latest\n")
        monkeypatch.chdir(elsewhere)
        sample = {
            "ArtifactName": str(scanned),
            "Results": [
                {
                    "Target": "Dockerfile",
                    "Misconfigurations": [
                        {
                            "ID": "DS-0001",
                            "Title": "':latest' tag used",
                            "Severity": "MEDIUM",
                            "CauseMetadata": {"StartLine": 2, "EndLine": 2},
                        }
                    ],
                }
            ],
        }
        f = TrivyAdapter().parse(write(tmp_path, "t.json", json.dumps(sample)))[0]
        assert f.location["path"] == "Dockerfile"
        assert f.context is not None
        assert "FROM alpine:latest" in f.context["snippet"]
        assert "decoy" not in f.context["snippet"]

    def test_version_falls_back_to_top_level_then_unknown(self, tmp_path: Path):
        item = {"VulnerabilityID": "CVE-1", "Severity": "LOW"}
        cases = [
            ({"Trivy": {"Version": "0.74.0"}, "Version": "0.1.0"}, "0.74.0"),
            ({"Version": "0.50.0"}, "0.50.0"),
            ({"Trivy": "not a mapping", "Version": "0.50.0"}, "0.50.0"),
            ({"Trivy": {}}, "unknown"),
        ]
        for n, (top, expected) in enumerate(cases):
            sample = {**top, "Results": [{"Target": "x", "Vulnerabilities": [item]}]}
            path = write(tmp_path, f"v{n}.json", json.dumps(sample))
            assert TrivyAdapter().parse(path)[0].tool["version"] == expected, top
