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
- cvss extraction (#1243, ``TestTrivyCvss``) and trivy 0.74.0's own
  vulnerability output (``TestTrivy074RecordedVulnOutput``), recorded below

Recorded fixture ``tests/fixtures/samples/trivy/misconfig-0.74.json``: trivy
**0.74.0**'s JSON, byte for byte, recorded 2026-09-28 on Windows by running,
from inside a scratch directory holding only the three files listed below::

    trivy fs -q -f json --scanners vuln,secret,misconfig \\
        --skip-db-update --skip-check-update . -o misconfig-0.74.json

``--scanners`` is what JMo's repository descriptor passes
(``tool_descriptors._trivy``); scanning ``.`` from inside the directory keeps
``ArtifactName`` and every ``Target`` relative, so no machine path is
recorded. ``--skip-db-update --skip-check-update`` used the vulnerability DB
and check bundle already cached. Result: 47 misconfigurations, 0
vulnerabilities, 0 secrets. To re-record, recreate the three files verbatim::

    Dockerfile
        FROM alpine:latest as build
        RUN apk add curl
        RUN sudo apk add bash

        FROM alpine as build
        ENV DB_PASSWORD=example
        RUN apt-get update && apt-get -y dist-upgrade
        ADD app.py /app/app.py
        RUN cd /app && make
        CMD ["python3", "/app/app.py"]
        EXPOSE 22
        MAINTAINER example

    pod.yaml
        apiVersion: v1
        kind: Pod
        metadata:
          name: insecure-pod
        spec:
          hostNetwork: true
          hostPID: true
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

The two ``FROM alpine`` lines and the two open ingress rules are there on
purpose: each makes trivy report one check twice in one file, which is the
case that lost its lines (#1221's line defect). The rest gives every trivy key
in ``scripts/core/rule_equivalence.py`` a recorded finding; hadolint 2.14.0
(then 2.15.1, the pin, which adds DL3064 on the ``ENV`` line) and checkov
3.3.16 were run on the same three files to check each key's
partners (the lower-case ``as`` is for checkov: its CKV_DOCKER_11 matches
only `` as ``). ``apt-get -y dist-upgrade`` stays to show that DS-0024, which
0.74.0 ships deprecated, does not fire.

Recorded fixture ``tests/fixtures/samples/trivy/vuln-0.74.json`` (#1243): trivy
**0.74.0**'s own JSON, trimmed (how, below), recorded 2026-09-28 on Windows against a
throwaway npm project holding only a synthetic lockfile -- never a real
project's dependencies, per this repo's privacy convention for anything a
private repo's export would otherwise be needed for. From inside that
directory (``package.json``: ``{"dependencies": {"lodash": "4.17.4",
"minimist": "0.0.8"}}``), ``npm install --package-lock-only`` generated the
lockfile, then::

    trivy fs -q -f json --scanners vuln --skip-db-update --skip-check-update \\
        . -o vuln-0.74.json

``--skip-db-update --skip-check-update`` used the vulnerability DB already
cached locally (``trivy --version``: DB version 2). trivy's raw run found 12
vulnerabilities across both packages; the fixture keeps 3 (``CVE-2019-10744``,
``CVE-2018-16487``, ``CVE-2021-44906``) -- enough to cover a ``CVSS`` block
with all three of ``ghsa``/``nvd``/``redhat``, one missing ``ghsa`` entirely,
and one where NVD's and a vendor's V3 scores disagree (9.8 vs 3.1), which is
what proves NVD wins on real trivy output rather than by construction. The
other 9 (more lodash CVEs) were dropped only to keep the fixture small; none
of them exercises a shape these three do not already cover. So it is not byte
for byte, unlike ``misconfig-0.74.json``: trivy's output was parsed, its one
``Result``'s ``Vulnerabilities`` cut to those three (in trivy's order, every
other key and value as trivy wrote it, ``Packages`` included), and written
back with Python's ``json.dumps(indent=2)`` and a newline. That rewrite also
turned Go's HTML escapes (``\\u003c``, ``\\u003e``, ``\\u0026``, which
``misconfig-0.74.json`` still carries) into ``<``, ``>`` and ``&``; re-parsing
trivy's untrimmed output and cutting the list gives this file's document
exactly, key order included. ``ArtifactName``
is ``"."`` (scanned from inside the directory) and no path in the fixture
names this machine, grepped for ``Users``/``Jimmy``/a drive letter before
committing.

The "no NVD" and "V2-only" branches of ``_best_vulnerability_cvss`` are not
exercised by any real CVE found this way (every one of trivy's own DB entries
for these two packages carries NVD's V3), so those branches are covered by
hand-built ``TestTrivyCvss`` cases instead -- the same split
``TestTrivyRuleIdLineAndVersionChain`` already uses for secrets, and for the
same reason: a real fixture proves the common case, a hand-built one proves a
fallback no live CVE happened to need.
"""

import json
from pathlib import Path

from scripts.core.adapters.trivy_adapter import TrivyAdapter
from scripts.core.common_finding import fingerprint

RECORDED_074 = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "samples"
    / "trivy"
    / "misconfig-0.74.json"
)

RECORDED_074_VULN = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "samples"
    / "trivy"
    / "vuln-0.74.json"
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


class TestTrivySecretCwe:
    """A trivy secret carries CWE-798, as gitleaks' and trufflehog's do.

    trivy writes no CWE on a secret, and compliance enrichment reads
    ``risk.cwe`` and nowhere else, so a trivy secret reached no OWASP mapping.
    Since #1221 its ruleId is its RuleID (``github-pat``), the same string
    gitleaks prints, so the two cluster on the id alone; when trivy's CRITICAL
    finding led the cluster, the consensus copied trivy's empty ``risk`` and
    the secret left the ``owasp-top-10`` count. The load-order test is
    ``tests/integration/test_cross_tool_dedup_integration.py``.
    """

    def _parse(self, tmp_path: Path, results: list[dict]):
        sample = {"Trivy": {"Version": "0.74.0"}, "Results": results}
        return TrivyAdapter().parse(write(tmp_path, "trivy.json", json.dumps(sample)))

    def test_secret_carries_cwe_798_in_the_secret_scanners_shape(self, tmp_path: Path):
        findings = self._parse(
            tmp_path,
            [
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
        )
        assert len(findings) == 1
        # gitleaks_adapter's and trufflehog_adapter's (unverified) dict: trivy
        # verifies nothing either.
        assert findings[0].risk == {
            "cwe": ["CWE-798"],
            "confidence": "MEDIUM",
            "likelihood": "HIGH",
            "impact": "HIGH",
        }

    def test_vulnerabilities_and_misconfigurations_never_get_it(self, tmp_path: Path):
        findings = self._parse(
            tmp_path,
            [
                {
                    "Target": "package-lock.json",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-0001",
                            "Severity": "HIGH",
                            "CweIDs": ["CWE-79"],
                        },
                        {"VulnerabilityID": "CVE-2023-0002", "Severity": "LOW"},
                    ],
                },
                {
                    "Target": "Dockerfile",
                    "Misconfigurations": [{"ID": "DS-0002", "Severity": "HIGH"}],
                },
            ],
        )
        by_id = {f.ruleId: f for f in findings}
        assert set(by_id) == {"CVE-2023-0001", "CVE-2023-0002", "DS-0002"}
        assert by_id["CVE-2023-0001"].risk == {"cwe": ["CWE-79"]}
        assert by_id["CVE-2023-0002"].risk is None
        assert by_id["DS-0002"].risk is None

    def test_each_secret_gets_its_own_risk_dict(self, tmp_path: Path):
        """Enrichment writes into ``risk``; one shared dict would leak across."""
        findings = self._parse(
            tmp_path,
            [
                {
                    "Target": "a.py",
                    "Secrets": [
                        {
                            "RuleID": "github-pat",
                            "Severity": "CRITICAL",
                            "StartLine": 1,
                        },
                        {"RuleID": "private-key", "Severity": "HIGH", "StartLine": 2},
                    ],
                }
            ],
        )
        assert len(findings) == 2
        assert findings[0].risk == findings[1].risk
        assert findings[0].risk is not findings[1].risk


class TestTrivyCvss:
    """#1243: trivy vulnerabilities carried no ``cvss`` at all.

    NVD's score wins within a version; else any other source's. Across
    versions, v3.x outranks v4.0 outranks v2.0 regardless of source or numbers
    (Ruling 34, #1356).
    """

    def _vuln(self, tmp_path: Path, name: str, cvss: dict) -> Path:
        sample = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-CVSS",
                            "Severity": "HIGH",
                            "CVSS": cvss,
                        }
                    ],
                }
            ]
        }
        return write(tmp_path, name, json.dumps(sample))

    def test_nvd_v3_wins(self, tmp_path: Path):
        cvss = {
            "nvd": {
                "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "V2Score": 7.5,
                "V3Score": 9.8,
            },
            "redhat": {
                "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "V3Score": 8.1,
            },
        }
        f = TrivyAdapter().parse(self._vuln(tmp_path, "nvd_v3.json", cvss))[0]
        assert f.cvss == {
            "version": "3.x",
            "score": 9.8,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }

    def test_vendor_v3_used_when_nvd_absent(self, tmp_path: Path):
        cvss = {
            "ghsa": {
                "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "V3Score": 9.1,
            }
        }
        f = TrivyAdapter().parse(self._vuln(tmp_path, "vendor_v3.json", cvss))[0]
        assert f.cvss == {
            "version": "3.x",
            "score": 9.1,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }

    def test_vendor_v3_preferred_over_nvd_v2_only(self, tmp_path: Path):
        """v3 always outranks v2, even from a different source than NVD's."""
        cvss = {
            "nvd": {"V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P", "V2Score": 5.0},
            "redhat": {
                "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "V3Score": 7.2,
            },
        }
        f = TrivyAdapter().parse(self._vuln(tmp_path, "vendor_over_nvd_v2.json", cvss))[
            0
        ]
        assert f.cvss == {
            "version": "3.x",
            "score": 7.2,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }

    def test_nvd_v2_only_used_when_nothing_has_v3(self, tmp_path: Path):
        """A source with only V2 (old CVE, no V3 assigned anywhere)."""
        cvss = {"nvd": {"V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P", "V2Score": 5.0}}
        f = TrivyAdapter().parse(self._vuln(tmp_path, "nvd_v2_only.json", cvss))[0]
        assert f.cvss == {
            "version": "2.0",
            "score": 5.0,
            "vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
        }

    def test_vendor_v2_used_when_only_option(self, tmp_path: Path):
        cvss = {"ssapi": {"V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P", "V2Score": 4.3}}
        f = TrivyAdapter().parse(self._vuln(tmp_path, "vendor_v2_only.json", cvss))[0]
        assert f.cvss == {
            "version": "2.0",
            "score": 4.3,
            "vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
        }

    def test_v4_only_used_when_nothing_has_v3(self, tmp_path: Path):
        """Ruling 34 (#1356): an advisory with a v4.0 metric and nothing else."""
        cvss = {
            "nvd": {
                "V40Vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                "V40Score": 8.7,
            }
        }
        f = TrivyAdapter().parse(self._vuln(tmp_path, "v4_only.json", cvss))[0]
        assert f.cvss == {
            "version": "4.0",
            "score": 8.7,
            "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        }

    def test_v3_preferred_over_v4_even_with_a_lower_score(self, tmp_path: Path):
        """Ruling 34: v3.x outranks v4.0 whatever the numbers."""
        cvss = {
            "nvd": {
                "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "V3Score": 5.3,
                "V40Vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                "V40Score": 9.0,
            }
        }
        f = TrivyAdapter().parse(self._vuln(tmp_path, "v3_over_v4.json", cvss))[0]
        assert f.cvss == {
            "version": "3.x",
            "score": 5.3,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }

    def test_v4_preferred_over_v2_even_with_a_lower_score(self, tmp_path: Path):
        """Ruling 34: v4.0 outranks v2.0 whatever the numbers."""
        cvss = {
            "nvd": {
                "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                "V2Score": 10.0,
                "V40Vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
                "V40Score": 1.0,
            }
        }
        f = TrivyAdapter().parse(self._vuln(tmp_path, "v4_over_v2.json", cvss))[0]
        assert f.cvss == {
            "version": "4.0",
            "score": 1.0,
            "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
        }

    def test_vendor_v4_used_when_nvd_absent(self, tmp_path: Path):
        """NVD-first within a version (Ruling 34's tie-break) also holds for v4.0."""
        cvss = {
            "ghsa": {
                "V40Vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                "V40Score": 9.1,
            }
        }
        f = TrivyAdapter().parse(self._vuln(tmp_path, "vendor_v4.json", cvss))[0]
        assert f.cvss == {
            "version": "4.0",
            "score": 9.1,
            "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        }

    def test_no_cvss_block_omits_the_key(self, tmp_path: Path):
        sample = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-NOCVSS", "Severity": "HIGH"}
                    ],
                }
            ]
        }
        f = TrivyAdapter().parse(write(tmp_path, "no_cvss.json", json.dumps(sample)))[0]
        assert f.cvss is None
        assert "cvss" not in f.to_dict()

    def test_empty_cvss_block_omits_the_key(self, tmp_path: Path):
        f = TrivyAdapter().parse(self._vuln(tmp_path, "empty_cvss.json", {}))[0]
        assert f.cvss is None

    def test_cvss_block_with_no_numeric_score_omits_the_key(self, tmp_path: Path):
        """A source present but carrying neither ``V3Score`` nor ``V2Score``."""
        cvss = {"nvd": {"V3Vector": "", "V2Vector": ""}}
        f = TrivyAdapter().parse(self._vuln(tmp_path, "no_score.json", cvss))[0]
        assert f.cvss is None

    def test_misconfig_and_secret_never_carry_cvss(self, tmp_path: Path):
        """trivy's ``CVSS`` block only ever appears on vulnerabilities."""
        sample = {
            "Results": [
                {
                    "Target": "test",
                    "Misconfigurations": [
                        {"ID": "DS001", "Severity": "HIGH"},
                    ],
                    "Secrets": [
                        {"Title": "token", "Severity": "HIGH"},
                    ],
                }
            ]
        }
        findings = TrivyAdapter().parse(
            write(tmp_path, "no_vuln_cvss.json", json.dumps(sample))
        )
        assert len(findings) == 2
        assert all(f.cvss is None for f in findings)


class TestTrivy074RecordedVulnOutput:
    """#1243, asserted on trivy 0.74.0's own vulnerability output.

    Before the fix, every one of these carried no ``cvss`` at all, though
    trivy's raw ``CVSS`` block was right there in ``raw``.
    """

    def _parse(self):
        findings = TrivyAdapter().parse(RECORDED_074_VULN)
        assert len(findings) == 3
        return {f.ruleId: f for f in findings}

    def test_nvd_v3_wins_when_all_three_sources_agree(self):
        by_id = self._parse()
        f = by_id["CVE-2019-10744"]
        assert set(f.raw["CVSS"]) == {"ghsa", "nvd", "redhat"}
        assert f.cvss == {
            "version": "3.x",
            "score": 9.1,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
        }

    def test_nvd_v3_wins_when_ghsa_is_absent(self):
        by_id = self._parse()
        f = by_id["CVE-2018-16487"]
        assert "ghsa" not in f.raw["CVSS"]
        assert f.cvss == {
            "version": "3.x",
            "score": 5.6,
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
        }

    def test_nvd_v3_wins_over_a_disagreeing_vendor_score(self):
        """NVD 9.8 vs. redhat's 3.1 for the same CVE: NVD's must win."""
        by_id = self._parse()
        f = by_id["CVE-2021-44906"]
        assert f.raw["CVSS"]["redhat"]["V3Score"] == 3.1
        assert f.cvss == {
            "version": "3.x",
            "score": 9.8,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        }


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


class TestTrivy074RecordedOutput:
    """#1221 and the line defect, asserted on trivy 0.74.0's own output.

    0.74.0 names a misconfiguration's rule in ``ID`` (``DS-0001``), not
    ``RuleID`` or ``AVDID``, puts its lines in ``CauseMetadata``, not at the
    top level, and writes its version at ``Trivy.Version``, not ``Version``.
    Before this was fixed every one of the findings below had its Title as its
    rule id, line 0, and tool version ``unknown`` -- and the two findings of
    one check in one file shared an id, so deduplication kept one.
    """

    def _parse(self):
        findings = TrivyAdapter().parse(RECORDED_074)
        misconfigs = [f for f in findings if "misconfig" in f.tags]
        # Meta-guard: a fixture that silently parses to nothing satisfies
        # every "for each finding" assertion below.
        assert len(misconfigs) == len(findings) == 47
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
        assert len(by_id) == 47

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

    def test_context_when_trivy_scanned_one_file(self, tmp_path: Path, monkeypatch):
        """``jmo scan --iac <file>`` runs ``trivy config <file>``.

        Measured on 0.74.0: ``ArtifactName`` is then the file itself and
        ``Target`` its name, so the file's directory is the root.
        """
        scanned = tmp_path / "scanned"
        scanned.mkdir()
        (scanned / "Dockerfile").write_bytes(b"# scanned\nFROM alpine:latest\n")
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "Dockerfile").write_bytes(b"# decoy\nFROM decoy:latest\n")
        monkeypatch.chdir(elsewhere)
        sample = {
            "ArtifactName": str(scanned / "Dockerfile"),
            "ArtifactType": "filesystem",
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


class TestTrivyDependency:
    """#1346: a vulnerability names its installed package, and its id is keyed
    on it. trivy's message is the advisory title, which names no version, so
    without the package two installed versions of one package with one
    advisory shared an id and phase-1 deduplication kept one: 47 findings on a
    real lockfile became 38."""

    def test_a_recorded_vulnerability_carries_its_package(self):
        by_id = {f.ruleId: f for f in TrivyAdapter().parse(RECORDED_074_VULN)}
        assert by_id["CVE-2019-10744"].dependency == {
            "name": "lodash",
            "version": "4.17.4",
            "ecosystem": "npm",
            "aliases": ["GHSA-jf85-cpcp-j695"],
        }
        # No VendorIDs in trivy's record: no aliases, not a guessed one.
        assert by_id["CVE-2018-16487"].dependency["aliases"] == []
        assert by_id["CVE-2021-44906"].dependency["name"] == "minimist"

    def test_two_installed_versions_of_one_package_are_two_findings(self, tmp_path):
        def vuln(version):
            return {
                "VulnerabilityID": "CVE-2019-10744",
                "PkgName": "lodash",
                "PkgIdentifier": {"PURL": f"pkg:npm/lodash@{version}"},
                "InstalledVersion": version,
                "Severity": "CRITICAL",
                "Title": "nodejs-lodash: prototype pollution in defaultsDeep",
                "VendorIDs": ["GHSA-jf85-cpcp-j695"],
            }

        sample = {
            "Results": [
                {
                    "Target": "package-lock.json",
                    "Vulnerabilities": [vuln("4.13.1"), vuln("4.17.4")],
                }
            ]
        }
        findings = TrivyAdapter().parse(
            write(tmp_path, "trivy.json", json.dumps(sample))
        )
        assert len({f.id for f in findings}) == 2
        assert findings[0].id == fingerprint(
            "trivy",
            "CVE-2019-10744",
            "package-lock.json",
            0,
            "nodejs-lodash: prototype pollution in defaultsDeep",
            package="lodash@4.13.1",
        )

    def test_misconfigurations_and_secrets_have_none_and_keep_their_ids(self):
        findings = TrivyAdapter().parse(RECORDED_074)
        assert findings
        for f in findings:
            assert f.dependency is None
            assert f.id == fingerprint(
                "trivy",
                f.ruleId,
                f.location["path"],
                f.location["startLine"],
                f.message,
            )

    def test_no_package_without_both_name_and_version(self, tmp_path):
        sample = {
            "Results": [
                {
                    "Target": "package-lock.json",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-1",
                            "PkgName": "lodash",
                            "Severity": "LOW",
                        },
                        {
                            "VulnerabilityID": "CVE-2",
                            "InstalledVersion": "1.0",
                            "Severity": "LOW",
                        },
                    ],
                }
            ]
        }
        findings = TrivyAdapter().parse(
            write(tmp_path, "trivy.json", json.dumps(sample))
        )
        assert [f.dependency for f in findings] == [None, None]
