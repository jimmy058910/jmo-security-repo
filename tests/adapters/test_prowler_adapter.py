import json
import logging
from pathlib import Path

from scripts.core.adapters.prowler_adapter import ProwlerAdapter


def write_ndjson(p: Path, lines):
    """Write newline-delimited JSON (NDJSON) format."""
    p.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(json.dumps(line) for line in lines)
    p.write_text(content, encoding="utf-8")


def test_prowler_adapter_aws_fail(tmp_path: Path):
    """Test Prowler adapter with AWS FAIL finding."""
    findings = [
        {
            "CheckID": "s3_bucket_public_access",
            "Status": "FAIL",
            "CheckTitle": "S3 Bucket Public Access Block",
            "CheckType": "Data Protection",
            "ServiceName": "s3",
            "Severity": "high",
            "ResourceId": "my-public-bucket",
            "ResourceArn": "arn:aws:s3:::my-public-bucket",
            "ResourceType": "AWS::S3::Bucket",
            "Provider": "aws",
            "AccountUID": "123456789012",
            "Region": "us-east-1",
            "StatusExtended": "S3 bucket my-public-bucket has public access enabled",
            "Description": "S3 buckets should not allow public access",
            "Risk": "Data exposure risk",
            "RemediationCode": "aws s3api put-public-access-block --bucket my-public-bucket --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true",
            "RemediationUrl": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        }
    ]
    f = tmp_path / "prowler.json"
    write_ndjson(f, findings)
    adapter = ProwlerAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "s3_bucket_public_access"
    assert items[0].severity == "HIGH"
    assert "cloud-security" in items[0].tags
    assert "cspm" in items[0].tags
    assert "aws" in items[0].tags
    assert "s3" in items[0].tags
    assert items[0].context["provider"] == "aws"
    assert items[0].context["service_name"] == "s3"
    assert items[0].context["account_uid"] == "123456789012"
    assert items[0].context["region"] == "us-east-1"
    assert items[0].location["path"] == "arn:aws:s3:::my-public-bucket"


def test_prowler_adapter_azure_fail(tmp_path: Path):
    """Test Prowler adapter with Azure FAIL finding."""
    findings = [
        {
            "CheckID": "azure_storage_secure_transfer",
            "Status": "FAIL",
            "CheckTitle": "Storage Account Secure Transfer Required",
            "ServiceName": "storage",
            "Severity": "medium",
            "ResourceId": "mystorageaccount",
            "ResourceArn": "/subscriptions/sub-123/resourceGroups/rg-prod/providers/Microsoft.Storage/storageAccounts/mystorageaccount",
            "Provider": "azure",
            "AccountUID": "sub-123",
            "Region": "eastus",
            "StatusExtended": "Storage account mystorageaccount does not enforce secure transfer",
            "Description": "Azure Storage accounts should require secure transfer",
            "RemediationUrl": "https://learn.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer",
        }
    ]
    f = tmp_path / "prowler.json"
    write_ndjson(f, findings)
    adapter = ProwlerAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "azure_storage_secure_transfer"
    assert items[0].severity == "MEDIUM"
    assert "azure" in items[0].tags
    assert "storage" in items[0].tags
    assert items[0].context["provider"] == "azure"


def test_prowler_adapter_gcp_fail(tmp_path: Path):
    """Test Prowler adapter with GCP FAIL finding."""
    findings = [
        {
            "CheckID": "gcp_compute_instance_public_ip",
            "Status": "FAIL",
            "CheckTitle": "Compute Instance Public IP",
            "ServiceName": "compute",
            "Severity": "critical",
            "ResourceId": "instance-123",
            "ResourceType": "GCP::Compute::Instance",
            "Provider": "gcp",
            "AccountUID": "project-abc",
            "Region": "us-central1",
            "StatusExtended": "Compute instance instance-123 has public IP assigned",
            "Description": "Compute instances should not have public IPs",
        }
    ]
    f = tmp_path / "prowler.json"
    write_ndjson(f, findings)
    adapter = ProwlerAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].severity == "CRITICAL"  # critical normalized to CRITICAL
    assert "gcp" in items[0].tags
    assert "compute" in items[0].tags


def test_prowler_adapter_k8s_fail(tmp_path: Path):
    """Test Prowler adapter with Kubernetes FAIL finding."""
    findings = [
        {
            "CheckID": "k8s_privileged_container",
            "Status": "FAIL",
            "CheckTitle": "Privileged Container Detected",
            "ServiceName": "kubernetes",
            "Severity": "high",
            "ResourceId": "pod-nginx",
            "Provider": "kubernetes",
            "Region": "default-namespace",
            "StatusExtended": "Pod pod-nginx is running in privileged mode",
            "Description": "Containers should not run in privileged mode",
        }
    ]
    f = tmp_path / "prowler.json"
    write_ndjson(f, findings)
    adapter = ProwlerAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert "kubernetes" in items[0].tags
    assert items[0].context["provider"] == "kubernetes"


def test_prowler_adapter_pass_findings_skipped(tmp_path: Path):
    """Test Prowler adapter skips PASS findings."""
    findings = [
        {
            "CheckID": "check_pass",
            "Status": "PASS",
            "CheckTitle": "Passing Check",
            "Severity": "high",
            "ResourceId": "resource-1",
        },
        {
            "CheckID": "check_fail",
            "Status": "FAIL",
            "CheckTitle": "Failing Check",
            "Severity": "high",
            "ResourceId": "resource-2",
            "Provider": "aws",
            "ServiceName": "ec2",
        },
    ]
    f = tmp_path / "prowler.json"
    write_ndjson(f, findings)
    adapter = ProwlerAdapter()
    items = adapter.parse(f)

    # Only FAIL finding should be processed
    assert len(items) == 1
    assert items[0].ruleId == "check_fail"


def test_prowler_adapter_multiple_findings(tmp_path: Path):
    """Test Prowler adapter with multiple FAIL findings."""
    findings = [
        {
            "CheckID": "check_1",
            "Status": "FAIL",
            "CheckTitle": "Check 1",
            "Severity": "high",
            "ResourceId": "resource-1",
            "Provider": "aws",
            "ServiceName": "s3",
        },
        {
            "CheckID": "check_2",
            "Status": "FAIL",
            "CheckTitle": "Check 2",
            "Severity": "medium",
            "ResourceId": "resource-2",
            "Provider": "aws",
            "ServiceName": "ec2",
        },
        {
            "CheckID": "check_3",
            "Status": "FAIL",
            "CheckTitle": "Check 3",
            "Severity": "low",
            "ResourceId": "resource-3",
            "Provider": "azure",
            "ServiceName": "storage",
        },
    ]
    f = tmp_path / "prowler.json"
    write_ndjson(f, findings)
    adapter = ProwlerAdapter()
    items = adapter.parse(f)

    assert len(items) == 3
    assert items[0].severity == "HIGH"
    assert items[1].severity == "MEDIUM"
    assert items[2].severity == "LOW"


def test_prowler_adapter_location_fallback(tmp_path: Path):
    """Test Prowler adapter location path fallback logic."""
    findings = [
        {
            "CheckID": "check_arn",
            "Status": "FAIL",
            "CheckTitle": "Check with ARN",
            "Severity": "high",
            "ResourceId": "resource-1",
            "ResourceArn": "arn:aws:s3:::bucket-1",
            "Provider": "aws",
            "ServiceName": "s3",
        },
        {
            "CheckID": "check_id",
            "Status": "FAIL",
            "CheckTitle": "Check with ID only",
            "Severity": "high",
            "ResourceId": "resource-2",
            "Provider": "aws",
            "ServiceName": "ec2",
        },
        {
            "CheckID": "check_fallback",
            "Status": "FAIL",
            "CheckTitle": "Check with fallback",
            "Severity": "high",
            "Provider": "aws",
            "ServiceName": "iam",
        },
    ]
    f = tmp_path / "prowler.json"
    write_ndjson(f, findings)
    adapter = ProwlerAdapter()
    items = adapter.parse(f)

    assert len(items) == 3
    # First finding: ARN takes priority
    assert items[0].location["path"] == "arn:aws:s3:::bucket-1"
    # Second finding: ResourceId used
    assert items[1].location["path"] == "resource-2"
    # Third finding: Fallback to provider/service/check
    assert items[2].location["path"] == "aws/iam/check_fallback"


def test_prowler_adapter_invalid_json_line(tmp_path: Path):
    """Test Prowler adapter handles invalid JSON lines gracefully."""
    f = tmp_path / "prowler.json"
    f.parent.mkdir(parents=True, exist_ok=True)
    content = """{"CheckID": "check_1", "Status": "FAIL", "CheckTitle": "Valid", "Severity": "high", "ResourceId": "r1", "Provider": "aws", "ServiceName": "s3"}
{invalid json line}
{"CheckID": "check_2", "Status": "FAIL", "CheckTitle": "Valid", "Severity": "high", "ResourceId": "r2", "Provider": "aws", "ServiceName": "ec2"}"""
    f.write_text(content, encoding="utf-8")

    adapter = ProwlerAdapter()
    items = adapter.parse(f)

    # Should skip invalid line and process valid ones
    assert len(items) == 2
    assert items[0].ruleId == "check_1"
    assert items[1].ruleId == "check_2"


def test_prowler_adapter_empty_file(tmp_path: Path):
    """Test Prowler adapter handles empty file."""
    f = tmp_path / "prowler.json"
    f.write_text("", encoding="utf-8")
    adapter = ProwlerAdapter()
    items = adapter.parse(f)

    assert items == []


def test_prowler_adapter_compliance_enrichment(tmp_path: Path):
    """Test that Prowler findings are enriched with compliance mappings."""
    findings = [
        {
            "CheckID": "s3_bucket_encryption",
            "Status": "FAIL",
            "CheckTitle": "S3 Bucket Encryption",
            "Severity": "high",
            "ResourceId": "my-bucket",
            "Provider": "aws",
            "ServiceName": "s3",
        }
    ]
    f = tmp_path / "prowler.json"
    write_ndjson(f, findings)
    adapter = ProwlerAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Compliance field should exist (enriched by compliance_mapper)
    assert hasattr(items[0], "compliance")


class TestOcsfFormat:
    """prowler 5.x writes OCSF, whose field names share nothing with v3's.

    The adapter was written against prowler v3's flat native JSON
    (`CheckID`/`Status`/`Severity`). prowler 5.x emits `json-ocsf`: a JSON
    **array** of records keyed `status_code`/`severity`/`finding_info`/
    `resources`. Measured on prowler 5.35.0 against a Terraform+Dockerfile
    fixture: 88 records, 13 of them FAIL, which this adapter read as **zero
    findings** - a scanner that ran correctly and reported nothing.
    """

    def _ocsf_record(self, tmp_path, status="FAIL"):
        import json

        record = {
            "class_uid": 2001,
            "status_code": status,
            "severity": "High",
            "message": "Last USER command in Dockerfile should not be 'root'",
            "risk_details": "Running as root is dangerous.",
            "finding_info": {
                "uid": "prowler-iac-DS-0002-Dockerfile-1:1",
                "title": "Last USER command should not be root",
                "desc": "Ensure the last USER is not root.",
                "types": ["Infrastructure as Code"],
            },
            "resources": [
                {
                    "uid": "Dockerfile",
                    "name": "Dockerfile",
                    "type": "iac",
                    "group": {"name": "dockerfile"},
                    "data": {"details": ""},
                }
            ],
            "metadata": {"event_code": "DS-0002"},
        }
        p = tmp_path / "prowler.json"
        # write_bytes: write_text translates LF to CRLF on Windows.
        p.write_bytes(json.dumps([record]).encode("utf-8"))
        return p

    def test_ocsf_fail_record_becomes_a_finding(self, tmp_path):
        from scripts.core.adapters.prowler_adapter import ProwlerAdapter

        findings = ProwlerAdapter().parse(self._ocsf_record(tmp_path))

        assert len(findings) == 1, "OCSF records read as zero findings"
        assert findings[0].ruleId == "DS-0002"
        assert findings[0].severity == "HIGH"
        assert "Dockerfile" in str(findings[0].location.get("path", ""))

    def test_ocsf_pass_records_are_skipped(self, tmp_path):
        """PASS is the majority of prowler's output and is not a finding."""
        from scripts.core.adapters.prowler_adapter import ProwlerAdapter

        assert ProwlerAdapter().parse(self._ocsf_record(tmp_path, status="PASS")) == []


class TestProwlerDistinguishesEmptyFromUnreadable:
    """Chunk 5: prowler probes two formats, so BOTH probes must stay quiet.

    `_iter_prowler_records` tries NDJSON first and a JSON/OCSF array second.
    Each fails routinely when the *other* format is the one on disk, so both
    run with `log_errors=False` -- which left the case where **both** fail
    completely silent. A prowler output that is a proxy error page, a
    truncated write or an unrecognised shape produced 0 findings, rc=0 and
    nothing on any stream.

    The hard part is not reporting it; it is reporting it *without* firing on
    an empty result, which is prowler's most common healthy outcome.
    """

    def _warnings(self, caplog) -> list[str]:
        return [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]

    def _parse(self, tmp_path: Path, payload: bytes, caplog):
        p = tmp_path / "prowler.json"
        p.write_bytes(payload)
        with caplog.at_level(logging.WARNING):
            findings = ProwlerAdapter().parse(p)
        return findings, self._warnings(caplog)

    def test_empty_array_stays_quiet(self, tmp_path: Path, caplog) -> None:
        findings, warnings = self._parse(tmp_path, b"[]", caplog)
        assert findings == []
        assert not warnings

    def test_empty_object_stays_quiet(self, tmp_path: Path, caplog) -> None:
        findings, warnings = self._parse(tmp_path, b"{}", caplog)
        assert findings == []
        assert not warnings

    def test_array_of_empty_objects_stays_quiet(self, tmp_path: Path, caplog) -> None:
        findings, warnings = self._parse(tmp_path, b"[{},{}]", caplog)
        assert findings == []
        assert not warnings

    def test_html_error_page_is_reported(self, tmp_path: Path, caplog) -> None:
        """`curl` exits 0 on an HTTP error, so a proxy page reaching disk is a
        real failure mode -- it is why every Dockerfile download uses `-f`."""
        findings, warnings = self._parse(
            tmp_path, b"<html><body>502 Bad Gateway</body></html>", caplog
        )
        assert findings == []
        assert any("matched neither prowler format" in m for m in warnings)

    def test_literal_null_is_reported_with_the_accurate_reason(
        self, tmp_path: Path, caplog
    ) -> None:
        """A file containing `null` parsed fine -- it just holds nothing.

        `safe_load_json_file` returns its `default` on failure, so with
        `default=None` this case and a genuinely unparseable file collapse to
        the same value and get the same message. That message would then be
        false for one of them. The sentinel keeps them apart, so assert the
        *reason*, not merely that a warning happened -- asserting the generic
        half let a mutation reverting the sentinel survive.
        """
        findings, warnings = self._parse(tmp_path, b"null", caplog)
        assert findings == []
        assert any("parsed as NoneType" in m for m in warnings), warnings

    def test_unparseable_file_says_it_could_not_be_parsed(
        self, tmp_path: Path, caplog
    ) -> None:
        """The other side of the sentinel: this one genuinely did not parse."""
        findings, warnings = self._parse(tmp_path, b"{not json at all", caplog)
        assert findings == []
        assert any("could not be parsed as JSON" in m for m in warnings), warnings

    def test_non_empty_unknown_shape_is_reported(self, tmp_path: Path, caplog) -> None:
        """The case that survived the first version of this guard.

        Suppressing the warning whenever the NDJSON probe salvaged *something*
        looked reasonable and was wrong: this path is only reached once those
        records are known to carry no `CheckID`, so they are junk that gets
        discarded downstream. Measured with the suppression in place:
        `[{"totally": "unexpected"}]` gave 0 findings and 0 warnings.
        """
        findings, warnings = self._parse(
            tmp_path, b'[{"totally": "unexpected"}]', caplog
        )
        assert findings == []
        assert any("matched neither prowler format" in m for m in warnings)

    def test_truncated_ndjson_reports_the_lost_lines(
        self, tmp_path: Path, caplog
    ) -> None:
        """prowler's `log_errors=False` must not re-hide destroyed data."""
        findings, warnings = self._parse(
            tmp_path, b'{"CheckID": "a", "Status": "FAIL"}\n{"CheckI\n', caplog
        )
        assert len(findings) == 1
        assert any("1 line(s)" in m for m in warnings)


class TestProwlerReadsOcsfDeliveredAsNdjson:
    """Chunk 5: OCSF records one-per-line matched neither branch.

    The `CheckID` test does not match an OCSF record, and the JSON-array probe
    cannot parse a multi-line file at all -- so these fell through and were
    returned unconverted, then dropped downstream for having no `CheckID`.

    Measured against `origin/dev`: **0 findings**. After: 2.
    """

    PAYLOAD = (
        b'{"class_uid": 2001, "status_code": "FAIL", "severity": "High", '
        b'"finding_info": {"uid": "a", "title": "T1"}}\n'
        b'{"class_uid": 2001, "status_code": "FAIL", "severity": "High", '
        b'"finding_info": {"uid": "b", "title": "T2"}}\n'
    )

    def test_ndjson_ocsf_records_become_findings(self, tmp_path: Path) -> None:
        p = tmp_path / "prowler.json"
        p.write_bytes(self.PAYLOAD)

        findings = ProwlerAdapter().parse(p)

        assert len(findings) == 2
        # Assert they were genuinely CONVERTED, not passed through: a raw OCSF
        # record has no ruleId, so a pass-through would leave it empty.
        assert sorted(f.ruleId for f in findings) == ["a", "b"]

    def test_ndjson_ocsf_does_not_warn(self, tmp_path: Path, caplog) -> None:
        p = tmp_path / "prowler.json"
        p.write_bytes(self.PAYLOAD)

        with caplog.at_level(logging.WARNING):
            ProwlerAdapter().parse(p)

        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
