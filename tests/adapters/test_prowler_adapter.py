import json
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
