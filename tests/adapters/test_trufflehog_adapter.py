import json
from pathlib import Path

from scripts.core.adapters.trufflehog_adapter import load_trufflehog


def write_tmp(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_trufflehog_array(tmp_path: Path):
    sample = [
        {
            "DetectorName": "AWS",
            "Verified": True,
            "SourceMetadata": {"Data": {"Filesystem": {"file": "config/aws.yaml"}}},
            "StartLine": 7,
        }
    ]
    path = write_tmp(tmp_path, "th.json", json.dumps(sample))
    out = load_trufflehog(path)
    assert len(out) == 1
    item = out[0]
    assert item["severity"] == "HIGH"
    assert item["location"]["path"] == "config/aws.yaml"
    assert item["location"]["startLine"] == 7


def test_trufflehog_ndjson_and_nested(tmp_path: Path):
    ndjson = "\n".join(
        [
            json.dumps(
                {
                    "DetectorName": "Slack",
                    "Verified": True,
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "webhooks.js"}}},
                }
            ),
            json.dumps([[{"DetectorName": "Nested", "Verified": False}]]),
        ]
    )
    path = write_tmp(tmp_path, "th.ndjson", ndjson)
    out = load_trufflehog(path)
    # Should parse 2 findings
    assert len(out) == 2
    assert any(it["ruleId"] == "Slack" for it in out)
    assert any(it["ruleId"] == "Nested" for it in out)


def test_trufflehog_single_object_and_empty(tmp_path: Path):
    single = {"DetectorName": "JWT", "Verified": True, "Line": 12}
    p1 = write_tmp(tmp_path, "single.json", json.dumps(single))
    assert len(load_trufflehog(p1)) == 1
    empty = write_tmp(tmp_path, "empty.json", "")
    assert load_trufflehog(empty) == []


def test_trufflehog_verified_vs_unverified():
    """Test that verified secrets have HIGH severity, unverified have MEDIUM."""
    sample = [
        {
            "DetectorName": "GitHub",
            "Verified": True,
            "SourceMetadata": {"Data": {"Filesystem": {"file": "config.yml"}}},
            "Raw": "ghp_verifiedtoken123",
        },
        {
            "DetectorName": "AWS",
            "Verified": False,
            "SourceMetadata": {"Data": {"Filesystem": {"file": "secrets.txt"}}},
            "Raw": "AKIAIOSFODNN7EXAMPLE",
        },
    ]
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        json.dump(sample, f)
        path = Path(f.name)

    try:
        out = load_trufflehog(path)
        assert len(out) == 2

        # Verified should be HIGH
        verified = [f for f in out if f["ruleId"] == "GitHub"][0]
        assert verified["severity"] == "HIGH"

        # Unverified should be MEDIUM
        unverified = [f for f in out if f["ruleId"] == "AWS"][0]
        assert unverified["severity"] == "MEDIUM"
    finally:
        path.unlink()


def test_trufflehog_verification_endpoints():
    """Test that verified secrets include verification metadata."""
    sample = [
        {
            "DetectorName": "GitLab",
            "Verified": True,
            "SourceMetadata": {"Data": {"Filesystem": {"file": "gitlab_token.txt"}}},
            "Raw": "glpat-verifiedtoken",
            "ExtraData": {
                "account": "testuser",
                "endpoint": "https://gitlab.com/api/v4/user",
            },
        }
    ]
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        json.dump(sample, f)
        path = Path(f.name)

    try:
        out = load_trufflehog(path)
        assert len(out) == 1

        finding = out[0]
        # Should preserve raw field with verification metadata
        assert "raw" in finding
        assert "ExtraData" in finding["raw"] or "extradata" in str(finding).lower()
    finally:
        path.unlink()


def test_trufflehog_raw_field_preservation():
    """Test that raw field includes verification metadata."""
    sample = [
        {
            "DetectorName": "AWS",
            "Verified": True,
            "SourceMetadata": {"Data": {"Filesystem": {"file": "aws_creds.env"}}},
            "Raw": "AKIAIOSFODNN7VERIFIED",
            "ExtraData": {"region": "us-east-1", "account_id": "123456789012"},
            "VerificationError": None,
        }
    ]
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        json.dump(sample, f)
        path = Path(f.name)

    try:
        out = load_trufflehog(path)
        assert len(out) == 1

        finding = out[0]
        # Raw field should be preserved as dict
        assert "raw" in finding
        assert isinstance(finding["raw"], dict)
        # Should contain original trufflehog payload
        assert "DetectorName" in finding["raw"]
        assert finding["raw"]["DetectorName"] == "AWS"
    finally:
        path.unlink()


def test_trufflehog_multiple_verification_statuses():
    """Test handling of multiple secrets with different verification statuses."""
    sample = [
        {"DetectorName": "Stripe", "Verified": True, "SourceMetadata": {"Data": {"Filesystem": {"file": "payments.py"}}}},
        {"DetectorName": "Twilio", "Verified": False, "SourceMetadata": {"Data": {"Filesystem": {"file": "sms.js"}}}},
        {"DetectorName": "SendGrid", "Verified": True, "SourceMetadata": {"Data": {"Filesystem": {"file": "email.rb"}}}},
        {"DetectorName": "Mailchimp", "Verified": False, "SourceMetadata": {"Data": {"Filesystem": {"file": "marketing.go"}}}},
    ]
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        json.dump(sample, f)
        path = Path(f.name)

    try:
        out = load_trufflehog(path)
        assert len(out) == 4

        # Count verified vs unverified
        verified_count = sum(1 for f in out if f["severity"] == "HIGH")
        unverified_count = sum(1 for f in out if f["severity"] == "MEDIUM")

        assert verified_count == 2  # Stripe and SendGrid
        assert unverified_count == 2  # Twilio and Mailchimp
    finally:
        path.unlink()
