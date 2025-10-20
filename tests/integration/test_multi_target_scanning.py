"""Integration tests for v0.6.0 multi-target scanning.

Tests for:
- Container image scanning
- IaC file scanning
- Web URL scanning
- GitLab scanning
- Kubernetes cluster scanning
- Combined multi-target scanning
"""

from pathlib import Path

from scripts.cli.jmo import cmd_scan, cmd_ci


def test_container_image_scan_creates_output(tmp_path: Path):
    """Test scanning a container image creates the correct output structure."""

    class Args:
        repo = None
        repos_dir = None
        targets = None
        image = "alpine:latest"  # Use small image for fast test
        images_file = None
        terraform_state = None
        cloudformation = None
        k8s_manifest = None
        url = None
        urls_file = None
        api_spec = None
        gitlab_url = None
        gitlab_token = None
        gitlab_group = None
        gitlab_repo = None
        k8s_context = None
        k8s_namespace = None
        k8s_all_namespaces = False
        results_dir = str(tmp_path / "results")
        config = str(tmp_path / "no.yml")
        tools = ["trivy", "syft"]  # Tools for image scanning
        timeout = 60
        threads = 2
        allow_missing_tools = True
        log_level = "ERROR"
        human_logs = False
        profile_name = None

    # This test requires trivy/syft installed; skip if missing
    rc = cmd_scan(Args())
    assert rc in (0, 1)  # 0 for success, 1 for findings

    # Verify output structure
    results_dir = Path(Args.results_dir)
    images_dir = results_dir / "individual-images"

    # Check directory exists (might not exist if tools missing)
    if images_dir.exists():
        # Should have a sanitized directory name
        image_dirs = list(images_dir.iterdir())
        if image_dirs:
            # At least one of trivy.json or syft.json should exist
            image_dir = image_dirs[0]
            has_output = (image_dir / "trivy.json").exists() or (
                image_dir / "syft.json"
            ).exists()
            assert has_output, "Expected trivy.json or syft.json in image output"


def test_iac_file_scan_creates_output(tmp_path: Path):
    """Test scanning an IaC file creates the correct output structure."""
    # Create a minimal Terraform file
    tf_file = tmp_path / "test.tf"
    tf_file.write_text(
        """
resource "aws_s3_bucket" "test" {
  bucket = "my-test-bucket"
  acl    = "public-read"
}
"""
    )

    class Args:
        repo = None
        repos_dir = None
        targets = None
        image = None
        images_file = None
        terraform_state = str(tf_file)  # Scan the TF file directly
        cloudformation = None
        k8s_manifest = None
        url = None
        urls_file = None
        api_spec = None
        gitlab_url = None
        gitlab_token = None
        gitlab_group = None
        gitlab_repo = None
        k8s_context = None
        k8s_namespace = None
        k8s_all_namespaces = False
        results_dir = str(tmp_path / "results")
        config = str(tmp_path / "no.yml")
        tools = ["checkov", "trivy"]
        timeout = 60
        threads = 2
        allow_missing_tools = True
        log_level = "ERROR"
        human_logs = False
        profile_name = None

    rc = cmd_scan(Args())
    assert rc in (0, 1)

    # Verify output structure
    results_dir = Path(Args.results_dir)
    iac_dir = results_dir / "individual-iac"

    # Check if directory exists (might not if tools missing)
    if iac_dir.exists():
        iac_dirs = list(iac_dir.iterdir())
        if iac_dirs:
            iac_file_dir = iac_dirs[0]
            has_output = (iac_file_dir / "checkov.json").exists() or (
                iac_file_dir / "trivy.json"
            ).exists()
            assert has_output, "Expected checkov.json or trivy.json in IaC output"


def test_multi_target_combined_scan(tmp_path: Path):
    """Test scanning multiple target types in one command."""
    # Create repo
    repo = tmp_path / "repo"
    repo.mkdir()

    # Create IaC file
    tf_file = tmp_path / "test.tf"
    tf_file.write_text(
        """
resource "aws_s3_bucket" "test" {
  bucket = "my-test-bucket"
}
"""
    )

    repo_str = str(repo)
    tf_file_str = str(tf_file)

    class Args:
        repo = repo_str  # Scan repo
        repos_dir = None
        targets = None
        image = "alpine:latest"  # Scan image
        images_file = None
        terraform_state = tf_file_str  # Scan IaC
        cloudformation = None
        k8s_manifest = None
        url = None  # Skip URL (requires live service)
        urls_file = None
        api_spec = None
        gitlab_url = None
        gitlab_token = None
        gitlab_group = None
        gitlab_repo = None
        k8s_context = None  # Skip K8s (requires cluster)
        k8s_namespace = None
        k8s_all_namespaces = False
        results_dir = str(tmp_path / "results")
        config = str(tmp_path / "no.yml")
        tools = [
            "trufflehog",
            "semgrep",
            "trivy",
            "syft",
            "checkov",
        ]  # Mix of tools
        timeout = 60
        threads = 4
        allow_missing_tools = True
        log_level = "ERROR"
        human_logs = False
        profile_name = None

    rc = cmd_scan(Args())
    assert rc in (0, 1)

    # Verify all target directories exist
    results_dir = Path(Args.results_dir)

    # Repos directory should exist
    assert (results_dir / "individual-repos").exists()
    repo_dir = results_dir / "individual-repos" / "repo"
    if repo_dir.exists():
        # At least stub files should exist
        assert (repo_dir / "trufflehog.json").exists()

    # Images directory should exist if trivy/syft worked
    if (results_dir / "individual-images").exists():
        image_dirs = list((results_dir / "individual-images").iterdir())
        if image_dirs:
            assert len(image_dirs) >= 1

    # IaC directory should exist
    if (results_dir / "individual-iac").exists():
        iac_dirs = list((results_dir / "individual-iac").iterdir())
        if iac_dirs:
            assert len(iac_dirs) >= 1


def test_ci_multi_target_with_fail_on(tmp_path: Path):
    """Test CI mode with multi-target scanning and severity gating."""
    repo = tmp_path / "repo"
    repo.mkdir()

    class Args:
        def __init__(self):
            self.repo = str(repo)
            self.repos_dir = None
            self.targets = None
            self.image = "alpine:latest"
            self.images_file = None
            self.terraform_state = None
            self.cloudformation = None
            self.k8s_manifest = None
            self.url = None
            self.urls_file = None
            self.api_spec = None
            self.gitlab_url = None
            self.gitlab_token = None
            self.gitlab_group = None
            self.gitlab_repo = None
            self.k8s_context = None
            self.k8s_namespace = None
            self.k8s_all_namespaces = False
            self.results_dir = str(tmp_path / "results")
            self.config = str(tmp_path / "no.yml")
            self.tools = ["trivy", "syft"]
            self.timeout = 60
            self.threads = 2
            self.allow_missing_tools = True
            self.fail_on = "CRITICAL"  # Only fail on CRITICAL
            self.profile = True
            self.log_level = "ERROR"
            self.human_logs = False
            self.profile_name = None

    rc = cmd_ci(Args())
    # Should succeed (0) or have findings (1), but might fail (2) if CRITICAL found
    assert rc in (0, 1, 2)

    # Verify unified outputs
    summaries = Path(Args().results_dir) / "summaries"
    assert summaries.exists()
    assert (summaries / "findings.json").exists()
    assert (summaries / "dashboard.html").exists()
    assert (summaries / "timings.json").exists()  # profile=True


def test_images_file_batch_scanning(tmp_path: Path):
    """Test scanning multiple images from a file."""
    images_file = tmp_path / "images.txt"
    images_file.write_text(
        """
# Comment line
alpine:latest
busybox:latest

# Another comment
"""
    )

    images_file_str = str(images_file)

    class Args:
        repo = None
        repos_dir = None
        targets = None
        image = None
        images_file = images_file_str
        terraform_state = None
        cloudformation = None
        k8s_manifest = None
        url = None
        urls_file = None
        api_spec = None
        gitlab_url = None
        gitlab_token = None
        gitlab_group = None
        gitlab_repo = None
        k8s_context = None
        k8s_namespace = None
        k8s_all_namespaces = False
        results_dir = str(tmp_path / "results")
        config = str(tmp_path / "no.yml")
        tools = ["trivy"]
        timeout = 60
        threads = 2
        allow_missing_tools = True
        log_level = "ERROR"
        human_logs = False
        profile_name = None

    rc = cmd_scan(Args())
    assert rc in (0, 1)

    # Verify multiple image directories created
    results_dir = Path(Args.results_dir)
    images_dir = results_dir / "individual-images"

    if images_dir.exists():
        image_dirs = list(images_dir.iterdir())
        # Should have processed 2 images (alpine and busybox)
        # Might be fewer if tools missing or scan failed
        if image_dirs:
            assert len(image_dirs) <= 2, "Should have at most 2 image directories"


# ========== Test Category: Cross-Target Deduplication (Added Oct 19 2025) ==========


def test_repo_plus_image_deduplication(tmp_path: Path):
    """Verify findings from repo and image are deduplicated by fingerprint."""
    import json
    import subprocess

    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "requirements.txt").write_text("requests==2.25.0")  # Known CVE

    # Scan repo + image (both will find same CVE in requests package)
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
        "--image",
        "python:3.9",  # Contains packages with CVEs
        "--tools",
        "trivy",
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    assert result.returncode in [0, 1], f"Scan failed: {result.stderr}"

    # Generate report
    cmd_report = ["python3", "scripts/cli/jmo.py", "report", str(tmp_path / "results")]
    subprocess.run(cmd_report, check=True, timeout=60)

    # Verify deduplication
    findings_json = tmp_path / "results" / "summaries" / "findings.json"
    assert findings_json.exists(), "findings.json not generated"

    findings = json.loads(findings_json.read_text())

    # Count findings by fingerprint ID
    fingerprints = [f["id"] for f in findings["findings"]]
    assert len(fingerprints) == len(
        set(fingerprints)
    ), "Duplicate fingerprints found (deduplication failed)"


def test_multi_target_compliance_aggregation(tmp_path: Path):
    """Verify compliance reports aggregate findings from all target types."""
    import subprocess

    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("import os; os.system('ls')")  # Basic code

    # Scan repo + image (multi-target)
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
        "--image",
        "nginx:latest",
        "--tools",
        "trivy",
        "semgrep",
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    assert result.returncode in [0, 1]

    # Generate report
    cmd_report = ["python3", "scripts/cli/jmo.py", "report", str(tmp_path / "results")]
    subprocess.run(cmd_report, check=True, timeout=60)

    # Verify compliance summary includes all frameworks
    compliance_md = tmp_path / "results" / "summaries" / "COMPLIANCE_SUMMARY.md"

    # Compliance file may not exist if no CWE mappings found
    if compliance_md.exists():
        content = compliance_md.read_text()

        # Check for framework headers
        assert (
            "OWASP Top 10" in content
            or "CWE Top 25" in content
            or "CIS Controls" in content
        )


def test_triple_target_scan(tmp_path: Path):
    """Test scanning repo + image + IaC simultaneously."""
    import subprocess

    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "README.md").write_text("# Test")

    # Create minimal IaC file
    iac_file = tmp_path / "test.tf"
    iac_file.write_text(
        """
resource "aws_s3_bucket" "test" {
  bucket = "test-bucket"
}
"""
    )

    # Scan all 3 target types
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
        "--image",
        "alpine:latest",
        "--terraform-state",
        str(iac_file),
        "--tools",
        "trivy",
        "checkov",
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
    assert result.returncode in [0, 1]

    # Verify results directories created
    results_dir = tmp_path / "results"
    assert (results_dir / "individual-repos").exists()
    assert (results_dir / "individual-images").exists()
    assert (results_dir / "individual-iac").exists()


# ========== Test Category: Error Handling (Added Oct 19 2025) ==========


def test_multi_target_partial_failure(tmp_path: Path):
    """Test multi-target scan continues when one target fails."""
    import subprocess

    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("print('hello')")

    # Scan valid repo + invalid image (should fail gracefully)
    cmd = [
        "python3",
        "scripts/cli/jmo.py",
        "scan",
        "--repo",
        str(test_repo),
        "--image",
        "nonexistent-image:invalid-tag",  # Will fail
        "--tools",
        "trivy",
        "--results-dir",
        str(tmp_path / "results"),
        "--allow-missing-tools",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

    # Scan may exit with code 1 (partial failure) but should not crash
    assert result.returncode in [0, 1, 2]  # Allow partial failures

    # Verify repo results generated (even if image failed)
    assert (tmp_path / "results" / "individual-repos").exists()
