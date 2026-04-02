"""Rule ID equivalence mapping for cross-tool deduplication.

This module provides mappings between semantically equivalent rules across
different security scanning tools. When two tools report the same issue
using different rule IDs, this mapping helps identify them as duplicates.

Example:
    Trivy reports `:latest tag used` and Hadolint reports `DL3006` for the
    same issue on the same line. This mapping recognizes them as equivalent.

Usage:
    from scripts.core.rule_equivalence import get_canonical_rule_id

    canonical = get_canonical_rule_id("hadolint", "DL3006")
    # Returns: "dockerfile-latest-tag"

Author: JMo Security
Version: 1.0.0
"""

from __future__ import annotations

# Mapping of equivalent rules across tools
# Format: {canonical_id: [(tool, rule_id), ...]}
# Canonical IDs use lowercase-with-dashes format
RULE_EQUIVALENCE: dict[str, list[tuple[str, str]]] = {
    # ===== Dockerfile Best Practices =====
    "dockerfile-latest-tag": [
        ("trivy", ":latest tag used"),
        ("trivy", "DS001"),
        ("hadolint", "DL3006"),
        ("hadolint", "DL3007"),  # Using latest is prone to errors
        ("checkov", "CKV_DOCKER_1"),
        ("checkov", "CKV_DOCKER_7"),  # Ensure base image uses a non-latest tag
    ],
    "dockerfile-no-healthcheck": [
        ("trivy", "No HEALTHCHECK defined"),
        ("trivy", "DS026"),
        ("hadolint", "DL3055"),
        ("checkov", "CKV_DOCKER_2"),
    ],
    "dockerfile-no-user": [
        ("trivy", "Image user should not be 'root'"),
        ("trivy", "DS002"),
        ("trivy", "Running as root"),
        ("hadolint", "DL3002"),
        ("checkov", "CKV_DOCKER_3"),
        ("checkov", "CKV_DOCKER_8"),  # Ensure the last USER is not root
    ],
    "dockerfile-add-instead-of-copy": [
        ("trivy", "Consider using COPY instead of ADD"),
        ("trivy", "DS005"),
        ("hadolint", "DL3010"),
        ("checkov", "CKV_DOCKER_4"),
    ],
    "dockerfile-hardcoded-secret": [
        ("trivy", "Potential secret in ENV"),
        ("trivy", "DS017"),
        ("hadolint", "DL3059"),  # Multiple consecutive RUN with secrets
        ("checkov", "CKV_DOCKER_5"),
        ("checkov", "CKV_DOCKER_11"),  # Ensure secret args are not hard-coded
    ],
    "dockerfile-sudo": [
        ("trivy", "DS011"),  # sudo detected
        ("hadolint", "DL3004"),
        ("checkov", "CKV2_DOCKER_1"),
    ],
    "dockerfile-apt-get-upgrade": [
        ("trivy", "DS016"),  # apt-get upgrade
        ("hadolint", "DL3005"),
    ],
    "dockerfile-missing-apk-no-cache": [
        ("trivy", "DS014"),  # Missing --no-cache
        ("hadolint", "DL3018"),  # Pin versions in apk add
        ("hadolint", "DL3019"),  # Use --no-cache
    ],
    "dockerfile-curl-pipe-bash": [
        ("trivy", "DS013"),  # curl pipe to bash
        ("hadolint", "DL4006"),  # Set SHELL option pipefail
        ("checkov", "CKV_DOCKER_6"),
    ],
    "dockerfile-missing-version-pin": [
        ("trivy", "DS015"),  # Missing version pin in apt-get
        ("hadolint", "DL3008"),  # Pin versions in apt-get
    ],
    # ===== Infrastructure as Code =====
    "iac-public-s3-bucket": [
        ("trivy", "Public S3 bucket"),
        ("checkov", "CKV_AWS_19"),
        ("checkov", "CKV_AWS_20"),  # S3 Block Public Access
        ("checkov", "CKV_AWS_21"),  # S3 versioning
        ("prowler", "s3_bucket_public_access"),
    ],
    "iac-unencrypted-storage": [
        ("trivy", "Unencrypted storage"),
        ("checkov", "CKV_AWS_3"),  # EBS encryption
        ("checkov", "CKV_AWS_17"),  # RDS encryption
        ("prowler", "ec2_ebs_volume_encryption"),
    ],
    "iac-security-group-open-ingress": [
        ("trivy", "Security group allows open ingress"),
        ("trivy", "DS031"),
        ("checkov", "CKV_AWS_23"),  # Security group ingress
        ("checkov", "CKV_AWS_24"),  # Security group 0.0.0.0/0
        ("checkov", "CKV_AWS_25"),  # Security group unrestricted SSH
        ("prowler", "ec2_securitygroup_allow_ingress_from_internet"),
    ],
    # ===== Kubernetes Security =====
    "k8s-privileged-container": [
        ("trivy", "Privileged container"),
        ("trivy", "KSV001"),
        ("checkov", "CKV_K8S_1"),
        ("kubescape", "C-0057"),
    ],
    "k8s-root-container": [
        ("trivy", "Container running as root"),
        ("trivy", "KSV012"),
        ("checkov", "CKV_K8S_6"),
        ("checkov", "CKV_K8S_20"),
        ("kubescape", "C-0013"),
    ],
    "k8s-host-network": [
        ("trivy", "Host network enabled"),
        ("trivy", "KSV009"),
        ("checkov", "CKV_K8S_19"),
        ("kubescape", "C-0041"),
    ],
    "k8s-no-resource-limits": [
        ("trivy", "No resource limits"),
        ("trivy", "KSV011"),
        ("checkov", "CKV_K8S_11"),
        ("checkov", "CKV_K8S_12"),
        ("checkov", "CKV_K8S_13"),
        ("kubescape", "C-0009"),
    ],
    # ===== Secret Detection =====
    "secret-aws-access-key": [
        ("trufflehog", "AWS"),
        ("trufflehog", "aws-access-token"),
        ("gitleaks", "aws-access-token"),
        ("gitleaks", "aws-secret-access-key"),
        ("semgrep", "generic.secrets.security.detected-aws-account-id"),
        ("noseyparker", "AWS Access Key ID"),
    ],
    "secret-github-token": [
        ("trufflehog", "Github"),
        ("trufflehog", "github-pat"),
        ("gitleaks", "github-pat"),
        ("gitleaks", "github-token"),
        ("semgrep", "generic.secrets.security.detected-github-pat"),
        ("noseyparker", "GitHub Personal Access Token"),
    ],
    "secret-private-key": [
        ("trufflehog", "PrivateKey"),
        ("gitleaks", "private-key"),
        ("semgrep", "generic.secrets.security.detected-private-key"),
        ("noseyparker", "PEM-Encoded Private Key"),
    ],
    # ===== Code Security =====
    "code-sql-injection": [
        ("semgrep", "python.django.security.injection.sql.sql-injection"),
        ("semgrep", "python.sqlalchemy.security.sqlalchemy-execute-raw-query"),
        ("bandit", "B608"),
        ("bearer", "python_sql_injection"),
    ],
    "code-xss": [
        ("semgrep", "python.django.security.injection.reflected-data-httpresponse"),
        ("semgrep", "javascript.browser.security.dom-based-xss"),
        ("bandit", "B320"),
        ("bearer", "javascript_xss"),
    ],
    "code-command-injection": [
        ("semgrep", "python.lang.security.audit.dangerous-subprocess-use"),
        ("semgrep", "python.lang.security.audit.subprocess-shell-true"),
        ("bandit", "B602"),
        ("bandit", "B603"),
        ("bearer", "python_os_command_injection"),
    ],
    "code-path-traversal": [
        ("semgrep", "python.lang.security.audit.path-traversal"),
        ("bandit", "B310"),
        ("bearer", "python_path_traversal"),
    ],
    "code-hardcoded-password": [
        ("semgrep", "python.lang.security.audit.hardcoded-password"),
        ("semgrep", "generic.secrets.security.hardcoded-password"),
        ("bandit", "B105"),
        ("bandit", "B106"),
        ("trufflehog", "Password"),
        ("gitleaks", "generic-password"),
    ],
}

# Reverse mapping for fast lookup: (tool, rule_id) -> canonical_id
_REVERSE_MAP: dict[tuple[str, str], str] = {}


def _build_reverse_map() -> None:
    """Build reverse mapping for O(1) lookups."""
    global _REVERSE_MAP
    if _REVERSE_MAP:
        return
    for canonical_id, mappings in RULE_EQUIVALENCE.items():
        for tool, rule_id in mappings:
            # Normalize tool name to lowercase
            _REVERSE_MAP[(tool.lower(), rule_id)] = canonical_id
            # Also add lowercase rule_id for case-insensitive matching
            _REVERSE_MAP[(tool.lower(), rule_id.lower())] = canonical_id


def get_canonical_rule_id(tool: str, rule_id: str) -> str | None:
    """Get canonical rule ID for equivalence matching.

    Args:
        tool: Name of the security tool (e.g., "trivy", "hadolint")
        rule_id: Rule ID from the tool (e.g., "DL3006", ":latest tag used")

    Returns:
        Canonical rule ID if found in equivalence mapping, None otherwise.

    Example:
        >>> get_canonical_rule_id("hadolint", "DL3006")
        "dockerfile-latest-tag"
        >>> get_canonical_rule_id("trivy", ":latest tag used")
        "dockerfile-latest-tag"
        >>> get_canonical_rule_id("unknown", "RULE123")
        None

    """
    # Handle empty inputs
    if not tool or not rule_id:
        return None

    _build_reverse_map()

    # Try exact match first
    key = (tool.lower(), rule_id)
    if key in _REVERSE_MAP:
        return _REVERSE_MAP[key]

    # Try case-insensitive rule_id match
    key_lower = (tool.lower(), rule_id.lower())
    if key_lower in _REVERSE_MAP:
        return _REVERSE_MAP[key_lower]

    # Try substring matching for messages that may vary
    # (e.g., ":latest tag used" might appear as "Using :latest tag is not recommended")
    # Require minimum length to avoid matching everything
    tool_lower = tool.lower()
    rule_id_lower = rule_id.lower()
    if len(rule_id_lower) >= 3:  # Minimum 3 chars for substring matching
        for (mapped_tool, mapped_rule), canonical in _REVERSE_MAP.items():
            if mapped_tool == tool_lower:
                # Check if rule_id contains mapped_rule or vice versa
                if mapped_rule in rule_id_lower or rule_id_lower in mapped_rule:
                    return canonical

    return None


def are_rules_equivalent(
    tool1: str, rule1: str, tool2: str, rule2: str
) -> tuple[bool, str | None]:
    """Check if two rules from different tools are semantically equivalent.

    Args:
        tool1: First tool name
        rule1: First rule ID
        tool2: Second tool name
        rule2: Second rule ID

    Returns:
        Tuple of (is_equivalent, canonical_id).
        If equivalent, canonical_id is the shared identifier.
        If not equivalent, canonical_id is None.

    Example:
        >>> are_rules_equivalent("hadolint", "DL3006", "trivy", ":latest tag used")
        (True, "dockerfile-latest-tag")

    """
    canonical1 = get_canonical_rule_id(tool1, rule1)
    canonical2 = get_canonical_rule_id(tool2, rule2)

    if canonical1 and canonical2 and canonical1 == canonical2:
        return (True, canonical1)

    return (False, None)
