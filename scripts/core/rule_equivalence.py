"""Rule ID equivalence mapping for cross-tool deduplication.

This module provides mappings between semantically equivalent rules across
different security scanning tools. When two tools report the same issue
using different rule IDs, this mapping helps identify them as duplicates.

Example:
    Trivy reports `DS-0001` (`':latest' tag used`) and Hadolint reports
    `DL3006` for the same issue on the same line. This mapping recognizes them
    as equivalent.

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
#
# A match here returns 1.0 from `dedup_enhanced.metadata_similarity` -- the
# strongest possible signal -- so a wrong entry does not merely fail to help,
# it actively drives clustering. Two different controls listed together get
# merged into one finding, and the loser is only visible inside
# `context.duplicates`.
#
# COMMENT CONVENTION (#846). The table mixes two different relationships, and
# not marking which is which is how a wrong entry survived: the comment on
# `CKV_AWS_17` said "RDS encryption" while the rule checkov actually ships
# under that id is "Ensure all data stored in RDS is not publicly accessible".
#
#   `# alias:` one tool reporting one check under more than one id (none
#             now: hadolint DL3018/DL3019 were listed as one, and are "Pin
#             versions in apk add" and "Use the `--no-cache` switch")
#   `# cross:` different tools reporting the SAME issue -- what the table is
#             for, and the only relationship that should span tool names
#
# When adding an entry, quote the tool's own rule description rather than
# paraphrasing it. Three groups were measured wrong in #846 and every one was
# caught by comparing against `check_name` from a real scan.
#
# TRIVY KEYS (#1221) are the `ID` trivy 0.74.0 prints, each commented with the
# `Title` it prints beside it, both read from its own output
# (tests/fixtures/samples/trivy/misconfig-0.74.json) -- one id per group, the
# check the group names. The adapter used to make a misconfiguration's Title
# its rule id, so this table keyed trivy by Titles and by old ids (`DS001`).
# On 0.74.0's output no old id matched anything and three Titles did, and
# eight old ids named another check entirely (`DS031` sat here as "open
# ingress": it is the Dockerfile secrets check). Where 0.74.0 has no check for
# a group, the trivy key was dropped, not translated: `DS013` is "'RUN cd ...'
# to change directory", `DS015` is "'yum clean all' missing", and 0.74.0 ships
# `DS-0024` ("'apt-get dist-upgrade' used") deprecated, so it never fires. That
# left `dockerfile-apt-get-upgrade` (hadolint DL3005) and
# `dockerfile-missing-version-pin` (hadolint DL3008) with one tool each, and a
# one-tool group cannot deduplicate across tools, so both groups are gone.
#
# Live trivy keys made their partners live too, and eleven of those named a
# different check, so a correct trivy id could merge with the wrong control
# (the task review scored KSV-0012 "Runs as root user" against checkov's
# allowPrivilegeEscalation check at 0.778, over the 0.65 threshold, when the
# two share a line range). Every partner below was measured on
# the same three files: hadolint 2.14.0 and checkov 3.3.16 run on them, plus
# `checkov --list`; each comment quotes the tool's own words. A partner naming
# another check moved to the group of the trivy id that names it, or went. The
# guards are in tests/unit/test_rule_equivalence_table.py.
RULE_EQUIVALENCE: dict[str, list[tuple[str, str]]] = {
    # ===== Dockerfile Best Practices =====
    "dockerfile-latest-tag": [
        ("trivy", "DS-0001"),  # "':latest' tag used" (an untagged FROM too)
        ("hadolint", "DL3006"),  # "Always tag the version of an image explicitly"
        ("hadolint", "DL3007"),  # "Using latest is prone to errors if the image..."
        ("checkov", "CKV_DOCKER_7"),  # "Ensure the base image uses a non latest..."
    ],
    "dockerfile-no-healthcheck": [
        ("trivy", "DS-0026"),  # "No HEALTHCHECK defined"
        # "`HEALTHCHECK` instruction missing." -- off unless enabled. DL3055,
        # listed here until #1221, is "Label `commit` is not a valid git hash."
        ("hadolint", "DL3057"),
        # "Ensure that HEALTHCHECK instructions have been added to container images"
        ("checkov", "CKV_DOCKER_2"),
    ],
    "dockerfile-no-user": [
        ("trivy", "DS-0002"),  # "Image user should not be 'root'"
        ("hadolint", "DL3002"),  # "Last USER should not be root"
        ("checkov", "CKV_DOCKER_3"),  # "Ensure that a user for the container..."
        ("checkov", "CKV_DOCKER_8"),  # "Ensure the last USER is not root"
    ],
    "dockerfile-add-instead-of-copy": [
        ("trivy", "DS-0005"),  # "ADD instead of COPY"
        # "Use COPY instead of ADD for files and folders". DL3010, listed here
        # until #1221, is its opposite: "Use `ADD` for extracting archives".
        ("hadolint", "DL3020"),
        ("checkov", "CKV_DOCKER_4"),  # "Ensure that COPY is used instead of ADD..."
    ],
    "dockerfile-sudo": [
        ("trivy", "DS-0010"),  # "RUN using 'sudo'"
        ("hadolint", "DL3004"),  # "Do not use sudo as it leads to unpredictable..."
        ("checkov", "CKV2_DOCKER_1"),  # "Ensure that sudo isn't used"
    ],
    "dockerfile-missing-apk-no-cache": [
        ("trivy", "DS-0025"),  # "'apk add' is missing '--no-cache'"
        ("hadolint", "DL3019"),  # "Use the `--no-cache` switch to avoid ..."
    ],
    "dockerfile-update-alone": [
        ("trivy", "DS-0017"),  # "'RUN <package-manager> update' instruction alone"
        # "Ensure update instructions are not use alone in the Dockerfile". It
        # counts update RUNs against install RUNs over the whole file, so it
        # did not fire beside DS-0017 on the recorded Dockerfile.
        ("checkov", "CKV_DOCKER_5"),
    ],
    "dockerfile-duplicate-stage-alias": [
        ("trivy", "DS-0012"),  # "Duplicate aliases defined in different FROMs"
        ("hadolint", "DL3024"),  # "FROM aliases (stage names) must be unique"
        # "Ensure From Alias are unique for multistage builds." (matches a
        # lower-case ` as ` only)
        ("checkov", "CKV_DOCKER_11"),
    ],
    "dockerfile-port-22-exposed": [
        ("trivy", "DS-0004"),  # "Port 22 exposed"
        ("checkov", "CKV_DOCKER_1"),  # "Ensure port 22 is not exposed"
    ],
    "dockerfile-deprecated-maintainer": [
        ("trivy", "DS-0022"),  # "Deprecated MAINTAINER used"
        ("hadolint", "DL4000"),  # "MAINTAINER is deprecated"
        # "Ensure that LABEL maintainer is used instead of MAINTAINER (deprecated)"
        ("checkov", "CKV_DOCKER_6"),
    ],
    # REMOVED (#1221): `dockerfile-hardcoded-secret` held trivy DS-0031
    # ("Secrets passed via `build-args` or envs or copied secret files") with
    # hadolint DL3059 ("Multiple consecutive `RUN` instructions"), checkov
    # CKV_DOCKER_5 (update alone) and CKV_DOCKER_11 (stage aliases); neither
    # tool has a secrets-in-ENV check. `dockerfile-curl-pipe-bash` held hadolint
    # DL4006 (pipefail) with checkov CKV_DOCKER_6 (MAINTAINER), which moved.
    # ===== Infrastructure as Code =====
    "iac-public-s3-bucket": [
        ("trivy", "AWS-0092"),  # "S3 Buckets not publicly accessible through ACL."
        # cross: "S3 Bucket has an ACL defined which allows public READ access."
        ("checkov", "CKV_AWS_20"),
        # REMOVED (#846), measured against checkov's own `check_name`:
        #   CKV_AWS_21 "Ensure all data stored in the S3 bucket have versioning
        #              enabled" -- versioning, not public access
        #   CKV_AWS_19 "...securely encrypted at rest" -- encryption, not
        #              public access
        # Neither has a cross-tool counterpart here, so they are dropped rather
        # than relocated. A group is for one issue reported by several tools.
    ],
    "iac-unencrypted-storage": [
        ("trivy", "AWS-0026"),  # "EBS volumes must be encrypted"
        ("checkov", "CKV_AWS_3"),  # cross: EBS volume encryption
        # REMOVED (#846): CKV_AWS_17. Its inline comment here said "RDS
        # encryption"; checkov's own `check_name`, measured on a real scan, is
        # "Ensure all data stored in RDS is not publicly accessible". The
        # comment described a different rule than the one listed, which is how
        # a public-access control ended up in an encryption group.
    ],
    "iac-security-group-open-ingress": [
        # "Security groups should not allow unrestricted ingress to SSH or RDP
        # from any IP address."
        ("trivy", "AWS-0107"),
        # cross: both are "ingress from 0.0.0.0:0", to port 22 and 3389
        ("checkov", "CKV_AWS_24"),
        ("checkov", "CKV_AWS_25"),
        # REMOVED (#846): CKV_AWS_23 "Ensure every security group and rule has
        # a description" -- a documentation control, not an ingress finding.
        # Measured from checkov's own `check_name`.
    ],
    # ===== Kubernetes Security =====
    # checkov's "Do not admit ..." checks (CKV_K8S_1 to _7) read only a
    # PodSecurityPolicy; the pod-level checks are the ones that fire on a
    # workload, beside trivy's.
    "k8s-privileged-container": [
        # "Privileged"; the old key KSV001 is "Can elevate its own privileges"
        ("trivy", "KSV-0017"),
        ("checkov", "CKV_K8S_16"),  # "Container should not be privileged"
    ],
    "k8s-privilege-escalation": [
        ("trivy", "KSV-0001"),  # "Can elevate its own privileges"
        # "Containers should not run with allowPrivilegeEscalation"
        ("checkov", "CKV_K8S_20"),
    ],
    "k8s-host-pid": [
        ("trivy", "KSV-0010"),  # "Access to host PID"
        # "Containers should not share the host process ID namespace"
        ("checkov", "CKV_K8S_17"),
        # "Do not admit containers wishing to share the host process ID
        # namespace" (a PodSecurityPolicy); listed as privileged until #1221
        ("checkov", "CKV_K8S_1"),
    ],
    "k8s-root-container": [
        ("trivy", "KSV-0012"),  # "Runs as root user"
        ("checkov", "CKV_K8S_23"),  # "Minimize the admission of root containers"
        ("checkov", "CKV_K8S_6"),  # "Do not admit root containers" (a PSP)
    ],
    "k8s-host-network": [
        ("trivy", "KSV-0009"),  # "Access to host network"
        # "Containers should not share the host network namespace"
        ("checkov", "CKV_K8S_19"),
    ],
    "k8s-no-cpu-limits": [
        ("trivy", "KSV-0011"),  # "CPU not limited"
        ("checkov", "CKV_K8S_11"),  # "CPU limits should be set"
    ],
    "k8s-no-memory-limits": [
        ("trivy", "KSV-0018"),  # "Memory not limited"
        ("checkov", "CKV_K8S_13"),  # "Memory limits should be set"
    ],
    "k8s-no-memory-requests": [
        ("trivy", "KSV-0016"),  # "Memory requests not specified"
        ("checkov", "CKV_K8S_12"),  # "Memory requests should be set"
    ],
    # ===== Secret Detection =====
    # GITLEAKS KEYS (#1328) are the `id` gitleaks 8.30.1's default config
    # prints (`config/gitleaks.toml` at tag v8.30.1), each commented with the
    # `description` it prints beside it, read from the tool's own file -- the
    # same discipline the trivy keys above use. `aws-access-token` and
    # `github-pat` used to sit here under the tool name `trufflehog`: both are
    # gitleaks ids, so neither could ever match a real trufflehog finding
    # (trufflehog's own detectors for the same two secrets are named `AWS` and
    # `Github`, both already listed below and unaffected by this move).
    "secret-aws-access-key": [
        ("trufflehog", "AWS"),
        # "Identified a pattern that may indicate AWS credentials, risking
        # unauthorized cloud resource access and data breaches on AWS
        # platforms."
        ("gitleaks", "aws-access-token"),
        ("semgrep", "generic.secrets.security.detected-aws-account-id"),
    ],
    "secret-github-token": [
        ("trufflehog", "Github"),
        # "Uncovered a GitHub Personal Access Token, potentially leading to
        # unauthorized repository access and sensitive content exposure."
        ("gitleaks", "github-pat"),
        ("semgrep", "generic.secrets.security.detected-github-pat"),
    ],
    "secret-private-key": [
        ("trufflehog", "PrivateKey"),
        # "Identified a Private Key, which may compromise cryptographic
        # security and sensitive data encryption."
        ("gitleaks", "private-key"),
        ("semgrep", "generic.secrets.security.detected-private-key"),
    ],
    "secret-jwt": [
        ("trufflehog", "JWT"),
        # "Uncovered a JSON Web Token, which may lead to unauthorized access
        # to web applications and sensitive user data."
        ("gitleaks", "jwt"),
        # "Detected a Base64-encoded JSON Web Token, posing a risk of
        # exposing encoded authentication and data exchange information."
        # Fix-round-1 (#1328): a JWT wrapped in an extra base64 layer is
        # still the same secret class, and gitleaks' own regex for it is
        # narrow and structural (a fixed `ZXlK...` prefix decoding to the
        # JWT header's `eyJ`), not a catch-all like `generic-api-key` below
        # -- so, unlike that one, mapping it here does not trade a real
        # pairing for a wide blast radius. Listed explicitly, not left to
        # the substring fallback (removed for gitleaks just below): before
        # this fix-round it resolved to `secret-jwt` anyway, coincidentally,
        # by sharing gitleaks' `jwt` as a `-`-delimited prefix.
        ("gitleaks", "jwt-base64"),
    ],
    # `generic-api-key` ("Detected a Generic API Key...") is deliberately NOT
    # mapped anywhere. Measured on juice-shop `1618a611`, gitleaks reports
    # BOTH `jwt` and `generic-api-key` for the one secret at
    # `test/api/user.test.ts:280` -- but a cluster holds at most one finding
    # per tool (`FindingCluster.can_accept`), so gitleaks' `jwt` and its own
    # `generic-api-key` can never join the same cluster regardless of what
    # this table says: adding `generic-api-key` here would be inert for that
    # pairing. It would not be inert everywhere else -- `generic-api-key`
    # fires 54 times on that one repo alone, on secrets that have nothing to
    # do with a JWT, and location similarity keys on line only (not column),
    # so mapping it into `secret-jwt` risks merging two distinct secrets that
    # only happen to share a line elsewhere (the shape #1242 and the
    # `oauth.component.spec.ts:91` fixture below both guard against).
    # ===== Code Security =====
    "code-hardcoded-password": [
        ("semgrep", "python.lang.security.audit.hardcoded-password"),
        ("semgrep", "generic.secrets.security.hardcoded-password"),
        ("trufflehog", "Password"),
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
        rule_id: Rule ID from the tool (e.g., "DL3006", "DS-0001")

    Returns:
        Canonical rule ID if found in equivalence mapping, None otherwise.

    Example:
        >>> get_canonical_rule_id("hadolint", "DL3006")
        "dockerfile-latest-tag"
        >>> get_canonical_rule_id("trivy", "DS-0001")
        "dockerfile-latest-tag"
        >>> get_canonical_rule_id("unknown", "RULE123")
        None

    """
    # Handle empty inputs
    if not tool or not rule_id:
        return None

    _build_reverse_map()
    tool_lower = tool.lower()
    rule_id_lower = rule_id.lower()

    # Try exact match first
    key = (tool_lower, rule_id)
    if key in _REVERSE_MAP:
        return _REVERSE_MAP[key]

    # Try case-insensitive rule_id match
    key_lower = (tool_lower, rule_id_lower)
    if key_lower in _REVERSE_MAP:
        return _REVERSE_MAP[key_lower]

    # gitleaks ids are exact-match only -- no substring fallback (fix-round-1,
    # #1328). gitleaks 8.30.1 ships ~222 short, hyphen-delimited default-config
    # ids that share prefixes by design (`aws-access-token` /
    # `yandex-aws-access-token`; `jwt` / `jwt-base64`), unlike the aliasing the
    # fallback below exists for (trivy's `AVD-`-prefixed alias ids, semgrep's
    # dotted-suffix registry ids). Measured against all 222:
    # `yandex-aws-access-token` (a Yandex Cloud key, not AWS) resolved to
    # `secret-aws-access-key` and `jwt-base64` to `secret-jwt` purely because
    # each is a `-`-delimited prefix of an id this table lists -- the exact
    # #1242 shape (two different secrets, one line) this table exists to
    # avoid, except reachable cross-tool instead of within one tool. Every
    # gitleaks id this table intends to match is listed exactly (`jwt-base64`
    # included, above); nothing else should resolve.
    if tool_lower == "gitleaks":
        return None

    # Try substring matching for rule IDs that carry a suffix or vary in wording
    # (e.g. semgrep reports `...subprocess-shell-true.subprocess-shell-true` for
    # the rule mapped here as `...subprocess-shell-true`).
    # Require minimum length to avoid matching everything
    if len(rule_id_lower) >= 3:  # Minimum 3 chars for substring matching
        for (mapped_tool, mapped_rule), canonical in _REVERSE_MAP.items():
            if mapped_tool == tool_lower:
                # Check if rule_id contains mapped_rule or vice versa
                if _contains_on_boundary(rule_id_lower, mapped_rule) or (
                    _contains_on_boundary(mapped_rule, rule_id_lower)
                ):
                    return canonical

    return None


def _contains_on_boundary(haystack: str, needle: str) -> bool:
    """True if `needle` occurs in `haystack` delimited by non-alphanumerics.

    Plain containment is wrong for structured rule IDs, because their trailing
    number makes every short ID a prefix of longer ones. Measured against the
    real table: ``ckv_k8s_1`` ("privileged container") matched ``CKV_K8S_10``
    and ``CKV_K8S_14`` through ``CKV_K8S_18``, and ``ckv_aws_3`` ("EBS
    encryption") matched every ``CKV_AWS_3xx`` -- so unrelated checkov rules
    resolved to one canonical ID and scored a perfect metadata match against
    each other.

    Requiring the match to start and end on a boundary keeps the case the
    fallback exists for, where the separator is a real delimiter:

        >>> _contains_on_boundary("a.b.rule-x.rule-x", "a.b.rule-x")   # '.' follows
        True
        >>> _contains_on_boundary("ckv_k8s_14", "ckv_k8s_1")           # '4' follows
        False
    """
    if not needle or not haystack:
        return False

    start = haystack.find(needle)
    while start != -1:
        before_ok = start == 0 or not haystack[start - 1].isalnum()
        end = start + len(needle)
        after_ok = end == len(haystack) or not haystack[end].isalnum()
        if before_ok and after_ok:
            return True
        start = haystack.find(needle, start + 1)

    return False


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
        >>> are_rules_equivalent("hadolint", "DL3006", "trivy", "DS-0001")
        (True, "dockerfile-latest-tag")

    """
    canonical1 = get_canonical_rule_id(tool1, rule1)
    canonical2 = get_canonical_rule_id(tool2, rule2)

    if canonical1 and canonical2 and canonical1 == canonical2:
        return (True, canonical1)

    return (False, None)
