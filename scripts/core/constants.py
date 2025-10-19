"""
Centralized Constants for JMo Security

This module contains all magic numbers, hardcoded values, and configuration
constants used throughout the JMo Security codebase.

Benefits:
- Single source of truth for all constants
- Eliminates magic numbers scattered across code
- Easier to update values (change once, apply everywhere)
- Better code documentation through named constants
"""

# ============================================================================
# Schema Versions
# ============================================================================
# CommonFinding schema version (current)
SCHEMA_VERSION_CURRENT = "1.2.0"

# Historical schema versions (for backward compatibility)
SCHEMA_VERSION_V1_0 = "1.0.0"
SCHEMA_VERSION_V1_1 = "1.1.0"

# ============================================================================
# Timeouts (seconds)
# ============================================================================
# Default timeout for most tools
TIMEOUT_DEFAULT = 600  # 10 minutes

# Profile-specific timeouts
TIMEOUT_FAST = 300  # 5 minutes (fast profile)
TIMEOUT_DEEP = 900  # 15 minutes (deep profile)

# Tool-specific timeouts (tools that need more time)
TIMEOUT_NOSEYPARKER = 1200  # 20 minutes
TIMEOUT_AFLPLUSPLUS = 1800  # 30 minutes
TIMEOUT_TRIVY = 1200  # 20 minutes

# ============================================================================
# Threading/Concurrency
# ============================================================================
# Profile-specific thread counts
THREADS_FAST = 8  # Fast profile: maximum parallelism
THREADS_BALANCED = 4  # Balanced profile: moderate parallelism
THREADS_DEEP = 2  # Deep profile: limited parallelism

# Thread limits
THREADS_MIN = 1
THREADS_MAX = 128

# ============================================================================
# Retry Configuration
# ============================================================================
# Retry counts for flaky tools
RETRIES_DEFAULT = 0
RETRIES_DEEP_PROFILE = 1

# Retry backoff (seconds)
RETRY_BACKOFF_MIN = 1.0
RETRY_BACKOFF_MAX = 3.0

# ============================================================================
# Tool Names
# ============================================================================
# Secrets detection
TOOL_TRUFFLEHOG = "trufflehog"
TOOL_NOSEYPARKER = "noseyparker"
TOOL_GITLEAKS = "gitleaks"

# Static Analysis (SAST)
TOOL_SEMGREP = "semgrep"
TOOL_BANDIT = "bandit"

# Vulnerability Scanning
TOOL_TRIVY = "trivy"
TOOL_OSV_SCANNER = "osv-scanner"

# SBOM Generation
TOOL_SYFT = "syft"

# IaC Scanning
TOOL_CHECKOV = "checkov"
TOOL_TFSEC = "tfsec"

# Container Scanning
TOOL_HADOLINT = "hadolint"

# DAST/Web Scanning
TOOL_ZAP = "zap"

# Runtime Security
TOOL_FALCO = "falco"

# Fuzzing
TOOL_AFLPLUSPLUS = "afl++"

# All tools (for validation)
ALL_TOOLS = [
    TOOL_TRUFFLEHOG,
    TOOL_NOSEYPARKER,
    TOOL_GITLEAKS,
    TOOL_SEMGREP,
    TOOL_BANDIT,
    TOOL_TRIVY,
    TOOL_OSV_SCANNER,
    TOOL_SYFT,
    TOOL_CHECKOV,
    TOOL_TFSEC,
    TOOL_HADOLINT,
    TOOL_ZAP,
    TOOL_FALCO,
    TOOL_AFLPLUSPLUS,
]

# ============================================================================
# Severity Levels
# ============================================================================
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

# Severity order (highest to lowest)
SEVERITY_ORDER = [
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
]

# ============================================================================
# Profile Names
# ============================================================================
PROFILE_FAST = "fast"
PROFILE_BALANCED = "balanced"
PROFILE_DEEP = "deep"

# Profile configurations
PROFILE_FAST_TOOLS = [TOOL_TRUFFLEHOG, TOOL_SEMGREP, TOOL_TRIVY]
PROFILE_BALANCED_TOOLS = [
    TOOL_TRUFFLEHOG,
    TOOL_SEMGREP,
    TOOL_SYFT,
    TOOL_TRIVY,
    TOOL_CHECKOV,
    TOOL_HADOLINT,
    TOOL_ZAP,
]
PROFILE_DEEP_TOOLS = [
    TOOL_TRUFFLEHOG,
    TOOL_NOSEYPARKER,
    TOOL_SEMGREP,
    TOOL_BANDIT,
    TOOL_SYFT,
    TOOL_TRIVY,
    TOOL_CHECKOV,
    TOOL_HADOLINT,
    TOOL_ZAP,
    TOOL_FALCO,
    TOOL_AFLPLUSPLUS,
]

# ============================================================================
# Output Formats
# ============================================================================
OUTPUT_JSON = "json"
OUTPUT_MARKDOWN = "md"
OUTPUT_YAML = "yaml"
OUTPUT_HTML = "html"
OUTPUT_SARIF = "sarif"

ALL_OUTPUT_FORMATS = [
    OUTPUT_JSON,
    OUTPUT_MARKDOWN,
    OUTPUT_YAML,
    OUTPUT_HTML,
    OUTPUT_SARIF,
]

# ============================================================================
# Directory Structure
# ============================================================================
# Results directory structure
DIR_INDIVIDUAL_REPOS = "individual-repos"
DIR_INDIVIDUAL_IMAGES = "individual-images"
DIR_INDIVIDUAL_IAC = "individual-iac"
DIR_INDIVIDUAL_WEB = "individual-web"
DIR_INDIVIDUAL_GITLAB = "individual-gitlab"
DIR_INDIVIDUAL_K8S = "individual-k8s"
DIR_SUMMARIES = "summaries"

ALL_TARGET_DIRS = [
    DIR_INDIVIDUAL_REPOS,
    DIR_INDIVIDUAL_IMAGES,
    DIR_INDIVIDUAL_IAC,
    DIR_INDIVIDUAL_WEB,
    DIR_INDIVIDUAL_GITLAB,
    DIR_INDIVIDUAL_K8S,
]

# ============================================================================
# Compliance Frameworks
# ============================================================================
COMPLIANCE_OWASP_TOP10 = "owaspTop10_2021"
COMPLIANCE_CWE_TOP25 = "cweTop25_2024"
COMPLIANCE_CIS_CONTROLS = "cisControlsV8_1"
COMPLIANCE_NIST_CSF = "nistCsf2_0"
COMPLIANCE_PCI_DSS = "pciDss4_0"
COMPLIANCE_MITRE_ATTACK = "mitreAttack"

ALL_COMPLIANCE_FRAMEWORKS = [
    COMPLIANCE_OWASP_TOP10,
    COMPLIANCE_CWE_TOP25,
    COMPLIANCE_CIS_CONTROLS,
    COMPLIANCE_NIST_CSF,
    COMPLIANCE_PCI_DSS,
    COMPLIANCE_MITRE_ATTACK,
]

# ============================================================================
# Exit Codes
# ============================================================================
EXIT_SUCCESS = 0
EXIT_GENERAL_ERROR = 1
EXIT_CONFIG_ERROR = 2
EXIT_THRESHOLD_EXCEEDED = 1  # Used by --fail-on

# ============================================================================
# Profiling
# ============================================================================
PROFILING_MIN_THREADS = 2
PROFILING_MAX_THREADS = 16
PROFILING_DEFAULT_THREADS = 4

# ============================================================================
# Logging
# ============================================================================
LOG_LEVEL_DEBUG = "DEBUG"
LOG_LEVEL_INFO = "INFO"
LOG_LEVEL_WARN = "WARN"
LOG_LEVEL_ERROR = "ERROR"

ALL_LOG_LEVELS = [
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
]

# ============================================================================
# Return Codes (Tool Exit Codes)
# ============================================================================
# Common return codes for security tools
RC_OK = 0  # Clean/no findings
RC_FINDINGS = 1  # Findings detected
RC_ERROR = 2  # Tool error
RC_TIMEOUT = 124  # Timeout (from timeout command)

# Tool-specific return codes
RC_SEMGREP_OK = (0, 1, 2)  # Semgrep treats 0/1/2 as success
RC_TRIVY_OK = (0, 1)  # Trivy treats 0/1 as success
RC_CHECKOV_OK = (0, 1)  # Checkov treats 0/1 as success
RC_ZAP_OK = (0, 1, 2)  # ZAP treats 0/1/2 as success

# ============================================================================
# Fingerprinting
# ============================================================================
FINGERPRINT_MESSAGE_MAX_LENGTH = 120  # First 120 chars of message
FINGERPRINT_HASH_LENGTH = 16  # 16-char hex fingerprint
