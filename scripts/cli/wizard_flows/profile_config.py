"""
Profile configuration and time estimation for the wizard.

Contains:
- PROFILES: Scan profile definitions (fast/slim/balanced/deep)
- WIZARD_TOTAL_STEPS, DIFF_WIZARD_TOTAL_STEPS: Step count constants
- TOOL_TIME_ESTIMATES: Per-tool timing estimates in seconds
- calculate_time_estimate(): Dynamic time estimation based on available tools
- format_time_range(): Human-readable time formatting

These are pure data and utility functions with no UI dependencies,
making them safe to import from any module.
"""

from __future__ import annotations

from scripts.core.tool_registry import PROFILE_TOOLS

# Profile definitions with resource estimates (v1.0.0)
# Tool lists are imported from tool_registry.py (single source of truth)
PROFILES: dict[str, dict[str, str | int | list[str]]] = {
    "fast": {
        "name": "Fast",
        "description": f"Quick scans with {len(PROFILE_TOOLS['fast'])} core tools (secrets, SAST, SCA, IaC)",
        "tools": PROFILE_TOOLS["fast"],
        "timeout": 300,
        "threads": 8,
        "est_time": "5-10 minutes",
        "use_case": "Pre-commit checks, quick validation, CI/CD gate",
    },
    "slim": {
        "name": "Slim",
        "description": f"Cloud/IaC focused scans with {len(PROFILE_TOOLS['slim'])} tools (AWS, Azure, GCP, K8s)",
        "tools": PROFILE_TOOLS["slim"],
        "timeout": 500,
        "threads": 4,
        "est_time": "12-18 minutes",
        "use_case": "Cloud infrastructure, Kubernetes, IaC security",
    },
    "balanced": {
        "name": "Balanced",
        "description": f"Production CI/CD with {len(PROFILE_TOOLS['balanced'])} tools (cloud, API, DAST, license)",
        "tools": PROFILE_TOOLS["balanced"],
        "timeout": 600,
        "threads": 4,
        "est_time": "18-25 minutes",
        "use_case": "CI/CD pipelines, regular audits, production scans",
    },
    "deep": {
        "name": "Deep",
        "description": f"Comprehensive audits with all {len(PROFILE_TOOLS['deep'])} tools (mobile, fuzzing, runtime)",
        "tools": PROFILE_TOOLS["deep"],
        "timeout": 900,
        "threads": 2,
        "est_time": "40-70 minutes",
        "use_case": "Security audits, compliance scans, pre-release validation",
        "warning": (
            "First run note: dependency-check downloads the NVD database (~2GB) "
            "which can take 30-90 minutes. Subsequent runs use cached data (2-5 min). "
            "For faster reruns, mount a persistent volume: -v dep-check-cache:/root/.dependency-check"
        ),
    },
}

# Wizard step configuration - ensures consistent "Step X/Y" display
WIZARD_TOTAL_STEPS = (
    7  # Profile, Execution, Target Type, Target Config, Advanced, Review, Execute
)
DIFF_WIZARD_TOTAL_STEPS = 5  # Mode, Directories, Filters, Format, Execute

# Empirical per-tool timing estimates in seconds (Fix 2.2 - Issue #10)
# Based on actual runs against medium-sized repos (~10k-50k LOC)
TOOL_TIME_ESTIMATES: dict[str, int] = {
    # Fast tools (< 30s)
    "trufflehog": 15,
    "semgrep": 25,
    "hadolint": 5,
    "shellcheck": 10,
    # Medium tools (30s - 2min)
    "trivy": 45,
    "grype": 40,
    "syft": 30,
    "checkov": 60,
    "bearer": 50,
    "nuclei": 90,
    "noseyparker": 45,
    "bandit": 30,
    "gosec": 45,
    # Slow tools (2min+)
    "zap": 300,  # 5 min for DAST baseline
    "horusec": 180,
    # dependency-check: First run downloads NVD database (~2GB), taking 30-90 min.
    # Subsequent runs with cached database: 2-5 min.
    # Mount volume for cache persistence: -v dep-check-data:/root/.dependency-check
    "dependency-check": 240,  # Assumes cached; first run can be 30-90 min
    "prowler": 120,
    "kubescape": 90,
    "scancode": 150,
    "cdxgen": 60,
    "akto": 180,
    "yara": 45,
    "falco": 90,
    "afl++": 120,
    "mobsf": 300,
    "lynis": 60,
    # Default for unknown tools
    "_default": 60,
}


def calculate_time_estimate(available_tools: list[str]) -> tuple[int, int]:
    """Calculate dynamic time estimate based on available tools.

    Uses TOOL_TIME_ESTIMATES with parallelization factor for best-case
    and retry buffer for worst-case estimates.

    Args:
        available_tools: List of tool names that will actually run

    Returns:
        Tuple of (min_seconds, max_seconds) estimate
    """
    total = 0
    for tool in available_tools:
        total += TOOL_TIME_ESTIMATES.get(tool, TOOL_TIME_ESTIMATES["_default"])

    # Add buffer for overhead (parallel execution reduces time, but overhead adds)
    min_time = int(total * 0.6)  # Best case with parallelization
    max_time = int(total * 1.2)  # Worst case with retries

    return min_time, max_time


def format_time_range(min_sec: int, max_sec: int) -> str:
    """Format time range as human-readable string.

    Args:
        min_sec: Minimum time in seconds
        max_sec: Maximum time in seconds

    Returns:
        Human-readable time range (e.g., "4 min - 7 min")
    """

    def fmt(s: int) -> str:
        if s < 60:
            return f"{s}s"
        elif s < 3600:
            return f"{s // 60} min"
        else:
            return f"{s // 3600}h {(s % 3600) // 60}m"

    return f"{fmt(min_sec)} - {fmt(max_sec)}"


def get_profile_warning(profile: str) -> str | None:
    """Get warning message for a profile, if any.

    Args:
        profile: Profile name (fast, slim, balanced, deep)

    Returns:
        Warning message string, or None if no warning
    """
    profile_data = PROFILES.get(profile, {})
    return profile_data.get("warning")  # type: ignore[return-value]
