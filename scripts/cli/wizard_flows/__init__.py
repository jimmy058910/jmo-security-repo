"""Wizard flows module - Interactive security scanning workflows.

This module provides the building blocks for JMo Security's interactive
wizard system, including:

- Configuration models (TargetConfig, WizardConfig)
- Profile definitions and time estimation
- UI helpers for cross-platform terminal output
- Tool checking and installation
- Trend analysis workflows
- Diff comparison workflows
- Scan type flows (repo, stack, CI/CD, deployment, dependency)
- Validators for paths, URLs, and targets
- Target configurators for different scan types
- Command builder for secure subprocess execution

Public API:
    Configuration:
        - TargetConfig: Scan target configuration dataclass
        - WizardConfig: Wizard session configuration dataclass
        - PROFILES: Profile definitions dict
        - TOOL_TIME_ESTIMATES: Per-tool time estimates

    UI Helpers:
        - safe_print: Unicode-safe printing
        - prompt_text: Text input with validation
        - prompt_choice: Multiple choice selection
        - select_mode: Mode selection with numbered display

    Tool Management:
        - check_tools_for_profile: Pre-flight tool checking
        - check_policy_tools: OPA availability check
        - install_opa_tool: OPA installation helper

    Validators:
        - validate_path: Path validation
        - validate_url: URL validation
        - detect_iac_type: IaC type detection
        - validate_k8s_context: Kubernetes context validation
        - detect_docker: Docker availability check
        - check_docker_running: Docker daemon status check

    Target Configurators:
        - configure_repo_target: Repository target configuration
        - configure_image_target: Container image target configuration
        - configure_iac_target: IaC target configuration
        - configure_url_target: URL/DAST target configuration
        - configure_gitlab_target: GitLab target configuration
        - configure_k8s_target: Kubernetes target configuration

    Command Builder:
        - build_command_parts: Build secure command list

    Workflows:
        - offer_trend_analysis_after_scan: Post-scan trend menu
        - explore_trends_interactive: Trend exploration menu
        - run_diff_wizard_impl: Diff wizard implementation
        - policy_evaluation_menu: Policy evaluation flow

    Flow Classes:
        - BaseWizardFlow: Base class for wizard flows
        - RepoFlow, EntireStackFlow, CICDFlow, DeploymentFlow, DependencyFlow

    Telemetry:
        - send_wizard_telemetry: Send telemetry for wizard runs
        - prompt_telemetry_opt_in: Telemetry opt-in prompt
"""

from __future__ import annotations

# ==============================================================================
# Flow Classes (existing)
# ==============================================================================
from .base_flow import ArtifactGenerator as ArtifactGenerator
from .base_flow import BaseWizardFlow as BaseWizardFlow
from .base_flow import PromptHelper as PromptHelper
from .base_flow import TargetDetector as TargetDetector
from .cicd_flow import CICDFlow as CICDFlow
from .dependency_flow import DependencyFlow as DependencyFlow
from .deployment_flow import DeploymentFlow as DeploymentFlow
from .repo_flow import RepoFlow as RepoFlow
from .stack_flow import EntireStackFlow as EntireStackFlow

# ==============================================================================
# Validators (existing - newly exported)
# ==============================================================================
from .validators import check_docker_running as check_docker_running
from .validators import detect_docker as detect_docker
from .validators import detect_iac_type as detect_iac_type
from .validators import validate_k8s_context as validate_k8s_context
from .validators import validate_path as validate_path
from .validators import validate_url as validate_url

# ==============================================================================
# Target Configurators (existing - newly exported)
# ==============================================================================
from .target_configurators import configure_gitlab_target as configure_gitlab_target
from .target_configurators import configure_iac_target as configure_iac_target
from .target_configurators import configure_image_target as configure_image_target
from .target_configurators import configure_k8s_target as configure_k8s_target
from .target_configurators import configure_repo_target as configure_repo_target
from .target_configurators import configure_url_target as configure_url_target

# ==============================================================================
# Command Builder (existing - newly exported)
# ==============================================================================
from .command_builder import build_command_parts as build_command_parts

# ==============================================================================
# Policy Flow (existing - newly exported)
# ==============================================================================
from .policy_flow import (
    display_policy_violations_interactive as display_policy_violations_interactive,
)
from .policy_flow import policy_evaluation_menu as policy_evaluation_menu

# ==============================================================================
# Telemetry Helper (existing - newly exported)
# ==============================================================================
from .telemetry_helper import prompt_telemetry_opt_in as prompt_telemetry_opt_in
from .telemetry_helper import save_telemetry_preference as save_telemetry_preference
from .telemetry_helper import send_wizard_telemetry as send_wizard_telemetry

# ==============================================================================
# Phase 1: Configuration Models
# ==============================================================================
from .config_models import TargetConfig as TargetConfig
from .config_models import WizardConfig as WizardConfig

# ==============================================================================
# Phase 1: Profile Configuration
# ==============================================================================
from .profile_config import DIFF_WIZARD_TOTAL_STEPS as DIFF_WIZARD_TOTAL_STEPS
from .profile_config import PROFILES as PROFILES
from .profile_config import TOOL_TIME_ESTIMATES as TOOL_TIME_ESTIMATES
from .profile_config import WIZARD_TOTAL_STEPS as WIZARD_TOTAL_STEPS
from .profile_config import calculate_time_estimate as calculate_time_estimate
from .profile_config import format_time_range as format_time_range
from .profile_config import get_profile_warning as get_profile_warning

# ==============================================================================
# Phase 1: UI Helpers
# ==============================================================================
from .ui_helpers import UNICODE_FALLBACKS as UNICODE_FALLBACKS
from .ui_helpers import prompt_choice as prompt_choice
from .ui_helpers import prompt_text as prompt_text
from .ui_helpers import safe_print as safe_print
from .ui_helpers import select_mode as select_mode

# ==============================================================================
# Phase 2: Tool Checker
# ==============================================================================
from .tool_checker import check_tools_for_profile as check_tools_for_profile

# Private exports for backward compatibility (underscore-prefixed)
# These should be accessed via check_tools_for_profile() in new code
from .tool_checker import _auto_fix_tools as _auto_fix_tools
from .tool_checker import _check_policy_tools as _check_policy_tools
from .tool_checker import (
    _collect_missing_dependencies as _collect_missing_dependencies,
)
from .tool_checker import _install_opa_tool as _install_opa_tool
from .tool_checker import (
    _install_missing_tools_interactive as _install_missing_tools_interactive,
)
from .tool_checker import _show_all_fix_commands as _show_all_fix_commands

# ==============================================================================
# Phase 3: Trend Flow
# ==============================================================================
from .trend_flow import CompareArgs as CompareArgs
from .trend_flow import TrendArgs as TrendArgs
from .trend_flow import (
    explore_trends_interactive as explore_trends_interactive,
)
from .trend_flow import (
    offer_trend_analysis_after_scan as offer_trend_analysis_after_scan,
)

# Private exports for backward compatibility with tests
from .trend_flow import _compare_scans_interactive as _compare_scans_interactive
from .trend_flow import _explain_metrics_interactive as _explain_metrics_interactive
from .trend_flow import _export_trends_interactive as _export_trends_interactive
from .trend_flow import (
    _run_trend_command_interactive as _run_trend_command_interactive,
)

# ==============================================================================
# Phase 4: Diff Flow
# ==============================================================================
from .diff_flow import DiffArgs as DiffArgs
from .diff_flow import run_diff_wizard_impl as run_diff_wizard_impl

# ==============================================================================
# __all__ - Public API
# ==============================================================================
__all__ = [
    # Flow Classes
    "BaseWizardFlow",
    "TargetDetector",
    "PromptHelper",
    "ArtifactGenerator",
    "RepoFlow",
    "EntireStackFlow",
    "CICDFlow",
    "DeploymentFlow",
    "DependencyFlow",
    # Validators
    "validate_path",
    "validate_url",
    "detect_iac_type",
    "validate_k8s_context",
    "detect_docker",
    "check_docker_running",
    # Target Configurators
    "configure_repo_target",
    "configure_image_target",
    "configure_iac_target",
    "configure_url_target",
    "configure_gitlab_target",
    "configure_k8s_target",
    # Command Builder
    "build_command_parts",
    # Telemetry
    "send_wizard_telemetry",
    "prompt_telemetry_opt_in",
    "save_telemetry_preference",
    # Policy Flow
    "policy_evaluation_menu",
    "display_policy_violations_interactive",
    # Configuration (Phase 1)
    "TargetConfig",
    "WizardConfig",
    "PROFILES",
    "WIZARD_TOTAL_STEPS",
    "DIFF_WIZARD_TOTAL_STEPS",
    "TOOL_TIME_ESTIMATES",
    "calculate_time_estimate",
    "format_time_range",
    # UI Helpers (Phase 1)
    "UNICODE_FALLBACKS",
    "safe_print",
    "prompt_text",
    "prompt_choice",
    "select_mode",
    # Tool Checker (Phase 2)
    "check_tools_for_profile",
    # Trend Flow (Phase 3)
    "offer_trend_analysis_after_scan",
    "explore_trends_interactive",
    "TrendArgs",
    "CompareArgs",
    # Diff Flow (Phase 4)
    "run_diff_wizard_impl",
    "DiffArgs",
]
