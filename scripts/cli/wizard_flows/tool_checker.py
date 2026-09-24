"""Tool checking and installation utilities for the wizard.

Handles pre-flight checks for required security tools and provides
auto-fix capabilities for missing or misconfigured tools.

Functions:
    check_tools_for_matrix: Main tool availability check (every TOOL_MATRIX tool)
    _auto_fix_tools: Automatic tool installation with parallel support
    _show_all_fix_commands: Display manual fix commands
    _collect_missing_dependencies: Gather missing runtime deps
    _install_missing_tools_interactive: Interactive install with progress
    _check_policy_tools: OPA availability check
    _install_opa_tool: OPA installation helper
    _print_status_legend: Display tool status icon meanings
"""

from __future__ import annotations

import logging
import shlex
import subprocess  # nosec B404 - CLI needs subprocess
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# UI helper initialization (lazy to avoid import cycles)
# ---------------------------------------------------------------------------

_colorize = None
_UNICODE_FALLBACKS = None
_print_step = None


def _init_ui_helpers() -> None:
    """Initialize UI helpers lazily to avoid import cycles."""
    global _colorize, _UNICODE_FALLBACKS, _print_step
    if _colorize is None:
        from scripts.cli.wizard_flows.base_flow import PromptHelper
        from scripts.cli.wizard_flows.ui_helpers import UNICODE_FALLBACKS

        prompter = PromptHelper()
        _colorize = prompter.colorize
        _print_step = prompter.print_step
        _UNICODE_FALLBACKS = UNICODE_FALLBACKS


def _get_colorize() -> Any:
    """Get colorize function, initializing if needed."""
    _init_ui_helpers()
    return _colorize


def _get_unicode_fallbacks() -> dict[str, str]:
    """Get Unicode fallbacks dict, initializing if needed."""
    _init_ui_helpers()
    assert _UNICODE_FALLBACKS is not None  # guaranteed after _init_ui_helpers()
    return _UNICODE_FALLBACKS


def _get_print_step() -> Any:
    """Get print_step function, initializing if needed."""
    _init_ui_helpers()
    return _print_step


# ---------------------------------------------------------------------------
# Status Legend
# ---------------------------------------------------------------------------


def _print_status_legend() -> None:
    """Print the tool status legend at the start of tool check.

    Helps users understand what each status icon means.
    """
    colorize = _get_colorize()
    FALLBACKS = _get_unicode_fallbacks()

    print("\n" + colorize("Tool Status Legend:", "bold"))
    print(f"  {FALLBACKS.get('✅', '[OK]')}  = Ready to run")
    print(f"  {FALLBACKS.get('⚠', '[!]')}  = Needs attention (can be fixed)")
    print(f"  {FALLBACKS.get('✗', 'X')}   = Not installed")
    print("  !!  = Startup crash (needs reinstall)")
    print()


# ---------------------------------------------------------------------------
# Main tool checking function
# ---------------------------------------------------------------------------


def check_tools_for_matrix(
    yes: bool = False,
    use_docker: bool = False,
    auto_fix: bool = False,
    install_deps: bool = False,
) -> tuple[bool, list[str]]:
    """
    Check availability of every tool in TOOL_MATRIX.

    This is the pre-flight tool check that runs before scan execution.
    If tools are missing, offers to install them or continue anyway. Every
    matrix tool installs on every platform, so each one that is not ready is
    something the user can fix.

    Args:
        yes: Non-interactive mode (skip prompts)
        use_docker: True if using Docker (tools bundled in image)
        auto_fix: Automatically install missing tools without prompting
        install_deps: Automatically install missing dependencies (Java)

    Returns:
        Tuple of (should_continue: bool, available_tools: list[str])
    """
    from scripts.cli.wizard_flows.ui_helpers import WIZARD_TOTAL_STEPS

    colorize = _get_colorize()
    FALLBACKS = _get_unicode_fallbacks()
    print_step = _get_print_step()

    # Docker mode has all tools bundled - skip check
    if use_docker:
        return True, []

    print_step(1, WIZARD_TOTAL_STEPS, "Tool Pre-flight Check")

    # Show status legend at the start
    _print_status_legend()

    try:
        from scripts.cli.tool_manager import (
            ToolManager,
            ToolStatusSummary,
            ToolStatusType,
            get_remediation_for_tool,
        )
        from scripts.core.tool_registry import detect_platform

        manager = ToolManager()
        platform = detect_platform()

        # One probe per tool: the manager memoises check_tool, so the summary
        # below reads the same statuses rather than probing again.
        statuses = manager.check_matrix()
        summary: ToolStatusSummary = manager.get_tool_summary()

        print(colorize(f"\nTool matrix: {summary.total} tools", "blue"))
        print(f"\nChecking {summary.total} tools...")

        missing = [s for s in statuses.values() if not s.installed]
        outdated = [s for s in statuses.values() if s.is_outdated]
        # Use execution_ready for "available" (consistent with summary display)
        available = [name for name, s in statuses.items() if s.execution_ready]
        not_ready = [
            s for s in statuses.values() if s.installed and not s.execution_ready
        ]

        # Combine all tools that need attention
        tools_needing_attention = missing + not_ready

        # All tools present and ready
        if not tools_needing_attention:
            print(
                colorize(
                    f"\n{FALLBACKS.get('✅', '[OK]')} {summary.format_status_line()}",
                    "green",
                )
            )
            if outdated:
                print(
                    colorize(
                        f"{FALLBACKS.get('⚠', '[!]')} {len(outdated)} tool(s) outdated - run 'jmo tools update' when convenient",
                        "yellow",
                    )
                )
            return True, available

        # Show consolidated status with unified counts
        print(
            colorize(
                f"\n{FALLBACKS.get('✅', '[OK]')} {summary.execution_ready} tools ready",
                "green",
            )
        )
        print(
            colorize(
                f"{FALLBACKS.get('⚠', '[!]')} {len(tools_needing_attention)} tool(s) need attention:",
                "yellow",
            )
        )

        # Collect fix commands for display and potential auto-execution
        fix_info: list[dict] = []

        for status in tools_needing_attention:
            if not status.installed:
                issue = "NOT INSTALLED"
            # Phase 4: Detect startup crashes (pydantic conflicts, import errors)
            elif status.version_error:
                issue = f"STARTUP CRASH: {status.version_error}"
            else:
                issue = status.execution_warning or "Missing dependencies"

            remediation = get_remediation_for_tool(status.name, platform)
            fix_info.append(
                {
                    "name": status.name,
                    "issue": issue,
                    "installed": status.installed,
                    "remediation": remediation,
                    "version_error": status.version_error,  # Phase 4
                    "status_type": status.status_type,  # Chunk 3
                    "missing_deps": status.missing_deps or [],  # Chunk 4
                }
            )

            # Display the issue - use status_type for icon/color (Chunk 3)
            icon = f"[{status.status_icon}]"

            # Color based on status_type (Chunk 3: red for CRASH/FAILED/MISSING, yellow for others)
            print(f"\n  {icon} {colorize(status.name, status.status_color)}: {issue}")

            # Show fix command
            if status.status_type == ToolStatusType.CRASH:
                # Phase 4/Chunk 3: Suggest fix based on whether tool supports isolated venv
                # Lazy import to avoid circular dependency
                from scripts.cli.tool_installer import ISOLATED_TOOLS

                if status.name in ISOLATED_TOOLS:
                    # Tool will be reinstalled in isolated venv
                    print(
                        colorize(
                            "     Fix: jmo tools clean && jmo tools install "
                            f"{status.name}",
                            "cyan",
                        )
                    )
                    print(
                        colorize(
                            "     (Reinstalls in isolated venv to avoid pip conflicts)",
                            "dim",
                        )
                    )
                else:
                    # Tool not in ISOLATED_TOOLS - suggest manual pip reinstall
                    print(
                        colorize(
                            f"     Fix: pip uninstall {status.name} -y && "
                            f"pip install {status.name}",
                            "cyan",
                        )
                    )
                    print(
                        colorize(
                            "     (Dependency conflict - may need to resolve manually)",
                            "dim",
                        )
                    )
            elif remediation["commands"]:
                print(f"     Fix: {remediation['commands'][0]}")
                if len(remediation["commands"]) > 1:
                    for cmd in remediation["commands"][1:]:
                        print(f"          {cmd}")
            elif remediation["jmo_install"]:
                print(f"     Fix: {remediation['jmo_install']}")

        if outdated:
            print(
                colorize(
                    f"\n{FALLBACKS.get('⚠', '[!]')} {len(outdated)} tool(s) outdated - run 'jmo tools update' when convenient",
                    "yellow",
                )
            )

        # Non-interactive mode: handle auto_fix or continue with available tools
        if yes:
            # If auto_fix is enabled, automatically install missing tools
            if auto_fix:
                print(
                    colorize(
                        f"\nAuto-fix enabled: installing {len(tools_needing_attention)} missing tool(s)...",
                        "blue",
                    )
                )
                return _auto_fix_tools(
                    fix_info,
                    platform,
                    available,
                    auto_install_deps=install_deps,
                )

            # No auto_fix: continue with available tools
            print(
                colorize(
                    f"\nNon-interactive mode: continuing with {len(available)} available tools",
                    "yellow",
                )
            )
            skipped = [t["name"] for t in fix_info]
            print(f"Skipping: {', '.join(skipped)}")
            return True, available

        # Interactive: offer choices with auto-fix option
        print("\n" + "─" * 50)
        print(colorize("Options:", "blue"))
        print(f"  [1] Auto-fix all issues ({len(tools_needing_attention)} tools)")
        print(
            f"  [2] Continue with {len(available)} working tools (skip: {', '.join(t['name'] for t in fix_info[:3])}{'...' if len(fix_info) > 3 else ''})"
        )
        print("  [3] Show all fix commands (copy/paste manually)")
        print("  [4] Cancel wizard")

        while True:
            choice = input("\nChoice [1]: ").strip() or "1"
            if choice == "1":
                # Auto-fix: run remediation commands
                return _auto_fix_tools(fix_info, platform, available)
            elif choice == "2":
                print(
                    colorize(
                        f"\nContinuing with {len(available)} available tools", "yellow"
                    )
                )
                print("Note: Some scan categories may be skipped")
                return True, available
            elif choice == "3":
                # Show all commands for manual execution
                _show_all_fix_commands(fix_info, platform)
                # Ask again after showing commands
                continue
            elif choice == "4":
                return False, []
            else:
                print("Please enter 1, 2, 3, or 4")

    except ImportError as e:
        # Tool manager not available - continue anyway
        logger.warning(f"Tool check unavailable: {e}")
        colorize = _get_colorize()
        print(colorize("\nTool check unavailable - continuing anyway", "yellow"))
        return True, []
    except (
        Exception
    ) as e:  # Acceptable: graceful degradation — tool check must not block wizard
        logger.warning(f"Tool check failed: {e}")
        colorize = _get_colorize()
        print(colorize(f"\nTool check failed: {e} - continuing anyway", "yellow"))
        return True, []


# ---------------------------------------------------------------------------
# Fix command display
# ---------------------------------------------------------------------------


def _show_all_fix_commands(fix_info: list[dict], platform: str) -> None:
    """Show all fix commands in a copy-paste friendly format."""
    colorize = _get_colorize()

    print("\n" + "═" * 60)
    print(colorize("  FIX COMMANDS (copy and run in terminal)", "blue"))
    print("═" * 60)

    for info in fix_info:
        print(f"\n# {info['name']}: {info['issue']}")
        remediation = info["remediation"]
        if remediation["commands"]:
            for cmd in remediation["commands"]:
                print(cmd)
        elif remediation["jmo_install"]:
            print(remediation["jmo_install"])

    print("\n" + "═" * 60)
    print("After running these commands, restart the wizard with: jmo wizard")
    print("═" * 60 + "\n")


# ---------------------------------------------------------------------------
# Dependency collection helper
# ---------------------------------------------------------------------------


def _collect_missing_dependencies(fix_info: list[dict]) -> dict[str, list[str]]:
    """
    Collect missing dependencies and which tools need them.

    Scans the fix_info list for tools that have missing runtime dependencies
    (like Java) and groups them by dependency.

    Args:
        fix_info: List of tool fix info dicts from check_tools_for_matrix

    Returns:
        Dict mapping dependency name to list of tools requiring it.
        Example: {"java": ["zap"]}
    """
    deps: dict[str, list[str]] = {}

    for info in fix_info:
        # Check for missing_deps in the tool status
        # This is populated by ToolManager._verify_execution()
        missing = info.get("missing_deps", [])
        if not missing:
            continue

        for dep in missing:
            if dep not in deps:
                deps[dep] = []
            if info["name"] not in deps[dep]:
                deps[dep].append(info["name"])

    return deps


# ---------------------------------------------------------------------------
# Auto-fix tools (main installation logic)
# ---------------------------------------------------------------------------


def _auto_fix_tools(
    fix_info: list[dict],
    platform: str,
    available: list[str],
    auto_install_deps: bool = False,
) -> tuple[bool, list[str]]:
    """
    Automatically fix tools with issues using parallel installation.

    Uses a two-phase strategy, after installing any missing runtime dependency:
    1. Parallel installation for JMo-manageable tools (pip, binary downloads)
    2. Sequential execution for platform-specific commands

    Args:
        fix_info: List of dicts with tool name, issue, and remediation info
        platform: Current platform (linux, macos, windows)
        available: Currently available tool names
        auto_install_deps: Automatically install dependencies without prompting

    Returns:
        Tuple of (should_continue, updated_available_tools)
    """
    colorize = _get_colorize()
    FALLBACKS = _get_unicode_fallbacks()

    # Phase -1: Check for missing runtime dependencies (Chunk 4)
    # Dependencies like Java must be installed before the tools that need them
    missing_deps = _collect_missing_dependencies(fix_info)

    if missing_deps:
        # Import dependency installation functions (lazy import to avoid circular deps)
        from scripts.cli.tool_installer import (
            get_manual_dependency_command,
            install_dependency,
        )
        from scripts.core.install_config import DEPENDENCY_DISPLAY_NAMES

        print(
            colorize(
                f"\n{FALLBACKS.get('⚠', '[!]')} Some tools require runtime dependencies:",
                "yellow",
            )
        )
        for dep, tools in missing_deps.items():
            dep_display = DEPENDENCY_DISPLAY_NAMES.get(dep, dep)
            tools_str = ", ".join(tools)
            print(f"   - {dep_display} (required by: {tools_str})")

        # If auto_install_deps is enabled, skip the prompt and install
        if auto_install_deps:
            choice = "1"
            print(
                colorize(
                    "\nAuto-installing dependencies (--install-deps flag)...",
                    "blue",
                )
            )
        else:
            print(colorize("\nInstall missing dependencies?", "blue"))
            print("  [1] Yes, install automatically")
            print("  [2] No, skip tools requiring these dependencies")
            print("  [3] Cancel")

            choice = input("\nChoice [1]: ").strip() or "1"

        if choice == "1":
            print()  # Blank line before install output
            for dep in missing_deps:
                dep_display = DEPENDENCY_DISPLAY_NAMES.get(dep, dep)
                success, msg = install_dependency(dep, platform)
                if success:
                    print(
                        colorize(
                            f"   {FALLBACKS.get('✅', '[OK]')} {dep_display} installed: {msg}",
                            "green",
                        )
                    )
                else:
                    print(
                        colorize(
                            f"   {FALLBACKS.get('❌', '[X]')} {dep_display} install failed: {msg}",
                            "red",
                        )
                    )
                    manual_cmd = get_manual_dependency_command(dep, platform)
                    print(f"       Manual: {manual_cmd}")
            print()  # Blank line after install output
        elif choice == "3":
            print(colorize("Cancelled.", "yellow"))
            return False, available
        # choice == "2" continues without installing deps (tools may fail)

    # Every matrix tool installs on every platform, so each one listed here is
    # an auto-fix candidate.
    if not fix_info:
        return True, available

    print(
        colorize(
            f"\n{FALLBACKS.get('🔧', '[*]')} Auto-fixing {len(fix_info)} tool(s)...",
            "blue",
        )
    )
    print("─" * 50)

    # Separate tools into JMo-installable vs platform-specific commands
    jmo_tools: list[str] = []
    platform_commands: list[tuple[str, list[str]]] = []  # (tool_name, commands)

    for info in fix_info:
        tool_name = info["name"]
        remediation = info["remediation"]

        # Check if this tool can be installed via JMo's ToolInstaller
        jmo_install = remediation.get("jmo_install")
        commands = remediation.get("commands", [])

        if jmo_install and "jmo tools install" in jmo_install:
            # Tool can be installed via JMo - use parallel installer
            jmo_tools.append(tool_name)
        elif commands:
            # Has platform-specific commands - run separately
            platform_commands.append((tool_name, commands))
        else:
            # Default to JMo install
            jmo_tools.append(tool_name)

    fixed = 0
    failed = 0
    failed_tools: list[str] = []

    # Phase 1: Parallel installation for JMo-manageable tools
    if jmo_tools:
        print(
            colorize(
                f"\n{FALLBACKS.get('⚡', '[*]')} Installing {len(jmo_tools)} tools...",
                "cyan",
            )
        )
        print(
            colorize(
                "   (isolated venvs: sequential | binaries: parallel | pip batch: single command)",
                "dim",
            )
        )

        try:
            from scripts.cli.tool_installer import ToolInstaller

            installer = ToolInstaller()

            # Install only the tools that need fixing, not the whole matrix
            progress = installer.install_tools_parallel(
                tools=jmo_tools,  # Only install the tools that need fixing
                skip_installed=False,  # Don't skip - these are broken/missing
                max_workers=4,
                show_progress=True,
            )

            # Count results - all results are for our tools now
            for result in progress.results:
                if result.success:
                    if result.method != "skipped":
                        fixed += 1
                        print(
                            colorize(
                                f"   {FALLBACKS.get('✅', '[OK]')} {result.tool_name} installed!",
                                "green",
                            )
                        )
                        if result.tool_name not in available:
                            available.append(result.tool_name)
                else:
                    failed += 1
                    failed_tools.append(result.tool_name)
                    print(
                        colorize(
                            f"   {FALLBACKS.get('❌', '[X]')} {result.tool_name}: {result.message[:60]}",
                            "red",
                        )
                    )

        except ImportError as e:
            logger.warning(f"Could not import ToolInstaller: {e}")
            # Fall back to sequential installation
            for tool_name in jmo_tools:
                platform_commands.append(
                    (tool_name, [f"jmo tools install {tool_name} --yes"])
                )

    # Phase 2: Platform-specific commands (sequential, can't parallelize safely)
    if platform_commands:
        print(
            colorize(
                f"\n{FALLBACKS.get('🔧', '[*]')} Running {len(platform_commands)} platform-specific commands...",
                "blue",
            )
        )

        for tool_name, commands in platform_commands:
            print(f"\n{FALLBACKS.get('⏳', '[.]')} Fixing {tool_name}...")

            success = True
            for cmd in commands:
                if not cmd:
                    continue

                # Add --yes flag to jmo tools install commands to avoid interactive prompt
                if cmd.startswith("jmo tools install") and "--yes" not in cmd:
                    cmd = cmd + " --yes"

                # Split chained commands (e.g., "cmd1 && cmd2") into individual calls
                # to avoid shell=True (CWE-78 / project policy)
                sub_commands = [c.strip() for c in cmd.split("&&")]

                for sub_cmd in sub_commands:
                    if not sub_cmd:
                        continue

                    print(
                        f"   Running: {sub_cmd[:60]}{'...' if len(sub_cmd) > 60 else ''}"
                    )

                    try:
                        # Safety: sub_cmd is internally generated by _build_check_commands(),
                        # not from user input. shlex.split() is safe here.
                        proc_result = subprocess.run(
                            shlex.split(sub_cmd),
                            capture_output=True,
                            text=True,
                            encoding="utf-8",
                            errors="replace",
                            timeout=300,  # 5 minute timeout per command
                        )

                        if proc_result.returncode != 0:
                            if (
                                "error" in proc_result.stderr.lower()
                                or "failed" in proc_result.stderr.lower()
                            ):
                                print(
                                    colorize(
                                        f"   {FALLBACKS.get('❌', '[X]')} Failed: {proc_result.stderr[:100]}",
                                        "red",
                                    )
                                )
                                success = False
                                break
                            else:
                                logger.debug(
                                    f"Command returned {proc_result.returncode} but continuing"
                                )

                    except subprocess.TimeoutExpired:
                        print(
                            colorize(
                                f"   {FALLBACKS.get('❌', '[X]')} Timeout after 5 minutes",
                                "red",
                            )
                        )
                        success = False
                        break
                    except Exception as e:  # Acceptable: individual tool install failure — continue with others
                        print(
                            colorize(
                                f"   {FALLBACKS.get('❌', '[X]')} Error: {e}",
                                "red",
                            )
                        )
                        success = False
                        break

                # If a sub-command failed, stop processing remaining commands
                if not success:
                    break

            if success:
                print(
                    colorize(
                        f"   {FALLBACKS.get('✅', '[OK]')} {tool_name} fixed!",
                        "green",
                    )
                )
                fixed += 1
                if tool_name not in available:
                    available.append(tool_name)
            else:
                failed += 1
                failed_tools.append(tool_name)

    # Summary
    print("\n" + "─" * 50)
    if failed == 0:
        print(
            colorize(
                f"{FALLBACKS.get('✅', '[OK]')} All {fixed} tool(s) fixed successfully!",
                "green",
            )
        )
    else:
        print(
            colorize(
                f"{FALLBACKS.get('⚠', '[!]')} {fixed} fixed, {failed} failed",
                "yellow",
            )
        )
        print(f"Failed tools: {', '.join(failed_tools)}")
        print("These may require manual installation. See: docs/MANUAL_INSTALLATION.md")

    # Re-check tool status to update available list using unified summary
    print("\nRe-checking tool status...")
    try:
        from scripts.cli.tool_manager import ToolManager

        # A fresh manager: its status memo must not predate the installs above.
        manager = ToolManager()
        statuses = manager.check_matrix()
        summary = manager.get_tool_summary()

        # Get list of execution-ready tools
        available = [name for name, s in statuses.items() if s.execution_ready]

        if summary.execution_ready == summary.total:
            print(
                colorize(
                    f"{FALLBACKS.get('✅', '[OK]')} {summary.format_status_line()}",
                    "green",
                )
            )
        else:
            print(
                colorize(
                    f"{FALLBACKS.get('✅', '[OK]')} {summary.format_status_line()}",
                    "yellow",
                )
            )
            # Show breakdown of what still needs attention
            if summary.version_issues:
                print(
                    colorize(
                        f"  {FALLBACKS.get('⚠', '[!]')} {len(summary.version_issues)} with version issues: {', '.join(summary.version_issues)}",
                        "dim",
                    )
                )

    except (
        Exception
    ) as e:  # Acceptable: post-install re-check is optional — continue regardless
        logger.warning(f"Re-check failed: {e}")

    # Continue with whatever we have
    return True, available


# ---------------------------------------------------------------------------
# Interactive installation
# ---------------------------------------------------------------------------


def _install_missing_tools_interactive(
    missing: list,
    available: list[str],
) -> tuple[bool, list[str]]:
    """
    Install missing tools with progress display.

    Args:
        missing: List of ToolStatus for missing tools
        available: Currently available tool names

    Returns:
        Tuple of (should_continue, updated_available_tools)
    """
    colorize = _get_colorize()
    FALLBACKS = _get_unicode_fallbacks()

    try:
        from scripts.cli.tool_installer import ToolInstaller

        print(colorize(f"\nInstalling {len(missing)} missing tool(s)...", "blue"))

        installer = ToolInstaller()

        def progress_callback(tool_name: str, current: int, total: int) -> None:
            print(f"  [{current}/{total}] Installing {tool_name}...")

        installer.set_progress_callback(progress_callback)

        # Install only the missing tools
        from scripts.cli.tool_installer import InstallProgress

        progress = InstallProgress(total=len(missing))
        for status in missing:
            result = installer.install_tool(status.name)
            progress.add_result(result)
            if result.success:
                available.append(status.name)

        # Summary
        print()
        if progress.failed == 0:
            print(
                colorize(
                    f"{FALLBACKS.get('✅', '[OK]')} All {progress.successful} tool(s) installed!",
                    "green",
                )
            )
        else:
            print(
                colorize(
                    f"{progress.successful} installed, {progress.failed} failed",
                    "yellow",
                )
            )
            if progress.failed > 0:
                print(
                    "Some tools require manual installation. See: docs/MANUAL_INSTALLATION.md"
                )

        # Continue with whatever we have
        return True, available

    except ImportError as e:
        logger.warning(f"Tool installer unavailable: {e}")
        print(colorize(f"\nInstaller unavailable: {e}", "red"))
        print("Install manually using: jmo tools install")

        cont = input("Continue anyway? [y/N]: ").strip().lower()
        return cont == "y", available
    except (
        Exception
    ) as e:  # Acceptable: installation failure — report error, don't crash wizard
        logger.error(f"Installation failed: {e}")
        print(colorize(f"\nInstallation error: {e}", "red"))

        cont = input("Continue anyway? [y/N]: ").strip().lower()
        return cont == "y", available


# ---------------------------------------------------------------------------
# Policy tool checking (OPA)
# ---------------------------------------------------------------------------


def _check_policy_tools(
    policies: list[str] | None,
    skip_policies: bool,
    yes: bool = False,
    use_docker: bool = False,
) -> tuple[bool, bool]:
    """
    Check if OPA is available when policies are configured.

    This pre-flight check runs in Step 2 (after tool check) when the user
    has specified --policy flags. OPA is required for policy evaluation.

    Args:
        policies: List of policies to evaluate (e.g., ['owasp-top-10', 'zero-secrets'])
        skip_policies: Whether --skip-policies was specified
        yes: Non-interactive mode
        use_docker: Whether Docker mode is active (OPA bundled in image)

    Returns:
        Tuple of (should_continue: bool, policies_enabled: bool)
        - should_continue: Whether wizard should proceed
        - policies_enabled: Whether policy evaluation will run
    """
    colorize = _get_colorize()
    FALLBACKS = _get_unicode_fallbacks()

    # No policies configured or explicitly skipped - nothing to check
    if not policies or skip_policies:
        return True, False

    # Docker mode has OPA bundled - skip check
    if use_docker:
        return True, True

    # Check if OPA is available
    from scripts.cli.scan_utils import tool_exists

    print(
        f"\nChecking policy tool availability ({len(policies)} policies configured)..."
    )

    if tool_exists("opa", warn=False):
        print(
            colorize(
                f"{FALLBACKS.get('✅', '[OK]')} OPA available - policy evaluation enabled",
                "green",
            )
        )
        return True, True

    # OPA not found - warn user
    print(
        colorize(
            f"\n{FALLBACKS.get('⚠', '[!]')} OPA not installed",
            "yellow",
        )
    )
    print("Policy evaluation requires OPA (Open Policy Agent).")
    print(f"Configured policies: {', '.join(policies)}")

    # Non-interactive: continue without policies
    if yes:
        print(
            colorize(
                "\nNon-interactive mode: continuing without policy evaluation",
                "yellow",
            )
        )
        return True, False

    # Interactive: offer choices
    print("\n" + "─" * 50)
    print(colorize("Options:", "blue"))
    print("  [1] Continue scan without policy evaluation")
    print("  [2] Install OPA and continue")
    print("  [3] Cancel wizard")

    while True:
        choice = input("\nChoice [1]: ").strip() or "1"
        if choice == "1":
            print(
                colorize(
                    "\nContinuing without policy evaluation",
                    "yellow",
                )
            )
            return True, False
        elif choice == "2":
            # Attempt OPA installation
            return _install_opa_tool()
        elif choice == "3":
            return False, False
        else:
            print("Please enter 1, 2, or 3")


def _install_opa_tool() -> tuple[bool, bool]:
    """
    Install OPA tool.

    Returns:
        Tuple of (should_continue, policies_enabled)
    """
    colorize = _get_colorize()
    FALLBACKS = _get_unicode_fallbacks()

    print("\nInstalling OPA...")

    try:
        from scripts.cli.tool_installer import ToolInstaller

        installer = ToolInstaller()
        result = installer.install_tool("opa")

        if result.success:
            print(
                colorize(
                    f"{FALLBACKS.get('✅', '[OK]')} OPA installed successfully",
                    "green",
                )
            )
            return True, True
        else:
            print(
                colorize(
                    f"{FALLBACKS.get('❌', '[X]')} OPA installation failed: {result.message}",
                    "red",
                )
            )
            print("Continuing without policy evaluation")
            return True, False

    except ImportError as e:
        logger.warning(f"Tool installer unavailable: {e}")
        print(colorize(f"\nInstaller unavailable: {e}", "red"))
        print(
            "Install OPA manually: https://www.openpolicyagent.org/docs/latest/#running-opa"
        )
        return True, False
    except Exception as e:  # Acceptable: OPA install is optional — policy evaluation gracefully skipped
        logger.warning(f"OPA installation failed: {e}")
        print(colorize(f"\nInstallation failed: {e}", "red"))
        print("Continuing without policy evaluation")
        return True, False
