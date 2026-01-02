"""
CLI command handlers for `jmo tools`.

Provides check, install, update, list, and outdated subcommands
for managing security tool installations.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import TYPE_CHECKING

from scripts.cli.tool_manager import (
    ToolManager,
    ToolStatus,
    print_profile_summary,
    print_tool_status_table,
)
from scripts.core.tool_registry import PROFILE_TOOLS, ToolRegistry

if TYPE_CHECKING:
    pass


# ANSI color codes for terminal output
class Colors:
    """ANSI color codes."""

    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[0;34m"
    CYAN = "\033[0;36m"
    NC = "\033[0m"  # No Color

    @classmethod
    def supports_color(cls) -> bool:
        """Check if terminal supports color."""
        if not sys.stdout.isatty():
            return False
        if sys.platform == "win32":
            # Windows console may not support ANSI
            import os

            return os.environ.get("TERM") or os.environ.get("WT_SESSION")
        return True


def colorize(text: str, color: str) -> str:
    """
    Colorize text for terminal output.

    Args:
        text: Text to colorize
        color: Color name ('red', 'green', 'yellow', 'blue', 'cyan')

    Returns:
        Colorized text if terminal supports it, otherwise plain text
    """
    if not Colors.supports_color():
        return text

    color_map = {
        "red": Colors.RED,
        "green": Colors.GREEN,
        "yellow": Colors.YELLOW,
        "blue": Colors.BLUE,
        "cyan": Colors.CYAN,
    }
    code = color_map.get(color, "")
    if code:
        return f"{code}{text}{Colors.NC}"
    return text


def cmd_tools(args: argparse.Namespace) -> int:
    """
    Main dispatcher for `jmo tools` subcommands.

    Args:
        args: Parsed command line arguments

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    subcommand = getattr(args, "tools_command", None)

    handlers = {
        "check": cmd_tools_check,
        "install": cmd_tools_install,
        "update": cmd_tools_update,
        "list": cmd_tools_list,
        "outdated": cmd_tools_outdated,
        "uninstall": cmd_tools_uninstall,
        "debug": cmd_tools_debug,
    }

    handler = handlers.get(subcommand)
    if handler:
        return handler(args)

    # No subcommand - show status summary
    return cmd_tools_check(args)


def cmd_tools_check(args: argparse.Namespace) -> int:
    """
    Check tool installation status.

    Usage:
        jmo tools check                    # Check all tools
        jmo tools check --profile balanced # Check tools for profile
        jmo tools check trivy semgrep      # Check specific tools

    Returns:
        0 if all tools present, 1 if missing tools
    """
    manager = ToolManager()
    profile = getattr(args, "profile", None)
    tools = getattr(args, "tools", None) or []
    output_json = getattr(args, "json", False)

    # Determine what to check
    if tools:
        statuses = {t: manager.check_tool(t) for t in tools}
        title = f"Tool Status ({len(tools)} tools)"
    elif profile:
        statuses = manager.check_profile(profile)
        title = f"Tool Status for '{profile}' profile ({len(statuses)} tools)"
    else:
        # Default: show profile summary
        if output_json:
            summaries = {p: manager.get_profile_summary(p) for p in PROFILE_TOOLS}
            print(json.dumps(summaries, indent=2))
            return 0

        print_profile_summary(manager, colorize)

        # Also check critical outdated
        critical = manager.get_critical_outdated()
        if critical:
            print(colorize(f"\n{len(critical)} critical tool(s) need updates:", "yellow"))
            for s in critical:
                print(f"  - {s.name}: {s.installed_version} -> {s.expected_version}")
            print("\nRun `jmo tools update --critical-only` to update")

        return 0

    # JSON output
    if output_json:
        data = {
            name: {
                "installed": s.installed,
                "installed_version": s.installed_version,
                "expected_version": s.expected_version,
                "is_outdated": s.is_outdated,
                "is_critical": s.is_critical,
                "binary_path": s.binary_path,
            }
            for name, s in statuses.items()
        }
        print(json.dumps(data, indent=2))
        missing = [s for s in statuses.values() if not s.installed]
        return 1 if missing else 0

    # Print table
    print(f"\n{title}\n")
    print_tool_status_table(statuses, colorize, show_hints=True)

    # Summary
    missing = [s for s in statuses.values() if not s.installed]
    outdated = [s for s in statuses.values() if s.is_outdated]

    print()
    if missing:
        print(colorize(f"{len(missing)} tool(s) missing", "red"))
        print("Run `jmo tools install" + (f" --profile {profile}" if profile else "") + "` to install")
        return 1

    if outdated:
        critical = [s for s in outdated if s.is_critical]
        msg = f"{len(outdated)} tool(s) outdated"
        if critical:
            msg += f" ({len(critical)} critical)"
        print(colorize(msg, "yellow"))
        print("Run `jmo tools update` to update")

    if not missing and not outdated:
        print(colorize("All tools installed and up to date!", "green"))

    return 0


def cmd_tools_debug(args: argparse.Namespace) -> int:
    """
    Debug version detection for a specific tool.

    Usage:
        jmo tools debug shellcheck    # Debug shellcheck version detection
        jmo tools debug zap           # Debug ZAP version detection

    This command shows:
    - Binary path found
    - Version command used
    - Raw stdout/stderr output
    - Pattern matching result

    Returns:
        0 on success
    """
    import platform
    import subprocess
    from scripts.cli.tool_manager import (
        ToolManager,
        VERSION_COMMANDS,
        VERSION_PATTERNS,
        VERSION_TIMEOUTS,
    )

    tools = getattr(args, "tools", None) or []
    if not tools:
        print("Usage: jmo tools debug <tool_name>")
        print("Example: jmo tools debug shellcheck")
        return 1

    # Show system info first
    print(f"\n{'=' * 60}")
    print("System Information")
    print(f"{'=' * 60}")
    print(f"Platform: {platform.system()}")
    print(f"Machine: {platform.machine()}")
    print(f"Python: {platform.python_version()}")

    manager = ToolManager()

    for tool_name in tools:
        print(f"\n{'=' * 60}")
        print(f"Debugging version detection for: {colorize(tool_name, 'cyan')}")
        print(f"{'=' * 60}")

        # Get tool info
        tool_info = manager.registry.get_tool(tool_name)
        if tool_info:
            binary_name = tool_info.get_binary_name()
            print(f"Expected version: {tool_info.version}")
        else:
            binary_name = tool_name
            print(f"Warning: Tool '{tool_name}' not found in registry")

        print(f"Binary name: {binary_name}")

        # Find binary
        binary_path = manager._find_binary(binary_name)
        if binary_path:
            print(f"Binary path: {colorize(binary_path, 'green')}")
            # Show file type (helps diagnose architecture mismatches)
            try:
                file_result = subprocess.run(
                    ["file", binary_path],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if file_result.returncode == 0:
                    print(f"File type: {file_result.stdout.strip()}")
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass  # 'file' command not available
        else:
            print(f"Binary path: {colorize('NOT FOUND', 'red')}")
            print("\nThe tool binary could not be found in PATH or ~/.jmo/bin/")
            continue

        # Determine version command
        if tool_name in VERSION_COMMANDS:
            cmd = list(VERSION_COMMANDS[tool_name])
            cmd[0] = binary_path
            print(f"Version command: {' '.join(cmd)}")
        else:
            cmd = [binary_path, "--version"]
            print(f"Version command: {' '.join(cmd)} (default)")

        # Get timeout
        timeout = VERSION_TIMEOUTS.get(tool_name, 10)
        print(f"Timeout: {timeout}s")

        # Show pattern
        pattern = VERSION_PATTERNS.get(tool_name, VERSION_PATTERNS["default"])
        print(f"Pattern: {pattern.pattern}")

        # Run version command
        print(f"\n--- Running version command ---")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=manager._get_clean_env(),
            )
            print(f"Exit code: {result.returncode}")
            print(f"\nstdout ({len(result.stdout)} chars):")
            if result.stdout:
                print(f"  {repr(result.stdout[:500])}")
            else:
                print("  (empty)")
            print(f"\nstderr ({len(result.stderr)} chars):")
            if result.stderr:
                print(f"  {repr(result.stderr[:500])}")
            else:
                print("  (empty)")

            # Try parsing
            output = (result.stdout or "") + (result.stderr or "")
            if output.strip():
                match = pattern.search(output)
                print(f"\n--- Pattern matching ---")
                if match:
                    print(f"Matched version: {colorize(match.group(1), 'green')}")
                else:
                    print(f"Pattern match: {colorize('NO MATCH', 'red')}")
                    # Try default pattern as fallback
                    default_match = VERSION_PATTERNS["default"].search(output)
                    if default_match:
                        print(
                            f"Default pattern matched: {default_match.group(1)} "
                            f"(consider updating tool-specific pattern)"
                        )
            else:
                print(f"\n{colorize('No output to parse', 'yellow')}")

        except subprocess.TimeoutExpired:
            print(f"{colorize(f'TIMEOUT after {timeout}s', 'red')}")
            print("The tool is taking too long to respond.")
            print("This may indicate a Java startup issue or missing dependencies.")
        except FileNotFoundError:
            print(f"{colorize('Binary not executable or not found', 'red')}")
        except PermissionError:
            print(f"{colorize('Permission denied executing binary', 'red')}")
        except Exception as e:
            print(f"{colorize(f'Error: {type(e).__name__}: {e}', 'red')}")

    return 0


def cmd_tools_install(args: argparse.Namespace) -> int:
    """
    Install missing tools.

    Usage:
        jmo tools install                     # Install all missing
        jmo tools install --profile balanced  # Install for profile
        jmo tools install trivy semgrep       # Install specific tools
        jmo tools install --dry-run           # Show what would be installed
        jmo tools install --print-script      # Print install script

    Returns:
        0 on success, 1 on failure
    """
    manager = ToolManager()
    profile = getattr(args, "profile", None) or "balanced"
    tools_arg = getattr(args, "tools", None) or []
    dry_run = getattr(args, "dry_run", False)
    print_script = getattr(args, "print_script", False)
    yes = getattr(args, "yes", False)

    # Determine which tools to install
    if tools_arg:
        # Specific tools requested
        missing = []
        for t in tools_arg:
            status = manager.check_tool(t)
            if not status.installed:
                missing.append(status)
            else:
                print(f"{t}: already installed ({status.installed_version})")
    else:
        # Install missing for profile
        missing = manager.get_missing_tools(profile)

    if not missing:
        print(colorize("All tools are already installed!", "green"))
        return 0

    # Print script mode
    if print_script:
        script = _generate_install_script(missing, manager.platform)
        print(script)
        return 0

    # Show what will be installed
    print(f"\n{len(missing)} tool(s) to install:\n")
    for status in missing:
        critical = " [CRITICAL]" if status.is_critical else ""
        print(f"  - {status.name}{critical}")

    print(f"\nPlatform: {manager.platform}")
    print()

    # Interactive confirmation
    if not yes and sys.stdin.isatty():
        response = input("Proceed with installation? [Y/n] ").strip().lower()
        if response and response != "y":
            print("Installation cancelled")
            return 0

    # Dry run mode
    if dry_run:
        print(colorize("\n[DRY RUN] Would install:", "cyan"))
        for status in missing:
            print(f"  {status.name}: {status.install_hint}")
        return 0

    # Actually install
    # Import installer here to avoid circular imports
    from scripts.cli.tool_installer import ToolInstaller, print_install_progress

    installer = ToolInstaller()

    # Set up progress callback for real-time feedback
    def progress_callback(tool_name: str, current: int, total: int) -> None:
        print(f"[{current}/{total}] Installing {tool_name}...")

    installer.set_progress_callback(progress_callback)

    # Install the tools
    if tools_arg:
        # Install specific tools
        from scripts.cli.tool_installer import InstallProgress

        progress = InstallProgress(total=len(missing))
        for status in missing:
            result = installer.install_tool(status.name, force=True)
            progress.add_result(result)
    else:
        # Install for profile
        progress = installer.install_missing(profile)

    # Print results
    print_install_progress(progress, colorize)

    # Summary
    if progress.failed == 0:
        return 0
    else:
        print("\nSome tools require manual installation. Run with --print-script for hints.")
        return 1


def cmd_tools_update(args: argparse.Namespace) -> int:
    """
    Update outdated tools.

    Usage:
        jmo tools update                  # Update all outdated
        jmo tools update --critical-only  # Update critical tools only
        jmo tools update trivy            # Update specific tool
    """
    manager = ToolManager()
    critical_only = getattr(args, "critical_only", False)
    tools_arg = getattr(args, "tools", None) or []
    yes = getattr(args, "yes", False)

    # Determine which tools to update
    if tools_arg:
        outdated = []
        for t in tools_arg:
            status = manager.check_tool(t)
            if status.installed and status.is_outdated:
                outdated.append(status)
            elif not status.installed:
                print(f"{t}: not installed")
            else:
                print(f"{t}: already up to date ({status.installed_version})")
    elif critical_only:
        outdated = manager.get_critical_outdated()
    else:
        outdated = manager.get_outdated_tools()

    if not outdated:
        print(colorize("All tools are up to date!", "green"))
        return 0

    # Show what will be updated
    print(f"\n{len(outdated)} tool(s) to update:\n")
    print(f"{'Tool':<20}  {'Current':<12}  {'Latest':<12}  {'Priority'}")
    print("-" * 60)
    for status in outdated:
        priority = colorize("CRITICAL", "red") if status.is_critical else "normal"
        print(
            f"{status.name:<20}  {status.installed_version or '?':<12}  "
            f"{status.expected_version or '?':<12}  {priority}"
        )

    print()

    # Interactive confirmation
    if not yes and sys.stdin.isatty():
        response = input("Proceed with updates? [Y/n] ").strip().lower()
        if response and response != "y":
            print("Update cancelled")
            return 0

    # Actually update (reinstall with force)
    from scripts.cli.tool_installer import ToolInstaller, InstallProgress, print_install_progress

    installer = ToolInstaller()

    # Set up progress callback
    def progress_callback(tool_name: str, current: int, total: int) -> None:
        print(f"[{current}/{total}] Updating {tool_name}...")

    installer.set_progress_callback(progress_callback)

    progress = InstallProgress(total=len(outdated))
    for status in outdated:
        # Force reinstall to update
        result = installer.install_tool(status.name, force=True)
        progress.add_result(result)

    # Print results
    print_install_progress(progress, colorize)

    # Summary
    if progress.failed == 0:
        print(colorize(f"\nAll {progress.successful} tool(s) updated successfully!", "green"))
        return 0
    else:
        print(colorize(f"\n{progress.successful} updated, {progress.failed} failed", "yellow"))
        return 1


def cmd_tools_list(args: argparse.Namespace) -> int:
    """
    List available tools and profiles.

    Usage:
        jmo tools list                    # List all tools
        jmo tools list --profile balanced # List tools in profile
        jmo tools list --profiles         # List available profiles
    """
    show_profiles = getattr(args, "profiles", False)
    profile = getattr(args, "profile", None)
    output_json = getattr(args, "json", False)

    registry = ToolRegistry()

    if show_profiles:
        # List profiles
        if output_json:
            data = {p: {"tools": PROFILE_TOOLS[p], "count": len(PROFILE_TOOLS[p])} for p in PROFILE_TOOLS}
            print(json.dumps(data, indent=2))
            return 0

        print("\nAvailable Profiles:\n")
        print(f"{'Profile':<12}  {'Tools':<6}  {'Description'}")
        print("-" * 60)

        profile_desc = {
            "fast": "Pre-commit checks, quick validation (5-10 min)",
            "slim": "Cloud/IaC focused, AWS/Azure/GCP/K8s (12-18 min)",
            "balanced": "Production CI/CD, recommended (18-25 min)",
            "deep": "Comprehensive audits, compliance (40-70 min)",
        }

        for name in ["fast", "slim", "balanced", "deep"]:
            count = len(PROFILE_TOOLS[name])
            desc = profile_desc.get(name, "")
            print(f"{name:<12}  {count:<6}  {desc}")

        return 0

    # List tools
    if profile:
        tools = registry.get_tools_for_profile(profile)
        title = f"Tools in '{profile}' profile ({len(tools)} tools)"
    else:
        tools = registry.get_all_tools()
        title = f"All registered tools ({len(tools)} tools)"

    if output_json:
        data = [
            {
                "name": t.name,
                "version": t.version,
                "category": t.category,
                "critical": t.critical,
                "description": t.description,
            }
            for t in tools
        ]
        print(json.dumps(data, indent=2))
        return 0

    print(f"\n{title}\n")
    print(f"{'Tool':<20}  {'Version':<12}  {'Category':<15}  {'Critical'}")
    print("-" * 65)

    for t in sorted(tools, key=lambda x: x.name):
        critical = colorize("YES", "red") if t.critical else ""
        print(f"{t.name:<20}  {t.version:<12}  {t.category:<15}  {critical}")

    return 0


def cmd_tools_outdated(args: argparse.Namespace) -> int:
    """
    Show only outdated tools (shortcut for `jmo tools check --outdated`).

    Usage:
        jmo tools outdated
        jmo tools outdated --critical-only
    """
    manager = ToolManager()
    critical_only = getattr(args, "critical_only", False)
    output_json = getattr(args, "json", False)

    if critical_only:
        outdated = manager.get_critical_outdated()
    else:
        outdated = manager.get_outdated_tools()

    if not outdated:
        print(colorize("All tools are up to date!", "green"))
        return 0

    if output_json:
        data = [
            {
                "name": s.name,
                "installed_version": s.installed_version,
                "expected_version": s.expected_version,
                "is_critical": s.is_critical,
            }
            for s in outdated
        ]
        print(json.dumps(data, indent=2))
        return 1 if any(s.is_critical for s in outdated) else 0

    print(f"\n{len(outdated)} outdated tool(s):\n")
    print(f"{'Tool':<20}  {'Installed':<12}  {'Latest':<12}  {'Priority'}")
    print("-" * 60)

    for s in outdated:
        priority = colorize("CRITICAL", "red") if s.is_critical else "normal"
        print(
            f"{s.name:<20}  {s.installed_version or '?':<12}  "
            f"{s.expected_version or '?':<12}  {priority}"
        )

    print()
    print("Run `jmo tools update` to update all")
    if any(s.is_critical for s in outdated):
        print("Run `jmo tools update --critical-only` to update critical tools only")

    # Return error code if critical updates pending
    return 1 if any(s.is_critical for s in outdated) else 0


def _generate_install_script(missing: list[ToolStatus], platform: str) -> str:
    """
    Generate shell script to install missing tools.

    Args:
        missing: List of missing tool statuses
        platform: Target platform

    Returns:
        Shell script as string
    """
    lines = [
        "#!/bin/bash",
        "# JMo Security - Tool Installation Script",
        f"# Generated for platform: {platform}",
        "# Run with: bash install-tools.sh",
        "",
        "set -e",
        "",
    ]

    registry = ToolRegistry()

    for status in missing:
        tool = registry.get_tool(status.name)
        if not tool:
            lines.append(f"# {status.name}: Unknown tool")
            continue

        lines.append(f"# Install {status.name}")

        # Generate platform-specific command
        if platform == "macos" and tool.brew_package:
            lines.append(f"brew install {tool.brew_package}")
        elif platform == "linux" and tool.apt_package:
            lines.append(f"sudo apt-get install -y {tool.apt_package}")
        elif tool.pypi_package:
            lines.append(f"pip install {tool.pypi_package}")
        elif tool.npm_package:
            lines.append(f"npm install -g {tool.npm_package}")
        else:
            lines.append(f"# Manual install required: {status.install_hint}")

        lines.append("")

    return "\n".join(lines)


def cmd_tools_uninstall(args: argparse.Namespace) -> int:
    """
    Uninstall JMo Security and optionally all tools.

    Usage:
        jmo tools uninstall              # Uninstall JMo suite only (keep tools)
        jmo tools uninstall --all        # Uninstall everything (suite + tools)
        jmo tools uninstall --dry-run    # Show what would be removed

    Returns:
        0 on success, 1 on failure
    """
    import shutil
    from pathlib import Path

    uninstall_all = getattr(args, "all", False)
    dry_run = getattr(args, "dry_run", False)
    yes = getattr(args, "yes", False)

    # Collect items to remove
    jmo_dir = Path.home() / ".jmo"
    kubescape_dir = Path.home() / ".kubescape"

    print("\n" + "=" * 60)
    if uninstall_all:
        print("  JMo Security - COMPLETE UNINSTALL")
        print("  This will remove JMo AND all security tools")
    else:
        print("  JMo Security - Suite Uninstall")
        print("  This will remove JMo but KEEP security tools installed")
    print("=" * 60)

    # === Part 1: JMo Suite removal ===
    print("\n" + colorize("JMo Suite:", "bold"))

    jmo_items = []
    if jmo_dir.exists():
        # List contents
        for item in jmo_dir.iterdir():
            size = _get_dir_size(item) if item.is_dir() else item.stat().st_size
            jmo_items.append((item, size))
            print(f"  - {item.name}/ ({_format_size(size)})" if item.is_dir() else f"  - {item.name} ({_format_size(size)})")

        if not jmo_items:
            print("  (empty)")
    else:
        print("  ~/.jmo not found (already clean)")

    # Check for pip-installed jmo package
    jmo_pip_installed = _check_pip_package("jmo-security")

    if jmo_pip_installed:
        print(f"  - jmo-security (pip package)")

    # === Part 2: Tools removal (only if --all) ===
    tools_to_remove = []
    if uninstall_all:
        print("\n" + colorize("Security Tools:", "bold"))
        tools_to_remove = _get_installed_tools()

        if tools_to_remove:
            # Group by install method
            pip_tools = [t for t in tools_to_remove if t[1] == "pip"]
            npm_tools = [t for t in tools_to_remove if t[1] == "npm"]
            binary_tools = [t for t in tools_to_remove if t[1] == "binary"]
            brew_tools = [t for t in tools_to_remove if t[1] == "brew"]

            if pip_tools:
                print(f"  pip: {', '.join(t[0] for t in pip_tools)}")
            if npm_tools:
                print(f"  npm: {', '.join(t[0] for t in npm_tools)}")
            if binary_tools:
                print(f"  binary: {', '.join(t[0] for t in binary_tools)}")
            if brew_tools:
                print(f"  brew: {', '.join(t[0] for t in brew_tools)} (manual removal)")

            # Kubescape special dir
            if kubescape_dir.exists():
                print(f"  - ~/.kubescape/ ({_format_size(_get_dir_size(kubescape_dir))})")
        else:
            print("  No JMo-managed tools found")

    # === Confirmation ===
    print()
    if dry_run:
        print(colorize("[DRY RUN] No changes made.", "cyan"))
        return 0

    if not yes:
        if uninstall_all:
            prompt = "Remove JMo suite AND all security tools? This cannot be undone! [y/N]: "
        else:
            prompt = "Remove JMo suite? (Tools will remain installed) [y/N]: "

        try:
            response = input(prompt).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return 0

        if response != "y":
            print("Cancelled.")
            return 0

    # === Execute removal ===
    print()
    errors = []

    # Remove ~/.jmo
    if jmo_dir.exists():
        try:
            print(f"Removing {jmo_dir}...", end=" ", flush=True)
            shutil.rmtree(jmo_dir)
            print(colorize("done", "green"))
        except Exception as e:
            print(colorize(f"failed: {e}", "red"))
            errors.append(str(e))

    # Uninstall pip package
    if jmo_pip_installed:
        try:
            print("Uninstalling jmo-security pip package...", end=" ", flush=True)
            import subprocess
            result = subprocess.run(
                [sys.executable, "-m", "pip", "uninstall", "-y", "jmo-security"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                print(colorize("done", "green"))
            else:
                print(colorize("failed", "yellow"))
        except Exception as e:
            print(colorize(f"failed: {e}", "red"))
            errors.append(str(e))

    # Remove tools if --all
    if uninstall_all and tools_to_remove:
        print("\nRemoving security tools...")
        _uninstall_tools(tools_to_remove, errors)

        # Remove kubescape dir
        if kubescape_dir.exists():
            try:
                print(f"Removing {kubescape_dir}...", end=" ", flush=True)
                shutil.rmtree(kubescape_dir)
                print(colorize("done", "green"))
            except Exception as e:
                print(colorize(f"failed: {e}", "red"))
                errors.append(str(e))

    # === Summary ===
    print("\n" + "=" * 60)
    if errors:
        print(colorize(f"Completed with {len(errors)} error(s)", "yellow"))
        for err in errors[:3]:
            print(f"  - {err}")
    else:
        if uninstall_all:
            print(colorize("JMo Security completely uninstalled!", "green"))
        else:
            print(colorize("JMo Security suite removed.", "green"))
            print("Security tools remain installed on your system.")
    print("=" * 60)

    return 1 if errors else 0


def _check_pip_package(package: str) -> bool:
    """Check if a pip package is installed."""
    import subprocess
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "show", package],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0
    except Exception:
        return False


def _get_installed_tools() -> list[tuple[str, str]]:
    """
    Get list of installed JMo-managed tools.

    Returns:
        List of (tool_name, install_method) tuples
    """
    from scripts.cli.tool_manager import ToolManager

    tools = []
    manager = ToolManager()

    # Check all tools in registry
    all_statuses = manager.check_all_tools()

    for name, status in all_statuses.items():
        if status.installed:
            # Determine install method
            tool_info = manager.registry.get_tool(name)
            if tool_info:
                if tool_info.pypi_package:
                    tools.append((name, "pip"))
                elif tool_info.npm_package:
                    tools.append((name, "npm"))
                elif tool_info.brew_package:
                    tools.append((name, "brew"))
                else:
                    tools.append((name, "binary"))

    return tools


def _uninstall_tools(tools: list[tuple[str, str]], errors: list[str]) -> None:
    """Uninstall tools by their install method."""
    import subprocess

    from scripts.core.tool_registry import ToolRegistry

    registry = ToolRegistry()

    # Group by method
    pip_tools = []
    npm_tools = []

    for name, method in tools:
        tool_info = registry.get_tool(name)
        if not tool_info:
            continue

        if method == "pip" and tool_info.pypi_package:
            pip_tools.append(tool_info.pypi_package)
        elif method == "npm" and tool_info.npm_package:
            npm_tools.append(tool_info.npm_package)

    # Uninstall pip tools in batch
    if pip_tools:
        try:
            print(f"  Uninstalling pip packages: {', '.join(pip_tools[:5])}{'...' if len(pip_tools) > 5 else ''}")
            result = subprocess.run(
                [sys.executable, "-m", "pip", "uninstall", "-y"] + pip_tools,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                print(colorize("    done", "green"))
            else:
                print(colorize(f"    partial: {result.stderr[:100]}", "yellow"))
        except Exception as e:
            print(colorize(f"    failed: {e}", "red"))
            errors.append(f"pip uninstall: {e}")

    # Uninstall npm tools
    if npm_tools:
        try:
            print(f"  Uninstalling npm packages: {', '.join(npm_tools)}")
            for pkg in npm_tools:
                result = subprocess.run(
                    ["npm", "uninstall", "-g", pkg],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
            print(colorize("    done", "green"))
        except Exception as e:
            print(colorize(f"    failed: {e}", "red"))
            errors.append(f"npm uninstall: {e}")

    # Binary tools - remove from ~/.jmo/bin
    jmo_bin = Path.home() / ".jmo" / "bin"
    if jmo_bin.exists():
        try:
            print(f"  Removing ~/.jmo/bin/...")
            import shutil
            shutil.rmtree(jmo_bin)
            print(colorize("    done", "green"))
        except Exception as e:
            print(colorize(f"    failed: {e}", "red"))
            errors.append(f"binary removal: {e}")

    # Brew tools need manual removal
    brew_tools = [name for name, method in tools if method == "brew"]
    if brew_tools:
        print(colorize(f"\n  NOTE: Homebrew tools must be removed manually:", "yellow"))
        print(f"    brew uninstall {' '.join(brew_tools)}")


def _get_dir_size(path: Path) -> int:
    """Get total size of a directory in bytes."""
    total = 0
    try:
        for item in path.rglob("*"):
            if item.is_file():
                total += item.stat().st_size
    except (OSError, PermissionError):
        pass
    return total


def _format_size(size_bytes: int) -> str:
    """Format size in human-readable form."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
