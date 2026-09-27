"""
CLI command handlers for `jmo tools`.

Provides check, install, update, list, and outdated subcommands
for managing security tool installations.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from scripts.cli.tool_manager import (
    ToolManager,
    ToolStatus,
    print_tool_status_table,
)
from scripts.core.paths import clean_isolated_venvs
from scripts.core.tool_registry import POLICY_ENGINE, TOOL_MATRIX, ToolRegistry

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

            return bool(os.environ.get("TERM") or os.environ.get("WT_SESSION"))
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
    subcommand: str | None = getattr(args, "tools_command", None)

    handlers = {
        "check": cmd_tools_check,
        "install": cmd_tools_install,
        "update": cmd_tools_update,
        "list": cmd_tools_list,
        "outdated": cmd_tools_outdated,
        "uninstall": cmd_tools_uninstall,
        "debug": cmd_tools_debug,
        "clean": cmd_tools_clean,  # Phase 5: Clean isolated venvs
    }

    handler = handlers.get(subcommand) if subcommand else None
    if handler:
        return handler(args)

    # No subcommand - show status summary
    return cmd_tools_check(args)


def _status_json(status: ToolStatus) -> dict:
    """The machine-readable fields of one tool's status."""
    return {
        "installed": status.installed,
        "installed_version": status.installed_version,
        "expected_version": status.expected_version,
        "is_outdated": status.is_outdated,
        "is_critical": status.is_critical,
        "execution_ready": status.execution_ready,
        "binary_path": status.binary_path,
    }


def cmd_tools_check(args: argparse.Namespace) -> int:
    """
    Check tool installation status.

    Usage:
        jmo tools check                    # Every scanner, plus the policy engine
        jmo tools check trivy semgrep      # Check specific tools

    With no tool names the table is the scan matrix (TOOL_MATRIX) and the
    policy engine gets a line of its own below it: opa evaluates policies in
    the report phase and scans nothing, so it is not one of the scanners.

    Returns:
        0 when every checked tool is installed and able to run, 1 otherwise
    """
    manager = ToolManager()
    tools = getattr(args, "tools", None) or []
    output_json = getattr(args, "json", False)

    policy_engine: ToolStatus | None = None
    if tools:
        statuses = {t: manager.check_tool(t) for t in tools}
        title = f"Tool Status ({len(tools)} tools)"
    else:
        statuses = manager.check_matrix()
        policy_engine = manager.check_tool(POLICY_ENGINE)
        title = f"Tool Status ({len(statuses)} scanners)"

    everything = list(statuses.values()) + ([policy_engine] if policy_engine else [])
    # A tool that cannot run contributes nothing to a scan, the same as a
    # missing one, so both fail the check (#788, #1136).
    rc = 0 if all(s.installed and s.execution_ready for s in everything) else 1

    if output_json:
        data: dict = {"tools": {name: _status_json(s) for name, s in statuses.items()}}
        if policy_engine is not None:
            data["policy_engine"] = {
                "name": POLICY_ENGINE,
                **_status_json(policy_engine),
            }
        print(json.dumps(data, indent=2))
        return rc

    # Print table
    print(f"\n{title}\n")
    print_tool_status_table(statuses, colorize, show_hints=True)

    if policy_engine is not None:
        if not policy_engine.installed:
            engine = (
                colorize("MISSING", "red") + f" -> jmo tools install {POLICY_ENGINE}"
            )
        elif not policy_engine.execution_ready:
            engine = colorize("NOT READY", "yellow") + (
                f" - {policy_engine.execution_warning}"
                if policy_engine.execution_warning
                else ""
            )
        else:
            engine = (
                colorize("OK", "green") + f" {policy_engine.installed_version or '-'}"
            )
        print(f"\nPolicy engine: {POLICY_ENGINE}  {engine}")

    missing = [s for s in everything if not s.installed]
    outdated = [s for s in statuses.values() if s.is_outdated]
    # Installed and unable to run. For a scan this is the same outcome as
    # missing - zap without Java exits 1 and writes nothing - so it belongs in
    # the summary and in the exit code, not only in the table (#1136).
    not_ready = [s for s in everything if s.installed and not s.execution_ready]

    print()
    if not_ready:
        print(
            colorize(
                f"{len(not_ready)} tool(s) installed but not able to run",
                "yellow",
            )
        )
        for s in not_ready:
            print(f"  - {s.name}: {s.execution_warning or 'cannot run'}")

    if missing:
        print(colorize(f"{len(missing)} tool(s) missing", "red"))
        print("Run `jmo tools install` to install")

    if outdated:
        critical = [s for s in outdated if s.is_critical]
        msg = f"{len(outdated)} tool(s) outdated"
        if critical:
            msg += f" ({len(critical)} critical)"
        print(colorize(msg, "yellow"))
        print("Run `jmo tools update` to update")

    if not missing and not outdated and not not_ready:
        print(colorize("All tools installed and up to date!", "green"))

    return rc


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
        VERSION_COMMANDS,
        VERSION_PATTERNS,
        VERSION_TIMEOUTS,
        ToolManager,
    )

    tools = getattr(args, "tools", None) or []
    if getattr(args, "all", False) is True:
        tools = list(TOOL_MATRIX)
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
                    encoding="utf-8",
                    errors="replace",
                    timeout=5,
                )
                if file_result.returncode == 0:
                    print(f"File type: {file_result.stdout.strip()}")
            except (
                FileNotFoundError,
                PermissionError,
                subprocess.TimeoutExpired,
                OSError,
            ):
                # 'file' command unavailable: missing (FileNotFoundError) on slim
                # base images without the `file` package, or partial PATH match
                # that resolves to a non-executable (PermissionError on execve).
                # Catch the broader OSError umbrella to cover other edge cases.
                pass
        else:
            print(f"Binary path: {colorize('NOT FOUND', 'red')}")
            print("\nThe tool binary could not be found in PATH or ~/.jmo/bin/")
            continue

        # Determine version command
        if tool_name in VERSION_COMMANDS:
            version_cmd_config = VERSION_COMMANDS[tool_name]
            # Handle platform-specific commands (dict) vs universal commands (list)
            if isinstance(version_cmd_config, dict):
                current_platform = platform.system().lower()
                if current_platform == "darwin":
                    current_platform = "macos"
                cmd_template = version_cmd_config.get(current_platform)
                if not cmd_template:
                    cmd_template = version_cmd_config.get("default")
                if not cmd_template:
                    cmd_template = [binary_path, "--version"]
                cmd = list(cmd_template)
                print(
                    f"Version command: {' '.join(cmd)} (platform: {current_platform})"
                )
            else:
                cmd = list(version_cmd_config)
                print(f"Version command: {' '.join(cmd)}")
            cmd[0] = binary_path
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
        print("\n--- Running version command ---")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                env=manager._get_clean_env(),
            )
            print(f"Exit code: {result.returncode}")
            print(f"\nstdout ({len(result.stdout)} chars):")
            if result.stdout:
                print(f"  {result.stdout[:500]!r}")
            else:
                print("  (empty)")
            print(f"\nstderr ({len(result.stderr)} chars):")
            if result.stderr:
                print(f"  {result.stderr[:500]!r}")
            else:
                print("  (empty)")

            # Try parsing
            output = (result.stdout or "") + (result.stderr or "")
            if output.strip():
                match = pattern.search(output)
                print("\n--- Pattern matching ---")
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
        jmo tools install                     # Install all missing (parallel)
        jmo tools install trivy semgrep       # Install specific tools
        jmo tools install --dry-run           # Show what would be installed
        jmo tools install --print-script      # Print install script
        jmo tools install --sequential        # Install sequentially (slower)
        jmo tools install --jobs 8            # Use 8 parallel workers

    Returns:
        0 on success, 1 on failure
    """
    manager = ToolManager()
    tools_arg = getattr(args, "tools", None) or []
    dry_run = getattr(args, "dry_run", False)
    print_script = getattr(args, "print_script", False)
    yes = getattr(args, "yes", False)
    sequential = getattr(args, "sequential", False)
    jobs = getattr(args, "jobs", 4)
    # Ensure jobs is an integer (handles MagicMock in tests)
    if not isinstance(jobs, int):
        jobs = 4
    max_workers = min(jobs, 8)  # Cap at 8

    force = getattr(args, "force", False)
    # Ensure force is a real bool (handles MagicMock in tests), mirroring the
    # `jobs` guard above. A MagicMock attribute is truthy, so `bool(getattr(...))`
    # silently makes force=True and routes *every* tool into the install list.
    if not isinstance(force, bool):
        force = False

    # Determine which tools to install
    if tools_arg:
        # Specific tools requested
        missing = []
        for t in tools_arg:
            status = manager.check_tool(t)
            if force or not status.installed:
                missing.append(status)
            elif not status.execution_ready:
                # Present but unable to run - an incomplete install, not a
                # finished one. yara reaches this state with its engine
                # installed and no rules, where it would report every scan
                # clean. Say so rather than printing a bare "already installed".
                print(
                    f"{t}: installed ({status.installed_version}) but not ready"
                    f" - {status.execution_warning}"
                )
            else:
                print(f"{t}: already installed ({status.installed_version})")
    else:
        # Every scanner, plus the policy engine: policy evaluation is on by
        # default (jmo.yml policy.auto_evaluate), so a default install that
        # left opa out would leave that step with nothing to run.
        missing = manager.get_missing_tools([*TOOL_MATRIX, POLICY_ENGINE])

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
    if not sequential:
        print(f"Mode: Parallel (max {max_workers} workers)")
    else:
        print("Mode: Sequential")
    print()

    # Dry run mode - show preview and exit (no confirmation needed)
    if dry_run:
        print(colorize("\n[DRY RUN] Would install:", "cyan"))
        for status in missing:
            print(f"  {status.name}: {status.install_hint}")
        return 0

    # Interactive confirmation (only for actual install)
    #
    # `sys.stdin.isatty()` is not a reliable non-interactivity test: under Git
    # Bash on Windows it returns True while stdin is already at EOF, so `input()`
    # ran and raised an unhandled EOFError with a traceback - making `jmo tools
    # install` unusable from CI, cron, Docker builds and any scan runner.
    # EOF means nobody is there to answer, which is the same situation as a
    # non-tty, so it takes the same branch: proceed. (The uninstall prompt below
    # defaults the other way on purpose - it is destructive.)
    if not yes and sys.stdin.isatty():
        try:
            response = input("Proceed with installation? [Y/n] ").strip().lower()
        except EOFError:
            response = ""
        if response and response != "y":
            print("Installation cancelled")
            return 0

    # Actually install
    # Import installer here to avoid circular imports
    from scripts.cli.tool_installer import ToolInstaller, print_install_progress

    installer = ToolInstaller()

    # Install the tools
    if tools_arg:
        # Install specific tools - use sequential mode for specific tools
        from scripts.cli.tool_installer import InstallProgress

        progress = InstallProgress(total=len(missing))
        for status in missing:
            result = installer.install_tool(status.name, force=True)
            progress.add_result(result)
    elif sequential:
        # Sequential installation mode (--sequential flag)
        def progress_callback(tool_name: str, current: int, total: int) -> None:
            print(f"[{current}/{total}] Installing {tool_name}...")

        installer.set_progress_callback(progress_callback)
        progress = installer.install_tools([s.name for s in missing])
    else:
        # Default: Parallel installation mode
        print(
            colorize(f"\n[Parallel] Installing with {max_workers} workers...\n", "cyan")
        )
        progress = installer.install_tools_parallel(
            [s.name for s in missing],
            skip_installed=True,
            max_workers=max_workers,
            show_progress=sys.stdout.isatty(),
        )

    # Print results
    print_install_progress(progress, colorize)

    # Summary
    if progress.failed == 0:
        return 0
    else:
        print("\nSome tools failed to install. Run with --print-script for hints.")
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
    # See cmd_tools_install: isatty() can be True with stdin already at EOF.
    if not yes and sys.stdin.isatty():
        try:
            response = input("Proceed with updates? [Y/n] ").strip().lower()
        except EOFError:
            response = ""
        if response and response != "y":
            print("Update cancelled")
            return 0

    # Actually update (reinstall with force)
    from scripts.cli.tool_installer import (
        InstallProgress,
        ToolInstaller,
        print_install_progress,
    )

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
        print(
            colorize(
                f"\nAll {progress.successful} tool(s) updated successfully!", "green"
            )
        )
        return 0
    else:
        print(
            colorize(
                f"\n{progress.successful} updated, {progress.failed} failed", "yellow"
            )
        )
        return 1


def cmd_tools_list(args: argparse.Namespace) -> int:
    """
    List available tools.

    Usage:
        jmo tools list                    # List all registered tools
    """
    output_json = getattr(args, "json", False)

    registry = ToolRegistry()
    tools = registry.get_all_tools()
    title = f"All registered tools ({len(tools)} tools)"

    if output_json:
        tools_data = [
            {
                "name": t.name,
                "version": t.version,
                "category": t.category,
                "critical": t.critical,
                "description": t.description,
            }
            for t in tools
        ]
        print(json.dumps(tools_data, indent=2))
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
    Show only outdated tools.

    This used to call itself "a shortcut for `jmo tools check --outdated`",
    a flag `jmo tools check` does not define - it exits 2 with
    `unrecognized arguments: --outdated` (#1137). There is no shortcut; this
    subcommand is the only way to ask the question.

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
        if platform == "linux" and tool.apt_package:
            lines.append(f"sudo apt-get install -y {tool.apt_package}")
        elif tool.pypi_package:
            lines.append(f"pip install {tool.pypi_package}")
        else:
            lines.append(f"jmo tools install {status.name}")

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

    uninstall_all = getattr(args, "all", False)
    dry_run = getattr(args, "dry_run", False)
    yes = getattr(args, "yes", False)

    # Collect items to remove
    jmo_dir = Path.home() / ".jmo"

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
        # Directories are listed by name, files with their size.
        #
        # A directory size meant `rglob("*")` plus a `stat()` per file across
        # the whole of `~/.jmo`, before this command printed anything or asked
        # anything. Measured on a machine with the `balanced` toolchain
        # installed, `~/.jmo/tools` alone holds 165,419 files: the command sat
        # silent for **89 seconds** to produce two numbers, and `--dry-run` did
        # not escape it because the listing runs first. Nothing else ever read
        # the sizes - removal is a single `shutil.rmtree` of the whole tree
        # (#1207).
        #
        # A capped walk was considered and rejected: a few thousand files out
        # of 165,419 yields a lower bound two orders of magnitude under the
        # truth, and a wrong number in front of an irreversible delete is worse
        # than no number. A file's size stays, because that is one `stat()` and
        # it is exact.
        for item in jmo_dir.iterdir():
            jmo_items.append(item)
            if item.is_dir():
                print(f"  - {item.name}/")
            else:
                print(f"  - {item.name} ({_format_size(item.stat().st_size)})")

        if not jmo_items:
            print("  (empty)")
    else:
        print("  ~/.jmo not found (already clean)")

    # Check for pip-installed jmo package
    jmo_pip_installed = _check_pip_package("jmo-security")

    if jmo_pip_installed:
        print("  - jmo-security (pip package)")

    # === Part 2: Tools removal (only if --all) ===
    tools_to_remove = []
    if uninstall_all:
        print("\n" + colorize("Security Tools:", "bold"))
        tools_to_remove = _get_installed_tools()

        if tools_to_remove:
            # Group by install method
            pip_tools = [t for t in tools_to_remove if t[1] == "pip"]
            binary_tools = [t for t in tools_to_remove if t[1] == "binary"]

            if pip_tools:
                print(f"  pip: {', '.join(t[0] for t in pip_tools)}")
            if binary_tools:
                print(f"  binary: {', '.join(t[0] for t in binary_tools)}")
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
                encoding="utf-8",
                errors="replace",
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
            encoding="utf-8",
            errors="replace",
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
                else:
                    tools.append((name, "binary"))

    return tools


def _uninstall_tools(tools: list[tuple[str, str]], errors: list[str]) -> None:
    """Uninstall tools by their install method."""
    import subprocess

    from scripts.core.tool_registry import ToolRegistry

    registry = ToolRegistry()

    pip_tools = []

    for name, method in tools:
        tool_info = registry.get_tool(name)
        if not tool_info:
            continue

        if method == "pip" and tool_info.pypi_package:
            pip_tools.append(tool_info.pypi_package)

    # Uninstall pip tools in batch
    if pip_tools:
        try:
            print(
                f"  Uninstalling pip packages: {', '.join(pip_tools[:5])}{'...' if len(pip_tools) > 5 else ''}"
            )
            result = subprocess.run(
                [sys.executable, "-m", "pip", "uninstall", "-y"] + pip_tools,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
            )
            if result.returncode == 0:
                print(colorize("    done", "green"))
            else:
                print(colorize(f"    partial: {result.stderr[:100]}", "yellow"))
        except Exception as e:
            print(colorize(f"    failed: {e}", "red"))
            errors.append(f"pip uninstall: {e}")

    # Binary tools - remove from ~/.jmo/bin
    jmo_bin = Path.home() / ".jmo" / "bin"
    if jmo_bin.exists():
        try:
            print("  Removing ~/.jmo/bin/...")
            import shutil

            shutil.rmtree(jmo_bin)
            print(colorize("    done", "green"))
        except Exception as e:
            print(colorize(f"    failed: {e}", "red"))
            errors.append(f"binary removal: {e}")


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


def cmd_tools_clean(args: argparse.Namespace) -> int:
    """
    Clean isolated virtual environments (Phase 5).

    Removes the isolated venvs of the Python tools (semgrep, checkov).
    Useful when you need to fix a corrupted installation or reclaim disk space.

    Usage:
        jmo tools clean           # Show what would be removed (dry run)
        jmo tools clean --force   # Actually remove the isolated venvs

    Returns:
        0 on success, 1 if errors occurred
    """
    force = getattr(args, "force", False)

    print("\n" + "=" * 60)
    print("  JMo Security - Isolated Venv Cleanup")
    print("=" * 60)

    # Get list of venvs to clean
    if force:
        print(colorize("\nRemoving isolated virtual environments...", "yellow"))
        removed = clean_isolated_venvs(dry_run=False)
    else:
        print("\nDry run - showing what would be removed:")
        removed = clean_isolated_venvs(dry_run=True)

    if not removed:
        print(colorize("\nNo isolated venvs found.", "cyan"))
        print("Location: ~/.jmo/tools/venvs/")
        return 0

    print(f"\n{len(removed)} isolated venv(s):")
    for path in removed:
        if force:
            print(f"  {colorize('[REMOVED]', 'green')} {path}")
        else:
            print(f"  {colorize('[would remove]', 'cyan')} {path}")

    print()
    if force:
        print(colorize(f"Cleaned {len(removed)} isolated venv(s).", "green"))
        print("\nTo reinstall tools in isolated venvs, run:")
        print("  jmo tools install semgrep checkov")
    else:
        print("To actually remove these, run:")
        print(colorize("  jmo tools clean --force", "cyan"))

    print("=" * 60)
    return 0
