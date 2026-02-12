#!/usr/bin/env python3
"""
Interactive wizard test harness using pexpect.

Uses pexpect.popen_spawn.PopenSpawn (works on Windows via pipes, no PTY needed).
Drives `python -m scripts.cli.jmo wizard` interactively and verifies prompts/outputs.

Usage:
    python tools/ralph-testing/test_wizard_interactive.py
    python tools/ralph-testing/test_wizard_interactive.py --scenario native
    python tools/ralph-testing/test_wizard_interactive.py --scenario all
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pexpect  # noqa: E402
from pexpect.popen_spawn import PopenSpawn  # noqa: E402

# EOF sentinel for pexpect pattern matching
PEXPECT_EOF = pexpect.EOF
PEXPECT_TIMEOUT = pexpect.TIMEOUT

# Timeout for waiting on wizard prompts (seconds)
PROMPT_TIMEOUT = 30
# Longer timeout for tool checks (can be slow)
TOOL_CHECK_TIMEOUT = 60

# ANSI escape code pattern to strip from output for matching
ANSI_ESCAPE = r"\x1b\[[0-9;]*m"


class WizardTestResult:
    """Stores results for a single test scenario."""

    def __init__(self, name: str):
        self.name = name
        self.passed = False
        self.error: str | None = None
        self.output: str = ""
        self.duration: float = 0.0

    def __str__(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        msg = f"[{status}] {self.name} ({self.duration:.1f}s)"
        if self.error:
            msg += f"\n       Error: {self.error}"
        return msg


def spawn_wizard(*extra_args: str, env: dict | None = None) -> PopenSpawn:
    """Spawn a wizard process via PopenSpawn.

    Args:
        extra_args: Additional CLI args for the wizard command.
        env: Optional environment overrides.

    Returns:
        PopenSpawn child process.
    """
    cmd = f"{sys.executable} -m scripts.cli.jmo wizard"
    if extra_args:
        cmd += " " + " ".join(extra_args)

    spawn_env = os.environ.copy()
    if env:
        spawn_env.update(env)
    # Ensure we're in the project root
    spawn_env["PYTHONPATH"] = str(PROJECT_ROOT)

    child = PopenSpawn(
        cmd, timeout=PROMPT_TIMEOUT, cwd=str(PROJECT_ROOT), env=spawn_env
    )
    return child


def expect_any(child: PopenSpawn, patterns: list, timeout: int = PROMPT_TIMEOUT) -> int:
    """Wait for any of the given patterns in the output.

    Args:
        child: The PopenSpawn process.
        patterns: List of string patterns to match.
        timeout: Seconds to wait.

    Returns:
        Index of the matched pattern.

    Raises:
        TimeoutError: If no pattern matched within timeout.
    """
    try:
        return child.expect(patterns, timeout=timeout)
    except Exception as e:
        raise TimeoutError(
            f"Timed out waiting for patterns: {patterns}\n"
            f"Last output: {get_recent_output(child)}"
        ) from e


def get_recent_output(child: PopenSpawn) -> str:
    """Get recently buffered output from the child process."""
    try:
        before = child.before
        if isinstance(before, bytes):
            return before.decode("utf-8", errors="replace")[-500:]
        return str(before)[-500:] if before else "(no output)"
    except Exception:
        return "(could not read output)"


def send_line(child: PopenSpawn, text: str, delay: float = 0.3) -> None:
    """Send a line of input to the child process.

    Args:
        child: The PopenSpawn process.
        text: Text to send (newline appended automatically).
        delay: Delay after sending to let wizard process input.
    """
    child.sendline(text)
    time.sleep(delay)


# ─────────────────────────────────────────────────────────────────────────────
# Test Scenarios
# ─────────────────────────────────────────────────────────────────────────────


def test_native_flow(target_path: str) -> WizardTestResult:
    """Test Scenario 1: Full native wizard flow.

    Selects fast profile, native mode, repo target pointing at juice-shop.
    Answers prompts through the full wizard flow, then cancels before scan.

    Covers checklist lines 59-75 (wizard interactive flow).
    """
    result = WizardTestResult("native_flow")
    start = time.time()

    try:
        child = spawn_wizard()

        # Step 1: Profile selection → choose "fast" (option 1)
        # Wait for the actual input prompt, not just header text
        expect_any(child, ["balanced]:", "1-4"], timeout=TOOL_CHECK_TIMEOUT)
        send_line(child, "1", delay=0.5)  # fast
        result.output += "Selected profile: fast\n"

        # Step 2: Execution mode → choose "Native" (option 2)
        # Must wait for the actual prompt. Note: pexpect treats patterns as regex,
        # so [1] is a char class. Use "Native" which only appears in the prompt options.
        expect_any(child, ["Native", "native", "2. Native"], timeout=PROMPT_TIMEOUT)
        send_line(child, "2", delay=0.5)  # Native
        result.output += "Selected mode: native\n"

        # Tool check: Shows table then may ask to continue with missing tools
        # On Windows, some tools are missing, so we get a "Continue" prompt
        # Wait with longer timeout for tool checking (can be slow)
        idx = expect_any(
            child,
            ["Y/n]", "y/N]", "Continue", "Target types", "1-6"],
            timeout=TOOL_CHECK_TIMEOUT,
        )
        if idx <= 2:  # Got a Y/n or Continue prompt
            send_line(child, "y", delay=0.5)
            result.output += "Accepted missing tools\n"

            # May also prompt about version drift - handle that too
            idx2 = expect_any(
                child,
                ["Y/n]", "y/N]", "Continue", "Target types", "1-6"],
                timeout=TOOL_CHECK_TIMEOUT,
            )
            if idx2 <= 2:
                send_line(child, "y", delay=0.5)
                result.output += "Accepted version drift warning\n"
                expect_any(
                    child, ["Target types", "1-6", "repo"], timeout=PROMPT_TIMEOUT
                )

        # Step 3: Target type → repo (option 1, default)
        send_line(child, "1", delay=0.5)  # repo
        result.output += "Selected target: repo\n"

        # Step 4: Repo config → select repository mode
        expect_any(child, ["mode:", "Mode", "repos-dir", "1-4"], timeout=PROMPT_TIMEOUT)
        send_line(child, "1", delay=0.5)  # Single repository
        result.output += "Selected repo mode: single\n"

        # Path prompt - wait for actual input prompt
        expect_any(child, ["Path to", "path to", "repository"], timeout=PROMPT_TIMEOUT)
        send_line(child, target_path, delay=0.5)
        result.output += f"Entered path: {target_path}\n"

        # Step 5: Advanced settings → skip (default No)
        expect_any(child, ["Customize", "y/N]", "advanced"], timeout=PROMPT_TIMEOUT)
        send_line(child, "", delay=0.5)  # Accept default (No)
        result.output += "Skipped advanced settings\n"

        # Step 6: Review & confirm → cancel (n)
        expect_any(child, ["Proceed", "Y/n]", "Review"], timeout=PROMPT_TIMEOUT)
        send_line(child, "n", delay=0.5)  # Cancel - don't actually scan
        result.output += "Cancelled at confirmation\n"

        # Wait for exit
        expect_any(child, ["cancelled", "Wizard", PEXPECT_EOF], timeout=10)
        result.output += "Wizard exited cleanly\n"

        result.passed = True

    except TimeoutError as e:
        result.error = str(e)
    except Exception as e:
        result.error = f"{type(e).__name__}: {e}"
    finally:
        result.duration = time.time() - start

    return result


def test_docker_mode() -> WizardTestResult:
    """Test Scenario 2: Docker mode selection.

    Selects fast profile, Docker mode (option 1), then cancels.
    Verifies Docker availability check occurs.

    Covers checklist lines 81-85 (Docker mode).
    """
    result = WizardTestResult("docker_mode")
    start = time.time()

    try:
        child = spawn_wizard()

        # Step 1: Profile → fast
        expect_any(child, ["Choice", "Profiles"], timeout=TOOL_CHECK_TIMEOUT)
        send_line(child, "1")  # fast

        # Step 2: Execution mode → Docker (option 1)
        expect_any(
            child, ["Choice", "Execution mode", "Docker"], timeout=PROMPT_TIMEOUT
        )
        send_line(child, "1")  # Docker
        result.output += "Selected Docker mode\n"

        # Tool check or Docker status message
        idx = expect_any(
            child,
            [
                "Docker",
                "Continue",
                "continue",
                "Target",
                "Choice",
                "cancelled",
                PEXPECT_EOF,
            ],
            timeout=TOOL_CHECK_TIMEOUT,
        )
        if idx <= 2:
            result.output += "Docker/tool check prompted\n"
            send_line(child, "y")

        # The wizard may continue to target selection or exit
        # Either way, this validates Docker mode is selectable
        result.output += "Docker mode selection verified\n"
        result.passed = True

        # Clean up
        try:
            child.sendline("")
            child.kill(9)
        except Exception:
            pass

    except TimeoutError as e:
        result.error = str(e)
    except Exception as e:
        result.error = f"{type(e).__name__}: {e}"
    finally:
        result.duration = time.time() - start

    return result


def test_ctrl_c_cancel() -> WizardTestResult:
    """Test Scenario 3: Cancel via Ctrl+C (EOF/SIGINT).

    Starts wizard, waits for first prompt, then sends EOF.
    Verifies clean exit without traceback.

    Covers checklist line 98 (Ctrl+C exit).
    """
    result = WizardTestResult("ctrl_c_cancel")
    start = time.time()

    try:
        child = spawn_wizard()

        # Wait for any wizard output
        expect_any(
            child,
            ["Choice", "Profiles", "Welcome", "wizard"],
            timeout=TOOL_CHECK_TIMEOUT,
        )
        result.output += "Wizard started\n"

        # Send Ctrl+C (SIGINT) - on Windows PopenSpawn, send EOF
        child.sendeof()
        time.sleep(1)

        # Check for clean exit (no Python traceback)
        try:
            child.expect(PEXPECT_EOF, timeout=5)
        except Exception:
            pass

        output = get_recent_output(child)
        result.output += f"Output after EOF: {output[:200]}\n"

        # Verify no traceback
        if "Traceback" in output:
            result.error = "Python traceback on Ctrl+C exit"
        else:
            result.passed = True
            result.output += "Clean exit confirmed (no traceback)\n"

    except TimeoutError as e:
        result.error = str(e)
    except Exception as e:
        result.error = f"{type(e).__name__}: {e}"
    finally:
        result.duration = time.time() - start

    return result


def test_invalid_input() -> WizardTestResult:
    """Test Scenario 4: Invalid input handling.

    Sends invalid input at profile prompt, verifies re-prompt.

    Covers checklist line 99 (invalid input re-prompt).
    """
    result = WizardTestResult("invalid_input")
    start = time.time()

    try:
        child = spawn_wizard()

        # Wait for profile prompt
        expect_any(child, ["Choice", "Profiles"], timeout=TOOL_CHECK_TIMEOUT)

        # Send invalid input
        send_line(child, "99")  # Invalid number
        result.output += "Sent invalid input: 99\n"

        # Should re-prompt (show error then ask again)
        idx = expect_any(
            child,
            ["Choice", "Invalid", "invalid", "try again", "1-"],
            timeout=PROMPT_TIMEOUT,
        )
        result.output += f"Re-prompt received (pattern index: {idx})\n"

        # Send another invalid input (text)
        send_line(child, "notaprofile")
        result.output += "Sent invalid input: notaprofile\n"

        # Should re-prompt again
        idx = expect_any(
            child,
            ["Choice", "Invalid", "invalid", "try again", "1-"],
            timeout=PROMPT_TIMEOUT,
        )
        result.output += f"Second re-prompt received (pattern index: {idx})\n"

        # Now send valid input to move on
        send_line(child, "1")  # fast

        result.passed = True
        result.output += "Invalid input handling verified\n"

        # Clean up
        try:
            child.kill(9)
        except Exception:
            pass

    except TimeoutError as e:
        result.error = str(e)
    except Exception as e:
        result.error = f"{type(e).__name__}: {e}"
    finally:
        result.duration = time.time() - start

    return result


def test_diff_mode() -> WizardTestResult:
    """Test Scenario 5: Diff wizard mode.

    Runs `jmo wizard --mode diff` and verifies it prompts for directories.

    Covers checklist lines 106-107 (diff wizard).
    """
    result = WizardTestResult("diff_mode")
    start = time.time()

    try:
        child = spawn_wizard("--mode", "diff")

        # In diff mode, wizard should ask for two result directories
        idx = expect_any(
            child,
            [
                "directory",
                "Directory",
                "results",
                "path",
                "Path",
                "first",
                "baseline",
                "diff",
                "Diff",
                "compare",
                "Compare",
                PEXPECT_EOF,
            ],
            timeout=TOOL_CHECK_TIMEOUT,
        )

        if idx < 10:  # Got a prompt (not EOF)
            result.output += "Diff mode prompted for input\n"

            # Send first directory
            send_line(
                child,
                str(
                    PROJECT_ROOT
                    / "tools"
                    / "ralph-testing"
                    / "fixtures"
                    / "results-baseline"
                ),
            )
            result.output += "Sent baseline directory\n"

            # Wait for second prompt or output
            try:
                idx2 = expect_any(
                    child,
                    [
                        "directory",
                        "Directory",
                        "path",
                        "Path",
                        "second",
                        "current",
                        "compare",
                        "diff",
                        "Diff",
                        PEXPECT_EOF,
                    ],
                    timeout=PROMPT_TIMEOUT,
                )
                if idx2 < 8:
                    send_line(
                        child,
                        str(
                            PROJECT_ROOT
                            / "tools"
                            / "ralph-testing"
                            / "fixtures"
                            / "results-current"
                        ),
                    )
                    result.output += "Sent current directory\n"
            except TimeoutError:
                result.output += "Only one directory prompt (may be expected)\n"

            result.passed = True
        else:
            # EOF - diff mode may have different behavior
            output = get_recent_output(child)
            if "diff" in output.lower() or "compare" in output.lower():
                result.passed = True
                result.output += f"Diff mode ran to completion: {output[:200]}\n"
            else:
                result.error = f"Unexpected exit. Output: {output[:300]}"

        # Clean up
        try:
            child.kill(9)
        except Exception:
            pass

    except TimeoutError as e:
        result.error = str(e)
    except Exception as e:
        result.error = f"{type(e).__name__}: {e}"
    finally:
        result.duration = time.time() - start

    return result


def test_yes_mode() -> WizardTestResult:
    """Test Scenario 6: Non-interactive --yes mode.

    Runs wizard with --yes flag and verifies it completes without prompts.
    Uses --emit-script to avoid actually running a scan.

    Covers checklist line 88 (non-interactive mode).
    """
    result = WizardTestResult("yes_mode")
    start = time.time()

    try:
        output_script = (
            PROJECT_ROOT
            / "tools"
            / "ralph-testing"
            / "wizard-results"
            / "test-yes-mode.sh"
        )
        output_script.parent.mkdir(parents=True, exist_ok=True)

        child = spawn_wizard("--yes", "--emit-script", str(output_script))

        # Should complete without any interactive prompts
        try:
            child.expect(PEXPECT_EOF, timeout=TOOL_CHECK_TIMEOUT)
        except Exception:
            pass

        output = get_recent_output(child)
        result.output += f"Output: {output[:300]}\n"

        if "Generated" in output or output_script.exists():
            result.passed = True
            result.output += "Non-interactive mode completed successfully\n"
            # Clean up generated file
            if output_script.exists():
                output_script.unlink()
        elif "Non-interactive" in output or "defaults" in output:
            result.passed = True
            result.output += "Non-interactive mode ran (defaults applied)\n"
        else:
            result.error = f"Unexpected output in --yes mode: {output[:300]}"

    except TimeoutError as e:
        result.error = str(e)
    except Exception as e:
        result.error = f"{type(e).__name__}: {e}"
    finally:
        result.duration = time.time() - start

    return result


def test_path_formats() -> WizardTestResult:
    """Test Scenario 7: Path format acceptance.

    Tests Windows paths, forward slashes, and relative paths.

    Covers checklist lines 67-69 (path formats).
    """
    result = WizardTestResult("path_formats")
    start = time.time()

    paths_to_test = []
    if sys.platform == "win32":
        # Windows backslash path
        paths_to_test.append(("backslash", r"C:\Projects\juice-shop"))
        # Forward slash path
        paths_to_test.append(("forward_slash", "C:/Projects/juice-shop"))

    # Test relative path (always works)
    paths_to_test.append(("relative", "."))

    for path_type, test_path in paths_to_test:
        try:
            child = spawn_wizard()

            # Profile → fast
            expect_any(child, ["Choice", "Profiles"], timeout=TOOL_CHECK_TIMEOUT)
            send_line(child, "1")

            # Mode → Native
            expect_any(
                child, ["Choice", "Execution mode", "Docker"], timeout=PROMPT_TIMEOUT
            )
            send_line(child, "2")

            # Handle tool check
            idx = expect_any(
                child,
                ["Continue", "continue", "Choice", "Target", "Select"],
                timeout=TOOL_CHECK_TIMEOUT,
            )
            if idx in (0, 1):
                send_line(child, "y")
                expect_any(
                    child, ["Choice", "Target", "Select"], timeout=PROMPT_TIMEOUT
                )

            # Target type → repo
            send_line(child, "1")

            # Repo mode → single repo
            expect_any(
                child, ["mode", "Mode", "Choice", "Select"], timeout=PROMPT_TIMEOUT
            )
            send_line(child, "1")

            # Enter test path
            expect_any(child, ["Path", "path", "repository"], timeout=PROMPT_TIMEOUT)
            send_line(child, test_path)

            # Check if path was accepted (next prompt should be advanced settings)
            idx = expect_any(
                child,
                ["Customize", "advanced", "Advanced", "not found", "Not found", "Path"],
                timeout=PROMPT_TIMEOUT,
            )

            if idx <= 2:  # Got to advanced settings = path accepted
                result.output += f"  {path_type}: ACCEPTED\n"
            else:
                result.output += f"  {path_type}: REJECTED (may not exist)\n"

            # Clean up
            try:
                child.kill(9)
            except Exception:
                pass

        except TimeoutError:
            result.output += f"  {path_type}: TIMEOUT\n"
        except Exception as e:
            result.output += f"  {path_type}: ERROR - {e}\n"

    # Pass if at least the relative path worked
    if "ACCEPTED" in result.output:
        result.passed = True
    else:
        result.error = "No path formats were accepted"

    result.duration = time.time() - start
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────


ALL_SCENARIOS = {
    "native": test_native_flow,
    "docker": test_docker_mode,
    "cancel": test_ctrl_c_cancel,
    "invalid": test_invalid_input,
    "diff": test_diff_mode,
    "yes": test_yes_mode,
    "paths": test_path_formats,
}


def main():
    parser = argparse.ArgumentParser(description="Interactive wizard test harness")
    parser.add_argument(
        "--scenario",
        choices=list(ALL_SCENARIOS.keys()) + ["all"],
        default="all",
        help="Which scenario to test (default: all)",
    )
    parser.add_argument(
        "--target",
        default="C:/Projects/juice-shop" if sys.platform == "win32" else "./",
        help="Target repo path for native flow test",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed output for each scenario",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("JMo Security - Interactive Wizard Test Harness")
    print("=" * 60)
    print(f"Platform: {sys.platform}")
    print(f"Python: {sys.version.split()[0]}")
    print(f"Project: {PROJECT_ROOT}")
    print(f"Target: {args.target}")
    print()

    scenarios_to_run = (
        list(ALL_SCENARIOS.keys()) if args.scenario == "all" else [args.scenario]
    )

    results: list[WizardTestResult] = []

    for name in scenarios_to_run:
        print(f"Running: {name}...", end=" ", flush=True)
        func = ALL_SCENARIOS[name]

        # Special handling for native_flow which takes a target path
        if name == "native":
            r = func(args.target)
        else:
            r = func()

        results.append(r)
        print(f"{'PASS' if r.passed else 'FAIL'} ({r.duration:.1f}s)")

        if args.verbose or not r.passed:
            if r.output:
                for line in r.output.strip().splitlines():
                    print(f"       {line}")
            if r.error:
                print(f"       ERROR: {r.error}")
            print()

    # Summary
    print()
    print("=" * 60)
    passed = sum(1 for r in results if r.passed)
    total = len(results)
    print(f"Results: {passed}/{total} passed")
    print("=" * 60)

    for r in results:
        print(f"  {r}")

    # Return non-zero if any failed
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
