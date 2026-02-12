#!/usr/bin/env python3
"""
Migrate state from old files to unified-state.json.

This script reads:
- audit-state.json (audit history and cooldowns)
- wizard-scan-progress.md (wizard testing state)
- IMPLEMENTATION_PLAN.md (task counts)

And consolidates them into unified-state.json.

Run once to migrate, then the loop.ps1 will use unified-state.json exclusively.
"""

import json
import re
from datetime import datetime
from pathlib import Path


def parse_wizard_progress(content: str) -> dict:
    """Parse wizard-scan-progress.md and extract state."""
    state = {
        "status": "not_started",
        "consecutive_successes": 0,
        "last_run": None,
        "last_duration_seconds": 0,
        "last_tools_ok": 0,
        "last_tools_failed": 0,
        "last_findings": 0,
        "blocking_issue": None,
    }

    # Parse iteration count
    if match := re.search(r"Iteration Count\s*\|\s*(\d+)", content):
        pass  # Just for validation

    # Parse consecutive successes
    if match := re.search(r"Consecutive Successes\s*\|\s*(\d+)", content):
        state["consecutive_successes"] = int(match.group(1))

    # Parse status
    if match := re.search(r"Status\s*\|\s*(\w+)", content):
        raw_status = match.group(1).upper()
        status_map = {
            "NOT_STARTED": "not_started",
            "IN_PROGRESS": "in_progress",
            "COMPLETE": "passing",
            "FAILED": "failing",
            "PASSING": "passing",
        }
        state["status"] = status_map.get(raw_status, "in_progress")

    # Parse last iteration details
    if match := re.search(r"\*\*Date:\*\*\s*(.+)", content):
        try:
            date_str = match.group(1).strip()
            # Parse date like "2026-02-01 21:28"
            dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M")
            state["last_run"] = dt.isoformat() + "Z"
        except ValueError:
            pass

    if match := re.search(r"\*\*Duration:\*\*\s*~?(\d+)", content):
        state["last_duration_seconds"] = int(match.group(1))

    if match := re.search(r"\*\*Tools Run:\*\*\s*(\d+)/(\d+)", content):
        state["last_tools_ok"] = int(match.group(1))

    if match := re.search(r"\*\*Tools Failed:\*\*\s*(\d+)", content):
        state["last_tools_failed"] = int(match.group(1))

    if match := re.search(r"\*\*Findings Count:\*\*\s*(\d+)", content):
        state["last_findings"] = int(match.group(1))

    # Parse blocking issue from Open Issues table
    if match := re.search(r"\|\s*(TASK-\d+)\s*\|.*?\|\s*High\s*\|", content):
        state["blocking_issue"] = match.group(1)

    return state


def parse_implementation_plan(content: str) -> dict:
    """Parse IMPLEMENTATION_PLAN.md and count tasks."""
    tasks = {
        "total": 0,
        "open": 0,
        "in_progress": 0,
        "resolved": 0,
        "by_tag": {
            "WIZARD-HANG": 0,
            "WIZARD-CRASH": 0,
            "WIZARD-CONFIG": 0,
            "WIZARD-OUTPUT": 0,
            "BUG": 0,
            "COVERAGE": 0,
            "SECURITY": 0,
        },
    }

    # Count tasks by status
    tasks["total"] = len(re.findall(r"### TASK-\d+", content))
    tasks["open"] = len(re.findall(r"\*\*Status:\*\*\s*Open(?!\s*\|)", content))
    tasks["in_progress"] = len(
        re.findall(r"\*\*Status:\*\*\s*In Progress(?!\s*\|)", content)
    )
    tasks["resolved"] = len(re.findall(r"\*\*Status:\*\*\s*Resolved(?!\s*\|)", content))

    # Count by tag - only count open tasks with each tag
    for tag in tasks["by_tag"]:
        tasks["by_tag"][tag] = len(
            re.findall(
                rf"### TASK-\d+:.*?\[{tag}\].*?\*\*Status:\*\*\s*Open",
                content,
                re.DOTALL,
            )
        )

    return tasks


def migrate():
    """Migrate old state files to unified-state.json."""
    ralph_dir = Path(__file__).parent

    # Load existing unified state as template
    unified_file = ralph_dir / "unified-state.json"
    if unified_file.exists():
        with open(unified_file) as f:
            unified = json.load(f)
    else:
        # Create default structure (v2.1 - no cooldowns)
        unified = {
            "version": "2.1.0",
            "description": "Unified state for Ralph Loop auto mode (dual-phase cycling)",
            "last_updated": datetime.now().isoformat() + "Z",
            "wizard_scan": {
                "repo": {},
                "image": {},
                "required_successes": 3,
            },
            "full_audit": {},
            "tasks": {},
            "completion": {},
        }

    # Migrate audit-state.json
    audit_file = ralph_dir / "audit-state.json"
    if audit_file.exists():
        print(f"Reading {audit_file}...")
        with open(audit_file) as f:
            audit_state = json.load(f)

        # Copy audits to full_audit
        if "audits" in audit_state:
            unified["full_audit"] = audit_state["audits"]

    # Migrate wizard-scan-progress.md
    wizard_file = ralph_dir / "wizard-scan-progress.md"
    if wizard_file.exists():
        print(f"Reading {wizard_file}...")
        with open(wizard_file) as f:
            wizard_content = f.read()

        repo_state = parse_wizard_progress(wizard_content)
        unified["wizard_scan"]["repo"] = repo_state

        # Image mode starts fresh (not in old format)
        unified["wizard_scan"]["image"] = {
            "status": "not_started",
            "consecutive_successes": 0,
            "last_run": None,
            "last_duration_seconds": 0,
            "last_tools_ok": 0,
            "last_tools_failed": 0,
            "last_findings": 0,
            "blocking_issue": None,
        }

    # Migrate IMPLEMENTATION_PLAN.md task counts
    plan_file = ralph_dir / "IMPLEMENTATION_PLAN.md"
    if plan_file.exists():
        print(f"Reading {plan_file}...")
        with open(plan_file) as f:
            plan_content = f.read()

        unified["tasks"] = parse_implementation_plan(plan_content)

    # Calculate completion status (v2.1 - no cooldown checks)
    repo = unified["wizard_scan"].get("repo", {})
    image = unified["wizard_scan"].get("image", {})
    tasks = unified.get("tasks", {})

    unified["completion"] = {
        "wizard_repo_passing": repo.get("consecutive_successes", 0) >= 3,
        "wizard_image_passing": image.get("consecutive_successes", 0) >= 3,
        "no_open_tasks": tasks.get("open", 1) == 0,
        "is_complete": False,  # Calculated below
    }

    # Overall completion (session-based, no cooldowns)
    c = unified["completion"]
    c["is_complete"] = (
        c["wizard_repo_passing"] and c["wizard_image_passing"] and c["no_open_tasks"]
    )

    # Update timestamp
    unified["last_updated"] = datetime.now().isoformat() + "Z"

    # Write unified state
    print(f"Writing {unified_file}...")
    with open(unified_file, "w") as f:
        json.dump(unified, f, indent=2)

    print("\nMigration complete!")
    print(f"  Repo wizard: {repo.get('consecutive_successes', 0)}/3 successes")
    print(f"  Image wizard: {image.get('consecutive_successes', 0)}/3 successes")
    print(f"  Open tasks: {tasks.get('open', 0)}")
    print(f"  Complete: {c['is_complete']}")


if __name__ == "__main__":
    migrate()
