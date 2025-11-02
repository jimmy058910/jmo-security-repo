"""Command handlers for 'jmo schedule' subcommands.

This module implements all 8 schedule subcommands:
- create: Create new schedule
- list: List all schedules
- get: Get schedule details
- update: Update schedule
- export: Export workflow file
- install: Install to local cron
- uninstall: Remove from cron
- delete: Delete schedule
- validate: Validate schedule configuration
"""

import json
import sys
from datetime import datetime
from pathlib import Path

import yaml
from croniter import croniter

from scripts.core.schedule_manager import (
    ScheduleManager,
    ScanSchedule,
    ScheduleMetadata,
    ScheduleSpec,
    ScheduleStatus,
    BackendConfig,
    JobTemplateSpec,
)
from scripts.core.workflow_generators import (
    GitHubActionsGenerator,
    GitLabCIGenerator,
)
from scripts.core.cron_installer import (
    CronInstaller,
    UnsupportedPlatformError,
    CronNotAvailableError,
    CronInstallError,
)


def cmd_schedule(args):
    """Handle 'jmo schedule' subcommands.

    Routes to appropriate subcommand handler based on args.schedule_action.
    """
    manager = ScheduleManager()

    try:
        if args.schedule_action == "create":
            return _cmd_schedule_create(args, manager)
        elif args.schedule_action == "list":
            return _cmd_schedule_list(args, manager)
        elif args.schedule_action == "get":
            return _cmd_schedule_get(args, manager)
        elif args.schedule_action == "update":
            return _cmd_schedule_update(args, manager)
        elif args.schedule_action == "export":
            return _cmd_schedule_export(args, manager)
        elif args.schedule_action == "install":
            return _cmd_schedule_install(args, manager)
        elif args.schedule_action == "uninstall":
            return _cmd_schedule_uninstall(args, manager)
        elif args.schedule_action == "delete":
            return _cmd_schedule_delete(args, manager)
        elif args.schedule_action == "validate":
            return _cmd_schedule_validate(args, manager)
        else:
            _error(f"Unknown schedule action: {args.schedule_action}")
            return 1
    except Exception as e:
        _error(str(e))
        return 1


def _cmd_schedule_create(args, manager: ScheduleManager) -> int:
    """Create a new schedule.

    Args:
        args: Parsed command-line arguments
        manager: ScheduleManager instance

    Returns:
        int: 0 on success, 1 on failure
    """
    # Validate cron expression
    try:
        croniter(args.cron)
    except Exception as e:
        _error(f"Invalid cron expression '{args.cron}': {e}")
        return 1

    # Parse labels
    labels = {}
    if args.label:
        for label in args.label:
            if "=" not in label:
                _error(f"Invalid label format '{label}' (expected KEY=VALUE)")
                return 1
            key, value = label.split("=", 1)
            labels[key.strip()] = value.strip()

    # Build targets dictionary
    targets = {}

    # Repositories
    if args.repos_dir:
        targets["repositories"] = {"repos_dir": args.repos_dir}

    # Container images
    if args.image:
        targets["images"] = args.image

    # Web URLs
    if args.url:
        targets["web"] = {"urls": args.url}

    # Validate at least one target
    if not targets:
        _error("No targets specified. Use --repos-dir, --image, or --url")
        return 1

    # Build notifications configuration
    notifications = {"enabled": False, "channels": []}
    if args.slack_webhook:
        notifications = {
            "enabled": True,
            "channels": [
                {
                    "type": "slack",
                    "url": args.slack_webhook,
                    "events": ["failure", "success"],
                }
            ],
        }

    # Create schedule object
    annotations = {}
    if args.description:
        annotations["description"] = args.description
    else:
        annotations["description"] = f"{args.profile.capitalize()} scan"

    schedule = ScanSchedule(
        metadata=ScheduleMetadata(
            name=args.name,
            labels=labels,
            annotations=annotations,
            creationTimestamp=datetime.utcnow().isoformat() + "Z",
        ),
        spec=ScheduleSpec(
            schedule=args.cron,
            timezone=args.timezone,
            suspend=False,
            backend=BackendConfig(
                type=args.backend,
            ),
            jobTemplate=JobTemplateSpec(
                profile=args.profile,
                targets=targets,
                options={},
                results={"retention_days": 90},
                notifications=notifications,
            ),
        ),
        status=ScheduleStatus(),
    )

    # Save schedule
    manager.create(schedule)
    _success(f"Created schedule '{args.name}'")
    _info(f"Backend: {args.backend}")
    _info(f"Cron: {args.cron}")
    _info(f"Profile: {args.profile}")

    # Show next steps
    if args.backend == "github-actions":
        _info("")
        _info("Next steps:")
        _info(
            f"  1. Export workflow: jmo schedule export {args.name} > .github/workflows/jmo-{args.name}.yml"
        )
        _info("  2. Commit and push to GitHub")
    elif args.backend == "gitlab-ci":
        _info("")
        _info("Next steps:")
        _info(
            f"  1. Export workflow: jmo schedule export {args.name} >> .gitlab-ci.yml"
        )
        _info("  2. Commit and push to GitLab")
    elif args.backend == "local-cron":
        _info("")
        _info("Next steps:")
        _info(f"  1. Install to cron: jmo schedule install {args.name}")

    return 0


def _cmd_schedule_list(args, manager: ScheduleManager) -> int:
    """List all schedules with optional filtering."""
    # Parse label filters
    label_filters = {}
    if args.label:
        for label in args.label:
            if "=" not in label:
                _error(f"Invalid label filter '{label}' (expected KEY=VALUE)")
                return 1
            key, value = label.split("=", 1)
            label_filters[key.strip()] = value.strip()

    # Get all schedules
    schedules = manager.list(labels=label_filters if label_filters else None)

    # Apply label filtering (already done above via labels parameter)
    if label_filters:
        filtered = []
        for schedule in schedules:
            match = True
            for key, value in label_filters.items():
                if schedule.metadata.labels.get(key) != value:
                    match = False
                    break
            if match:
                filtered.append(schedule)
        schedules = filtered

    # Output
    if args.format == "table":
        _print_schedules_table(schedules)
    elif args.format == "json":
        data = [s.to_dict() for s in schedules]
        print(json.dumps(data, indent=2))
    elif args.format == "yaml":
        data = [s.to_dict() for s in schedules]
        print(yaml.dump(data, sort_keys=False))

    return 0


def _cmd_schedule_get(args, manager: ScheduleManager) -> int:
    """Get details of a specific schedule."""
    schedule = manager.get(args.name)
    if not schedule:
        _error(f"Schedule '{args.name}' not found")
        return 1

    if args.format == "json":
        print(json.dumps(schedule.to_dict(), indent=2))
    elif args.format == "yaml":
        print(yaml.dump(schedule.to_dict(), sort_keys=False))

    return 0


def _cmd_schedule_update(args, manager: ScheduleManager) -> int:
    """Update an existing schedule."""
    schedule = manager.get(args.name)
    if not schedule:
        _error(f"Schedule '{args.name}' not found")
        return 1

    # Update fields
    if args.cron:
        # Validate new cron expression
        try:
            croniter(args.cron)
        except Exception as e:
            _error(f"Invalid cron expression '{args.cron}': {e}")
            return 1
        schedule.spec.schedule = args.cron

    if args.profile:
        schedule.spec.jobTemplate.profile = args.profile

    if args.suspend:
        schedule.spec.suspend = True
    elif args.resume:
        schedule.spec.suspend = False

    # Save updated schedule
    manager.update(schedule)
    _success(f"Updated schedule '{args.name}'")

    return 0


def _cmd_schedule_export(args, manager: ScheduleManager) -> int:
    """Export schedule as workflow file."""
    schedule = manager.get(args.name)
    if not schedule:
        _error(f"Schedule '{args.name}' not found")
        return 1

    # Determine backend
    backend = args.backend if args.backend else schedule.spec.backend.type

    # Generate workflow
    generator: GitHubActionsGenerator | GitLabCIGenerator
    if backend == "github-actions":
        generator = GitHubActionsGenerator()
        workflow = generator.generate(schedule)
    elif backend == "gitlab-ci":
        generator = GitLabCIGenerator()
        workflow = generator.generate(schedule)
    else:
        _error(
            f"Cannot export backend type '{backend}' (use github-actions or gitlab-ci)"
        )
        return 1

    # Output
    if args.output:
        Path(args.output).write_text(workflow)
        _success(f"Exported to {args.output}")
    else:
        print(workflow, end="")

    return 0


def _cmd_schedule_install(args, manager: ScheduleManager) -> int:
    """Install schedule to local cron."""
    schedule = manager.get(args.name)
    if not schedule:
        _error(f"Schedule '{args.name}' not found")
        return 1

    try:
        installer = CronInstaller()
        installer.install(schedule)
        _success(f"Installed schedule '{args.name}' to crontab")
        _info(f"Cron expression: {schedule.spec.schedule}")
        _info("Verify with: crontab -l")
    except UnsupportedPlatformError as e:
        _error(str(e))
        return 1
    except (CronNotAvailableError, CronInstallError) as e:
        _error(f"Cron installation failed: {e}")
        return 1

    return 0


def _cmd_schedule_uninstall(args, manager: ScheduleManager) -> int:
    """Remove schedule from local cron."""
    try:
        installer = CronInstaller()
        if installer.uninstall(args.name):
            _success(f"Removed schedule '{args.name}' from crontab")
        else:
            _error(f"Schedule '{args.name}' not found in crontab")
            return 1
    except UnsupportedPlatformError as e:
        _error(str(e))
        return 1
    except (CronNotAvailableError, CronInstallError) as e:
        _error(f"Cron removal failed: {e}")
        return 1

    return 0


def _cmd_schedule_delete(args, manager: ScheduleManager) -> int:
    """Delete a schedule."""
    schedule = manager.get(args.name)
    if not schedule:
        _error(f"Schedule '{args.name}' not found")
        return 1

    # Confirmation prompt (unless --force)
    if not args.force:
        _warn(f"Delete schedule '{args.name}'? This cannot be undone.")
        response = input("Type 'yes' to confirm: ")
        if response.lower() != "yes":
            _info("Cancelled")
            return 0

    manager.delete(args.name)
    _success(f"Deleted schedule '{args.name}'")

    return 0


def _cmd_schedule_validate(args, manager: ScheduleManager) -> int:
    """Validate schedule configuration."""
    schedule = manager.get(args.name)
    if not schedule:
        _error(f"Schedule '{args.name}' not found")
        return 1

    # Validate cron expression
    try:
        croniter(schedule.spec.schedule)
        _success("Cron expression valid")
    except Exception as e:
        _error(f"Invalid cron expression: {e}")
        return 1

    # Validate targets
    if not schedule.spec.jobTemplate.targets:
        _error("No targets configured")
        return 1
    _success(f"Targets configured: {list(schedule.spec.jobTemplate.targets.keys())}")

    # Validate backend
    if schedule.spec.backend.type not in ("github-actions", "gitlab-ci", "local-cron"):
        _error(f"Unknown backend type: {schedule.spec.backend.type}")
        return 1
    _success(f"Backend valid: {schedule.spec.backend.type}")

    _success("Schedule configuration valid")
    return 0


# Utility functions for colored output


def _print_schedules_table(schedules: list[ScanSchedule]) -> None:
    """Print schedules in table format."""
    if not schedules:
        _info("No schedules found")
        return

    # Header
    print(f"{'NAME':<20} {'BACKEND':<15} {'PROFILE':<10} {'CRON':<20} {'STATUS':<10}")
    print("-" * 80)

    # Rows
    for schedule in schedules:
        name = schedule.metadata.name[:19]
        backend = schedule.spec.backend.type[:14]
        profile = schedule.spec.jobTemplate.profile[:9]
        cron = schedule.spec.schedule[:19]
        status = "SUSPENDED" if schedule.spec.suspend else "ACTIVE"

        print(f"{name:<20} {backend:<15} {profile:<10} {cron:<20} {status:<10}")


def _success(msg: str) -> None:
    """Print success message in green."""
    print(f"\x1b[32m✓\x1b[0m {msg}", file=sys.stderr)


def _info(msg: str) -> None:
    """Print info message."""
    print(f"  {msg}", file=sys.stderr)


def _warn(msg: str) -> None:
    """Print warning message in yellow."""
    print(f"\x1b[33m⚠\x1b[0m {msg}", file=sys.stderr)


def _error(msg: str) -> None:
    """Print error message in red."""
    print(f"\x1b[31m✗\x1b[0m {msg}", file=sys.stderr)
