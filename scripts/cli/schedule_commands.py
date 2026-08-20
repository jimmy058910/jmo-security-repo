"""Command handlers for 'jmo schedule' subcommands.

This module implements all 9 schedule subcommands:
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

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import yaml
from croniter import croniter

from scripts.core.cron_installer import (
    CronInstaller,
    CronInstallError,
    CronNotAvailableError,
    UnsupportedPlatformError,
)
from scripts.core.schedule_manager import (
    BackendConfig,
    JobTemplateSpec,
    ScanSchedule,
    ScheduleManager,
    ScheduleMetadata,
    ScheduleSpec,
    ScheduleStatus,
)
from scripts.core.unicode_utils import safe_print
from scripts.core.validation import SCHEDULE_NAME_PATTERN
from scripts.core.workflow_generators import (
    GitHubActionsGenerator,
    GitLabCIGenerator,
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
    # Validate the name here, at creation, rather than only at `install`.
    #
    # `CronInstaller.install` has always called validate_schedule_name -- but
    # `create` called nothing, so every name the installer rejects was accepted
    # and persisted: "evil; rm -rf /", "../../etc/passwd", "has space",
    # "9starts-with-digit" and names over 64 characters all stored at rc 0.
    # The failure only appeared later, on Linux, at install time; on Windows it
    # could not appear at all. Rejecting at the point of entry is where the
    # user can still fix it.
    # Matched against SCHEDULE_NAME_PATTERN rather than by calling
    # validate_schedule_name(): that predicate also logs at ERROR, which would
    # print the same rejection twice -- once as a JSON log line, once as the
    # message below. The rule itself still lives in exactly one place, and
    # test_schedule_name_gate_matches_installer pins this gate to the
    # installer's so the two cannot drift apart.
    if not SCHEDULE_NAME_PATTERN.match(args.name or ""):
        _error(
            f"Invalid schedule name '{args.name}'. Names must start with a "
            f"letter, be 1-64 characters, and contain only letters, digits, "
            f"hyphens or underscores."
        )
        return 1

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
            creationTimestamp=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
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

    _warn_nonstandard_cron(args.cron)
    _warn_timezone_ignored(args.backend, args.timezone)

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
    schedules = manager.list(labels=label_filters or None)

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

    # An update with no field to update is a mistake, not a no-op. It used to
    # bump `metadata.generation`, rewrite schedules.json and report "Updated
    # schedule 'x'" having changed nothing a user could name -- a success
    # message for work that did not happen, which is the one thing this
    # command must never produce.
    if not (args.cron or args.profile or args.suspend or args.resume):
        _error(
            f"Nothing to update for '{args.name}'. Pass at least one of "
            f"--cron, --profile, --suspend or --resume."
        )
        return 1

    # Update fields
    if args.cron:
        # Validate new cron expression
        try:
            croniter(args.cron)
        except Exception as e:
            _error(f"Invalid cron expression '{args.cron}': {e}")
            return 1
        _warn_nonstandard_cron(args.cron)
        schedule.spec.schedule = args.cron

    if args.profile:
        schedule.spec.jobTemplate.profile = args.profile

    if args.suspend:
        schedule.spec.suspend = True
    elif args.resume:
        schedule.spec.suspend = False

    # Save updated schedule. `manager.update` recomputes nextScheduleTime from
    # the stored cron, so echoing it here shows the user the change landed --
    # and would have made the stale-next-run bug visible the first time anyone
    # ran `update --cron`.
    manager.update(schedule)
    _success(f"Updated schedule '{args.name}'")
    _info(f"Cron: {schedule.spec.schedule}")
    _info(f"Next run: {schedule.status.nextScheduleTime}")

    return 0


def _cmd_schedule_export(args, manager: ScheduleManager) -> int:
    """Export schedule as workflow file."""
    schedule = manager.get(args.name)
    if not schedule:
        _error(f"Schedule '{args.name}' not found")
        return 1

    # Determine backend
    backend = args.backend or schedule.spec.backend.type

    _warn_timezone_ignored(backend, schedule.spec.timezone)

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
        Path(args.output).write_text(workflow, encoding="utf-8")
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
        try:
            response = input("Type 'yes' to confirm: ")
        except (EOFError, KeyboardInterrupt):
            # Nobody is there to confirm a destructive action, so decline it.
            # Every peer prompt already does this -- `history prune`,
            # `tools uninstall`, the first-run and resume prompts -- and this
            # was the one that raised instead (#789).
            _info("Cancelled")
            return 0
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

    # "Valid" above means "croniter parses it", which is a broader set than
    # either backend accepts. Saying so here is the point of a `validate`
    # subcommand -- it reported "Cron expression valid" then
    # "Schedule configuration valid" for `@daily`, which GitHub Actions cannot
    # run and `jmo schedule install` refuses.
    _warn_nonstandard_cron(schedule.spec.schedule)

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


def _warn_nonstandard_cron(cron_expr: str) -> None:
    """Say so when a cron expression croniter accepts but the backends do not.

    Three parsers see this string and they do not agree:

    | expression      | croniter (create/validate) | validate_cron_expression (install) |
    |-----------------|----------------------------|------------------------------------|
    | `0 2 * * *`     | accepts                    | accepts                            |
    | `0 0 2 * * *`   | accepts (6-field, seconds) | rejects                            |
    | `@daily`        | accepts                    | rejects                            |
    | `0 2 * * MON`   | accepts                    | rejects                            |

    All three of the bottom rows were accepted at rc 0, persisted, reported
    valid by `jmo schedule validate`, and written into the exported workflow --
    where GitHub Actions requires five POSIX fields and does not support the
    `@` shorthand at all, so the workflow it produced could not run.
    """
    fields = cron_expr.split()
    if cron_expr.startswith("@"):
        _warn(
            f"'{cron_expr}' is a croniter shorthand. GitHub Actions and "
            f"`jmo schedule install` both require a 5-field cron expression "
            f"and will reject it -- use e.g. '0 0 * * *'."
        )
    elif len(fields) != 5:
        _warn(
            f"'{cron_expr}' has {len(fields)} fields. GitHub Actions and "
            f"`jmo schedule install` both require exactly 5."
        )


def _warn_timezone_ignored(backend: str, timezone: str) -> None:
    """Say so when the chosen backend cannot honour `--timezone`.

    GitHub Actions has no timezone field: `schedule.cron` is always evaluated
    in UTC. The generator therefore never emitted the timezone, and nothing
    said so -- `--timezone America/New_York` was accepted, persisted, shown by
    `jmo schedule get`, and then silently dropped, so the workflow ran at a
    different wall-clock hour than the one the user asked for. The GitLab
    generator does surface it, in the instructions for the GitLab UI, which is
    where a GitLab schedule's timezone is actually configured.
    """
    if backend == "github-actions" and timezone and timezone.upper() != "UTC":
        _warn(
            f"GitHub Actions runs cron in UTC and has no timezone setting, so "
            f"'{timezone}' will be ignored. Convert the cron expression to UTC, "
            f"or use --backend local-cron / gitlab-ci."
        )


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


def _use_color() -> bool:
    """Whether stderr can render ANSI colour.

    These helpers all write to stderr, so the check is on stderr -- not the
    `sys.stdout.isatty()` that `tool_commands.Colors.supports_color()` uses for
    its own stdout writers. The Windows arm matches that helper: a bare
    conhost may not process escape sequences, and TERM/WT_SESSION are what
    distinguish the consoles that do.

    Without this the escapes were unconditional, so `jmo schedule create 2>log`
    wrote literal `\x1b[32m` into the log file.
    """
    if not getattr(sys.stderr, "isatty", lambda: False)():
        return False
    if sys.platform == "win32":
        return bool(os.environ.get("TERM") or os.environ.get("WT_SESSION"))
    return True


def _mark(glyph: str, color: str, msg: str) -> None:
    """Write one status line to stderr, colour- and encoding-safe.

    `safe_print` applies UNICODE_FALLBACKS, which already carries the three
    glyphs used here (U+2713 -> "[v]", U+2717 -> "[x]", U+26A0 -> "[!]").
    Bypassing it with a bare `print()` is what made every schedule status line
    render as a bare "?" on a cp1252 console: `harden_console_streams` stops
    the UnicodeEncodeError, so nothing crashed and nothing was flagged --
    "? Created schedule 'x'" and "? Schedule 'y' not found" read identically.
    Measured across create/validate/update/get/install/delete: 9 bare "?".
    """
    prefix = f"\x1b[{color}m{glyph}\x1b[0m" if _use_color() else glyph
    safe_print(f"{prefix} {msg}", stream=sys.stderr)


def _success(msg: str) -> None:
    """Print success message in green."""
    _mark("✓", "32", msg)


def _info(msg: str) -> None:
    """Print info message."""
    safe_print(f"  {msg}", stream=sys.stderr)


def _warn(msg: str) -> None:
    """Print warning message in yellow."""
    _mark("⚠", "33", msg)


def _error(msg: str) -> None:
    """Print error message in red."""
    _mark("✗", "31", msg)
