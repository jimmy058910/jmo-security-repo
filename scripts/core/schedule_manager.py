"""Schedule management following Kubernetes CronJob API patterns."""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from croniter import croniter


@dataclass
class ScheduleMetadata:
    """Kubernetes-style metadata."""

    name: str
    uid: str = field(default_factory=lambda: str(uuid.uuid4()))
    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)
    creationTimestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    generation: int = 1


@dataclass
class BackendConfig:
    """Backend-specific configuration."""

    type: str  # "github-actions" | "gitlab-ci" | "local-cron"
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class JobTemplateSpec:
    """Scan job specification."""

    profile: str
    targets: dict[str, Any]
    results: dict[str, Any]
    options: dict[str, Any]
    notifications: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScheduleSpec:
    """Schedule specification (Kubernetes CronJob-inspired)."""

    schedule: str  # Cron syntax
    timezone: str = "UTC"
    suspend: bool = False
    concurrencyPolicy: str = "Forbid"  # Forbid|Allow|Replace
    startingDeadlineSeconds: int | None = None
    successfulJobsHistoryLimit: int = 30
    failedJobsHistoryLimit: int = 10
    backend: BackendConfig = field(
        default_factory=lambda: BackendConfig(type="github-actions")
    )
    jobTemplate: JobTemplateSpec = field(
        default_factory=lambda: JobTemplateSpec(
            profile="balanced", targets={}, results={}, options={}
        )
    )


@dataclass
class ScheduleStatus:
    """Runtime status."""

    conditions: list[dict[str, Any]] = field(default_factory=list)
    lastScheduleTime: str | None = None
    lastSuccessfulTime: str | None = None
    nextScheduleTime: str | None = None
    active: int = 0
    succeeded: int = 0
    failed: int = 0


@dataclass
class ScanSchedule:
    """Complete schedule resource."""

    apiVersion: str = "jmo.security/v1alpha1"
    kind: str = "ScanSchedule"
    metadata: ScheduleMetadata = field(
        default_factory=lambda: ScheduleMetadata(name="")
    )
    spec: ScheduleSpec = field(
        default_factory=lambda: ScheduleSpec(
            schedule="",
            jobTemplate=JobTemplateSpec(profile="", targets={}, results={}, options={}),
        )
    )
    status: ScheduleStatus = field(default_factory=lambda: ScheduleStatus())

    def to_dict(self) -> dict:
        """Convert schedule to dictionary for JSON/YAML serialization."""
        return asdict(self)

    @classmethod
    def from_simple_args(
        cls,
        name: str,
        cron: str,
        profile: str,
        repos_dir: str | None = None,
        backend: str = "github-actions",
        labels: dict[str, str] | None = None,
        **kwargs,
    ) -> "ScanSchedule":
        """Convenience factory for creating schedules with simplified args.

        This method provides a simpler API for tests and CLI usage:

        ScanSchedule.from_simple_args(
            name="nightly-scan",
            cron="0 2 * * *",
            profile="balanced",
            repos_dir="~/repos",
            labels={"env": "prod"}
        )

        Instead of the verbose nested structure:

        ScanSchedule(
            metadata=ScheduleMetadata(name="nightly-scan", labels={"env": "prod"}),
            spec=ScheduleSpec(
                schedule="0 2 * * *",
                jobTemplate=JobTemplateSpec(
                    profile="balanced",
                    targets={"repos_dir": "~/repos"},
                    ...
                )
            )
        )
        """
        # Build targets from simplified args
        targets = {}
        if repos_dir:
            targets["repos_dir"] = repos_dir

        # Extract other target types from kwargs
        for key in ["image", "terraform_state", "url", "gitlab_repo", "k8s_context"]:
            if key in kwargs:
                targets[key] = kwargs.pop(key)

        # Build results config
        results = kwargs.pop("results", {"dir": "./results"})

        # Build options
        options = kwargs.pop("options", {})

        # Build annotations (description stored here)
        annotations = kwargs.pop("annotations", {})
        if "description" in kwargs:
            annotations["description"] = kwargs.pop("description")

        # Create nested structure
        return cls(
            metadata=ScheduleMetadata(
                name=name,
                labels=labels or {},
                annotations=annotations,
            ),
            spec=ScheduleSpec(
                schedule=cron,
                backend=BackendConfig(
                    type=backend, config=kwargs.pop("backend_config", {})
                ),
                jobTemplate=JobTemplateSpec(
                    profile=profile,
                    targets=targets,
                    results=results,
                    options=options,
                ),
                timezone=kwargs.pop("timezone", "UTC"),
                suspend=kwargs.pop("suspend", False),
            ),
        )


class ScheduleManager:
    """Manage scan schedules with Kubernetes-inspired API."""

    def __init__(self, config_dir: Path | None = None):
        if config_dir is None:
            # Respect HOME environment variable for testing
            home = os.environ.get("HOME")
            if home:
                self.config_dir = Path(home) / ".jmo"
            else:
                self.config_dir = Path.home() / ".jmo"
        else:
            self.config_dir = config_dir
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.schedules_file = self.config_dir / "schedules.json"
        self._ensure_file_exists()

    def _ensure_file_exists(self):
        """Create schedules.json if not exists with secure permissions (0o600)."""
        if not self.schedules_file.exists():
            manifest = {
                "apiVersion": "jmo.security/v2",
                "kind": "ScheduleManifest",
                "metadata": {
                    "version": "2.0.0",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                },
                "schedules": [],
            }
            self.schedules_file.write_text(json.dumps(manifest, indent=2))
            # Set secure permissions (read/write for owner only)
            self.schedules_file.chmod(0o600)

    def create(self, schedule: ScanSchedule) -> ScanSchedule:
        """Create new schedule."""
        # Validate cron syntax
        try:
            croniter(schedule.spec.schedule)
        except ValueError as e:
            raise ValueError(f"Invalid cron syntax: {e}")

        # Compute next run time
        now = datetime.now(timezone.utc)
        cron = croniter(schedule.spec.schedule, now)
        schedule.status.nextScheduleTime = cron.get_next(datetime).isoformat()

        # Add condition
        schedule.status.conditions.append(
            {
                "type": "Ready",
                "status": "True",
                "lastTransitionTime": now.isoformat(),
                "reason": "Created",
                "message": "Schedule created successfully",
            }
        )

        # Load existing manifest
        manifest = json.loads(self.schedules_file.read_text())

        # Check for duplicate name
        if any(
            s["metadata"]["name"] == schedule.metadata.name
            for s in manifest["schedules"]
        ):
            raise ValueError(f"Schedule '{schedule.metadata.name}' already exists")

        # Append and save
        manifest["schedules"].append(self._to_dict(schedule))
        self.schedules_file.write_text(json.dumps(manifest, indent=2))

        return schedule

    def list(self, labels: dict[str, str] | None = None) -> list[ScanSchedule]:
        """List schedules, optionally filtered by labels."""
        manifest = json.loads(self.schedules_file.read_text())
        schedules = [self._from_dict(s) for s in manifest["schedules"]]

        if labels:
            schedules = [
                s
                for s in schedules
                if all(s.metadata.labels.get(k) == v for k, v in labels.items())
            ]

        return schedules

    def get(self, name: str) -> ScanSchedule | None:
        """Get schedule by name."""
        schedules = self.list()
        for schedule in schedules:
            if schedule.metadata.name == name:
                return schedule
        return None

    def update(self, schedule: ScanSchedule) -> ScanSchedule:
        """Update existing schedule."""
        manifest = json.loads(self.schedules_file.read_text())

        # Find and replace
        for i, s in enumerate(manifest["schedules"]):
            if s["metadata"]["name"] == schedule.metadata.name:
                schedule.metadata.generation += 1
                manifest["schedules"][i] = self._to_dict(schedule)
                break
        else:
            raise ValueError(f"Schedule '{schedule.metadata.name}' not found")

        self.schedules_file.write_text(json.dumps(manifest, indent=2))
        return schedule

    def delete(self, name: str) -> bool:
        """Delete schedule by name."""
        manifest = json.loads(self.schedules_file.read_text())
        original_count = len(manifest["schedules"])

        manifest["schedules"] = [
            s for s in manifest["schedules"] if s["metadata"]["name"] != name
        ]

        if len(manifest["schedules"]) == original_count:
            return False  # Not found

        self.schedules_file.write_text(json.dumps(manifest, indent=2))
        return True

    def _to_dict(self, schedule: ScanSchedule) -> dict:
        """Convert dataclass to dict."""
        return asdict(schedule)

    def _from_dict(self, data: dict) -> ScanSchedule:
        """Convert dict to dataclass."""
        # Reconstruct nested dataclasses
        metadata = ScheduleMetadata(**data["metadata"])
        backend = BackendConfig(**data["spec"]["backend"])
        job_template = JobTemplateSpec(**data["spec"]["jobTemplate"])
        spec = ScheduleSpec(
            **{**data["spec"], "backend": backend, "jobTemplate": job_template}
        )
        status = ScheduleStatus(**data["status"])

        return ScanSchedule(
            apiVersion=data["apiVersion"],
            kind=data["kind"],
            metadata=metadata,
            spec=spec,
            status=status,
        )
