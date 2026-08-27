"""Schedule management following Kubernetes CronJob API patterns."""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import asdict, dataclass, field, fields
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

from croniter import croniter

logger = logging.getLogger(__name__)

_T = TypeVar("_T")


@dataclass
class ScheduleMetadata:
    """Kubernetes-style metadata."""

    name: str
    uid: str = field(default_factory=lambda: str(uuid.uuid4()))
    labels: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)
    creationTimestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
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
    ) -> ScanSchedule:
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
        # Build targets in the nested shape the consumers actually read.
        #
        # This used to write flat keys -- targets["repos_dir"], targets["image"],
        # targets["url"] and so on. Every consumer (both workflow generators and
        # the cron installer) reads the nested shape the CLI writes:
        # targets["repositories"]["repos_dir"], targets["images"], and
        # targets["web"]["urls"]. The two sets were entirely disjoint -- six keys
        # written, seven read, zero in common -- so a schedule built through this
        # factory exported a workflow that ran `jmo scan` with **no target at
        # all**, and did it at rc 0 with valid YAML and no warning. That is also
        # the shape docs/SCHEDULE_GUIDE.md's Quick Start taught.
        targets: dict[str, Any] = {}

        repo = kwargs.pop("repo", None)
        if repos_dir or repo:
            repositories: dict[str, Any] = {}
            if repo:
                repositories["repo"] = repo
            if repos_dir:
                repositories["repos_dir"] = repos_dir
            targets["repositories"] = repositories

        # `--image` and `--url` are repeatable on the CLI and the consumers
        # iterate them, so a bare scalar is normalised to a one-element list
        # rather than silently iterating its characters.
        if "image" in kwargs:
            image = kwargs.pop("image")
            targets["images"] = [image] if isinstance(image, str) else list(image)

        web: dict[str, Any] = {}
        if "url" in kwargs:
            url = kwargs.pop("url")
            web["urls"] = [url] if isinstance(url, str) else list(url)
        if "api_spec" in kwargs:
            web["api_spec"] = kwargs.pop("api_spec")
        if web:
            targets["web"] = web

        iac = {
            key: kwargs.pop(key)
            for key in ("terraform_state", "cloudformation", "k8s_manifest")
            if key in kwargs
        }
        if iac:
            targets["iac"] = iac

        gitlab: dict[str, Any] = {}
        if "gitlab_repo" in kwargs:
            gitlab["repo"] = kwargs.pop("gitlab_repo")
        if "gitlab_group" in kwargs:
            gitlab["group"] = kwargs.pop("gitlab_group")
        if gitlab:
            targets["gitlab"] = gitlab

        kubernetes: dict[str, Any] = {}
        if "k8s_context" in kwargs:
            kubernetes["context"] = kwargs.pop("k8s_context")
        if "k8s_namespace" in kwargs:
            kubernetes["namespace"] = kwargs.pop("k8s_namespace")
        if kubernetes:
            targets["kubernetes"] = kubernetes

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
        # `Path.home()`, not `os.environ["HOME"]`. Every other consumer of
        # ~/.jmo resolves it with Path.home() -- 24 sites, covering history,
        # policies, tool installs, the EPSS/KEV caches and config.yml. This was
        # the only one that read HOME, and on Windows the two disagree:
        # Path.home() reads USERPROFILE and never consults HOME, so a user who
        # sets HOME (routine for git and ssh) got their schedules in one
        # directory and everything else in another, silently.
        #
        # The old branch's comment said "for testing", and Path.home() still
        # honours HOME on POSIX -- so that affordance survives exactly where it
        # ever worked. `config_dir` is the injection point that works on every
        # platform, and it is what the tests already pass.
        self.config_dir = config_dir if config_dir is not None else Path.home() / ".jmo"
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
                    "created_at": datetime.now(UTC).isoformat(),
                },
                "schedules": [],
            }
            self.schedules_file.write_text(
                json.dumps(manifest, indent=2), encoding="utf-8"
            )
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
        now = datetime.now(UTC)
        schedule.status.nextScheduleTime = self._next_run(schedule.spec.schedule, now)

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
        manifest = json.loads(self.schedules_file.read_text(encoding="utf-8"))

        # Check for duplicate name
        if any(
            s["metadata"]["name"] == schedule.metadata.name
            for s in manifest["schedules"]
        ):
            raise ValueError(f"Schedule '{schedule.metadata.name}' already exists")

        # Append and save
        manifest["schedules"].append(self._to_dict(schedule))
        self.schedules_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        return schedule

    def list(self, labels: dict[str, str] | None = None) -> list[ScanSchedule]:
        """List schedules, optionally filtered by labels."""
        manifest = json.loads(self.schedules_file.read_text(encoding="utf-8"))
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
        """Update existing schedule, recomputing the next run time.

        The recompute is the point. `update` used to persist the new cron and
        leave `status.nextScheduleTime` at the value derived from the *old*
        one, so `jmo schedule get` reported a next run the schedule could never
        produce: after changing `0 2 * * *` to `30 5 * * 1`, it still read
        Friday 02:00 for a Monday-05:30 schedule -- three days and three and a
        half hours out, on the wrong weekday, at rc 0 with a success message.
        """
        manifest = json.loads(self.schedules_file.read_text(encoding="utf-8"))

        # Find and replace
        for i, s in enumerate(manifest["schedules"]):
            if s["metadata"]["name"] == schedule.metadata.name:
                schedule.metadata.generation += 1
                schedule.status.nextScheduleTime = self._next_run(
                    schedule.spec.schedule
                )
                manifest["schedules"][i] = self._to_dict(schedule)
                break
        else:
            raise ValueError(f"Schedule '{schedule.metadata.name}' not found")

        self.schedules_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return schedule

    def delete(self, name: str) -> bool:
        """Delete schedule by name."""
        manifest = json.loads(self.schedules_file.read_text(encoding="utf-8"))
        original_count = len(manifest["schedules"])

        manifest["schedules"] = [
            s for s in manifest["schedules"] if s["metadata"]["name"] != name
        ]

        if len(manifest["schedules"]) == original_count:
            return False  # Not found

        self.schedules_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return True

    @staticmethod
    def _next_run(cron_expr: str, now: datetime | None = None) -> str:
        """Next fire time for `cron_expr`, as an ISO-8601 string."""
        base = now or datetime.now(UTC)
        return croniter(cron_expr, base).get_next(datetime).isoformat()

    def _to_dict(self, schedule: ScanSchedule) -> dict:
        """Convert dataclass to dict."""
        return asdict(schedule)

    def _rehydrate(
        self, cls: type[_T], data: dict[str, Any], *, where: str, name: str
    ) -> _T:
        """Build *cls* from *data*, tolerating keys *cls* does not declare.

        Splatting the stored dict straight in made **one** unrecognised key
        anywhere in the file take out *every* schedule: `list()` rehydrates the
        whole manifest in one pass, and `get`/`update`/`export`/`install`/
        `uninstall`/`validate` all route through it. Only `create` and `delete`
        read the raw JSON, so `jmo schedule delete` was the sole way back.

        An unknown key means "written by a newer version", which is exactly
        what a long-lived user file whose format already records an
        `apiVersion` should survive. A *missing* required key is a different
        thing -- genuine corruption -- and still raises, because inventing a
        default there would report a schedule the user never wrote.

        The filter is derived from ``dataclasses.fields``, not a hand-kept
        allowlist: a new field must become loadable without a second edit.
        """
        known = {f.name for f in fields(cls)}  # type: ignore[arg-type]
        unknown = sorted(set(data) - known)
        if unknown:
            # Warn rather than drop silently. `update` re-serialises with
            # `asdict`, so a tolerated key nobody mentions is deleted from the
            # file one command later -- silent data loss dressed as leniency.
            logger.warning(
                "%s: ignoring unrecognised %s key(s) %s in %s. "
                "This schedule was probably written by a newer version of jmo; "
                "these keys are dropped if the schedule is updated.",
                name,
                where,
                ", ".join(unknown),
                self.schedules_file,
            )
        return cls(**{k: v for k, v in data.items() if k in known})

    def _from_dict(self, data: dict) -> ScanSchedule:
        """Convert dict to dataclass."""
        # Name first: it is what makes the warnings below identify *which*
        # schedule in the manifest carries the surprise. Read defensively --
        # a manifest broken enough to lack it should still produce warnings
        # that say so rather than a KeyError from the logging call.
        name = str(data.get("metadata", {}).get("name", "<unnamed>"))

        # Reconstruct nested dataclasses
        metadata = self._rehydrate(
            ScheduleMetadata, data["metadata"], where="metadata", name=name
        )
        backend = self._rehydrate(
            BackendConfig, data["spec"]["backend"], where="spec.backend", name=name
        )
        job_template = self._rehydrate(
            JobTemplateSpec,
            data["spec"]["jobTemplate"],
            where="spec.jobTemplate",
            name=name,
        )
        spec = self._rehydrate(
            ScheduleSpec,
            {**data["spec"], "backend": backend, "jobTemplate": job_template},
            where="spec",
            name=name,
        )
        status = self._rehydrate(
            ScheduleStatus, data["status"], where="status", name=name
        )

        return ScanSchedule(
            apiVersion=data["apiVersion"],
            kind=data["kind"],
            metadata=metadata,
            spec=spec,
            status=status,
        )
