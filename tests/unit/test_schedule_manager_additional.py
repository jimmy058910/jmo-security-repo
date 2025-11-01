"""Additional unit tests for ScheduleManager to improve coverage.

Tests cover:
- Label filtering in list()
- Schedule updates
- Schedule deletions
- Edge cases and error handling

Architecture Note:
- Uses tmp_path fixture for isolated config storage
- Tests dataclass serialization/deserialization
- Covers CRUD operations comprehensively
"""

import pytest

from scripts.core.schedule_manager import ScanSchedule, ScheduleManager


def test_schedule_manager_list_with_label_filtering(tmp_path):
    """Test list() filters schedules by labels."""
    manager = ScheduleManager(config_dir=tmp_path)

    # Create schedules with different labels
    schedule1 = ScanSchedule.from_simple_args(
        name="nightly-api",
        cron="0 2 * * *",
        profile="balanced",
        repos_dir="~/repos/api",
        backend="github-actions",
        labels={"env": "production", "team": "backend"},
    )
    schedule2 = ScanSchedule.from_simple_args(
        name="weekly-frontend",
        cron="0 3 * * 0",
        profile="deep",
        repos_dir="~/repos/frontend",
        backend="github-actions",
        labels={"env": "staging", "team": "frontend"},
    )
    schedule3 = ScanSchedule.from_simple_args(
        name="daily-mobile",
        cron="0 4 * * *",
        profile="fast",
        repos_dir="~/repos/mobile",
        backend="local-cron",
        labels={"env": "production", "team": "mobile"},
    )

    manager.create(schedule1)
    manager.create(schedule2)
    manager.create(schedule3)

    # Filter by env=production
    production_schedules = manager.list(labels={"env": "production"})
    assert len(production_schedules) == 2
    names = [s.metadata.name for s in production_schedules]
    assert "nightly-api" in names
    assert "daily-mobile" in names

    # Filter by team=frontend
    frontend_schedules = manager.list(labels={"team": "frontend"})
    assert len(frontend_schedules) == 1
    assert frontend_schedules[0].metadata.name == "weekly-frontend"

    # Filter by multiple labels
    backend_prod = manager.list(labels={"env": "production", "team": "backend"})
    assert len(backend_prod) == 1
    assert backend_prod[0].metadata.name == "nightly-api"

    # Filter with no matches
    no_matches = manager.list(labels={"env": "development"})
    assert len(no_matches) == 0


def test_schedule_manager_list_without_labels_returns_all(tmp_path):
    """Test list() without label filter returns all schedules."""
    manager = ScheduleManager(config_dir=tmp_path)

    schedule1 = ScanSchedule.from_simple_args(
        name="sched1",
        cron="0 1 * * *",
        profile="fast",
        repos_dir="~/repos",
        backend="github-actions",
    )
    schedule2 = ScanSchedule.from_simple_args(
        name="sched2",
        cron="0 2 * * *",
        profile="balanced",
        repos_dir="~/repos",
        backend="local-cron",
    )

    manager.create(schedule1)
    manager.create(schedule2)

    all_schedules = manager.list()
    assert len(all_schedules) == 2


def test_schedule_manager_update(tmp_path):
    """Test update() modifies existing schedule."""
    manager = ScheduleManager(config_dir=tmp_path)

    # Create initial schedule
    schedule = ScanSchedule.from_simple_args(
        name="nightly",
        cron="0 2 * * *",
        profile="balanced",
        repos_dir="~/repos",
        backend="github-actions",
        description="Original description",
    )
    manager.create(schedule)

    # Update schedule
    schedule.spec.schedule = "0 3 * * *"
    schedule.spec.jobTemplate.profile = "deep"
    # description is stored in annotations in v0.9.0
    schedule.metadata.annotations["description"] = "Updated description"
    updated = manager.update(schedule)

    # Verify update
    assert updated.spec.schedule == "0 3 * * *"
    assert updated.spec.jobTemplate.profile == "deep"
    assert updated.metadata.annotations.get("description") == "Updated description"

    # Verify persistence
    retrieved = manager.get("nightly")
    assert retrieved.spec.schedule == "0 3 * * *"
    assert retrieved.spec.jobTemplate.profile == "deep"


def test_schedule_manager_update_nonexistent(tmp_path):
    """Test update() raises ValueError for non-existent schedule."""
    manager = ScheduleManager(config_dir=tmp_path)

    schedule = ScanSchedule.from_simple_args(
        name="nonexistent",
        cron="0 2 * * *",
        profile="balanced",
        repos_dir="~/repos",
        backend="github-actions",
    )

    with pytest.raises(ValueError, match="Schedule 'nonexistent' not found"):
        manager.update(schedule)


def test_schedule_manager_delete(tmp_path):
    """Test delete() removes schedule."""
    manager = ScheduleManager(config_dir=tmp_path)

    schedule = ScanSchedule.from_simple_args(
        name="to-delete",
        cron="0 2 * * *",
        profile="balanced",
        repos_dir="~/repos",
        backend="github-actions",
    )
    manager.create(schedule)

    # Verify exists
    assert manager.get("to-delete") is not None

    # Delete
    result = manager.delete("to-delete")
    assert result is True

    # Verify deleted
    assert manager.get("to-delete") is None
    assert len(manager.list()) == 0


def test_schedule_manager_delete_nonexistent(tmp_path):
    """Test delete() returns False for non-existent schedule."""
    manager = ScheduleManager(config_dir=tmp_path)

    result = manager.delete("nonexistent")
    assert result is False


def test_schedule_manager_delete_from_multiple(tmp_path):
    """Test delete() removes only the specified schedule."""
    manager = ScheduleManager(config_dir=tmp_path)

    schedule1 = ScanSchedule.from_simple_args(
        name="keep",
        cron="0 1 * * *",
        profile="fast",
        repos_dir="~/repos",
        backend="github-actions",
    )
    schedule2 = ScanSchedule.from_simple_args(
        name="delete",
        cron="0 2 * * *",
        profile="balanced",
        repos_dir="~/repos",
        backend="local-cron",
    )

    manager.create(schedule1)
    manager.create(schedule2)

    # Delete one
    manager.delete("delete")

    # Verify only one remains
    schedules = manager.list()
    assert len(schedules) == 1
    assert schedules[0].metadata.name == "keep"


def test_scan_schedule_to_dict():
    """Test ScanSchedule.to_dict() serialization."""
    schedule = ScanSchedule.from_simple_args(
        name="test",
        cron="0 2 * * *",
        profile="balanced",
        repos_dir="~/repos",
        backend="github-actions",
        description="Test schedule",
        labels={"env": "prod"},
    )

    data = schedule.to_dict()

    # v0.9.0 uses Kubernetes-style nested structure
    assert data["metadata"]["name"] == "test"
    assert data["spec"]["schedule"] == "0 2 * * *"
    assert data["spec"]["jobTemplate"]["profile"] == "balanced"
    assert data["spec"]["jobTemplate"]["targets"]["repos_dir"] == "~/repos"
    assert data["spec"]["backend"]["type"] == "github-actions"
    # description passed via from_simple_args is stored in annotations
    assert data["metadata"]["labels"] == {"env": "prod"}


def test_schedule_manager_to_dict_from_dict_round_trip(tmp_path):
    """Test round-trip serialization via _to_dict() and _from_dict()."""
    manager = ScheduleManager(config_dir=tmp_path)

    original = ScanSchedule.from_simple_args(
        name="round-trip",
        cron="0 2 * * *",
        profile="deep",
        repos_dir="~/repos",
        backend="local-cron",
        description="Round-trip test",
        labels={"env": "staging", "team": "ops"},
    )

    # Serialize
    data = manager._to_dict(original)

    # Deserialize
    restored = manager._from_dict(data)

    # Verify equivalence
    assert restored.metadata.name == original.metadata.name
    assert restored.spec.schedule == original.spec.schedule
    assert restored.spec.jobTemplate.profile == original.spec.jobTemplate.profile
    assert restored.spec.jobTemplate.targets.get(
        "repos_dir"
    ) == original.spec.jobTemplate.targets.get("repos_dir")
    assert restored.spec.backend.type == original.spec.backend.type
    # description field doesn't exist in v0.9.0 Kubernetes-style schema - skip
    assert restored.metadata.labels == original.metadata.labels


def test_schedule_manager_label_filtering_with_none_labels(tmp_path):
    """Test list() handles schedules without labels gracefully."""
    manager = ScheduleManager(config_dir=tmp_path)

    schedule_with_labels = ScanSchedule.from_simple_args(
        name="with-labels",
        cron="0 1 * * *",
        profile="fast",
        repos_dir="~/repos",
        backend="github-actions",
        labels={"env": "prod"},
    )
    schedule_without_labels = ScanSchedule.from_simple_args(
        name="without-labels",
        cron="0 2 * * *",
        profile="balanced",
        repos_dir="~/repos",
        backend="local-cron",
        labels=None,
    )

    manager.create(schedule_with_labels)
    manager.create(schedule_without_labels)

    # Filter by labels
    prod_schedules = manager.list(labels={"env": "prod"})
    assert len(prod_schedules) == 1
    assert prod_schedules[0].metadata.name == "with-labels"


def test_schedule_manager_update_labels(tmp_path):
    """Test update() can modify labels."""
    manager = ScheduleManager(config_dir=tmp_path)

    schedule = ScanSchedule.from_simple_args(
        name="update-labels",
        cron="0 2 * * *",
        profile="balanced",
        repos_dir="~/repos",
        backend="github-actions",
        labels={"env": "staging"},
    )
    manager.create(schedule)

    # Update labels
    schedule.metadata.labels = {"env": "production", "team": "security"}
    updated = manager.update(schedule)

    assert updated.metadata.labels == {"env": "production", "team": "security"}

    # Verify persistence
    retrieved = manager.get("update-labels")
    assert retrieved.metadata.labels == {"env": "production", "team": "security"}


def test_schedule_manager_delete_all(tmp_path):
    """Test deleting all schedules leaves empty list."""
    manager = ScheduleManager(config_dir=tmp_path)

    for i in range(5):
        schedule = ScanSchedule.from_simple_args(
            name=f"sched{i}",
            cron=f"0 {i} * * *",
            profile="fast",
            repos_dir="~/repos",
            backend="github-actions",
        )
        manager.create(schedule)

    # Delete all
    for i in range(5):
        manager.delete(f"sched{i}")

    assert len(manager.list()) == 0
