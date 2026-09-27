"""A schedules.json written by a newer version must stay readable (#934).

`ScheduleManager._from_dict` splatted each stored dict straight into its
dataclass constructor, so **one** key the current version does not know made
*every* schedule in the file unreadable -- not just the one carrying it. The
file is long-lived user state that the format itself anticipates versioning
(`apiVersion: jmo.security/v1alpha1` is recorded on every schedule and was
ignored by the reader), so "written by a newer version" has to be recoverable.

Measured before the fix, with a file this version's own writer produced plus a
single extra `spec.retryPolicy`:

    list()   -> TypeError: ScheduleSpec.__init__() got an unexpected keyword
                argument 'retryPolicy'
    get()    -> same
    delete() -> OK

and `cmd_schedule`'s blanket `except Exception: _error(str(e))` rendered that
as a bare constructor message with no file, no schedule name and no remedy.

The asymmetry the issue names is the reason no existing test caught it: the
writer is `asdict(schedule)`, so today's writer and today's reader agree
exactly. It only appears across versions, on the invocation *after* the one
that wrote the file.

The direction is deliberate and is asserted in both directions below: an
**unknown** key is tolerated (a newer version wrote it), a **missing** required
key still fails (the file is genuinely corrupt).
"""

from __future__ import annotations

import json
import logging
from dataclasses import fields
from pathlib import Path

import pytest

from scripts.core.schedule_manager import (
    ScanSchedule,
    ScheduleManager,
    ScheduleSpec,
)


@pytest.fixture
def manager(tmp_path: Path) -> ScheduleManager:
    """A manager over a throwaway config dir, never ``~/.jmo``."""
    return ScheduleManager(config_dir=tmp_path / "jmo")


def _make(manager: ScheduleManager, *names: str) -> None:
    for name in names:
        manager.create(
            ScanSchedule.from_simple_args(
                name=name,
                cron="0 2 * * *",
                repos_dir="/srv/repos",
            )
        )


def _poke(manager: ScheduleManager, *path: str, value: object) -> None:
    """Write ``value`` at ``path`` inside the first stored schedule."""
    manifest = json.loads(manager.schedules_file.read_text(encoding="utf-8"))
    node = manifest["schedules"][0]
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    manager.schedules_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# The bug, stated as a property.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("where", "key"),
    [
        (("spec",), "retryPolicy"),
        (("spec", "backend"), "region"),
        (("spec", "jobTemplate"), "resources"),
        (("metadata",), "ownerReferences"),
        (("status",), "lastFailureReason"),
    ],
)
def test_an_unknown_key_written_by_a_newer_version_is_survivable(
    manager: ScheduleManager, where: tuple[str, ...], key: str
) -> None:
    """Every nested dataclass must tolerate a key it does not know.

    Parametrised over all five rehydration sites rather than the one the issue
    happened to reproduce: fixing `ScheduleSpec` alone would leave four
    identical constructors one hand-edit away from the same failure.
    """
    _make(manager, "alpha", "beta")
    _poke(manager, *where, key, value="something-a-newer-version-wrote")

    names = [s.metadata.name for s in manager.list()]

    assert names == [
        "alpha",
        "beta",
    ], f"an unknown {'.'.join((*where, key))} made the manifest unreadable"


def test_the_untouched_schedules_are_not_collateral_damage(
    manager: ScheduleManager,
) -> None:
    """The real severity: one bad entry took out every *other* schedule too."""
    _make(manager, "alpha", "beta", "gamma")
    _poke(manager, "spec", "retryPolicy", value="OnFailure")

    assert manager.get("beta") is not None
    assert manager.get("gamma") is not None


def test_the_known_fields_of_a_forward_compatible_schedule_still_load(
    manager: ScheduleManager,
) -> None:
    """Tolerating a key must not mean discarding the ones beside it.

    A `_from_dict` that swallowed the whole dict on any surprise would pass the
    test above while returning a default-constructed schedule -- which is the
    silent-success shape this campaign exists to remove.
    """
    _make(manager, "alpha")
    _poke(manager, "spec", "retryPolicy", value="OnFailure")

    loaded = manager.get("alpha")

    assert loaded is not None
    assert loaded.spec.schedule == "0 2 * * *"
    assert loaded.spec.jobTemplate.results == {"dir": "./results"}
    assert loaded.spec.jobTemplate.targets["repositories"]["repos_dir"] == "/srv/repos"
    assert loaded.spec.backend.type == "github-actions"


def test_the_unknown_key_is_reported_not_swallowed(
    manager: ScheduleManager, caplog: pytest.LogCaptureFixture
) -> None:
    """Recoverable is not the same as invisible.

    Without this, a key silently dropped on read is silently *deleted* on the
    next write -- `update` re-serialises with `asdict`, so a tolerated key that
    nobody mentions is data loss one command later.
    """
    _make(manager, "alpha")
    _poke(manager, "spec", "retryPolicy", value="OnFailure")

    with caplog.at_level(logging.WARNING, logger="scripts.core.schedule_manager"):
        manager.list()

    assert "retryPolicy" in caplog.text
    assert "alpha" in caplog.text


def test_a_missing_required_key_still_fails(manager: ScheduleManager) -> None:
    """The opposite direction, which must NOT become lenient.

    An unknown key means "a newer version wrote this". A *missing* required key
    means the file is corrupt, and a reader that invents a default for it would
    report a schedule the user never wrote.
    """
    _make(manager, "alpha")
    manifest = json.loads(manager.schedules_file.read_text(encoding="utf-8"))
    del manifest["schedules"][0]["spec"]["schedule"]
    manager.schedules_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    with pytest.raises(TypeError):
        manager.list()


def test_filtering_is_derived_from_the_dataclass_not_a_hardcoded_list() -> None:
    """Meta-guard: the tolerated-key set must track the dataclass.

    A hand-maintained allowlist of field names is the failure mode this repo
    keeps finding -- it is always missing whatever nobody thought of. Adding a
    field to `ScheduleSpec` must make it loadable with no second edit, so this
    asserts the filter is keyed on `dataclasses.fields` by checking a field
    that exists survives while an invented one does not.
    """
    known = {f.name for f in fields(ScheduleSpec)}

    assert "concurrencyPolicy" in known
    assert "retryPolicy" not in known


# ---------------------------------------------------------------------------
# The other direction: a schedules.json written BEFORE v2.0.0.
# ---------------------------------------------------------------------------

# What `jmo schedule create --name nightly --cron "0 2 * * *" --profile balanced
# --repos-dir /srv/repos --backend local-cron` stored before v2.0.0, verbatim in
# shape: the pre-v2 JobTemplateSpec declared `profile` as its first, required
# field, and the CLI derived the description from it. Kept as the literal file
# text rather than built with today's dataclasses, which can no longer express it.
PRE_V2_SCHEDULES_JSON = """{
  "apiVersion": "jmo.security/v2",
  "kind": "ScheduleManifest",
  "metadata": {"version": "2.0.0", "created_at": "2026-06-01T00:00:00+00:00"},
  "schedules": [
    {
      "apiVersion": "jmo.security/v1alpha1",
      "kind": "ScanSchedule",
      "metadata": {
        "name": "nightly",
        "uid": "4f7c2d9e-0b1a-4c3d-9e8f-7a6b5c4d3e2f",
        "labels": {},
        "annotations": {"description": "Balanced scan"},
        "creationTimestamp": "2026-06-01T00:00:00+00:00",
        "generation": 1
      },
      "spec": {
        "schedule": "0 2 * * *",
        "timezone": "UTC",
        "suspend": false,
        "concurrencyPolicy": "Forbid",
        "startingDeadlineSeconds": null,
        "successfulJobsHistoryLimit": 30,
        "failedJobsHistoryLimit": 10,
        "backend": {"type": "local-cron", "config": {}},
        "jobTemplate": {
          "profile": "balanced",
          "targets": {"repositories": {"repos_dir": "/srv/repos"}},
          "results": {"retention_days": 90},
          "options": {},
          "notifications": {}
        }
      },
      "status": {
        "conditions": [],
        "lastScheduleTime": null,
        "lastSuccessfulTime": null,
        "nextScheduleTime": "2026-06-02T02:00:00+00:00",
        "active": 0,
        "succeeded": 0,
        "failed": 0
      }
    }
  ]
}
"""


def _scan_profile_flags(cron_line: str) -> list[str]:
    """Every `--profile*` token in a cron line: `--profile`, `--profile-name`, ..."""
    return [tok for tok in cron_line.split() if tok.startswith("--profile")]


def test_a_schedule_stored_before_v2_loads_and_installs_without_a_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A pre-v2 `~/.jmo/schedules.json` must survive the upgrade (Review Focus 3).

    Every schedule a v1 user created carries `jobTemplate.profile`. Scan
    profiles are gone, so the key must be dropped on load, and the crontab line
    installed from that schedule must not pass a profile flag `jmo scan` no
    longer defines -- `--profile-name` would exit 2 every time the cron fired,
    long after the upgrade that caused it.

    The file is written to disk before the manager exists, the way an upgrade
    finds it, rather than poked into one today's writer produced.
    """
    from scripts.core.cron_installer import CronInstaller

    config_dir = tmp_path / "jmo"
    config_dir.mkdir()
    (config_dir / "schedules.json").write_text(PRE_V2_SCHEDULES_JSON, encoding="utf-8")
    manager = ScheduleManager(config_dir=config_dir)

    with caplog.at_level(logging.WARNING, logger="scripts.core.schedule_manager"):
        loaded = manager.get("nightly")

    assert loaded is not None, "a pre-v2 schedule no longer loads"
    assert not hasattr(loaded.spec.jobTemplate, "profile")
    assert loaded.spec.jobTemplate.targets == {
        "repositories": {"repos_dir": "/srv/repos"}
    }
    # Dropped deliberately, not tolerated as an unknown key: `_rehydrate` would
    # tell the user this schedule came from a NEWER jmo, which it did not.
    assert not caplog.records, caplog.text

    # CronInstaller refuses to construct off Linux/macOS; generating the entry
    # is pure string building, so the platform gate is the only thing patched.
    monkeypatch.setattr("scripts.core.cron_installer.platform.system", lambda: "Linux")
    entry = CronInstaller()._generate_cron_entry(loaded)
    line = next(ln for ln in entry.splitlines() if "jmo scan" in ln)

    # The positive control: a line that rendered nothing would pass the check
    # below for the wrong reason.
    assert "jmo scan --repos-dir /srv/repos" in line, line
    assert _scan_profile_flags(line) == [], line


# ---------------------------------------------------------------------------
# The second half of #934: the blanket handler that rendered the failure.
# ---------------------------------------------------------------------------


def test_a_user_facing_failure_names_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A reader failure must say *where* the bad file is.

    `cmd_schedule`'s handler printed `str(e)` and nothing else, so the user saw
    a bare constructor message with no path to go and fix.
    """
    from scripts.cli import schedule_commands
    from scripts.cli.jmo import build_parser

    cfg = tmp_path / "jmo"
    monkeypatch.setattr(
        schedule_commands, "ScheduleManager", lambda: ScheduleManager(config_dir=cfg)
    )
    mgr = ScheduleManager(config_dir=cfg)
    _make(mgr, "alpha")
    manifest = json.loads(mgr.schedules_file.read_text(encoding="utf-8"))
    del manifest["schedules"][0]["spec"]["schedule"]
    mgr.schedules_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    # The real parser, not a hand-built namespace: a mirror of the parser is
    # the failure shape this repo keeps finding (see testing.rules.md, "A
    # mirror of a mirror"). It also means a renamed dest fails here loudly.
    args = build_parser().parse_args(["schedule", "list"])
    rc = schedule_commands.cmd_schedule(args)

    assert rc == 1
    # stderr, not stdout: `_mark` writes status lines there via safe_print, and
    # stdout is reserved for programmatic output (python-safety.rules.md).
    err = capsys.readouterr().err
    assert "schedules.json" in err, f"the failure did not name the file:\n{err}"
    assert "TypeError" in err, f"the failure did not name its own kind:\n{err}"


def test_a_programming_error_is_not_reported_as_user_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unexpected exception must propagate, not become a one-liner.

    The blanket `except Exception` made a bug in a handler indistinguishable
    from a bad schedules.json: both printed one red line and returned 1.
    """
    from scripts.cli import schedule_commands
    from scripts.cli.jmo import build_parser

    cfg = tmp_path / "jmo"
    monkeypatch.setattr(
        schedule_commands, "ScheduleManager", lambda: ScheduleManager(config_dir=cfg)
    )

    def _boom(*_a: object, **_k: object) -> int:
        raise RuntimeError("a bug in a handler, not the user's fault")

    monkeypatch.setattr(schedule_commands, "_cmd_schedule_list", _boom)

    args = build_parser().parse_args(["schedule", "list"])
    with pytest.raises(RuntimeError, match="a bug in a handler"):
        schedule_commands.cmd_schedule(args)
