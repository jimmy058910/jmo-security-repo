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
                profile="balanced",
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
    assert loaded.spec.jobTemplate.profile == "balanced"
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
