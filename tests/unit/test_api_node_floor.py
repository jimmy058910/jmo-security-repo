"""The subscribe endpoint's declared Node floor is one its dependencies run on (#1586).

`scripts/api/package.json` declared `node >=18.0.0` while its `resend` (6.34.1 in
the lock) declares `>=20`, so the floor promised a Node the endpoint's own
dependency does not support. Read from `package-lock.json` rather than restated:
the next dependency that raises its floor fails this test too.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

API = Path(__file__).resolve().parents[2] / "scripts" / "api"


def _floor_major(spec: str) -> int:
    match = re.fullmatch(r"\s*>=\s*(\d+)(?:\.\d+){0,2}\s*", spec)
    assert match, f"not a plain >= floor: {spec!r}"
    return int(match[1])


def _accepts_major(spec: str, major: int) -> bool:
    """Whether a Node `engines` range admits `<major>.0.0`, for the forms npm
    packages here write: `>=N[.M.P]`, a bare `N`, `^N`, joined by `||`."""
    for alternative in spec.split("||"):
        alternative = alternative.strip()
        floor = re.fullmatch(r">=\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?", alternative)
        if floor:
            if (int(floor[1]), int(floor[2] or 0), int(floor[3] or 0)) <= (major, 0, 0):
                return True
            continue
        exact = re.fullmatch(r"\^?(\d+)(?:\.x)?", alternative)
        if exact:
            if int(exact[1]) == major:
                return True
            continue
        raise AssertionError(f"a range form this test does not read: {spec!r}")
    return False


def _runtime_floors() -> dict[str, str]:
    lock = json.loads((API / "package-lock.json").read_text(encoding="utf-8"))
    return {
        name: info["engines"]["node"]
        for name, info in lock["packages"].items()
        if name
        and not info.get("dev")
        and isinstance(info.get("engines"), dict)
        and "node" in info["engines"]
    }


def test_the_lock_is_read() -> None:
    """Meta-guard: resend is the dependency that declares a floor."""
    assert "node_modules/resend" in _runtime_floors()


@pytest.mark.parametrize(("package", "spec"), sorted(_runtime_floors().items()))
def test_every_runtime_dependency_runs_on_the_declared_floor(
    package: str, spec: str
) -> None:
    manifest = json.loads((API / "package.json").read_text(encoding="utf-8"))
    floor = _floor_major(manifest["engines"]["node"])
    assert _accepts_major(spec, floor), (package, spec, floor)
