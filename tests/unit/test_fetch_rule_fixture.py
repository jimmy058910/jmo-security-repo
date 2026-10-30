"""scripts/dev/fetch_rule_fixture.py: the four juice-shop files the rule guard scans.

The files are never committed: `lib/insecurity.ts` holds an RSA private key (the
`detect-private-key` hook refuses it) and `routes/login.ts` line 65 trips gitleaks'
`generic-api-key`, both measured. So the guard fetches them by commit and checks
each against a sha256 before it lets the file land. Every test here is offline: the
network call is replaced, and the pins are replaced with the hashes of the stand-in
bytes, except the one test that holds the real pins and the real destination.
"""

from __future__ import annotations

import hashlib
import io
import shutil
import subprocess
import urllib.error
from pathlib import Path

import pytest

from scripts.dev import fetch_rule_fixture as frf

ROOT = Path(__file__).resolve().parents[2]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


GOOD = {
    "routes/a.ts": b"export const a = 1\n",
    "lib/b.ts": b"export const b = 2\n",
}


@pytest.fixture
def pins(monkeypatch):
    """Two stand-in files with their true hashes, and a fetch that serves them."""
    monkeypatch.setattr(frf, "FILES", {p: _sha(d) for p, d in GOOD.items()})
    monkeypatch.setattr(frf, "COMMIT", "c0ffee")
    asked: list[str] = []

    def serve(url: str) -> bytes:
        asked.append(url)
        for path, data in GOOD.items():
            if url.endswith("/" + path):
                return data
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, io.BytesIO())  # type: ignore[arg-type]

    monkeypatch.setattr(frf, "fetch_bytes", serve)
    return asked


def test_the_pins_are_the_ones_the_guard_was_measured_on() -> None:
    """The commit and the four hashes, from the plan's measured table. A pin
    changed by a typo would make every fetch fail, or worse, fetch other code."""
    assert frf.COMMIT == "401393872069a1cedc8cdd26e89f2f8e05fe0dab"
    assert frf.FILES == {
        "routes/login.ts": "a75800151ddeda7b18ad683cd3c75fecadf48d23b507c5e531426285a1feb67a",
        "routes/search.ts": "0c23e746dfe31ec29aa6477e076a0a4d55d27afd90446e668b1dc10b88416967",
        "lib/insecurity.ts": "cc8eb6a6bc249de6c2616706a27123842dbfafb8b967595365f671be5e9ca7f0",
        "views/promotionVideo.pug": "d9c4ab0b3a96c832fbde18346f900df727ab20cd0d4ce229e7a8ef3d0bd0c285",
    }


def test_the_files_are_fetched_by_commit_from_raw_githubusercontent(
    tmp_path, pins
) -> None:
    assert frf.main(["--dest", str(tmp_path)]) == 0

    assert sorted(pins) == [
        "https://raw.githubusercontent.com/juice-shop/juice-shop/c0ffee/lib/b.ts",
        "https://raw.githubusercontent.com/juice-shop/juice-shop/c0ffee/routes/a.ts",
    ]
    for path, data in GOOD.items():
        assert (tmp_path / path).read_bytes() == data


def test_a_second_run_fetches_nothing(tmp_path, pins) -> None:
    assert frf.main(["--dest", str(tmp_path)]) == 0
    pins.clear()

    assert frf.main(["--dest", str(tmp_path)]) == 0

    assert pins == [], "a file already present with the right hash was fetched again"


def test_a_present_file_with_the_wrong_content_is_replaced(tmp_path, pins) -> None:
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "b.ts").write_bytes(b"edited by hand\n")

    assert frf.main(["--dest", str(tmp_path)]) == 0

    assert (tmp_path / "lib" / "b.ts").read_bytes() == GOOD["lib/b.ts"]
    assert (tmp_path / "routes" / "a.ts").read_bytes() == GOOD["routes/a.ts"]


def test_a_mismatch_names_the_path_and_both_hashes_and_lands_nothing(
    tmp_path, pins, monkeypatch, capsys
) -> None:
    served = b"not what was pinned\n"
    monkeypatch.setattr(frf, "fetch_bytes", lambda url: served)

    code = frf.main(["--dest", str(tmp_path)])

    err = capsys.readouterr().err
    assert code != 0
    for path, expected in frf.FILES.items():
        assert path in err, f"{path} is not named"
        assert f"expected {expected}" in err
    assert f"got {_sha(served)}" in err
    assert not any(p.is_file() for p in tmp_path.rglob("*")), (
        "a file that failed its hash was left on disk"
    )


def test_a_mismatch_does_not_replace_a_good_file(tmp_path, pins, monkeypatch) -> None:
    """The temp name is verified before the rename, so a bad download never
    reaches the place a good file may already stand."""
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "b.ts").write_bytes(b"edited by hand\n")
    monkeypatch.setattr(frf, "fetch_bytes", lambda url: b"wrong\n")

    assert frf.main(["--dest", str(tmp_path)]) != 0

    assert (tmp_path / "lib" / "b.ts").read_bytes() == b"edited by hand\n"
    assert sorted(p.name for p in (tmp_path / "lib").iterdir()) == ["b.ts"], (
        "a temporary file was left beside it"
    )


def test_a_network_failure_names_the_path_and_exits_non_zero(
    tmp_path, pins, monkeypatch, capsys
) -> None:
    def down(url: str) -> bytes:
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(frf, "fetch_bytes", down)

    code = frf.main(["--dest", str(tmp_path)])

    err = capsys.readouterr().err
    assert code != 0
    assert "routes/a.ts" in err or "lib/b.ts" in err
    assert "no route to host" in err
    assert not any(p.is_file() for p in tmp_path.rglob("*"))


def test_every_request_has_a_timeout(monkeypatch) -> None:
    seen: dict = {}

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(request, timeout=None):
        seen["timeout"] = timeout
        return Response(b"x")

    monkeypatch.setattr(frf.urllib.request, "urlopen", fake_urlopen)

    assert frf.fetch_bytes("https://raw.githubusercontent.com/x/y/z/p") == b"x"
    assert isinstance(seen["timeout"], (int, float)) and 0 < seen["timeout"] <= 120


def test_nothing_is_fetched_over_anything_but_https() -> None:
    assert frf.URL.startswith(
        "https://raw.githubusercontent.com/juice-shop/juice-shop/"
    )


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not on PATH")
def test_the_default_destination_cannot_be_committed() -> None:
    """The real destination, whatever is or is not in it. `lib/insecurity.ts`
    holds a private key and `git add -A` must not be able to stage it."""
    if not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    dest = frf.DEFAULT_DEST
    assert dest == ROOT / "tests" / "fixtures" / "rule_bundle" / "juice-shop"
    for path in (*frf.FILES, "anything/else.ts"):
        done = subprocess.run(
            ["git", "check-ignore", "-q", "--no-index", str(dest / path)],
            cwd=ROOT,
            capture_output=True,
            timeout=60,
        )
        assert done.returncode == 0, f"{dest / path} is not gitignored"
