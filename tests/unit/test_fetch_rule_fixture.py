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


def test_a_failed_download_leaves_what_stands_in_its_place_untouched(
    tmp_path, pins, monkeypatch
) -> None:
    """The temp name is verified before the rename, so a bad download never
    reaches the place a file may already stand, wrong as that file may be."""
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "b.ts").write_bytes(b"edited by hand\n")
    monkeypatch.setattr(frf, "fetch_bytes", lambda url: b"wrong\n")

    assert frf.main(["--dest", str(tmp_path)]) != 0

    assert (tmp_path / "lib" / "b.ts").read_bytes() == b"edited by hand\n"
    assert sorted(p.name for p in (tmp_path / "lib").iterdir()) == ["b.ts"], (
        "a temporary file was left beside it"
    )


def test_a_file_that_matches_its_pin_is_kept_beside_one_that_fails(
    tmp_path, pins, monkeypatch
) -> None:
    """A good file is not asked for again, so a download that does not match
    cannot replace it; the other file's failure leaves it where it was."""
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "a.ts").write_bytes(GOOD["routes/a.ts"])
    asked: list[str] = []

    def wrong(url: str) -> bytes:
        asked.append(url)
        return b"wrong\n"

    monkeypatch.setattr(frf, "fetch_bytes", wrong)

    assert frf.main(["--dest", str(tmp_path)]) != 0

    assert (tmp_path / "routes" / "a.ts").read_bytes() == GOOD["routes/a.ts"]
    assert [u for u in asked if u.endswith("a.ts")] == []
    assert not (tmp_path / "lib" / "b.ts").exists()


def test_a_network_failure_names_the_path_and_exits_non_zero(
    tmp_path, pins, monkeypatch, capsys
) -> None:
    def down(url: str) -> bytes:
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(frf, "fetch_bytes", down)

    code = frf.main(["--dest", str(tmp_path)])

    err = capsys.readouterr().err
    assert code != 0
    assert "routes/a.ts" in err and "lib/b.ts" in err
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


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://x/y", code, "status", {}, io.BytesIO())  # type: ignore[arg-type]


TRANSIENT = [
    pytest.param(lambda: _http_error(500), id="500"),
    pytest.param(lambda: _http_error(502), id="502"),
    pytest.param(lambda: _http_error(503), id="503"),
    pytest.param(lambda: TimeoutError("timed out"), id="timeout"),
    pytest.param(
        lambda: urllib.error.URLError(TimeoutError("timed out")), id="urlerror-timeout"
    ),
]
PERMANENT = [
    pytest.param(lambda: _http_error(404), id="404"),
    pytest.param(lambda: _http_error(403), id="403"),
    pytest.param(lambda: urllib.error.URLError(ConnectionRefusedError()), id="refused"),
    pytest.param(lambda: urllib.error.URLError("no route to host"), id="no-route"),
]


class _Body(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _script_urlopen(monkeypatch, outcomes):
    """urlopen that raises or returns what `outcomes` says, one per call; returns
    the call count (a list) and the waits made between attempts."""
    calls: list[str] = []
    slept: list[float] = []
    remaining = list(outcomes)

    def urlopen(request, timeout=None):
        calls.append(request.full_url)
        outcome = remaining.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return _Body(outcome)

    monkeypatch.setattr(frf.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(frf.time, "sleep", slept.append)
    return calls, slept


@pytest.mark.parametrize("failure", TRANSIENT)
def test_a_server_error_or_a_timeout_is_retried_once(monkeypatch, failure) -> None:
    calls, slept = _script_urlopen(monkeypatch, [failure(), b"body"])

    assert frf.fetch_bytes("https://x/y") == b"body"

    assert len(calls) == 2
    assert slept == [frf.RETRY_DELAY_S]


@pytest.mark.parametrize("failure", TRANSIENT)
def test_a_second_failure_is_raised_not_retried_again(monkeypatch, failure) -> None:
    calls, _ = _script_urlopen(monkeypatch, [failure(), failure(), b"never read"])

    with pytest.raises(OSError):
        frf.fetch_bytes("https://x/y")

    assert len(calls) == 2


@pytest.mark.parametrize("failure", PERMANENT)
def test_a_client_error_or_a_refused_connection_is_not_retried(
    monkeypatch, failure
) -> None:
    calls, slept = _script_urlopen(monkeypatch, [failure(), b"never read"])

    with pytest.raises(OSError):
        frf.fetch_bytes("https://x/y")

    assert len(calls) == 1
    assert slept == []


def test_a_flaky_server_still_gives_the_files_and_exit_0(tmp_path, monkeypatch) -> None:
    """Through `main`: each file's first request is a 503."""
    monkeypatch.setattr(frf, "FILES", {p: _sha(d) for p, d in GOOD.items()})
    monkeypatch.setattr(frf, "COMMIT", "c0ffee")
    failed: set[str] = set()
    monkeypatch.setattr(frf.time, "sleep", lambda s: None)

    def urlopen(request, timeout=None):
        url = request.full_url
        if url not in failed:
            failed.add(url)
            raise _http_error(503)
        return _Body(next(d for p, d in GOOD.items() if url.endswith("/" + p)))

    monkeypatch.setattr(frf.urllib.request, "urlopen", urlopen)

    assert frf.main(["--dest", str(tmp_path)]) == 0

    for path, data in GOOD.items():
        assert (tmp_path / path).read_bytes() == data


def test_a_destination_that_cannot_be_made_is_exit_2_naming_the_path(
    tmp_path, pins, capsys
) -> None:
    """A file where the directory should be: `mkdir` raises, which used to be a
    traceback and exit 1 because it stood outside the `try`."""
    blocker = tmp_path / "blocked"
    blocker.write_bytes(b"a file, not a directory\n")

    code = frf.main(["--dest", str(blocker)])

    err = capsys.readouterr().err
    assert code == 2
    assert "routes/a.ts" in err and "lib/b.ts" in err
    assert "could not write" in err
    assert blocker.read_bytes() == b"a file, not a directory\n"


def test_a_write_that_fails_part_way_removes_its_temporary_file(
    tmp_path, pins, monkeypatch, capsys
) -> None:
    """The rename fails after the bytes were written: the `.part` file is there
    when it does, and gone afterwards, and nothing lands under the real name."""
    part_existed: list[bool] = []

    def full_disk(src, dst):
        part_existed.append(Path(src).is_file())
        raise OSError("no space left on device")

    monkeypatch.setattr(frf.os, "replace", full_disk)

    code = frf.main(["--dest", str(tmp_path)])

    err = capsys.readouterr().err
    assert code == 2
    assert part_existed == [True, True], "the failing branch was not reached"
    assert "no space left on device" in err
    assert "routes/a.ts" in err and "lib/b.ts" in err
    assert not any(p.is_file() for p in tmp_path.rglob("*")), sorted(
        str(p) for p in tmp_path.rglob("*")
    )


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
