"""osv-scanner's offline databases, the read side (v2.0.0 Phase 4, O1).

osv-scanner reads `<cache>/osv-scalibr/<ecosystem>/all.zip` from the directory
`OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY` names (measured, 2.6.0). The ecosystem
is the bucket name at osv-vulnerabilities.storage.googleapis.com, spelled as
the bucket spells it: a directory named `pypi` is a database osv-scanner never
finds.
"""

from __future__ import annotations

import http.server
import io
import threading
import zipfile
from contextlib import contextmanager
from pathlib import Path

import pytest

from scripts.core import osv_database
from scripts.core.osv_database import (
    ECOSYSTEMS,
    LOCKFILE_ECOSYSTEMS,
    FetchResult,
    cache_dir,
    database_path,
    ecosystem_of,
    fetch_all,
    fetch_ecosystem,
    present_ecosystems,
)

# Every name osv-scanner 2.6.0 accepts through `-L` (measured one by one,
# 2026-09-27), and its bucket. `requirements*.txt` is a pattern: two names
# stand for it.
ACCEPTED = {
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "bun.lock": "npm",
    "requirements.txt": "PyPI",
    "requirements-dev.txt": "PyPI",
    "poetry.lock": "PyPI",
    "Pipfile.lock": "PyPI",
    "pdm.lock": "PyPI",
    "uv.lock": "PyPI",
    "pylock.toml": "PyPI",
    "go.mod": "Go",
    "Cargo.lock": "crates.io",
    "composer.lock": "Packagist",
    "Gemfile.lock": "RubyGems",
    "gradle.lockfile": "Maven",
    "pom.xml": "Maven",
    "packages.lock.json": "NuGet",
    "packages.config": "NuGet",
    "pubspec.lock": "Pub",
    "mix.lock": "Hex",
    # Ruling 31: mapped here, fetched by O2 beside the ten.
    "renv.lock": "CRAN",
}

# Each aborts the WHOLE osv-scanner run when handed through `-L` (rc 127, no
# output, every other lockfile's findings lost; measured on 2.6.0). It decides
# by the exact name, so a differently cased accepted name is rejected too
# ("could not determine extractor", measured on `Requirements.txt`,
# `Package-Lock.json`); the walk's glob ignores case on Windows and found both.
REJECTED = (
    "go.sum",
    "requirements.in",
    "package.json",
    "Pipfile",
    "pyproject.toml",
    "verification-metadata.xml",
    "deps.json",
    "Requirements.txt",
    "requirements.TXT",
    "REQUIREMENTS-dev.txt",
    "Package-Lock.json",
    "cargo.lock",
)


@pytest.mark.parametrize(("name", "ecosystem"), sorted(ACCEPTED.items()))
def test_every_accepted_lockfile_maps_to_its_bucket(name, ecosystem) -> None:
    assert ecosystem_of(name) == ecosystem
    # By name wherever it sits in the tree.
    assert ecosystem_of(f"services/api/{name}") == ecosystem


@pytest.mark.parametrize("name", REJECTED)
def test_a_name_osv_scanner_rejects_maps_to_nothing(name) -> None:
    assert ecosystem_of(name) is None


def test_the_wildcard_is_exact_only_where_it_is_spelled() -> None:
    """Measured, 2.6.0: `requirements-Dev.txt` is read (rc 1, its finding),
    `Requirements.txt` is not. The fixed parts of the pattern are exact."""
    assert ecosystem_of("requirements-Dev.txt") == "PyPI"
    assert ecosystem_of("Requirements-dev.txt") is None


def test_a_conan_lockfile_is_not_read() -> None:
    """Ruling 42: OSV publishes no ConanCenter database (404, and absent from
    its ecosystems list), so a `conan.lock` could only ever fail its row."""
    assert ecosystem_of("conan.lock") is None
    assert "ConanCenter" not in ECOSYSTEMS


def test_the_map_is_exactly_the_accepted_names() -> None:
    """The walk's patterns are derived from this map, so a name added here is
    a name handed to osv-scanner: one it rejects would cost every other
    lockfile's findings."""
    stood_for = {"requirements.txt", "requirements-dev.txt"}
    assert set(LOCKFILE_ECOSYSTEMS) == (set(ACCEPTED) - stood_for) | {
        "requirements*.txt"
    }


def test_the_ecosystems_are_the_eleven_bucket_spellings() -> None:
    assert set(ECOSYSTEMS) == {
        "npm",
        "PyPI",
        "Go",
        "Maven",
        "crates.io",
        "RubyGems",
        "Packagist",
        "NuGet",
        "Pub",
        "Hex",
        "CRAN",
    }
    assert len(ECOSYSTEMS) == len(set(ECOSYSTEMS))


def test_the_cache_is_jmos_own_and_resolved_when_asked(tmp_path, monkeypatch) -> None:
    """Under the home directory as the other `~/.jmo` paths are, and read at
    call time, so a changed home is followed."""
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

    assert cache_dir() == tmp_path / ".jmo" / "osv-db"
    assert database_path("npm") == (
        tmp_path / ".jmo" / "osv-db" / "osv-scalibr" / "npm" / "all.zip"
    )
    assert database_path("PyPI", tmp_path / "c") == (
        tmp_path / "c" / "osv-scalibr" / "PyPI" / "all.zip"
    )


def test_present_means_the_zip_is_there(tmp_path) -> None:
    for ecosystem in ("npm", "Go"):
        path = database_path(ecosystem, tmp_path)
        path.parent.mkdir(parents=True)
        path.write_bytes(b"PK")
    # A directory without its zip (an interrupted fetch) is not a database,
    # and nor is a directory where the zip should be.
    (tmp_path / "osv-scalibr" / "PyPI").mkdir(parents=True)
    database_path("Maven", tmp_path).mkdir(parents=True)

    assert present_ecosystems(cache=tmp_path) == {"npm", "Go"}
    assert present_ecosystems(["Go", "PyPI"], cache=tmp_path) == {"Go"}


def test_the_default_cache_is_the_one_consulted(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(osv_database, "cache_dir", lambda: tmp_path)
    path = database_path("crates.io")
    path.parent.mkdir(parents=True)
    path.write_bytes(b"PK")

    assert present_ecosystems() == {"crates.io"}


def test_an_unreadable_cache_counts_as_absent(tmp_path, monkeypatch) -> None:
    """Python 3.12 raises from `is_file()` where 3.11 returned False (#1163)."""

    def denied(self) -> bool:
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "is_file", denied)

    assert present_ecosystems(cache=tmp_path) == frozenset()


# ---------------------------------------------------------------------------
# The fetch side (Task O2, Ruling 30/31): `fetch_ecosystem`/`fetch_all` fill
# the cache `present_ecosystems` above reads. Exercised against a local
# `http.server` on 127.0.0.1, never the real OSV host -- see task-O2-report.md
# for the one real fetch (crates.io, into a scratch tmp dir, through this same
# module function) and the two HEAD-only size checks.
# ---------------------------------------------------------------------------


def _zip_bytes(content: bytes = b"a synthetic advisory, for testzip to walk") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("all.json", content)
    return buf.getvalue()


@contextmanager
def _serve(handler_cls: type[http.server.BaseHTTPRequestHandler]):
    """A local HTTP server on 127.0.0.1, an ephemeral port.

    Teardown joins the thread with a timeout, never a bare `.join()`
    (Windows hang-prevention rule) -- `server.shutdown()` unblocks
    `serve_forever()` first, so the join is not what does the waiting.
    """
    server = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=10)


class _GoodZip(http.server.BaseHTTPRequestHandler):
    """Every ecosystem gets the same well-formed zip."""

    BODY = _zip_bytes()

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Length", str(len(self.BODY)))
        self.end_headers()
        self.wfile.write(self.BODY)

    def log_message(self, *args: object) -> None:  # quiet the test output
        pass


class _NotFound(http.server.BaseHTTPRequestHandler):
    """An HTML error page -- must never be kept as the zip (`curl -f`)."""

    BODY = b"<html><body>Not Found</body></html>"

    def do_GET(self) -> None:
        self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(self.BODY)))
        self.end_headers()
        self.wfile.write(self.BODY)

    def log_message(self, *args: object) -> None:
        pass


class _CorruptZip(http.server.BaseHTTPRequestHandler):
    """200 OK, but the body is not a zip at all."""

    BODY = b"not a zip file, just plain bytes" * 50

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Length", str(len(self.BODY)))
        self.end_headers()
        self.wfile.write(self.BODY)

    def log_message(self, *args: object) -> None:
        pass


class _Interrupted(http.server.BaseHTTPRequestHandler):
    """Announces a Content-Length it never delivers, then drops the socket."""

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Length", "1000000")
        self.end_headers()
        self.wfile.write(b"only a few bytes before the connection dies")
        self.close_connection = True

    def log_message(self, *args: object) -> None:
        pass


class _MixedResults(http.server.BaseHTTPRequestHandler):
    """PyPI's path 404s; every other ecosystem gets a good zip."""

    GOOD = _zip_bytes()

    def do_GET(self) -> None:
        if self.path.startswith("/PyPI/"):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Length", str(len(self.GOOD)))
        self.end_headers()
        self.wfile.write(self.GOOD)

    def log_message(self, *args: object) -> None:
        pass


def test_fetch_ecosystem_downloads_a_good_zip(tmp_path) -> None:
    with _serve(_GoodZip) as base_url:
        result = fetch_ecosystem("npm", cache=tmp_path, base_url=base_url)

    assert result.success
    assert result.ecosystem == "npm"
    dest = database_path("npm", tmp_path)
    assert dest.read_bytes() == _GoodZip.BODY
    # No stray `.part` temp file left beside the real database.
    assert list(dest.parent.iterdir()) == [dest]


def test_fetch_ecosystem_http_error_fails_and_keeps_the_old_zip(tmp_path) -> None:
    dest = database_path("npm", tmp_path)
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"yesterday's good zip")

    with _serve(_NotFound) as base_url:
        result = fetch_ecosystem("npm", cache=tmp_path, base_url=base_url)

    assert not result.success
    assert "404" in result.message
    # The 404 page is never mistaken for the database.
    assert dest.read_bytes() == b"yesterday's good zip"
    assert list(dest.parent.iterdir()) == [dest]


def test_fetch_ecosystem_corrupt_zip_fails_testzip_and_keeps_the_old_zip(
    tmp_path,
) -> None:
    dest = database_path("npm", tmp_path)
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"yesterday's good zip")

    with _serve(_CorruptZip) as base_url:
        result = fetch_ecosystem("npm", cache=tmp_path, base_url=base_url)

    assert not result.success
    assert "corrupt zip" in result.message
    assert dest.read_bytes() == b"yesterday's good zip"
    assert list(dest.parent.iterdir()) == [dest]


def test_fetch_ecosystem_interrupted_download_leaves_no_partial_file(
    tmp_path,
) -> None:
    dest = database_path("npm", tmp_path)
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"yesterday's good zip")

    with _serve(_Interrupted) as base_url:
        result = fetch_ecosystem("npm", cache=tmp_path, base_url=base_url)

    assert not result.success
    assert dest.read_bytes() == b"yesterday's good zip"
    # Nothing survives beside the (unchanged) real database.
    assert list(dest.parent.iterdir()) == [dest]


def test_fetch_ecosystem_replaces_atomically_via_a_same_dir_temp_file(
    tmp_path, monkeypatch
) -> None:
    """`os.replace` is the only thing that ever creates or overwrites `dest`,
    and its source is a temp file in `dest`'s own directory (Ruling 31's
    atomic-replace requirement: never a cross-filesystem copy)."""
    calls: list[tuple[Path, Path]] = []
    real_replace = osv_database.os.replace

    def spy(src: object, dst: object) -> None:
        calls.append((Path(src), Path(dst)))
        real_replace(src, dst)

    monkeypatch.setattr(osv_database.os, "replace", spy)

    with _serve(_GoodZip) as base_url:
        result = fetch_ecosystem("npm", cache=tmp_path, base_url=base_url)

    assert result.success
    assert len(calls) == 1
    src, dst = calls[0]
    assert dst == database_path("npm", tmp_path)
    assert src.parent == dst.parent
    assert src != dst


def test_fetch_all_continues_past_one_ecosystem_failing(tmp_path) -> None:
    with _serve(_MixedResults) as base_url:
        results = fetch_all(["npm", "PyPI", "Go"], cache=tmp_path, base_url=base_url)

    by_ecosystem = {r.ecosystem: r for r in results}
    assert by_ecosystem["npm"].success
    assert by_ecosystem["Go"].success
    assert not by_ecosystem["PyPI"].success
    assert database_path("npm", tmp_path).is_file()
    assert database_path("Go", tmp_path).is_file()
    assert not database_path("PyPI", tmp_path).is_file()


def test_fetch_all_defaults_to_every_ecosystem_the_map_names(
    tmp_path, monkeypatch
) -> None:
    """No second, hand-written ecosystem list for the fetch side (Ruling 31)."""
    seen: list[str] = []

    def fake_fetch(eco, cache=None, *, base_url="", timeout=0):
        seen.append(eco)
        return FetchResult(eco, True, "stub")

    monkeypatch.setattr(osv_database, "fetch_ecosystem", fake_fetch)

    fetch_all(cache=tmp_path)

    assert seen == list(ECOSYSTEMS)
