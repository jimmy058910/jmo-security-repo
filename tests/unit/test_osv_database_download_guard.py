"""Guard: `_guard_no_unmarked_osv_database_download` must still detect a real
download (fix round 1, review Ruling 43, named risk (b)).

`tests/conftest.py`'s autouse fixture wraps `osv_database._get` (a name that
exists only in that module -- patching `requests.get` itself would also
intercept every OTHER module's real, unrelated network calls, measured
directly against `kev_integration.py`'s real CISA feed fetch) for every test
and blocks any call whose host is not a local test server, unless the test
declares `@pytest.mark.requires_tools`. A guard that cannot fail is worse
than no guard - it is confidence without substance (the same argument
`tests/unit/test_scanner_spawn_guard.py` makes for the Popen guard) - so this
proves the underlying detection logic (`osv_download_host_is_allowed`,
`make_osv_download_guard`) still fires.

Deliberately never lets a fake "real" request reach anywhere: the whole point
is proving the block happens BEFORE the delegate (a stand-in for the real
`requests.get`) is ever called, using a fake delegate that raises if it is
- the same shape `test_recorder_detects_a_deliberate_spawn_without_a_real_process`
uses for the Popen guard, with a fake `Popen.__init__` standing in for a real
process.
"""

from __future__ import annotations

import pytest

from tests.conftest import make_osv_download_guard, osv_download_host_is_allowed


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8080/npm/all.zip",
        "https://127.0.0.1/npm/all.zip",
        "http://localhost:9/PyPI/all.zip",
        "http://localhost/npm/all.zip",
    ],
)
def test_a_local_test_server_is_allowed(url) -> None:
    assert osv_download_host_is_allowed(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
        "https://osv-vulnerabilities.storage.googleapis.com/CRAN/all.zip",
        "http://example.com/npm/all.zip",
        # Not localhost just because it contains the string.
        "http://notlocalhost.example.com/all.zip",
        "http://127.0.0.1.evil.example.com/all.zip",
    ],
)
def test_a_real_host_is_not_allowed(url) -> None:
    assert osv_download_host_is_allowed(url) is False


def test_the_guard_blocks_a_real_host_before_the_real_transport_runs() -> None:
    """The floor this guard exists for: without it, a bare `fetch_ecosystem`
    call with no `base_url` override would reach the real OSV host. Proves
    the wrapper intercepts before the delegate - a stand-in for the real
    `requests.get` - is ever called."""
    delegate_calls: list[str] = []
    blocked_urls: list[str] = []

    def fake_delegate(url, *a, **kw):
        delegate_calls.append(url)
        raise AssertionError("must not be reached for a non-local host")

    def on_blocked(url: str) -> None:
        blocked_urls.append(url)
        raise RuntimeError(f"blocked: {url}")

    guarded_get = make_osv_download_guard(fake_delegate, on_blocked)

    with pytest.raises(RuntimeError, match="^blocked:"):
        guarded_get("https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip")

    assert blocked_urls == [
        "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"
    ]
    assert delegate_calls == []  # the real transport was never reached


def test_the_guard_passes_a_local_test_server_straight_through() -> None:
    delegate_calls: list[str] = []

    def fake_delegate(url, *a, **kw):
        delegate_calls.append(url)
        return "ok"

    def on_blocked(url: str) -> None:
        raise RuntimeError(f"blocked: {url}")  # pragma: no cover - must not fire

    guarded_get = make_osv_download_guard(fake_delegate, on_blocked)

    result = guarded_get("http://127.0.0.1:9/npm/all.zip", stream=True, timeout=300)

    assert result == "ok"
    assert delegate_calls == ["http://127.0.0.1:9/npm/all.zip"]


def test_the_guard_forwards_args_and_kwargs_to_the_delegate() -> None:
    """The wrapper must not silently drop `stream=True`/`timeout=` -- the
    real call always passes both."""
    seen: list[tuple[tuple, dict]] = []

    def fake_delegate(url, *a, **kw):
        seen.append((a, kw))
        return "ok"

    guarded_get = make_osv_download_guard(fake_delegate, lambda url: None)

    guarded_get("http://127.0.0.1:9/npm/all.zip", stream=True, timeout=300)

    assert seen == [((), {"stream": True, "timeout": 300})]
