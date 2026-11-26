"""Regression tests for #849 - EPSS request volume and URL bounds.

Measured with `requests.get` mocked to answer "EPSS knows none of these", which
is the case the defect is about:

======  ==========  =========  ==========  ==========  ==========
 CVEs   individual  bulk URL    total req   total req   sqlite
        requests      chars      (cold)      (warm)      conns
======  ==========  =========  ==========  ==========  ==========
before
  2000        2000     28,038        2001        2001       4000
after
  2000           0      1,438          20           0       2001
======  ==========  =========  ==========  ==========  ==========

Four separate defects fall out of that:

1. **No negative caching.** `_fetch_from_api` returned None on `total == 0` and
   `_cache_score` was only reached on a hit, so an unknown CVE produced a fresh
   HTTP request on every finding, on every run, forever.
2. **The bulk URL was unbounded.** 2000 CVEs joined into one query string is
   28 KB against a conservative practical limit of 2048. Past the limit the
   bulk call fails, `except Exception` logs a warning, and every finding falls
   through to the per-finding path -- so defect 2's failure mode *is* defect 1
   at full scale.
3. **The bulk result was discarded** into `_`, so it only ever helped as a
   cache pre-warm, which is exactly what defect 1 prevented.
4. **Two SQLite connections per lookup**, because `_get_cached_score` and
   `_is_cache_valid` each opened one and each re-read the same row.
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.core.epss_integration import EPSSClient
from scripts.core.priority_calculator import PriorityCalculator

REAL_CONNECT = sqlite3.connect


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class RequestSpy:
    """Records every URL and answers 'EPSS knows none of these' by default."""

    def __init__(self, known: dict[str, float] | None = None):
        self.urls: list[str] = []
        self.known = known or {}

    def __call__(self, url, **kwargs):
        self.urls.append(url)
        asked = url.split("cve=", 1)[1].split(",") if "cve=" in url else []
        data = [
            {
                "cve": cve,
                "epss": self.known[cve],
                "percentile": 0.5,
                "date": "2026-01-01",
            }
            for cve in asked
            if cve in self.known
        ]
        return FakeResponse({"total": len(data), "data": data})

    @property
    def bulk_urls(self):
        return [u for u in self.urls if "," in u]

    @property
    def individual_urls(self):
        return [u for u in self.urls if "," not in u]


def _findings(cves):
    return [
        {
            "id": f"f{i}",
            "severity": "HIGH",
            "tool": {"name": "trivy"},
            "location": {"path": "a"},
            "message": "m",
            "raw": {"VulnerabilityID": cve},
        }
        for i, cve in enumerate(cves)
    ]


def _cves(n):
    return [f"CVE-2024-{1000 + i}" for i in range(n)]


# ---------------------------------------------------------------------------
# 1 + 3: request volume
# ---------------------------------------------------------------------------


def test_unknown_cves_produce_no_per_finding_requests(tmp_path: Path):
    """The headline. 500 unscored CVEs used to mean 500 sequential GETs."""
    spy = RequestSpy()
    calc = PriorityCalculator(cache_dir=str(tmp_path))

    with patch("scripts.core.epss_integration.requests.get", spy):
        result = calc.calculate_priorities_bulk(_findings(_cves(500)))

    assert len(result) == 500, "every finding must still get a priority"
    assert spy.individual_urls == [], (
        f"{len(spy.individual_urls)} per-finding requests were made"
    )


def test_a_repeat_run_asks_nothing_at_all(tmp_path: Path):
    """Negative caching, measured the only way that proves it: run twice."""
    calc = PriorityCalculator(cache_dir=str(tmp_path))
    findings = _findings(_cves(50))

    with patch("scripts.core.epss_integration.requests.get", RequestSpy()):
        calc.calculate_priorities_bulk(findings)

    warm = RequestSpy()
    with patch("scripts.core.epss_integration.requests.get", warm):
        calc.calculate_priorities_bulk(findings)

    assert warm.urls == [], f"a warm cache still made {len(warm.urls)} request(s)"


def test_get_score_remembers_a_miss_on_its_own(tmp_path: Path):
    """The single-CVE path caches a miss too, not only the bulk path.

    A mutation that removed the miss write from `get_score` survived every other
    test here: they all reach the bulk path, and the run merely got *slower*
    (10.4s against a 4.9s baseline) rather than failing.
    """
    cve = "CVE-2024-1000"
    client = EPSSClient(cache_dir=tmp_path)
    spy = RequestSpy()

    with patch("scripts.core.epss_integration.requests.get", spy):
        assert client.get_score(cve) is None
        first = len(spy.urls)
        assert client.get_score(cve) is None
        assert client.get_score(cve) is None

    assert first == 1, f"the first lookup made {first} requests"
    assert len(spy.urls) == 1, (
        f"asking about the same unknown CVE 3 times made {len(spy.urls)} requests"
    )


def test_bulk_uses_the_prewarmed_result_instead_of_re_querying(tmp_path: Path):
    """Defect 3, which request counting cannot see.

    Once misses are cached, re-querying per finding costs no extra HTTP request
    - only an extra database lookup each - so every request-based assertion in
    this file passes with the pre-warm discarded. The property is that the
    per-finding loop does not consult the client at all.
    """
    cves = _cves(25)
    calc = PriorityCalculator(cache_dir=str(tmp_path))
    calls: list[str] = []
    real_get_score = calc.epss_client.get_score

    def counting_get_score(cve):
        calls.append(cve)
        return real_get_score(cve)

    with patch("scripts.core.epss_integration.requests.get", RequestSpy()):
        with patch.object(calc.epss_client, "get_score", counting_get_score):
            result = calc.calculate_priorities_bulk(_findings(cves))

    assert len(result) == 25
    assert calls == [], (
        f"the per-finding loop called get_score {len(calls)} times instead of "
        "reading the pre-warmed bulk result"
    )


def test_a_standalone_calculate_priority_still_queries(tmp_path: Path):
    """The negative control for the pre-warm.

    Outside `calculate_priorities_bulk` there is no pre-warmed result, so the
    client must still be consulted - otherwise the optimisation would silently
    turn single-finding scoring into a no-op.
    """
    cve = "CVE-2024-1000"
    calc = PriorityCalculator(cache_dir=str(tmp_path))

    with patch("scripts.core.epss_integration.requests.get", RequestSpy({cve: 0.6})):
        score = calc.calculate_priority(_findings([cve])[0])

    assert score.epss == pytest.approx(0.6)


def test_a_known_score_still_reaches_the_finding(tmp_path: Path):
    """The negative control.

    Suppressing requests is easy; the enrichment has to still work. Without
    this, an implementation that returned early would pass every test above.
    """
    cve = "CVE-2024-1000"
    spy = RequestSpy(known={cve: 0.97})
    calc = PriorityCalculator(cache_dir=str(tmp_path))

    with patch("scripts.core.epss_integration.requests.get", spy):
        result = calc.calculate_priorities_bulk(_findings([cve]))

    assert result["f0"].epss == pytest.approx(0.97)
    assert result["f0"].priority > 0


def test_a_network_failure_is_not_remembered_as_a_missing_score(tmp_path: Path):
    """An outage is not evidence that EPSS lacks a score.

    Caching it as one would suppress the real answer for a whole TTL.
    """
    cve = "CVE-2024-1000"

    def boom(url, **kwargs):
        raise OSError("network down")

    client = EPSSClient(cache_dir=tmp_path)
    with patch("scripts.core.epss_integration.requests.get", boom):
        assert client.get_score(cve) is None

    spy = RequestSpy(known={cve: 0.5})
    with patch("scripts.core.epss_integration.requests.get", spy):
        score = client.get_score(cve)

    assert score is not None and score.epss == pytest.approx(0.5)
    assert spy.urls, "the retry must actually reach the API"


# ---------------------------------------------------------------------------
# 2: URL bounds
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("count", [50, 500, 2000])
def test_the_bulk_url_stays_under_the_practical_limit(tmp_path: Path, count: int):
    """2048 chars is the conservative bound; 2000 CVEs used to make 28 KB."""
    spy = RequestSpy()
    client = EPSSClient(cache_dir=tmp_path)

    with patch("scripts.core.epss_integration.requests.get", spy):
        client.get_scores_bulk(_cves(count))

    assert spy.urls, "no request was made at all"
    longest = max(len(u) for u in spy.urls)
    assert longest <= 2048, f"bulk URL reached {longest} chars"


def test_every_cve_is_still_asked_about_across_the_chunks(tmp_path: Path):
    """Chunking must not drop anyone.

    A chunker that asked about only the first batch would satisfy the URL bound
    above while silently losing 95% of the CVEs.
    """
    cves = _cves(250)
    spy = RequestSpy(known=dict.fromkeys(cves, 0.1))
    client = EPSSClient(cache_dir=tmp_path)

    with patch("scripts.core.epss_integration.requests.get", spy):
        scores = client.get_scores_bulk(cves)

    asked = {c for url in spy.urls for c in url.split("cve=", 1)[1].split(",")}
    assert asked == set(cves), f"{len(set(cves) - asked)} CVEs were never asked about"
    assert set(scores) == set(cves)


# ---------------------------------------------------------------------------
# 4: connections
# ---------------------------------------------------------------------------


def test_a_cache_hit_costs_one_connection_not_two(tmp_path: Path):
    """`_get_cached_score` + `_is_cache_valid` each opened their own."""
    cve = "CVE-2024-1000"
    client = EPSSClient(cache_dir=tmp_path)
    with patch("scripts.core.epss_integration.requests.get", RequestSpy({cve: 0.4})):
        client.get_score(cve)

    conns: list = []

    def spy(*a, **kw):
        conns.append(a[0] if a else None)
        return REAL_CONNECT(*a, **kw)

    with patch.object(sqlite3, "connect", spy):
        score = client.get_score(cve)

    assert score is not None, "the cached score must still be returned"
    assert len(conns) == 1, f"a cache hit opened {len(conns)} connections"


def test_recording_many_misses_uses_one_connection(tmp_path: Path):
    """At 2000 unknown CVEs, one connection instead of 2000."""
    client = EPSSClient(cache_dir=tmp_path)
    conns: list = []

    def spy(*a, **kw):
        conns.append(a[0] if a else None)
        return REAL_CONNECT(*a, **kw)

    with patch.object(sqlite3, "connect", spy):
        client._cache_misses(_cves(2000))

    assert len(conns) == 1, f"{len(conns)} connections for one batch of misses"


class CommitCounter:
    """A `sqlite3.connect` stand-in that counts connections and commits.

    A commit is a disk flush, so the commit count, not wall time, is what makes
    a bulk fetch slow on a busy disk (#1673). Counting it measures the code
    rather than the machine.
    """

    def __init__(self):
        self.connections = 0
        self.commits = 0
        counter = self

        class CountingConnection(sqlite3.Connection):
            def commit(self):
                counter.commits += 1
                return super().commit()

        self._factory = CountingConnection

    def __call__(self, *a, **kw):
        self.connections += 1
        return REAL_CONNECT(*a, factory=self._factory, **kw)


@pytest.mark.parametrize(
    ("found", "missed"),
    [(250, 0), (100, 150)],
    ids=["all-found", "found-and-missed"],
)
def test_a_bulk_fetch_commits_once_per_kind_of_row(
    tmp_path: Path, found: int, missed: int
):
    """#1673: the found scores were cached with one commit each.

    A 100-CVE fetch made 100 commits, one disk flush per score, while the misses
    from the same call were already one transaction. 250 CVEs span three API
    chunks, so a count that grew with rows or with chunks would show here.
    """
    from datetime import datetime, timedelta

    cves = _cves(found + missed)
    known = {cve: round(0.001 * (i + 1), 3) for i, cve in enumerate(cves[:found])}
    client = EPSSClient(cache_dir=tmp_path)
    counter = CommitCounter()

    with patch("scripts.core.epss_integration.requests.get", RequestSpy(known)):
        with patch.object(sqlite3, "connect", counter):
            scores = client.get_scores_bulk(cves)

    expected = 1 + (1 if missed else 0)
    assert counter.commits == expected, (
        f"{counter.commits} commits for {found} found and {missed} missed CVEs; "
        f"expected {expected} (one per kind of row). 0 means the writes no "
        "longer go through Connection.commit, so this counter cannot see them."
    )
    assert set(scores) == set(known)

    # The rows a reader of the cache sees are the same as before the batching.
    conn = REAL_CONNECT(client.cache_path)
    try:
        rows = {
            row[0]: row[1:]
            for row in conn.execute(
                "SELECT cve, epss, percentile, date, cached_at, found FROM epss_scores"
            )
        }
    finally:
        conn.close()
    assert set(rows) == set(cves)
    for cve in cves:
        epss, percentile, date, cached_at, row_found = rows[cve]
        assert datetime.now() - datetime.fromisoformat(cached_at) < timedelta(minutes=5)
        if cve in known:
            assert (epss, percentile, date, row_found) == (
                known[cve],
                0.5,
                "2026-01-01",
                1,
            )
        else:
            assert (epss, percentile, date, row_found) == (None, None, None, 0)


def _unwritable(*_a, **_k):
    raise sqlite3.OperationalError("attempt to write a readonly database")


@pytest.mark.parametrize("failing", ["_cache_scores", "_cache_misses"])
def test_a_cache_that_cannot_be_written_keeps_the_bulk_scores(
    tmp_path: Path, failing: str, caplog
):
    """The cache write sat inside the fetch's `try`, before the scores were
    kept. Measured with the cache file and folder read-only: a bulk call that
    fetched 99 scores returned 0. The write raises here rather than through
    file permissions: Windows has none to set, and root ignores them."""
    cves = _cves(100)
    known = dict.fromkeys(cves[:99], 0.5)
    client = EPSSClient(cache_dir=tmp_path)

    with (
        patch("scripts.core.epss_integration.requests.get", RequestSpy(known)),
        patch.object(EPSSClient, failing, _unwritable),
        caplog.at_level(logging.WARNING),
    ):
        scores = client.get_scores_bulk(cves)

    assert set(scores) == set(known)
    assert "could not be written" in caplog.text


def test_a_cache_that_cannot_be_written_keeps_a_single_score(tmp_path: Path, caplog):
    """`get_score` had the same order: measured, None for a CVE it had just
    fetched. An unknown CVE still answers None, without raising."""
    known_cve, unknown_cve = _cves(2)
    client = EPSSClient(cache_dir=tmp_path)

    with (
        patch(
            "scripts.core.epss_integration.requests.get", RequestSpy({known_cve: 0.5})
        ),
        patch.object(EPSSClient, "_cache_scores", _unwritable),
        patch.object(EPSSClient, "_cache_misses", _unwritable),
        caplog.at_level(logging.WARNING),
    ):
        score = client.get_score(known_cve)
        missing = client.get_score(unknown_cve)

    assert score is not None and score.epss == 0.5
    assert missing is None
    assert caplog.text.count("could not be written") == 2


def test_an_expired_negative_entry_is_asked_about_again(tmp_path: Path):
    """A miss is remembered, not remembered forever.

    "Not scored yet" is temporary - EPSS publishes new CVEs daily.
    """
    from datetime import datetime, timedelta

    cve = "CVE-2024-1000"
    client = EPSSClient(cache_dir=tmp_path)
    with patch("scripts.core.epss_integration.requests.get", RequestSpy()):
        assert client.get_score(cve) is None

    stale = (
        datetime.now() - timedelta(days=client.NEGATIVE_CACHE_TTL_DAYS + 1)
    ).isoformat()
    conn = REAL_CONNECT(client.cache_path)
    conn.execute("UPDATE epss_scores SET cached_at = ? WHERE cve = ?", (stale, cve))
    conn.commit()
    conn.close()

    spy = RequestSpy(known={cve: 0.8})
    with patch("scripts.core.epss_integration.requests.get", spy):
        score = client.get_score(cve)

    assert score is not None and score.epss == pytest.approx(0.8)


def test_the_negative_ttl_is_shorter_than_the_positive_one():
    assert EPSSClient.NEGATIVE_CACHE_TTL_DAYS < EPSSClient.CACHE_TTL_DAYS


def test_an_existing_cache_without_the_found_column_is_migrated(tmp_path: Path):
    """A warm cache on disk predates negative caching and must survive."""
    cache = tmp_path / "epss_scores.db"
    conn = REAL_CONNECT(cache)
    conn.execute(
        "CREATE TABLE epss_scores (cve TEXT PRIMARY KEY, epss REAL, "
        "percentile REAL, date TEXT, cached_at TEXT)"
    )
    from datetime import datetime

    conn.execute(
        "INSERT INTO epss_scores VALUES (?, ?, ?, ?, ?)",
        ("CVE-2024-1000", 0.6, 0.9, "2026-01-01", datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()

    client = EPSSClient(cache_dir=tmp_path)
    score = client.get_score("CVE-2024-1000")

    assert score is not None, "the pre-existing cached score was lost"
    assert score.epss == pytest.approx(0.6)
