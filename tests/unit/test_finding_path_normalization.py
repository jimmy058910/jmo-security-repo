"""Regression tests for #861 - `location.path` normalization.

A single `deep` scan of one directory produced four spellings of one file and
shipped the scanning machine's home directory into `findings.sarif` and
`dashboard.html`. Measured on a real 153-finding scan before the fix:

    absolute paths     24        backslash separators   107
    leading separators 64        distinct paths          16

and after it: 0, 0, 0, and 7 - with `python/vulnerable_app.py` collapsing from
two spellings (17 + 2) into one (19).

These assert the **properties** rather than the shapes that happened to be
wrong: "one spelling per location", "no scan root survives in a stored path",
"an id is re-keyed only when it can be shown to have come from the old path".
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.core import normalize_and_report as nr
from scripts.core.adapters.common import normalize_finding_path
from scripts.core.common_finding import fingerprint

BS = chr(92)  # a literal backslash, spelled so no escape processing can eat it
ROOT = "C:" + BS + "work" + BS + "repo"


# ---------------------------------------------------------------------------
# The pure normalizer
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "roots", "expected", "why"),
    [
        ("python" + BS + "app.py", (), "python/app.py", "horusec spelling"),
        ("/iac/x.tf", (), "iac/x.tf", "leading separator"),
        (BS + "iac" + BS + "x.tf", (), "iac/x.tf", "leading separator + backslash"),
        ("iac/x.tf", (), "iac/x.tf", "already canonical, unchanged"),
        (ROOT + BS + "iac" + BS + "x.tf", (ROOT,), "iac/x.tf", "absolute under root"),
        (
            "C:/work/repo/iac/x.tf",
            ("c:/WORK/repo",),
            "iac/x.tf",
            "root case-insensitive",
        ),
        ("C:/work/repo/a/x.tf", ("C:/work", "C:/work/repo"), "a/x.tf", "deepest root"),
        ("", (), "", "empty stays empty"),
    ],
)
def test_normalizer_produces_one_repo_relative_posix_spelling(
    raw: str, roots: tuple[str, ...], expected: str, why: str
):
    assert normalize_finding_path(raw, roots) == expected, why


@pytest.mark.parametrize(
    ("raw", "why"),
    [
        ("https://example.com/a/b", "zap stores a URL in location.path"),
        ("http://h/a", "zap, no query string"),
        # The separator rewrite is what would corrupt a URL, so the case that
        # proves the guard is load bearing is a URL containing a backslash.
        # Without the guard this becomes `https://h/a/b` - a different resource.
        ("https://h/a" + BS + "b", "a URL whose path contains a backslash"),
        ("myhost", "lynis stores a bare hostname"),
        ("myhost:openssl", "lynis stores hostname:package"),
        ("C:/elsewhere/x.tf", "absolute but under no scanned root"),
        # Likewise, `C:/elsewhere/x.tf` alone cannot fail if the drive-letter
        # guard is deleted - nothing else in the function touches it. A UNC
        # path can: `lstrip("/")` would turn it into a relative path.
        ("//server/share/x.tf", "a UNC path must not be made relative"),
    ],
)
def test_values_that_are_not_repo_paths_are_returned_unchanged(raw: str, why: str):
    """`location.path` is polymorphic; only one of its shapes is a repo path.

    Measured in #861: zap writes `uri.split("?")[0]`, lynis writes a hostname
    and `f"{hostname}:{package}"`. Rewriting those would corrupt data that was
    already correct. The absolute-outside-every-root case is deliberate too --
    stripping a drive letter is the mistake #538 made, where normalizing the
    pattern `C:/*` to `*` suppressed an entire scan.
    """
    assert normalize_finding_path(raw, (ROOT,)) == raw, why


# ---------------------------------------------------------------------------
# Path rewriting + id re-keying
# ---------------------------------------------------------------------------


def _path_derived_finding() -> dict:
    """A finding whose id came from `location.path`, as 25 of 29 adapters build."""
    path = ROOT + BS + "python" + BS + "app.py"
    return {
        "id": fingerprint("bandit", "B403", path, 5, "pickle import"),
        "ruleId": "B403",
        "tool": {"name": "bandit", "version": "1.9.4"},
        "location": {"path": path, "startLine": 5},
        "message": "pickle import",
    }


def test_path_derived_id_is_rekeyed_to_the_normalized_path():
    finding = _path_derived_finding()
    before = finding["id"]

    changed, rekeyed = nr._normalize_paths_and_ids([finding], (ROOT,))

    assert (changed, rekeyed) == (1, 1)
    assert finding["location"]["path"] == "python/app.py"
    assert finding["id"] == fingerprint(
        "bandit", "B403", "python/app.py", 5, "pickle import"
    )
    assert finding["id"] != before, "an id keyed on the old path must not survive"


def test_two_spellings_of_one_location_become_one_id():
    """The property that makes dedup work at all.

    Two adapters reporting the same file must end up with the same id, or
    `deduplicate_findings_memory_efficient` cannot tell they are one location.
    """
    absolute = ROOT + BS + "python" + BS + "app.py"
    relative = "python" + BS + "app.py"
    findings = [
        {
            "id": fingerprint("t", "R1", absolute, 5, "m"),
            "ruleId": "R1",
            "tool": {"name": "t"},
            "location": {"path": absolute, "startLine": 5},
            "message": "m",
        },
        {
            "id": fingerprint("t", "R1", relative, 5, "m"),
            "ruleId": "R1",
            "tool": {"name": "t"},
            "location": {"path": relative, "startLine": 5},
            "message": "m",
        },
    ]
    assert findings[0]["id"] != findings[1]["id"], "precondition: two ids before"

    nr._normalize_paths_and_ids(findings, (ROOT,))

    assert {f["location"]["path"] for f in findings} == {"python/app.py"}
    assert findings[0]["id"] == findings[1]["id"]
    assert len(nr.deduplicate_findings_memory_efficient(findings)) == 1


def test_an_id_built_from_a_custom_key_is_never_rekeyed():
    """zap, cdxgen, nuclei and mobsf do not fingerprint on `location.path`.

    zap keys on `f"{uri}:{method}:{param}:{idx}"` so that several instances of
    one alert on one URI stay distinct. Re-keying those from `location.path`
    would give every instance the same id and dedup would then delete all but
    the first - a path cleanup turning into silent finding loss.

    The path here still normalizes; only the id is left alone.
    """
    custom = fingerprint("zap", "ZAP-79", "http://h/a:GET:q:0", 0, "XSS")
    findings = [
        {
            "id": custom,
            "ruleId": "ZAP-79",
            "tool": {"name": "zap"},
            "location": {"path": ROOT + BS + "a" + BS + "b.html", "startLine": 0},
            "message": "XSS",
        }
    ]

    changed, rekeyed = nr._normalize_paths_and_ids(findings, (ROOT,))

    assert changed == 1, "the path is still normalized"
    assert rekeyed == 0, "an id we cannot prove came from the path must not move"
    assert findings[0]["id"] == custom


def test_the_two_fingerprint_formulas_agree_except_on_line_and_whitespace():
    """Pins *why* the legacy branch exists, so its test cannot go vacuous.

    Measured: the formulas are byte-identical for an integer line and an
    unpadded message, and differ only when the line is missing (`0` vs `""`)
    or the message needs stripping. A legacy-branch test written with
    `startLine=3, message="boom"` therefore exercises the **first** branch and
    passes with the legacy branch deleted - which is what the mutation run
    caught here.
    """
    path = "a/b.py"
    same = fingerprint("trivy", "CVE-1", path, 3, "boom") == (
        nr._legacy_plugin_fingerprint("trivy", "CVE-1", path, 3, "boom")
    )
    assert same, "formulas must agree on the common case, or the guard is untested"

    assert fingerprint("trivy", "CVE-1", path, None, "boom") != (
        nr._legacy_plugin_fingerprint("trivy", "CVE-1", path, "", "boom")
    ), "a missing line is what distinguishes them"


def test_legacy_plugin_fingerprint_formula_is_also_recognised():
    """trivy, trufflehog and semgrep use `AdapterPlugin.get_fingerprint`.

    It renders a missing line as `""` where `fingerprint()` uses `0`. An id
    built by that second formula must be re-keyed too, or those three tools
    keep stale ids while every other tool's move.

    `startLine` is deliberately absent: with it present as an int the two
    formulas coincide and this test would pass even with the legacy branch
    removed.
    """
    path = ROOT + BS + "a" + BS + "b.py"
    finding = {
        "id": nr._legacy_plugin_fingerprint("trivy", "CVE-1", path, "", "boom"),
        "ruleId": "CVE-1",
        "tool": {"name": "trivy"},
        "location": {"path": path},
        "message": "boom",
    }
    assert finding["id"] != fingerprint(
        "trivy", "CVE-1", path, None, "boom"
    ), "precondition: this id must be reachable only by the legacy formula"

    changed, rekeyed = nr._normalize_paths_and_ids([finding], (ROOT,))

    assert (changed, rekeyed) == (1, 1)
    assert finding["id"] == nr._legacy_plugin_fingerprint(
        "trivy", "CVE-1", "a/b.py", "", "boom"
    )


def test_findings_without_a_usable_path_are_left_alone():
    findings = [
        {"id": "a", "location": {}},
        {"id": "b", "location": {"path": ""}},
        {"id": "c"},
        {"id": "d", "location": "not-a-dict"},
    ]
    assert nr._normalize_paths_and_ids(findings, (ROOT,)) == (0, 0)


# ---------------------------------------------------------------------------
# End to end, through the path the issue describes
# ---------------------------------------------------------------------------


def test_scan_roots_reads_repo_paths(tmp_path: Path):
    (tmp_path / ".scan_metadata.json").write_text(
        json.dumps({"repo_paths": [ROOT, "", 7]}), encoding="utf-8"
    )
    assert nr.scan_roots(tmp_path) == (ROOT,)


@pytest.mark.parametrize(
    "meta",
    ["", "{not json", json.dumps([1, 2]), json.dumps({"repo_paths": "nope"})],
)
def test_scan_roots_survives_a_results_dir_jmo_did_not_write(tmp_path: Path, meta: str):
    if meta:
        (tmp_path / ".scan_metadata.json").write_text(meta, encoding="utf-8")
    assert nr.scan_roots(tmp_path) == ()


def test_gather_results_strips_the_scan_root_from_a_real_bandit_output(tmp_path: Path):
    """The user-visible half of #861, through `gather_results`.

    Before the fix this produced
    `C:\\Users\\<user>\\...\\python\\vulnerable_app.py`, which then reached
    `findings.sarif` (the artifact uploaded to the GitHub Security tab) and
    `dashboard.html` (the one people share).
    """
    root = tmp_path / "repo"
    results = tmp_path / "results"
    scanned = root / "python" / "vulnerable_app.py"
    (results / "individual-repos" / "repo").mkdir(parents=True)
    (results / ".scan_metadata.json").write_text(
        json.dumps({"repo_paths": [str(root)]}), encoding="utf-8"
    )
    (results / "individual-repos" / "repo" / "bandit.json").write_text(
        json.dumps(
            {
                "errors": [],
                "results": [
                    {
                        "filename": str(scanned),
                        "issue_confidence": "HIGH",
                        "issue_severity": "LOW",
                        "issue_text": "Consider possible security implications.",
                        "issue_cwe": {"id": 502},
                        "line_number": 5,
                        "test_id": "B403",
                        "test_name": "blacklist",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    findings = nr.gather_results(results)

    assert findings, "the bandit adapter produced nothing to assert on"
    paths = [(f.get("location") or {}).get("path") for f in findings]
    assert paths == ["python/vulnerable_app.py"]
    # The property, not the spelling: no stored path may contain the scan root.
    assert not any(
        str(root).replace(BS, "/").casefold() in (p or "").casefold() for p in paths
    ), f"the scan root survived into a stored path: {paths}"
