"""Unit tests for the e2e scan validators in tests/e2e/conftest.py.

U1, U5, M1 and W1 passed for as long as they existed without scanning anything:
they handed ``jmo ci --repo`` a URL, it rejected the only target ("Every target
was rejected", rc 1, ``meta.target_count`` 0), and the validators accepted the
empty outputs it still wrote because they checked that files exist. These tests
build results trees by hand, with no scan, and hold the validators to what a
scan that scanned looks like.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.e2e.conftest import validate_basic_scan, validate_multi_target

FINDING = {"id": "f1", "fingerprint_id": "aaaa", "severity": "HIGH"}


def write_results(
    root: Path,
    *,
    findings: list[dict] | None = None,
    meta: dict | None = None,
    targets: dict[str, list[str]] | None = None,
    raw: object = None,
    summary: bool = True,
    dashboard: bool = True,
) -> Path:
    """Build the results tree ``jmo ci`` writes, minus the scanning.

    ``targets`` maps a per-target directory (``individual-repos``) to the target
    directories inside it. ``meta`` defaults to the scan's own count of them, so
    a test states only what it varies. ``raw`` replaces the whole findings.json.
    """
    targets = targets or {}
    findings = findings or []
    if meta is None:
        meta = {"target_count": sum(len(names) for names in targets.values())}

    summaries = root / "summaries"
    summaries.mkdir(parents=True)
    document = raw if raw is not None else {"meta": meta, "findings": findings}
    (summaries / "findings.json").write_text(json.dumps(document), encoding="utf-8")
    if summary:
        (summaries / "SUMMARY.md").write_text("# Summary\n", encoding="utf-8")
    if dashboard:
        (summaries / "dashboard.html").write_text("<html></html>", encoding="utf-8")

    for kind, names in targets.items():
        (root / kind).mkdir()
        for name in names:
            (root / kind / name).mkdir()
    return root


class TestValidateBasicScan:
    def test_a_repository_scan_with_findings_passes(self, tmp_path):
        write_results(
            tmp_path,
            findings=[FINDING],
            targets={"individual-repos": ["juice-shop"]},
        )

        validate_basic_scan(tmp_path)

    def test_a_scan_that_rejected_every_target_fails(self, tmp_path):
        """The U1 bug: a URL given to ``--repo`` leaves ``target_count`` 0."""
        write_results(tmp_path, meta={"target_count": 0})

        with pytest.raises(AssertionError, match=r"target_count >= 1.*read 0"):
            validate_basic_scan(tmp_path)

    @pytest.mark.parametrize("value", [None, "1", True, -1, 1.0])
    def test_target_count_must_be_a_positive_integer(self, tmp_path, value):
        write_results(tmp_path, meta={"target_count": value})

        with pytest.raises(AssertionError, match="target_count >= 1"):
            validate_basic_scan(tmp_path)

    def test_a_missing_target_count_fails(self, tmp_path):
        write_results(tmp_path, meta={})

        with pytest.raises(AssertionError, match=r"target_count >= 1.*read None"):
            validate_basic_scan(tmp_path)

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ([FINDING], "JSON object.*read list"),
            ({"findings": [FINDING]}, "'meta' object"),
            ({"meta": [], "findings": []}, "'meta' object"),
        ],
    )
    def test_findings_json_without_a_meta_object_fails(self, tmp_path, raw, expected):
        """A bare list or a missing ``meta`` cannot say what was scanned."""
        write_results(tmp_path, raw=raw)

        with pytest.raises(AssertionError, match=expected):
            validate_basic_scan(tmp_path)

    def test_a_repository_target_with_no_findings_fails(self, tmp_path):
        """A real repository scan that finds nothing scanned nothing."""
        write_results(tmp_path, targets={"individual-repos": ["juice-shop"]})

        with pytest.raises(AssertionError, match=r"repository target.*juice-shop.*0"):
            validate_basic_scan(tmp_path)

    def test_a_gitlab_target_with_no_findings_fails(self, tmp_path):
        """A1's shape: ``--gitlab-repo`` leaves ``individual-repos`` empty and
        writes the clone's outputs to ``individual-gitlab``."""
        write_results(
            tmp_path,
            targets={
                "individual-repos": [],
                "individual-gitlab": ["juice-shop_juice-shop"],
                "individual-images": ["alpine"],
            },
        )

        with pytest.raises(
            AssertionError,
            match=r"repository target.*individual-gitlab/juice-shop_juice-shop.*0",
        ):
            validate_basic_scan(tmp_path)

    def test_a_gitlab_target_with_findings_passes(self, tmp_path):
        write_results(
            tmp_path,
            findings=[FINDING],
            targets={
                "individual-repos": [],
                "individual-gitlab": ["juice-shop_juice-shop"],
                "individual-images": ["alpine"],
            },
        )

        validate_basic_scan(tmp_path)

    def test_a_repository_target_is_named_with_its_directory(self, tmp_path):
        write_results(
            tmp_path,
            targets={
                "individual-repos": ["a"],
                "individual-gitlab": ["b_c"],
            },
        )

        with pytest.raises(AssertionError) as raised:
            validate_basic_scan(tmp_path)

        assert "individual-repos/a" in str(raised.value)
        assert "individual-gitlab/b_c" in str(raised.value)

    def test_a_stray_file_in_individual_gitlab_is_not_a_target(self, tmp_path):
        write_results(tmp_path, targets={"individual-images": ["alpine"]})
        (tmp_path / "individual-gitlab").mkdir()
        (tmp_path / "individual-gitlab" / "notes.txt").write_text("x", encoding="utf-8")

        validate_basic_scan(tmp_path)

    def test_a_scan_of_another_kind_may_find_nothing(self, tmp_path):
        write_results(tmp_path, targets={"individual-images": ["alpine"]})

        validate_basic_scan(tmp_path)

    def test_an_empty_individual_repos_directory_is_not_a_repository_target(
        self, tmp_path
    ):
        """``jmo ci --terraform-state`` (U3) leaves ``individual-repos`` empty."""
        write_results(
            tmp_path, targets={"individual-repos": [], "individual-iac": ["tf"]}
        )

        validate_basic_scan(tmp_path)

    def test_a_stray_file_in_individual_repos_is_not_a_target(self, tmp_path):
        write_results(tmp_path, targets={"individual-images": ["alpine"]})
        (tmp_path / "individual-repos").mkdir()
        (tmp_path / "individual-repos" / "notes.txt").write_text("x", encoding="utf-8")

        validate_basic_scan(tmp_path)

    def test_a_missing_findings_json_fails(self, tmp_path):
        (tmp_path / "summaries").mkdir()

        with pytest.raises(AssertionError, match="findings.json not found"):
            validate_basic_scan(tmp_path)

    @pytest.mark.parametrize(
        ("missing", "kwargs"),
        [("SUMMARY.md", {"summary": False}), ("dashboard.html", {"dashboard": False})],
    )
    def test_a_missing_report_file_fails(self, tmp_path, missing, kwargs):
        write_results(
            tmp_path,
            findings=[FINDING],
            targets={"individual-repos": ["juice-shop"]},
            **kwargs,
        )

        with pytest.raises(AssertionError, match=f"{missing} not found"):
            validate_basic_scan(tmp_path)


class TestValidateMultiTarget:
    def test_unique_fingerprints_pass(self, tmp_path):
        write_results(
            tmp_path,
            findings=[FINDING, {**FINDING, "id": "f2", "fingerprint_id": "bbbb"}],
            targets={"individual-repos": ["juice-shop"], "individual-iac": ["tf"]},
        )

        validate_multi_target(tmp_path)

    def test_duplicate_fingerprints_fail(self, tmp_path):
        write_results(
            tmp_path,
            findings=[FINDING, {**FINDING, "id": "f2"}],
            targets={"individual-repos": ["juice-shop"]},
        )

        with pytest.raises(AssertionError, match="Duplicate fingerprint"):
            validate_multi_target(tmp_path)

    def test_it_inherits_the_target_count_check(self, tmp_path):
        write_results(tmp_path, meta={"target_count": 0})

        with pytest.raises(AssertionError, match="target_count >= 1"):
            validate_multi_target(tmp_path)

    def test_it_inherits_the_repository_findings_check(self, tmp_path):
        write_results(
            tmp_path,
            targets={"individual-repos": ["juice-shop"], "individual-iac": ["tf"]},
        )

        with pytest.raises(AssertionError, match="repository target"):
            validate_multi_target(tmp_path)
