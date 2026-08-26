#!/usr/bin/env python3
"""Tests for suppression selectors (path / ruleId / severity / line) and for
malformed-config handling in scripts/core/suppress.py.

Before #538 the engine matched findings by exact ``id`` only, and every other
documented selector was dropped at load time with no log record. A malformed
config raised out of ``load_suppressions`` and killed ``jmo report`` with a raw
traceback after the whole parse had completed.

The measured shapes these tests encode:

- ``location.path`` is not written uniformly. A single scan of a single
  directory produced four spellings of the same file (``iac/x.tf``,
  ``iac\\x.tf``, ``\\iac\\x.tf``, ``C:\\...\\iac\\x.tf``), so a matcher that
  compares the raw string suppresses under half the findings in a file the user
  named explicitly.
- ``fnmatch.fnmatch`` normcases on Windows and not on POSIX, so a pattern
  checked into a repo would match different findings on a dev box than in CI.
  Matching must be platform-stable.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from scripts.core.suppress import (
    Suppression,
    filter_suppressed,
    filter_suppressed_with_summary,
    load_suppressions,
)

BS = chr(92)  # backslash, kept out of literals so this file stays readable


def _write(tmp_path: Path, body: str) -> str:
    p = tmp_path / "jmo.suppress.yml"
    p.write_bytes(body.encode("utf-8"))
    return str(p)


def _finding(**kw) -> dict:
    """A CommonFinding-shaped dict with sensible defaults."""
    loc = {"path": kw.pop("path", "src/app.py")}
    if "line" in kw:
        loc["startLine"] = kw.pop("line")
    return {
        "id": kw.pop("id", "aaaabbbbccccdddd"),
        "ruleId": kw.pop("ruleId", "B101"),
        "severity": kw.pop("severity", "HIGH"),
        "location": loc,
        "message": kw.pop("message", "example"),
        **kw,
    }


# ============================================================================
# 1. Malformed configs must not crash `jmo report`
# ============================================================================


class TestMalformedConfigDoesNotRaise:
    """A broken jmo.suppress.yml must never propagate out of load_suppressions.

    Measured on origin/dev: five separate malformed shapes each exited
    `jmo report` with rc=1 and a raw traceback, *after* gather_results() had
    already parsed every tool's output.
    """

    @pytest.mark.parametrize(
        ("label", "body"),
        [
            ("suppressions key present but null", "suppressions:\n"),
            ("legacy suppress key null", "suppress:\n"),
            ("entries is a mapping", "suppressions:\n  a: 1\n  b: 2\n"),
            ("entries is a scalar", "suppressions: hello\n"),
            ("entry is a bare string", "suppressions:\n  - just-a-string\n"),
            ("entry is null", "suppressions:\n  -\n"),
            ("document is a bare string", "hello\n"),
            ("document is a bare number", "42\n"),
            ("unparseable yaml", "suppressions:\n  - id: 'unclosed\n"),
            ("tabs are illegal in yaml", "suppressions:\n" + chr(9) + "- id: a\n"),
        ],
    )
    def test_malformed_config_returns_empty_instead_of_raising(
        self, tmp_path: Path, label: str, body: str
    ):
        result = load_suppressions(_write(tmp_path, body))

        assert result == {}, f"{label} should yield no suppressions, not raise"

    @pytest.mark.parametrize(
        ("label", "body"),
        [
            ("suppressions key present but null", "suppressions:\n"),
            ("unparseable yaml", "suppressions:\n  - id: 'unclosed\n"),
            ("entry is a bare string", "suppressions:\n  - just-a-string\n"),
        ],
    )
    def test_malformed_config_is_reported_at_warning_or_worse(
        self, tmp_path: Path, caplog, label: str, body: str
    ):
        with caplog.at_level(logging.WARNING, logger="scripts.core.suppress"):
            load_suppressions(_write(tmp_path, body))

        assert [
            r for r in caplog.records if r.levelno >= logging.WARNING
        ], f"{label} was accepted silently"

    def test_a_healthy_config_emits_no_warning(self, tmp_path: Path, caplog):
        """Control: the guards above must not fire on a valid file."""
        body = 'suppressions:\n  - id: "abc123"\n    reason: "reviewed"\n'

        with caplog.at_level(logging.DEBUG, logger="scripts.core.suppress"):
            result = load_suppressions(_write(tmp_path, body))

        assert len(result) == 1
        assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []

    def test_one_bad_entry_does_not_discard_the_good_ones(self, tmp_path: Path):
        body = (
            "suppressions:\n"
            "  - just-a-string\n"
            '  - id: "keepme"\n'
            '    reason: "reviewed"\n'
        )

        result = load_suppressions(_write(tmp_path, body))

        assert "keepme" in result


# ============================================================================
# 2. A key the engine cannot use never fails silently
# ============================================================================


class TestNoOpKeysAreReported:
    def test_entry_with_no_selector_is_skipped_and_reported(
        self, tmp_path: Path, caplog
    ):
        body = 'suppressions:\n  - reason: "no selector at all"\n'

        with caplog.at_level(logging.WARNING, logger="scripts.core.suppress"):
            result = load_suppressions(_write(tmp_path, body))

        assert result == {}, "a selectorless entry must not match everything"
        assert any(
            "no selector" in r.getMessage().lower() for r in caplog.records
        ), "a selectorless entry was dropped silently"

    def test_unknown_key_is_named_in_the_warning(self, tmp_path: Path, caplog):
        body = 'suppressions:\n  - idd: "typo"\n    reason: "r"\n'

        with caplog.at_level(logging.WARNING, logger="scripts.core.suppress"):
            load_suppressions(_write(tmp_path, body))

        assert any(
            "idd" in r.getMessage() for r in caplog.records
        ), "an unrecognised key must be named, not silently ignored"

    def test_known_selector_keys_do_not_warn(self, tmp_path: Path, caplog):
        body = (
            "suppressions:\n"
            '  - path: "src/*"\n'
            '    ruleId: "B101"\n'
            '    severity: "HIGH"\n'
            "    line: [1, 2]\n"
            '    reason: "r"\n'
        )

        with caplog.at_level(logging.WARNING, logger="scripts.core.suppress"):
            result = load_suppressions(_write(tmp_path, body))

        assert len(result) == 1
        assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []


# ============================================================================
# 3. path selector -- the shape the real corpus actually produces
# ============================================================================


class TestPathSelector:
    def test_path_glob_suppresses_a_matching_finding(self, tmp_path: Path):
        sups = load_suppressions(
            _write(tmp_path, 'suppressions:\n  - path: "iac/*"\n    reason: "r"\n')
        )

        kept = filter_suppressed([_finding(path="iac/aws-s3-public.tf")], sups)

        assert kept == []

    def test_path_glob_leaves_a_non_matching_finding(self, tmp_path: Path):
        sups = load_suppressions(
            _write(tmp_path, 'suppressions:\n  - path: "iac/*"\n    reason: "r"\n')
        )

        kept = filter_suppressed([_finding(path="src/app.py")], sups)

        assert len(kept) == 1

    @pytest.mark.parametrize(
        ("label", "path"),
        [
            ("forward slashes", "iac/aws-s3-public.tf"),
            ("backslashes", "iac" + BS + "aws-s3-public.tf"),
            ("leading backslash", BS + "iac" + BS + "aws-s3-public.tf"),
            ("leading forward slash", "/iac" + BS + "aws-s3-public.tf"),
            (
                "absolute windows path",
                "C:" + BS + "work" + BS + "repo" + BS + "iac" + BS + "aws-s3-public.tf",
            ),
            ("absolute posix path", "/home/j/repo/iac/aws-s3-public.tf"),
            ("nested under another dir", "checkout/repo/iac/aws-s3-public.tf"),
        ],
    )
    def test_one_pattern_matches_every_spelling_a_real_scan_produces(
        self, tmp_path: Path, label: str, path: str
    ):
        """A single deep scan produced four spellings of one file.

        Matching the raw string suppressed 37 of that file's 77 findings.
        """
        sups = load_suppressions(
            _write(tmp_path, 'suppressions:\n  - path: "iac/*"\n    reason: "r"\n')
        )

        kept = filter_suppressed([_finding(path=path)], sups)

        assert kept == [], f"{label} was not matched by iac/*"

    def test_pattern_matching_is_case_sensitive_on_every_platform(self, tmp_path: Path):
        """fnmatch.fnmatch normcases on Windows only.

        Measured: pattern 'IAC/*' matched 101 findings on Windows and 0 on
        POSIX. A config checked into a repo must not behave differently in CI.
        """
        sups = load_suppressions(
            _write(tmp_path, 'suppressions:\n  - path: "IAC/*"\n    reason: "r"\n')
        )

        kept = filter_suppressed([_finding(path="iac/aws-s3-public.tf")], sups)

        assert len(kept) == 1, "case-insensitive match leaked in from the platform"

    def test_a_partial_component_is_not_a_match(self, tmp_path: Path):
        """Suffix matching must align to a path separator.

        Otherwise 'iac/*' would capture 'my-iac/secret.tf'.
        """
        sups = load_suppressions(
            _write(tmp_path, 'suppressions:\n  - path: "iac/*"\n    reason: "r"\n')
        )

        kept = filter_suppressed([_finding(path="my-iac/secret.tf")], sups)

        assert len(kept) == 1

    def test_finding_with_no_path_is_not_suppressed_by_a_path_rule(
        self, tmp_path: Path
    ):
        sups = load_suppressions(
            _write(tmp_path, 'suppressions:\n  - path: "*"\n    reason: "r"\n')
        )
        finding = {"id": "x", "ruleId": "R", "severity": "HIGH", "location": {}}

        kept = filter_suppressed([finding], sups)

        assert len(kept) == 1


# ============================================================================
# 4. ruleId / severity / line selectors
# ============================================================================


class TestOtherSelectors:
    def test_rule_id_exact_match(self, tmp_path: Path):
        sups = load_suppressions(
            _write(tmp_path, 'suppressions:\n  - ruleId: "B101"\n    reason: "r"\n')
        )

        kept = filter_suppressed(
            [_finding(ruleId="B101"), _finding(ruleId="B602", id="other")], sups
        )

        assert [f["ruleId"] for f in kept] == ["B602"]

    def test_rule_id_accepts_a_glob_for_semgrep_style_ids(self, tmp_path: Path):
        """Real semgrep ruleIds reach 113 characters.

        The repo's own config wrote `ruleId: "run-shell-injection"` against
        `yaml.github-actions.security.run-shell-injection.run-shell-injection`,
        which exact matching can never hit.
        """
        sups = load_suppressions(
            _write(
                tmp_path,
                'suppressions:\n  - ruleId: "*run-shell-injection*"\n    reason: "r"\n',
            )
        )
        long_id = "yaml.github-actions.security.run-shell-injection.run-shell-injection"

        kept = filter_suppressed([_finding(ruleId=long_id)], sups)

        assert kept == []

    def test_severity_matches_case_insensitively(self, tmp_path: Path):
        sups = load_suppressions(
            _write(tmp_path, 'suppressions:\n  - severity: "high"\n    reason: "r"\n')
        )

        kept = filter_suppressed(
            [_finding(severity="HIGH"), _finding(severity="LOW", id="other")], sups
        )

        assert [f["severity"] for f in kept] == ["LOW"]

    def test_line_scalar(self, tmp_path: Path):
        sups = load_suppressions(
            _write(tmp_path, 'suppressions:\n  - line: 74\n    reason: "r"\n')
        )

        kept = filter_suppressed(
            [_finding(line=74), _finding(line=75, id="other")], sups
        )

        assert [f["location"]["startLine"] for f in kept] == [75]

    def test_line_list(self, tmp_path: Path):
        sups = load_suppressions(
            _write(tmp_path, "suppressions:\n  - line: [74, 86]\n" '    reason: "r"\n')
        )

        kept = filter_suppressed(
            [
                _finding(line=74),
                _finding(line=86, id="b"),
                _finding(line=99, id="c"),
            ],
            sups,
        )

        assert [f["location"]["startLine"] for f in kept] == [99]

    def test_multiple_selectors_are_combined_with_and(self, tmp_path: Path):
        """The repo's own config relies on this: path + ruleId + line."""
        sups = load_suppressions(
            _write(
                tmp_path,
                "suppressions:\n"
                '  - path: "workflows/*"\n'
                '    ruleId: "*run-shell-injection*"\n'
                "    line: [74, 86]\n"
                '    reason: "r"\n',
            )
        )
        rule = "yaml.github-actions.security.run-shell-injection.run-shell-injection"
        findings = [
            _finding(path="workflows/ci.yml", ruleId=rule, line=74, id="match"),
            _finding(path="workflows/ci.yml", ruleId=rule, line=99, id="wrongline"),
            _finding(path="workflows/ci.yml", ruleId="B101", line=74, id="wrongrule"),
            _finding(path="src/app.py", ruleId=rule, line=74, id="wrongpath"),
        ]

        kept = filter_suppressed(findings, sups)

        assert sorted(f["id"] for f in kept) == ["wrongline", "wrongpath", "wrongrule"]


# ============================================================================
# 5. Backward compatibility -- id-only configs behave exactly as before
# ============================================================================


class TestIdOnlyBehaviourIsUnchanged:
    def test_id_still_matches_exactly(self, tmp_path: Path):
        sups = load_suppressions(
            _write(
                tmp_path, 'suppressions:\n  - id: "aaaabbbbccccdddd"\n    reason: "r"\n'
            )
        )

        kept = filter_suppressed(
            [_finding(id="aaaabbbbccccdddd"), _finding(id="different")], sups
        )

        assert [f["id"] for f in kept] == ["different"]

    def test_id_entries_are_still_keyed_by_id(self, tmp_path: Path):
        """csv_reporter and suppression_reporter both do suppressions.get(id)."""
        sups = load_suppressions(
            _write(tmp_path, 'suppressions:\n  - id: "abc123"\n    reason: "why"\n')
        )

        assert sups["abc123"].reason == "why"

    def test_expired_suppression_still_does_not_apply(self, tmp_path: Path):
        sups = load_suppressions(
            _write(
                tmp_path,
                'suppressions:\n  - path: "iac/*"\n'
                '    expires: "2000-01-01"\n    reason: "r"\n',
            )
        )

        kept = filter_suppressed([_finding(path="iac/x.tf")], sups)

        assert len(kept) == 1, "an expired selector rule must not suppress"


# ============================================================================
# 6. Summary attribution -- SUPPRESSIONS.md must be able to name the rule
# ============================================================================


class TestSummaryAttribution:
    def test_summary_counts_a_selector_suppression(self, tmp_path: Path):
        sups = load_suppressions(
            _write(tmp_path, 'suppressions:\n  - path: "iac/*"\n    reason: "r"\n')
        )

        _, summary = filter_suppressed_with_summary(
            [_finding(path="iac/x.tf", severity="HIGH")], sups
        )

        assert summary.total_suppressed == 1
        assert summary.by_severity == {"HIGH": 1}

    def test_summary_records_which_rule_suppressed_each_finding(self, tmp_path: Path):
        """Without this, SUPPRESSIONS.md drops every selector-suppressed row.

        write_suppression_report() looks each finding id up in the suppression
        dict; a path rule is not keyed by any finding id, so the row is skipped.
        """
        sups = load_suppressions(
            _write(tmp_path, 'suppressions:\n  - path: "iac/*"\n    reason: "why"\n')
        )

        _, summary = filter_suppressed_with_summary(
            [_finding(id="findingid1", path="iac/x.tf")], sups
        )

        assert summary.suppressed_by["findingid1"] in summary.by_rule


# ============================================================================
# 7. Gaps that mutation testing exposed
#
# Each test below exists because a mutant survived the first pass. Three were
# weak tests; one (the drive-letter strip) was a live bug in the fix itself.
# ============================================================================


class TestMutationExposedGaps:
    def test_a_pattern_may_be_written_with_a_leading_separator(self, tmp_path: Path):
        """Normalization is applied to the pattern, not only to the path.

        Mutant: removing `.lstrip("/")` survived, because suffix matching
        already handles a leading separator on the *path* side. It is the
        *pattern* side that needs it.
        """
        sups = load_suppressions(
            _write(tmp_path, 'suppressions:\n  - path: "/iac/*"\n    reason: "r"\n')
        )

        kept = filter_suppressed([_finding(path="iac/aws-s3-public.tf")], sups)

        assert kept == []

    def test_a_drive_qualified_pattern_does_not_match_a_relative_path(
        self, tmp_path: Path
    ):
        """Regression: `path: "C:/*"` once matched every finding in the scan.

        Normalization used to strip a drive letter from pattern and path
        alike, which rewrote the pattern `C:/*` to `*`. Silently suppressing
        an entire scan is the worst direction for a security tool to fail in.
        """
        sups = load_suppressions(
            _write(tmp_path, 'suppressions:\n  - path: "C:/*"\n    reason: "r"\n')
        )

        kept = filter_suppressed([_finding(path="src/app.py")], sups)

        assert len(kept) == 1

    def test_a_scalar_entries_value_warns_once_not_once_per_character(
        self, tmp_path: Path, caplog
    ):
        """The list guard exists for the message, not only for the outcome.

        Without it, `suppressions: hello` iterates the *string*, so each
        character is reported as a malformed entry. Asserting merely that
        "some warning fired" cannot tell the two apart.
        """
        with caplog.at_level(logging.WARNING, logger="scripts.core.suppress"):
            load_suppressions(_write(tmp_path, "suppressions: hello\n"))

        warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert len(warnings) == 1
        assert "should be a list" in warnings[0].getMessage()

    def test_a_hand_built_selectorless_suppression_matches_nothing(self):
        """filter_suppressed() is public and takes a dict a caller can build.

        load_suppressions() rejects selectorless entries, so this guard is
        unreachable through the loader -- but not through the API.
        """
        rule = Suppression(reason="no selector at all")

        kept = filter_suppressed([_finding()], {rule.key: rule})

        assert len(kept) == 1


# ============================================================================
# 8. An expiry that cannot be parsed must not silently mean "never expires"
# ============================================================================


class TestUnparseableExpiry:
    def test_an_unparseable_expires_string_is_reported(self, caplog):
        rule = Suppression(id="abc", expires="not-a-date")

        with caplog.at_level(logging.WARNING, logger="scripts.core.suppress"):
            active = rule.is_active()

        assert active is True, "an unreadable expiry still fails open, deliberately"
        assert any(
            "not-a-date" in r.getMessage() for r in caplog.records
        ), "an unreadable expiry silently became a permanent suppression"

    def test_an_unquoted_numeric_expires_is_reported(self, caplog):
        """`expires: 20251231` is an int in YAML, not a date.

        It previously logged at DEBUG and returned True, so a typo produced a
        suppression that never expired.
        """
        rule = Suppression(id="abc", expires=20251231)

        with caplog.at_level(logging.WARNING, logger="scripts.core.suppress"):
            rule.is_active()

        assert any(r.levelno >= logging.WARNING for r in caplog.records)

    def test_a_valid_expiry_is_silent(self, caplog):
        """Control: the guard must not fire on a well-formed date."""
        rule = Suppression(id="abc", expires="2999-01-01")

        with caplog.at_level(logging.DEBUG, logger="scripts.core.suppress"):
            active = rule.is_active()

        assert active is True
        assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []
