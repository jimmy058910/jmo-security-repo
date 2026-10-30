"""Unit tests for tests/integration/targets.py, the helpers the juice-shop and
WebGoat baseline test and scripts/dev/generate_baseline.py share.

The baseline test went years without asserting anything: it read
``<results>/findings.json`` (which ``jmo scan`` never writes), ignored the
scan's return code, and skipped when it found nothing. These tests hold the
pieces that let it fail honestly, without cloning anything or running a tool.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from tests.integration import targets
from tests.integration import test_baseline_validation as baseline_test
from tests.integration.targets import (
    CLONE_TIMEOUT,
    JUICE_SHOP_COMMIT,
    PINNED_TARGETS,
    WEBGOAT_COMMIT,
    bare_cwe,
    clone_at_commit,
    count_by_tool,
    finding_cwes,
    finding_tools,
    load_findings,
    run_scan,
)
from tests.integration.test_baseline_validation import (
    BASELINES_DIR,
    TargetScan,
    load_baseline,
)

SQLI_TITLED = (
    "CWE-89: Improper Neutralization of Special Elements used in an SQL "
    "Command ('SQL Injection')"
)


def finding(tool="opengrep", severity="HIGH", cwe=None, detected_by=None):
    item = {"tool": {"name": tool}, "severity": severity, "ruleId": f"{tool}.rule"}
    if cwe is not None:
        item["risk"] = {"cwe": cwe}
    if detected_by:
        item["detected_by"] = [{"name": name} for name in detected_by]
    return item


class TestBareCwe:
    """``risk.cwe`` comes in two spellings; both must reduce to one id."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("CWE-89", "CWE-89"),
            (SQLI_TITLED, "CWE-89"),
            ("89", "CWE-89"),
            (89, "CWE-89"),
            ("cwe-79", "CWE-79"),
            ("  CWE-79 ", "CWE-79"),
            ("CWE-0798", "CWE-798"),
        ],
    )
    def test_reduces_to_the_bare_id(self, value, expected):
        assert bare_cwe(value) == expected

    @pytest.mark.parametrize(
        "value", ["", "CWE-", "A03:2021", "injection", None, True, [], {"cwe": 89}]
    )
    def test_unparseable_is_none(self, value):
        assert bare_cwe(value) is None


class TestFindingCwes:
    def test_risk_cwe_in_both_spellings_is_one_id(self):
        finding = {"risk": {"cwe": ["CWE-89", SQLI_TITLED, "CWE-79"]}}
        assert finding_cwes(finding) == ["CWE-89", "CWE-79"]

    def test_none_risk_cwe_falls_back_to_metadata(self):
        # Roughly half of a real scan's findings carry risk.cwe = None.
        finding = {"risk": {"cwe": None}, "metadata": {"cwe": "79"}}
        assert finding_cwes(finding) == ["CWE-79"]

    def test_risk_cwe_wins_over_metadata(self):
        finding = {"risk": {"cwe": ["CWE-22"]}, "metadata": {"cwe": "79"}}
        assert finding_cwes(finding) == ["CWE-22"]

    def test_no_cwe_anywhere_is_empty(self):
        assert finding_cwes({"ruleId": "x", "risk": {"owasp": ["A03"]}}) == []
        assert finding_cwes({}) == []


class TestFindingTools:
    def test_unclustered_finding_has_its_own_tool(self):
        assert finding_tools({"tool": {"name": "opengrep"}}) == {"opengrep"}

    def test_clustered_finding_lists_every_member(self):
        # juice-shop's trufflehog findings were all merged into gitleaks':
        # the finding keeps one `tool` and lists both in `detected_by`.
        finding = {
            "tool": {"name": "gitleaks"},
            "detected_by": [
                {"name": "gitleaks", "version": "8.30.1"},
                {"name": "trufflehog", "version": "3.99.7"},
            ],
        }
        assert finding_tools(finding) == {"gitleaks", "trufflehog"}

    def test_empty_detected_by_falls_back_to_tool(self):
        finding = {"tool": {"name": "trivy"}, "detected_by": []}
        assert finding_tools(finding) == {"trivy"}

    def test_counts_each_finding_once_per_tool(self):
        findings = [
            {"tool": {"name": "opengrep"}},
            {"tool": {"name": "opengrep"}},
            {
                "tool": {"name": "gitleaks"},
                "detected_by": [{"name": "gitleaks"}, {"name": "trufflehog"}],
            },
        ]
        counts = count_by_tool(findings)
        assert dict(counts) == {"opengrep": 2, "gitleaks": 1, "trufflehog": 1}


class TestLoadFindings:
    def _write(self, results: Path, relative: str, payload) -> None:
        path = results / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(json.dumps(payload).encode("utf-8"))

    def test_reads_the_file_the_product_writes(self, tmp_path):
        self._write(
            tmp_path, "summaries/findings.json", {"meta": {}, "findings": [{"id": "a"}]}
        )
        assert load_findings(tmp_path) == [{"id": "a"}]

    def test_raises_when_the_summary_is_absent(self, tmp_path):
        # The old reader looked at <results>/findings.json and returned [] when
        # it was not there; a decoy at that path must not satisfy this one.
        self._write(tmp_path, "findings.json", {"findings": [{"id": "decoy"}]})
        with pytest.raises(FileNotFoundError, match="summaries"):
            load_findings(tmp_path)

    def test_zero_findings_is_an_empty_list_not_an_error(self, tmp_path):
        self._write(tmp_path, "summaries/findings.json", {"meta": {}, "findings": []})
        assert load_findings(tmp_path) == []

    @pytest.mark.parametrize("payload", [[{"id": "a"}], {"meta": {}}, "text"])
    def test_raises_on_an_unexpected_shape(self, tmp_path, payload):
        self._write(tmp_path, "summaries/findings.json", payload)
        with pytest.raises(ValueError, match="findings"):
            load_findings(tmp_path)


class TestRunScan:
    """The scan runs real tools, so only its contract with the product is tested."""

    def _run(self, monkeypatch, tmp_path, returncode=0):
        home = tmp_path / "home"
        (home / ".jmo").mkdir(parents=True)
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
        config = home / ".jmo" / "config.yml"
        config.write_bytes(b"scan_count: 7\n")
        calls: list[tuple[list[str], dict]] = []

        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            config.write_bytes(b"scan_count: 8\n")  # what _show_kofi_reminder does
            return subprocess.CompletedProcess(cmd, returncode, "out", "err")

        monkeypatch.setattr(targets.subprocess, "run", fake_run)
        results = tmp_path / "work" / "results"
        outcome = run_scan(tmp_path / "target", results)
        return outcome, calls, config, results

    def test_history_and_timeout_stay_contained(self, monkeypatch, tmp_path):
        outcome, calls, config, results = self._run(monkeypatch, tmp_path)
        (cmd, kwargs) = calls[0]
        assert cmd[cmd.index("--results-dir") + 1] == str(results)
        history = Path(cmd[cmd.index("--history-db") + 1])
        assert history.parent == results.parent, "history must stay in the scratch dir"
        assert kwargs["timeout"] > 0
        assert "shell" not in kwargs or kwargs["shell"] is False
        assert outcome.returncode == 0

    def test_config_counter_is_put_back(self, monkeypatch, tmp_path):
        _, _, config, _ = self._run(monkeypatch, tmp_path)
        assert config.read_bytes() == b"scan_count: 7\n"

    def test_returns_the_completed_process_so_stderr_can_be_reported(
        self, monkeypatch, tmp_path
    ):
        outcome, _, _, _ = self._run(monkeypatch, tmp_path, returncode=2)
        assert (outcome.returncode, outcome.stderr) == (2, "err")


def _git(repo: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-c", "commit.gpgsign=false", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return done.stdout.strip()


@pytest.fixture
def source_repo(tmp_path):
    """A local repository with two commits: (url, first sha, second sha)."""
    repo = tmp_path / "source"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    shas = []
    for name in ("first", "second"):
        (repo / f"{name}.txt").write_bytes(name.encode())
        _git(repo, "add", ".")
        _git(
            repo,
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "commit",
            "--quiet",
            "-m",
            name,
        )
        shas.append(_git(repo, "rev-parse", "HEAD"))
    # file:// so --depth is honoured, as it is against GitHub.
    return repo.as_uri(), shas[0], shas[1]


class TestCloneAtCommit:
    def test_checks_out_the_named_commit_not_the_tip(self, source_repo, tmp_path):
        url, first, _second = source_repo
        dest = tmp_path / "clone"
        clone_at_commit(url, first, dest)
        assert _git(dest, "rev-parse", "HEAD") == first
        assert (dest / "first.txt").exists()
        assert not (dest / "second.txt").exists(), "HEAD must be the pin, not the tip"

    def test_fetches_depth_one(self, source_repo, tmp_path):
        url, first, _second = source_repo
        dest = tmp_path / "clone"
        clone_at_commit(url, first, dest)
        assert _git(dest, "rev-list", "--count", "HEAD") == "1"

    def test_an_unknown_commit_raises_and_names_git_s_complaint(
        self, source_repo, tmp_path
    ):
        url, _first, _second = source_repo
        with pytest.raises(RuntimeError, match="fetch"):
            clone_at_commit(url, "0" * 40, tmp_path / "clone")

    def test_head_that_is_not_the_pin_raises(self, source_repo, tmp_path, monkeypatch):
        url, first, second = source_repo
        real_run = subprocess.run

        def lying_rev_parse(cmd, **kwargs):
            done = real_run(cmd, **kwargs)
            if "rev-parse" in cmd:
                return subprocess.CompletedProcess(cmd, 0, second + "\n", "")
            return done

        monkeypatch.setattr(targets.subprocess, "run", lying_rev_parse)
        with pytest.raises(RuntimeError, match="HEAD is"):
            clone_at_commit(url, first, tmp_path / "clone")

    def test_every_git_call_has_a_timeout_and_no_shell(
        self, source_repo, tmp_path, monkeypatch
    ):
        url, first, _second = source_repo
        real_run = subprocess.run
        calls = []

        def recording_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            return real_run(cmd, **kwargs)

        monkeypatch.setattr(targets.subprocess, "run", recording_run)
        clone_at_commit(url, first, tmp_path / "clone", timeout=17)
        assert len(calls) >= 4, "init, fetch, checkout and rev-parse"
        for cmd, kwargs in calls:
            assert isinstance(cmd, list), "list-form argv, never a shell string"
            assert kwargs["timeout"] == 17
            assert kwargs["check"] is True
            assert not kwargs.get("shell")

    def test_default_timeout_is_finite(self):
        assert 0 < CLONE_TIMEOUT <= 900


class TestPins:
    @pytest.mark.parametrize("commit", [JUICE_SHOP_COMMIT, WEBGOAT_COMMIT])
    def test_a_pin_is_a_full_sha(self, commit):
        assert len(commit) == 40 and set(commit) <= set("0123456789abcdef")

    def test_pinned_targets_use_the_constants(self):
        assert PINNED_TARGETS["juice-shop"].commit == JUICE_SHOP_COMMIT
        assert PINNED_TARGETS["webgoat"].commit == WEBGOAT_COMMIT


class TestScanAssertions:
    """The real-tool test's assertions, run against findings built from the baseline.

    They never executed before this change: the test read a file the product
    does not write and skipped on zero findings. Here each way a scan can drift
    from its baseline has to fail the test, and a faithful scan has to pass it.
    """

    NAME = "juice-shop"

    @pytest.fixture
    def baseline(self):
        return load_baseline(BASELINES_DIR / f"{self.NAME}.baseline.json")

    def _faithful_findings(self, baseline):
        """Findings that meet every row and keep every recorded tool reporting."""
        findings = []
        for row in baseline["expected_findings"]:
            findings += [
                finding(severity=row["severity"], cwe=[row["rule_id"]])
                for _ in range(row["min_count"])
            ]
        findings += [finding(tool=t) for t in baseline["metadata"]["findings_per_tool"]]
        return findings

    def _check(self, tmp_path, findings, returncode=0, stderr=""):
        summaries = tmp_path / "results" / "summaries"
        summaries.mkdir(parents=True)
        payload = {"meta": {}, "findings": findings}
        (summaries / "findings.json").write_bytes(json.dumps(payload).encode())
        scan = TargetScan(tmp_path / "target", tmp_path / "results", returncode, stderr)
        baseline_test.TestBaselineValidation().test_scan_matches_baseline(
            self.NAME, lambda name: scan
        )

    def test_a_faithful_scan_passes(self, baseline, tmp_path):
        self._check(tmp_path, self._faithful_findings(baseline))

    def test_a_failed_scan_fails_with_the_stderr_tail(self, baseline, tmp_path):
        stderr = "\n".join(f"line {i}" for i in range(100))
        with pytest.raises(AssertionError, match=r"(?s)exited 2.*line 99") as caught:
            self._check(tmp_path, self._faithful_findings(baseline), 2, stderr)
        assert "line 0\n" not in str(caught.value), "only the tail is quoted"

    def test_a_row_shy_of_its_count_fails(self, baseline, tmp_path):
        findings = self._faithful_findings(baseline)
        row = baseline["expected_findings"][0]
        gone = next(
            f for f in findings if f.get("risk", {}).get("cwe") == [row["rule_id"]]
        )
        findings.remove(gone)
        with pytest.raises(AssertionError, match=rf"{row['rule_id']} \(expected"):
            self._check(tmp_path, findings)

    def test_a_row_is_judged_at_any_severity(self, baseline, tmp_path):
        """Pooled rows: a lower severity than the row records still meets it."""
        findings = self._faithful_findings(baseline)
        for item in findings:
            item["severity"] = "INFO"
        self._check(tmp_path, findings)

    def test_a_recorded_tool_gone_silent_fails_naming_it(self, baseline, tmp_path):
        findings = [
            f
            for f in self._faithful_findings(baseline)
            if "opengrep" not in {f["tool"]["name"]}
        ]
        with pytest.raises(AssertionError, match="opengrep"):
            self._check(tmp_path, findings)

    def test_a_tool_that_only_reports_through_detected_by_still_counts(
        self, baseline, tmp_path
    ):
        findings = [
            f
            for f in self._faithful_findings(baseline)
            if f["tool"]["name"] != "trufflehog"
        ]
        findings.append(
            finding(tool="gitleaks", detected_by=["gitleaks", "trufflehog"])
        )
        self._check(tmp_path, findings)

    def test_a_scan_that_wrote_no_findings_file_fails(self, baseline, tmp_path):
        scan = TargetScan(tmp_path / "target", tmp_path / "results", 0, "")
        with pytest.raises(FileNotFoundError):
            baseline_test.TestBaselineValidation().test_scan_matches_baseline(
                self.NAME, lambda n: scan
            )
