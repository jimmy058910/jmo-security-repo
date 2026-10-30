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
from tests.integration.targets import (
    bare_cwe,
    count_by_tool,
    finding_cwes,
    finding_tools,
    load_findings,
    run_scan,
)

SQLI_TITLED = (
    "CWE-89: Improper Neutralization of Special Elements used in an SQL "
    "Command ('SQL Injection')"
)


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
