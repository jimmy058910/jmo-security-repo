#!/usr/bin/env python3
"""`jmo report`'s contract with its config: requested artifacts, or a warning.

Chunk 10's acceptance criterion is that **every artifact the config requests is
present or fails loudly**. Three ways it was neither:

* an `outputs:` value that gates no writer was discarded in silence -- measured
  `outputs: [sarrif]` and `outputs: [SARIF]` each produced no SARIF file and
  **0 log records at any level, including DEBUG**;
* `findings.yaml` going missing was reported at DEBUG;
* all three compliance artifacts failing to write was reported at DEBUG.

These assert the *behaviour* (a record was emitted at a level a normal run
shows), not the wording.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from scripts.cli import report_orchestrator
from scripts.cli.report_orchestrator import KNOWN_OUTPUTS, _warn_unknown_outputs

ORCHESTRATOR_SRC = Path(report_orchestrator.__file__)


class _Recorder:
    """Stands in for `_log_fn`, capturing (level, message) pairs."""

    def __init__(self) -> None:
        self.records: list[tuple[str, str]] = []

    def __call__(self, _args, level: str, message: str) -> None:
        self.records.append((level.upper(), message))

    def at(self, *levels: str) -> list[str]:
        return [m for lvl, m in self.records if lvl in levels]


class TestUnknownOutputFormats:
    def test_unknown_format_is_reported_at_warn(self):
        log = _Recorder()
        cfg = SimpleNamespace(outputs=["json", "sarrif"])
        unknown = _warn_unknown_outputs(cfg, SimpleNamespace(), log)

        assert unknown == ["sarrif"]
        warned = log.at("WARN", "ERROR")
        assert len(warned) == 1, log.records
        assert "sarrif" in warned[0]

    def test_case_variant_is_not_silently_accepted(self):
        """`SARIF` gates nothing -- the check is exact, so it must warn."""
        log = _Recorder()
        unknown = _warn_unknown_outputs(
            SimpleNamespace(outputs=["SARIF"]), SimpleNamespace(), log
        )
        assert unknown == ["SARIF"]
        assert log.at("WARN", "ERROR")

    def test_every_known_format_is_silent(self):
        """Negative control: a healthy config must emit nothing."""
        log = _Recorder()
        unknown = _warn_unknown_outputs(
            SimpleNamespace(outputs=list(KNOWN_OUTPUTS)), SimpleNamespace(), log
        )
        assert unknown == []
        assert log.records == []

    @pytest.mark.parametrize("outputs", [None, [], ()])
    def test_absent_or_empty_outputs_is_silent(self, outputs):
        log = _Recorder()
        assert _warn_unknown_outputs(SimpleNamespace(outputs=outputs), None, log) == []
        assert log.records == []

    def test_known_outputs_matches_the_gates_in_cmd_report(self):
        """The list and the gates it describes cannot drift apart.

        `KNOWN_OUTPUTS` is only meaningful if it names exactly the strings
        `cmd_report` tests against. Asserting the property by reading the
        module's AST beats hand-syncing two lists.
        """
        tree = ast.parse(ORCHESTRATOR_SRC.read_text(encoding="utf-8"))
        gated: set[str] = set()
        for node in ast.walk(tree):
            # matches: <str> in cfg.outputs
            if not isinstance(node, ast.Compare) or len(node.ops) != 1:
                continue
            if not isinstance(node.ops[0], ast.In):
                continue
            target = node.comparators[0]
            if (
                isinstance(target, ast.Attribute)
                and target.attr == "outputs"
                and isinstance(node.left, ast.Constant)
                and isinstance(node.left.value, str)
            ):
                gated.add(node.left.value)

        # meta-guard: an extractor that finds nothing passes every assertion
        assert len(gated) >= 5, f"AST scan found only {gated}; extractor is broken"
        assert gated == set(
            KNOWN_OUTPUTS
        ), f"gates {sorted(gated)} != KNOWN_OUTPUTS {sorted(KNOWN_OUTPUTS)}"


def _args(tmp_path: Path, out: Path):
    return SimpleNamespace(
        config=None,
        results_dir=str(tmp_path),
        results_dir_opt=None,
        results_dir_pos=None,
        out=str(out),
        profile=False,
        threads=None,
        fail_on=None,
        policies=None,
        store_history=False,
        log_level="DEBUG",
    )


class TestRequestedArtifactFailsLoudly:
    def test_missing_yaml_reporter_is_reported_at_warn(self, tmp_path):
        """The config asked for findings.yaml; it will not exist. Say so."""
        out = tmp_path / "summaries"
        log = _Recorder()
        with (
            patch.object(report_orchestrator, "gather_results", return_value=[]),
            patch.object(
                report_orchestrator,
                "write_yaml",
                side_effect=RuntimeError("PyYAML is not installed"),
            ),
        ):
            report_orchestrator.cmd_report(_args(tmp_path, out), log)

        warned = log.at("WARN", "ERROR")
        assert any("yaml" in m.lower() for m in warned), log.records
        assert not (out / "findings.yaml").exists()

    def test_compliance_write_failure_is_reported_at_warn(self, tmp_path):
        out = tmp_path / "summaries"
        log = _Recorder()
        with (
            patch.object(report_orchestrator, "gather_results", return_value=[]),
            patch.object(
                report_orchestrator,
                "write_compliance_summary",
                side_effect=OSError("disk full"),
            ),
        ):
            report_orchestrator.cmd_report(_args(tmp_path, out), log)

        warned = log.at("WARN", "ERROR")
        assert any("compliance" in m.lower() for m in warned), log.records

    def test_healthy_run_emits_no_artifact_warnings(self, tmp_path):
        """Negative control -- the warnings must not fire on a good run."""
        out = tmp_path / "summaries"
        log = _Recorder()
        with patch.object(report_orchestrator, "gather_results", return_value=[]):
            report_orchestrator.cmd_report(_args(tmp_path, out), log)

        noisy = [
            m
            for m in log.at("WARN", "ERROR")
            if "yaml" in m.lower() or "compliance" in m.lower() or "output" in m.lower()
        ]
        assert noisy == [], noisy


class TestUnknownFailOnThreshold:
    """A `--fail-on` value JMo does not recognise turns the CI gate off.

    `fail_code` returns 0 for any threshold outside `SEV_ORDER`, which is the
    same exit code as "nothing at or above the threshold". Measured on a real
    242-finding scan holding HIGH findings: `--fail-on HIGHH` exited **0**, and
    the only record at any level -- DEBUG included -- was the summary line
    reporting `threshold=HIGHH` as though it had been applied.
    """

    def test_unknown_threshold_is_reported_at_warn(self):
        log = _Recorder()
        assert (
            report_orchestrator._warn_unknown_threshold("HIGHH", SimpleNamespace(), log)
            == "HIGHH"
        )
        warned = log.at("WARN", "ERROR")
        assert len(warned) == 1, log.records
        assert "HIGHH" in warned[0]

    def test_the_warning_names_the_values_that_would_work(self):
        """A gate that silently does nothing is worth more than a bare 'invalid'."""
        log = _Recorder()
        report_orchestrator._warn_unknown_threshold("bogus", SimpleNamespace(), log)
        message = log.at("WARN")[0]
        for severity in report_orchestrator.SEV_ORDER:
            assert severity in message, message

    @pytest.mark.parametrize("threshold", ["CRITICAL", "HIGH", "medium", "Low", "INFO"])
    def test_every_valid_threshold_is_silent(self, threshold):
        """Negative control, including the case-insensitivity `fail_code` allows."""
        log = _Recorder()
        assert (
            report_orchestrator._warn_unknown_threshold(
                threshold, SimpleNamespace(), log
            )
            is None
        )
        assert log.records == []

    @pytest.mark.parametrize("threshold", [None, ""])
    def test_no_threshold_is_silent(self, threshold):
        """Not asking for a gate is not a broken gate."""
        log = _Recorder()
        assert (
            report_orchestrator._warn_unknown_threshold(
                threshold, SimpleNamespace(), log
            )
            is None
        )
        assert log.records == []

    def test_cmd_report_warns_and_still_exits_zero(self, tmp_path):
        """Through the real command: the exit code is unchanged, the silence is not.

        Changing the exit code would break every pipeline carrying a typo at
        upgrade time, which is the same population that needs to be told.
        """
        out = tmp_path / "summaries"
        args = _args(tmp_path, out)
        args.fail_on = "HIGHH"
        log = _Recorder()
        with patch.object(report_orchestrator, "gather_results", return_value=[]):
            rc = report_orchestrator.cmd_report(args, log)

        assert rc == 0
        assert any("HIGHH" in m for m in log.at("WARN", "ERROR")), log.records
