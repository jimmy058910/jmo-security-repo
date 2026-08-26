#!/usr/bin/env python3
"""`write_yaml`'s schema validation must actually validate something.

It never did. The schema path was built as::

    Path(__file__).parent.parent.parent / "docs/schemas/common_finding.v1.json"

and `yaml_reporter` lives in `scripts/core/reporters/`, so three parents is
`scripts/` -- resolving to `scripts/docs/schemas/common_finding.v1.json`, which
does not exist. The guarding `if schema_path.exists()` had no `else`, so the
report phase's only schema validation was a **silent no-op** for its whole
life. A real scan wrote a finding whose `risk.cwe` was a string where the
schema requires an array, and logged nothing at any level.

The tests below assert that validation FIRES on invalid input before asserting
it stays quiet on valid input -- a validator that never runs passes every
"no warnings" test there is.
"""

from __future__ import annotations

import contextlib
import logging
import os
from pathlib import Path

import pytest

from scripts.core.reporters import yaml_reporter
from scripts.core.reporters.yaml_reporter import write_yaml


@contextlib.contextmanager
def captured(logger: logging.Logger):
    """Collect records from THIS logger, immune to the ancestor chain.

    `caplog` attaches its handler to the **root** logger, so an ancestor left
    with `propagate = False` by an unrelated test silences every assertion made
    through it -- and a silenced capture makes "no warnings" tests pass while
    "a warning fired" tests fail, which reads exactly like a flake.

    That is not hypothetical: two tests in this file failed on xdist worker
    `gw5` with `caplog.records == []` while identical ones passed on other
    workers. `tests/conftest.py` restores what `configure_scan_logging()` sets,
    but only for state set *through* that function.

    Attaching to the module's own logger, forcing its level, and clearing both
    `disabled` flags removes every one of those dependencies.
    """
    records: list[logging.LogRecord] = []
    handler = logging.Handler()
    handler.emit = records.append  # type: ignore[method-assign]

    prior_level, prior_disabled = logger.level, logger.disabled
    prior_manager_disable = logger.manager.disable
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.disabled = False
    logger.manager.disable = logging.NOTSET
    try:
        yield records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(prior_level)
        logger.disabled = prior_disabled
        logger.manager.disable = prior_manager_disable


def _messages(records, min_level=logging.WARNING) -> list[str]:
    return [r.getMessage() for r in records if r.levelno >= min_level]


VALID = {
    "schemaVersion": "1.2.0",
    "id": "a1b2c3d4e5f60718",
    "ruleId": "B105",
    "severity": "HIGH",
    "tool": {"name": "bandit", "version": "1.9.2"},
    "location": {"path": "app.py", "startLine": 3},
    "message": "Hardcoded password",
}


def _invalid(**overrides):
    return {**VALID, **overrides}


class TestValidationActuallyRuns:
    def test_the_schema_is_the_repository_one(self):
        """Two ways this file could go vacuous, both measured.

        1. The original defect: the schema path was wrong, so nothing was ever
           validated.
        2. `SCHEMA_PATH` is a module constant built with `/`, and a test
           patching `Path.__truediv__` froze it to a **pytest tmpdir stub**
           containing `{"type": "object"}` -- which every finding satisfies.
           It still `exists()`, so an existence check alone passes.

        Assert identity, not existence.
        """
        from scripts.core.schema_validator import SCHEMA_PATH

        assert SCHEMA_PATH.exists(), SCHEMA_PATH
        assert SCHEMA_PATH.name == "common_finding.v1.json", SCHEMA_PATH
        assert SCHEMA_PATH.parent.name == "schemas", SCHEMA_PATH

        # Identity, not a spelling.
        #
        # This asserted `"Temp" not in str(SCHEMA_PATH)` as a proxy for "not a
        # pytest tmpdir". That fails for any checkout that merely lives under a
        # path containing "Temp": measured on a worktree under
        # %LOCALAPPDATA%\Temp, where the same commit passes from C:\Projects
        # (#877). A red test on an unmodified tree reads exactly like a
        # regression, and costs a real diagnosis every time.
        #
        # `os.path.join` rather than `/`, so this cannot be redirected by the
        # very `Path.__truediv__` patch it exists to catch. `parents[2]` walks
        # tests/reporters/ -> tests/ -> repo root, which is arithmetic
        # independent of schema_validator.py's own.
        expected = Path(
            os.path.join(
                str(Path(__file__).resolve().parents[2]),
                "docs",
                "schemas",
                "common_finding.v1.json",
            )
        )
        assert SCHEMA_PATH.resolve() == expected, f"schema repointed at {SCHEMA_PATH}"
        # and it is the real schema, not a permissive stub
        from scripts.core.schema_validator import load_schema

        schema = load_schema()
        assert schema["properties"]["risk"]["properties"]["cwe"]["type"] == "array"

    def test_wrong_typed_field_is_reported_at_warning(self, tmp_path):
        """risk.cwe as a string is the violation a real scan shipped."""
        bad = _invalid(risk={"cwe": "CWE-522: Insufficiently Protected Credentials"})
        with captured(yaml_reporter.logger) as records:
            write_yaml([bad], tmp_path / "findings.yaml")

        warned = _messages(records)
        assert warned, "schema validation produced no record at all"
        assert any("schema validation" in m.lower() for m in warned)
        assert (tmp_path / "findings.yaml").exists(), "the report must still be written"

    @pytest.mark.parametrize("field", ["id", "ruleId", "message"])
    def test_empty_required_string_is_reported(self, tmp_path, field):
        """#843 -- `required` cannot catch present-but-empty; minLength can.

        An empty `id` matters beyond tidiness: phase-1 dedup drops such a
        finding with no log and no count (#848).
        """
        with captured(yaml_reporter.logger) as records:
            write_yaml([_invalid(**{field: ""})], tmp_path / "findings.yaml")

        warned = _messages(records)
        assert any(field in m for m in warned), warned

    def test_failures_are_aggregated_into_one_record(self, tmp_path):
        """One record, not one per finding -- flooding hides a signal too."""
        findings = [_invalid(id="") for _ in range(50)]
        with captured(yaml_reporter.logger) as records:
            write_yaml(findings, tmp_path / "findings.yaml")

        relevant = [m for m in _messages(records) if "schema validation" in m.lower()]
        assert len(relevant) == 1, f"{len(relevant)} records for 50 bad findings"
        assert "50" in relevant[0]


class TestValidationStaysQuietWhenItShould:
    def test_valid_finding_produces_no_warning(self, tmp_path):
        """Negative control -- the guard must not fire on good input.

        Note the ordering in this file: the capture is proven to SEE records
        (above) before anything asserts their absence. A capture that sees
        nothing passes every test in this class.
        """
        with captured(yaml_reporter.logger) as records:
            write_yaml([VALID], tmp_path / "findings.yaml")

        assert _messages(records) == []

    def test_validate_false_skips_validation(self, tmp_path):
        bad = _invalid(id="")
        with captured(yaml_reporter.logger) as records:
            write_yaml([bad], tmp_path / "findings.yaml", validate=False)

        assert _messages(records) == []


class TestUnavailableSchemaIsReported:
    def test_missing_schema_is_reported_rather_than_silently_skipped(
        self, tmp_path, monkeypatch
    ):
        """The exact failure mode that hid for the module's whole life."""
        import scripts.core.schema_validator as sv

        monkeypatch.setattr(sv, "SCHEMA_PATH", Path(tmp_path / "nope.json"))
        with captured(yaml_reporter.logger) as records:
            write_yaml([VALID], tmp_path / "findings.yaml")

        warned = _messages(records)
        assert any("schema" in m.lower() for m in warned), warned
        assert (tmp_path / "findings.yaml").exists()
