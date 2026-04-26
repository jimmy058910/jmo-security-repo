#!/usr/bin/env python3
"""Tests for `scripts/dev/check_yaml_env_tilde.py`.

Exercises the `~/`-in-`env:` detection logic against:
- Real workflow YAML (must be clean)
- Synthetic violation cases (must be caught)
- Synthetic non-violation cases (must NOT be flagged)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.dev.check_yaml_env_tilde import (
    WORKFLOWS_DIR,
    find_env_tilde_violations,
)


def test_real_workflows_are_clean() -> None:
    """Current `.github/workflows/*.yml` must contain no `~/`-prefixed env values.

    This is the regression-prevention path: PR #331 fixed PRE_COMMIT_HOME's
    literal-tilde bug; this test ensures it stays fixed.
    """
    all_violations: list[tuple[Path, int, str, str]] = []
    for path in sorted(WORKFLOWS_DIR.glob("*.yml")):
        for line_num, key, val in find_env_tilde_violations(path):
            all_violations.append((path, line_num, key, val))

    assert (
        not all_violations
    ), f"Found literal `~/` in env: blocks across workflows: {all_violations}"


def test_violation_caught_workflow_level_env(tmp_path: Path) -> None:
    """Workflow-level `env:` block with `~/...` value must be flagged."""
    yml = tmp_path / "bad.yml"
    yml.write_text(
        """\
name: Bad
on: [push]
env:
  PRE_COMMIT_HOME: ~/.cache/pre-commit
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
""",
        encoding="utf-8",
    )
    violations = find_env_tilde_violations(yml)
    assert len(violations) == 1
    line_num, key, val = violations[0]
    assert key == "PRE_COMMIT_HOME"
    assert val == "~/.cache/pre-commit"
    assert line_num == 4


def test_violation_caught_step_level_env(tmp_path: Path) -> None:
    """Step-level `env:` block with `~/...` value must be flagged."""
    yml = tmp_path / "bad.yml"
    yml.write_text(
        """\
name: Bad
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: thing
        env:
          MY_CACHE: ~/somecache
        run: echo hi
""",
        encoding="utf-8",
    )
    violations = find_env_tilde_violations(yml)
    assert len(violations) == 1
    assert violations[0][1] == "MY_CACHE"
    assert violations[0][2] == "~/somecache"


def test_no_false_positive_actions_cache_path(tmp_path: Path) -> None:
    """`actions/cache@v4` `with: path: ~/...` must NOT be flagged.

    The `path:` value is consumed by the action's Node code which DOES
    expand `~`. Only `env:` block values are passed unmodified.
    """
    yml = tmp_path / "good.yml"
    yml.write_text(
        """\
name: Good
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: ~/.cache/pre-commit
          key: precommit-${{ runner.os }}
""",
        encoding="utf-8",
    )
    violations = find_env_tilde_violations(yml)
    assert violations == []


def test_no_false_positive_run_block_with_tilde(tmp_path: Path) -> None:
    """`run:` blocks invoking `cd ~/...` must NOT be flagged.

    `run:` is bash; bash DOES expand `~`. Only `env:` values are literal.
    """
    yml = tmp_path / "good.yml"
    yml.write_text(
        """\
name: Good
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          cd ~/repos/foo
          ls ~/.config/bar
""",
        encoding="utf-8",
    )
    violations = find_env_tilde_violations(yml)
    assert violations == []


def test_no_false_positive_absolute_path_in_env(tmp_path: Path) -> None:
    """`env:` blocks with absolute paths (the recommended fix) must NOT be flagged."""
    yml = tmp_path / "good.yml"
    yml.write_text(
        """\
name: Good
on: [push]
env:
  PRE_COMMIT_HOME: /home/runner/.cache/pre-commit
  ANOTHER_PATH: /tmp/foo
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
""",
        encoding="utf-8",
    )
    violations = find_env_tilde_violations(yml)
    assert violations == []


def test_handles_malformed_yaml_gracefully(tmp_path: Path) -> None:
    """Malformed YAML returns empty list (deferring to yamllint for syntax errors)."""
    yml = tmp_path / "broken.yml"
    yml.write_text(
        """\
name: Broken
this is not: valid yaml
  - because of this
   :
""",
        encoding="utf-8",
    )
    # Should not raise; should return empty
    violations = find_env_tilde_violations(yml)
    assert violations == []


@pytest.mark.parametrize(
    "env_value", ["~/cache", "~/.config/foo", "~/path with spaces"]
)
def test_various_tilde_path_forms_caught(tmp_path: Path, env_value: str) -> None:
    """All forms of `~/<anything>` in env values are caught."""
    yml = tmp_path / "bad.yml"
    yml.write_text(
        f"""\
name: Bad
on: [push]
env:
  MY_VAR: {env_value!r}
""",
        encoding="utf-8",
    )
    violations = find_env_tilde_violations(yml)
    assert len(violations) == 1
    assert violations[0][2] == env_value
