#!/usr/bin/env python3
"""Guard: doctests that state a security contract must actually run.

Regression for #758.

``scripts/cli/path_sanitizers.py`` is the path-traversal control applied to every
user-supplied name in a results path -- all three scan job types call it. Its
docstring examples stated a contract the code does not honour, and **nothing
executed them**: there is no ``--doctest-modules`` in ``pyproject.toml``,
``pytest.ini``, ``setup.cfg``, ``tox.ini`` or the ``Makefile``, so they had never
run in CI or locally.

Measured before the fix -- ``python -m doctest scripts/cli/path_sanitizers.py``::

    2 items had failures:
       2 of   4 in path_sanitizers._sanitize_path_component
       2 of   3 in path_sanitizers._validate_output_path
    7 tests in 3 items.
    3 passed and 4 failed.

Two were wrong values and two were malformed:

===========================  ==================  =======================
input                        docstring claimed   actually returns
===========================  ==================  =======================
``"../../../etc/passwd"``    ``'___etc_passwd'``  ``'______etc_passwd'``
``"..hidden"``               ``'hidden'``         ``'_hidden'``
===========================  ==================  =======================

Both follow from statement order: ``/`` is replaced before ``..`` (so the three
separators each become an underscore too), and ``..`` is replaced before
``lstrip(".")`` (so there is no leading dot left to strip). The behaviour is safe
either way -- this was documentation drift, not a traversal hole -- but it is the
docstring of a security control, and it is the first thing anyone reads before
writing a test against it.

The other two could not pass anywhere: one omitted doctest's required
``Traceback (most recent call last):`` header, and the other hardcoded
``PosixPath(...)``, which cannot pass on Windows at any value.

## Why a dedicated test rather than --doctest-modules

Turning on ``--doctest-modules`` globally would collect every docstring in
``scripts/``, most of which are prose examples never written to execute, and
would redden CI for reasons unrelated to any contract. This runs the modules
whose examples *are* the contract, and adding one is a single line.

The floor on ``attempted`` is the meta-guard. Without it, deleting the examples
would make this pass on nothing -- which is precisely the state #758 describes.
"""

from __future__ import annotations

import doctest
import importlib

import pytest

# module path -> the number of doctests it must have at least.
# The floor is a measurement, not a target: path_sanitizers has exactly 7.
CONTRACT_MODULES: dict[str, int] = {
    "scripts.cli.path_sanitizers": 7,
}


@pytest.mark.parametrize("module_path,minimum", sorted(CONTRACT_MODULES.items()))
def test_contract_doctests_pass(module_path: str, minimum: int) -> None:
    """Regression for #758: a security docstring nothing ran, stating it wrongly."""
    module = importlib.import_module(module_path)
    runner = doctest.testmod(
        module,
        optionflags=doctest.ELLIPSIS,
        verbose=False,
        report=False,
    )

    assert runner.attempted >= minimum, (
        f"{module_path} now runs {runner.attempted} doctests, fewer than the "
        f"{minimum} recorded. Examples were deleted rather than fixed, which is "
        "the state #758 was filed about -- a docstring nothing checks."
    )
    assert runner.failed == 0, (
        f"{module_path} has {runner.failed} failing doctest(s). These state a "
        "security contract, so a failure means the documentation and the code "
        "disagree about what the control does."
    )
