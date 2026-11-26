"""Tests for the child sessions of test_disk_floor.py to run, or be stopped.

Not named `test_*.py`, so no ordinary run collects it; pytest collects a file
named on its command line whatever it is called.
"""

import pytest


@pytest.mark.parametrize("number", range(8))
def test_probe(number: int):
    """Passes."""
