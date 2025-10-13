"""CLI package for jmo-security.

This file ensures setuptools treats `scripts/cli` as a proper Python package
so that the console entry point `jmo = scripts.cli.jmo:main` resolves correctly
when installed from PyPI.
"""
