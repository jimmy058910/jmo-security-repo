"""`jmo adapters list` / `validate`, and what "valid" has to mean.

`cmd_adapters validate` keyed its verdict off "did `_load_plugin` raise?".
`_load_plugin` treats "imported fine but defines no AdapterPlugin subclass" as
a warning, not an error -- so the one condition the command exists to check was
the one it did not check. Measured on `origin/dev`:

    $ jmo adapters validate not_an_adapter.py   # contents: `x = 1`
    [OK] Valid plugin: not_an_adapter.py
    rc=0

A bare `jmo adapters` was likewise the only subcommand in the CLI that reported
success while doing nothing (measured: history 1, tools 1, policy 2,
schedule 2, adapters 0 with no output at all).
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from scripts.cli.jmo import main

REAL_ADAPTER = "scripts/core/adapters/prowler_adapter.py"

MINIMAL_ADAPTER = """
from pathlib import Path
from scripts.core.plugin_api import AdapterPlugin, PluginMetadata, adapter_plugin

@adapter_plugin(PluginMetadata(name="fixture_tool", version="1.0.0"))
class FixtureAdapter(AdapterPlugin):
    @property
    def metadata(self):
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path):
        return []
"""


def _run(*argv: str) -> int:
    with patch("sys.argv", ["jmo", *argv]):
        return main()


class TestAdaptersValidate:
    def test_accepts_a_real_adapter(self, capsys):
        assert _run("adapters", "validate", REAL_ADAPTER) == 0
        assert "prowler" in capsys.readouterr().out

    def test_accepts_an_adapter_written_to_a_temp_file(self, tmp_path):
        plugin = tmp_path / "fixture_tool_adapter.py"
        plugin.write_text(MINIMAL_ADAPTER)
        assert _run("adapters", "validate", str(plugin)) == 0

    def test_rejects_a_python_file_defining_no_adapter(self, tmp_path, capsys):
        """The regression this file exists for."""
        plugin = tmp_path / "not_an_adapter.py"
        plugin.write_text("x = 1\n")

        rc = _run("adapters", "validate", str(plugin))

        assert rc == 1, "any importable Python file was reported as a valid plugin"
        assert "no AdapterPlugin subclass" in capsys.readouterr().out

    def test_rejects_a_file_that_runs_but_defines_no_adapter(self, tmp_path):
        """Module-level side effects do not make a file an adapter.

        `validate` imports the file, so its top level executes. That is
        faithful to what the loader does -- but executing without defining an
        adapter is still a failed validation, which is the half that was wrong.
        """
        plugin = tmp_path / "side_effect_adapter.py"
        plugin.write_text("PRINTED = 'module body ran'\n")

        assert _run("adapters", "validate", str(plugin)) == 1

    def test_rejects_a_syntactically_broken_file(self, tmp_path):
        plugin = tmp_path / "broken_adapter.py"
        plugin.write_text("this is not python at all !!!\n")
        assert _run("adapters", "validate", str(plugin)) == 1

    def test_rejects_a_missing_file(self, tmp_path):
        assert _run("adapters", "validate", str(tmp_path / "absent.py")) == 1


class TestAdaptersList:
    def test_lists_every_discovered_adapter_with_metadata(self, capsys):
        from scripts.core.plugin_loader import get_available_adapters

        assert _run("adapters", "list") == 0

        out = capsys.readouterr().out
        expected = get_available_adapters()
        assert expected, "no adapters discovered - the assertion below is vacuous"
        assert f"Found {len(expected)} adapter plugins" in out
        for name in expected:
            assert name in out
        # Every adapter must resolve metadata; these are the fallback strings.
        assert "(failed to load)" not in out
        assert "(loaded, no metadata)" not in out


class TestAdaptersRequiresASubcommand:
    def test_bare_adapters_exits_two(self):
        """argparse's own usage error, matching `policy` and `schedule`."""
        with pytest.raises(SystemExit) as excinfo:
            _run("adapters")
        assert excinfo.value.code == 2
