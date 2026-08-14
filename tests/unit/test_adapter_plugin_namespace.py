"""The module name adapters are loaded under, and what depends on it (#838).

`PluginLoader` used to load each adapter under the bare file stem
(`prowler_adapter`). Two separate properties broke as a result, and neither was
observable from a normal `import`, which is why 27 adapters and 8,000 tests did
not catch it:

1. `logging.getLogger(__name__)` inside an adapter named its logger after that
   bare module, making it a *sibling* of `scripts` rather than a child. The
   handler `configure_scan_logging` attaches to the `scripts` logger --
   the whole point of which is making `--log-level` reach the scan's loggers --
   therefore never saw those records, and they fell through to
   `logging.lastResort` as bare text. Measured on `origin/dev`: 17 of 27 adapter
   loggers outside `scripts`, 0 inside.

2. The bare stem is a different `sys.modules` key from the dotted path the rest
   of the codebase imports, so the plugin-loaded adapter and the imported one
   were two distinct module objects. `isinstance()` across them was False, and
   the test suite -- which imports normally -- exercised a different object,
   with a different logger, than production ran.

The tests below assert the *positive* shape (the loggers ARE under `scripts`,
the classes ARE identical) rather than the absence of the old symptom, because
an empty iteration lacks a symptom just as thoroughly as a fixed one. Each
adapter-wide test therefore also asserts it examined a non-zero number of
adapters.
"""

from __future__ import annotations

import argparse
import importlib
import logging
import sys
from pathlib import Path

import pytest

from scripts.core.plugin_loader import (
    PluginLoader,
    PluginRegistry,
    get_available_adapters,
    get_plugin_loader,
    get_plugin_registry,
)

MINIMAL_ADAPTER = """
import logging
from pathlib import Path
from scripts.core.plugin_api import AdapterPlugin, PluginMetadata, adapter_plugin

logger = logging.getLogger(__name__)

@adapter_plugin(PluginMetadata(name="{name}", version="1.0.0"))
class SomeAdapter(AdapterPlugin):
    @property
    def metadata(self):
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path):
        return []
"""


@pytest.fixture
def restore_scan_logging():
    """Undo `configure_scan_logging`, which mutates the process-global tree.

    Without this a level left on the `scripts` logger silently empties
    `caplog.text` for every later INFO assertion in the session.
    """
    yield
    from scripts.cli.jmo import reset_scan_logging

    reset_scan_logging()


class TestBuiltinAdapterModuleNames:
    def test_every_builtin_adapter_loads_under_the_scripts_namespace(self):
        registry = get_plugin_registry()
        names = get_available_adapters()
        assert names, "no adapters discovered - the sweep below would be vacuous"

        checked = 0
        outside = []
        for name in names:
            cls = registry.get(name)
            assert cls is not None, f"adapter {name!r} failed to load"
            checked += 1
            if not cls.__module__.startswith("scripts.core.adapters."):
                outside.append((name, cls.__module__))

        assert checked == len(names)
        assert not outside, (
            "adapter modules loaded outside the `scripts` package - their "
            f"`getLogger(__name__)` loggers are unreachable by --log-level: {outside}"
        )

    def test_no_adapter_module_lands_at_the_top_level_of_sys_modules(self):
        """Match the loader's own file stems, never a name shape.

        The first version of this test scanned `sys.modules` for anything
        ending in `_adapter` with no dot. That is a *pattern*, not the
        property, and pytest imports `tests/adapters/test_<tool>_adapter.py`
        under bare top-level names of its own — so it flagged all 27 of those
        instead. It passed locally only because the local suite is split into
        halves and `tests/adapters/` is in the other one from `tests/unit/`;
        CI's shards mix them, and it failed on every platform.
        """
        loader = get_plugin_loader()
        registry = get_plugin_registry()
        for name in get_available_adapters():
            registry.get(name)

        stems = {path.stem for path in loader._adapter_paths.values()}
        assert stems, "no adapter paths discovered - the assertion is vacuous"

        leaked = sorted(stems & set(sys.modules))
        assert not leaked, (
            "adapters occupying bare top-level sys.modules keys; each is a "
            f"second copy of an importable module: {leaked}"
        )

    def test_loader_returns_the_same_class_object_a_normal_import_yields(self):
        """The double-import hazard, stated as an identity."""
        loaded = get_plugin_registry().get("prowler")
        imported = importlib.import_module(
            "scripts.core.adapters.prowler_adapter"
        ).ProwlerAdapter

        assert loaded is imported, (
            "the plugin loader built a second copy of the adapter class; module "
            "state and logger are not shared with the imported one"
        )
        assert isinstance(loaded(), imported)

    def test_loading_a_builtin_does_not_replace_the_imported_module(self):
        """Identity is not enough on its own -- order is the discriminator.

        A file-based load under the *correct* dotted name still overwrites
        `sys.modules`, so a test that loads first and imports second gets the
        loader's replacement back and sees identity hold. Anything already
        holding the original class then fails `isinstance` against the new one,
        and now silently, because the module name matches.

        Establishing the canonical object *first* is what catches it. (This
        test exists because the identity assertion above survived exactly that
        mutation.)
        """
        module = importlib.import_module("scripts.core.adapters.prowler_adapter")
        original_class = module.ProwlerAdapter
        builtin_path = Path(module.__file__)

        registry = PluginRegistry()
        PluginLoader(registry)._load_plugin(builtin_path)

        assert (
            sys.modules["scripts.core.adapters.prowler_adapter"] is module
        ), "loading a built-in adapter replaced the already-imported module"
        assert registry.get("prowler") is original_class


class TestLogLevelReachesAdapterLoggers:
    """The user-visible property #838 was actually about."""

    def _adapter_logger(self) -> logging.Logger:
        cls = get_plugin_registry().get("prowler")
        module = sys.modules[cls.__module__]
        return module.logger

    def test_adapter_logger_is_a_child_of_the_scripts_logger(self):
        logger = self._adapter_logger()
        assert logger.name.startswith("scripts."), (
            f"adapter logger {logger.name!r} is a sibling of `scripts`, not a "
            "child, so configure_scan_logging cannot reach it"
        )

    def test_log_level_error_suppresses_an_adapter_warning(self, restore_scan_logging):
        from scripts.cli.jmo import configure_scan_logging

        logger = self._adapter_logger()
        configure_scan_logging(argparse.Namespace(log_level="ERROR", human_logs=False))
        assert not logger.isEnabledFor(logging.WARNING), (
            "--log-level ERROR did not suppress an adapter WARNING; on "
            "origin/dev prowler's 'matched neither format' warning printed at "
            "every level because its logger was outside `scripts`"
        )

    def test_log_level_debug_reaches_an_adapter_debug_record(
        self, restore_scan_logging
    ):
        from scripts.cli.jmo import configure_scan_logging

        logger = self._adapter_logger()
        configure_scan_logging(argparse.Namespace(log_level="DEBUG", human_logs=False))
        assert logger.isEnabledFor(
            logging.DEBUG
        ), "--log-level DEBUG did not reach an adapter logger"


class TestLoadPluginContract:
    def test_returns_the_registered_name_for_a_real_adapter(self, tmp_path):
        plugin_file = tmp_path / "widget_adapter.py"
        plugin_file.write_text(MINIMAL_ADAPTER.format(name="widget"))

        registry = PluginRegistry()
        registered = PluginLoader(registry)._load_plugin(plugin_file)

        assert registered == "widget"
        assert "widget" in registry.list_plugins()

    def test_returns_none_when_the_file_defines_no_adapter(self, tmp_path):
        """Loading without finding an adapter is not an exception.

        `jmo adapters validate` keyed success off "no exception raised", so a
        file containing `x = 1` reported a valid plugin and exit 0.
        """
        plugin_file = tmp_path / "nothing_adapter.py"
        plugin_file.write_text("x = 1\n")

        registry = PluginRegistry()
        registered = PluginLoader(registry)._load_plugin(plugin_file)

        assert registered is None
        assert registry.list_plugins() == []

    def test_a_module_that_fails_to_execute_is_not_left_in_sys_modules(self, tmp_path):
        """Otherwise the next load returns the half-initialised object."""
        plugin_file = tmp_path / "explodes_adapter.py"
        plugin_file.write_text("raise RuntimeError('boom')\n")

        loader = PluginLoader(PluginRegistry())
        module_name = loader._module_name_for(plugin_file)

        with pytest.raises(RuntimeError, match="boom"):
            loader._load_plugin(plugin_file)

        assert module_name not in sys.modules

        # The second attempt must re-run and re-raise, not silently succeed.
        with pytest.raises(RuntimeError, match="boom"):
            loader._load_plugin(plugin_file)


class TestExternalAdapterNames:
    """User adapters from ~/.jmo/adapters/ get a namespace too."""

    def test_external_adapter_is_namespaced_under_scripts(self, tmp_path):
        plugin_file = tmp_path / "external_adapter.py"
        plugin_file.write_text(MINIMAL_ADAPTER.format(name="external"))

        loader = PluginLoader(PluginRegistry())
        name = loader._module_name_for(plugin_file)

        assert name.startswith("scripts."), (
            f"external adapter module {name!r} is outside `scripts`, so its "
            "logger is unreachable by --log-level"
        )
        loader._load_plugin(plugin_file)
        assert sys.modules[name].logger.name.startswith("scripts.")

    def test_external_adapter_does_not_shadow_a_builtin_of_the_same_stem(
        self, tmp_path
    ):
        """A user adapter overrides by *registry name*, not by import path.

        Reusing the real dotted path would swap the built-in out from under
        every other importer in the process.
        """
        plugin_file = tmp_path / "prowler_adapter.py"
        plugin_file.write_text(MINIMAL_ADAPTER.format(name="prowler_user"))

        loader = PluginLoader(PluginRegistry())
        external_name = loader._module_name_for(plugin_file)
        builtin_name = loader._module_name_for(
            Path("scripts/core/adapters/prowler_adapter.py").resolve()
        )

        assert external_name != builtin_name
        assert builtin_name == "scripts.core.adapters.prowler_adapter"
