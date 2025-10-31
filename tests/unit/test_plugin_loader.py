"""Unit tests for plugin loader (plugin_loader.py)."""

from pathlib import Path

from scripts.core.plugin_api import AdapterPlugin, PluginMetadata, adapter_plugin
from scripts.core.plugin_loader import (
    PluginRegistry,
    PluginLoader,
    get_plugin_registry,
    get_plugin_loader,
    discover_adapters,
)


class TestPluginRegistry:
    """Test PluginRegistry class."""

    def test_empty_registry(self):
        """Test empty plugin registry."""
        registry = PluginRegistry()
        assert registry.list_plugins() == []
        assert registry.get_all_metadata() == {}
        assert registry.get("nonexistent") is None
        assert registry.get_metadata("nonexistent") is None

    def test_register_plugin(self):
        """Test registering a plugin."""
        registry = PluginRegistry()

        @adapter_plugin(PluginMetadata(name="test", version="1.0.0"))
        class TestAdapter(AdapterPlugin):
            @property
            def metadata(self):
                return self.__class__._plugin_metadata

            def parse(self, output_path: Path):
                return []

        metadata = TestAdapter._plugin_metadata
        registry.register("test", TestAdapter, metadata)

        assert "test" in registry.list_plugins()
        assert registry.get("test") == TestAdapter
        assert registry.get_metadata("test") == metadata

    def test_register_multiple_plugins(self):
        """Test registering multiple plugins."""
        registry = PluginRegistry()

        @adapter_plugin(PluginMetadata(name="plugin1", version="1.0.0"))
        class Plugin1(AdapterPlugin):
            @property
            def metadata(self):
                return self.__class__._plugin_metadata

            def parse(self, output_path: Path):
                return []

        @adapter_plugin(PluginMetadata(name="plugin2", version="2.0.0"))
        class Plugin2(AdapterPlugin):
            @property
            def metadata(self):
                return self.__class__._plugin_metadata

            def parse(self, output_path: Path):
                return []

        registry.register("plugin1", Plugin1, Plugin1._plugin_metadata)
        registry.register("plugin2", Plugin2, Plugin2._plugin_metadata)

        assert len(registry.list_plugins()) == 2
        assert "plugin1" in registry.list_plugins()
        assert "plugin2" in registry.list_plugins()
        assert registry.get("plugin1") == Plugin1
        assert registry.get("plugin2") == Plugin2

    def test_get_all_metadata(self):
        """Test get_all_metadata()."""
        registry = PluginRegistry()

        @adapter_plugin(PluginMetadata(name="test", version="1.0.0"))
        class TestAdapter(AdapterPlugin):
            @property
            def metadata(self):
                return self.__class__._plugin_metadata

            def parse(self, output_path: Path):
                return []

        metadata = TestAdapter._plugin_metadata
        registry.register("test", TestAdapter, metadata)

        all_metadata = registry.get_all_metadata()
        assert "test" in all_metadata
        assert all_metadata["test"] == metadata


class TestPluginLoader:
    """Test PluginLoader class."""

    def test_empty_loader(self):
        """Test PluginLoader with no plugins."""
        registry = PluginRegistry()
        loader = PluginLoader(registry)

        # Override search paths to empty directories
        loader.search_paths = []

        count = loader.discover_plugins()
        assert count == 0
        assert registry.list_plugins() == []

    def test_load_plugin_from_file(self, tmp_path):
        """Test loading plugin from file."""
        registry = PluginRegistry()
        loader = PluginLoader(registry)

        # Create test plugin file
        plugin_file = tmp_path / "test_adapter.py"
        plugin_file.write_text(
            """
from pathlib import Path
from scripts.core.plugin_api import AdapterPlugin, PluginMetadata, Finding, adapter_plugin

@adapter_plugin(PluginMetadata(name="test", version="1.0.0", tool_name="test-tool"))
class TestAdapter(AdapterPlugin):
    @property
    def metadata(self):
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path):
        return [Finding(id="test-001", ruleId="TEST", severity="HIGH", message="Test")]
"""
        )

        # Load plugin
        loader._load_plugin(plugin_file)

        assert "test" in registry.list_plugins()
        assert registry.get_metadata("test").name == "test"
        assert registry.get_metadata("test").version == "1.0.0"

    def test_discover_plugins_from_directory(self, tmp_path):
        """Test discovering plugins from directory."""
        registry = PluginRegistry()
        loader = PluginLoader(registry)

        # Create plugin directory
        plugin_dir = tmp_path / "adapters"
        plugin_dir.mkdir()

        # Create multiple plugin files
        (plugin_dir / "plugin1_adapter.py").write_text(
            """
from pathlib import Path
from scripts.core.plugin_api import AdapterPlugin, PluginMetadata, Finding, adapter_plugin

@adapter_plugin(PluginMetadata(name="plugin1", version="1.0.0"))
class Plugin1(AdapterPlugin):
    @property
    def metadata(self):
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path):
        return []
"""
        )

        (plugin_dir / "plugin2_adapter.py").write_text(
            """
from pathlib import Path
from scripts.core.plugin_api import AdapterPlugin, PluginMetadata, Finding, adapter_plugin

@adapter_plugin(PluginMetadata(name="plugin2", version="2.0.0"))
class Plugin2(AdapterPlugin):
    @property
    def metadata(self):
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path):
        return []
"""
        )

        # Override search paths
        loader.search_paths = [plugin_dir]

        # Discover plugins
        count = loader.discover_plugins()

        assert count == 2
        assert "plugin1" in registry.list_plugins()
        assert "plugin2" in registry.list_plugins()

    def test_load_plugin_missing_metadata(self, tmp_path):
        """Test loading plugin without metadata."""
        registry = PluginRegistry()
        loader = PluginLoader(registry)

        # Create plugin file without metadata
        plugin_file = tmp_path / "bad_adapter.py"
        plugin_file.write_text(
            """
from pathlib import Path
from scripts.core.plugin_api import AdapterPlugin

class BadAdapter(AdapterPlugin):
    def parse(self, output_path: Path):
        return []
"""
        )

        # Load plugin (should fail gracefully)
        loader._load_plugin(plugin_file)

        assert "bad" not in registry.list_plugins()

    def test_load_plugin_with_property_metadata(self, tmp_path):
        """Test loading plugin with metadata property."""
        registry = PluginRegistry()
        loader = PluginLoader(registry)

        # Create plugin file with property metadata
        plugin_file = tmp_path / "property_adapter.py"
        plugin_file.write_text(
            """
from pathlib import Path
from scripts.core.plugin_api import AdapterPlugin, PluginMetadata, Finding

class PropertyAdapter(AdapterPlugin):
    @property
    def metadata(self):
        return PluginMetadata(name="property", version="1.0.0")

    def parse(self, output_path: Path):
        return []
"""
        )

        # Load plugin
        loader._load_plugin(plugin_file)

        assert "property" in registry.list_plugins()

    def test_reload_plugin(self, tmp_path):
        """Test reloading a plugin.

        Note: This tests the reload mechanism (unregister + reload).
        Full hot-reload with code changes requires Python's import system
        to refresh, which is complex in testing. The important part is
        that the unregister + re-register flow works.
        """
        registry = PluginRegistry()
        loader = PluginLoader(registry)

        # Create plugin file
        plugin_dir = tmp_path / "adapters"
        plugin_dir.mkdir()
        plugin_file = plugin_dir / "reload_adapter.py"

        plugin_file.write_text(
            """
from pathlib import Path
from scripts.core.plugin_api import AdapterPlugin, PluginMetadata, Finding, adapter_plugin

@adapter_plugin(PluginMetadata(name="reload", version="1.0.0"))
class ReloadAdapter(AdapterPlugin):
    @property
    def metadata(self):
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path):
        return []
"""
        )

        # Override search paths
        loader.search_paths = [plugin_dir]

        # Load plugin
        loader._load_plugin(plugin_file)
        assert "reload" in registry.list_plugins()
        assert registry.get_metadata("reload").version == "1.0.0"

        # Test reload mechanism (unregister + re-register)
        # In real use, file would change, but for testing we verify the flow works
        success = loader.reload_plugin("reload")
        assert success is True
        # Plugin should still be registered (reloaded from same file)
        assert "reload" in registry.list_plugins()
        assert registry.get_metadata("reload") is not None

    def test_reload_nonexistent_plugin(self):
        """Test reloading nonexistent plugin."""
        registry = PluginRegistry()
        loader = PluginLoader(registry)
        loader.search_paths = []

        success = loader.reload_plugin("nonexistent")
        assert success is False


class TestGlobalFunctions:
    """Test global plugin functions."""

    def test_get_plugin_registry(self):
        """Test get_plugin_registry()."""
        registry = get_plugin_registry()
        assert isinstance(registry, PluginRegistry)

        # Verify singleton (same instance)
        registry2 = get_plugin_registry()
        assert registry is registry2

    def test_get_plugin_loader(self):
        """Test get_plugin_loader()."""
        loader = get_plugin_loader()
        assert isinstance(loader, PluginLoader)

        # Verify singleton (same instance)
        loader2 = get_plugin_loader()
        assert loader is loader2

    def test_discover_adapters(self, tmp_path, monkeypatch):
        """Test discover_adapters() function."""
        # Create plugin directory
        plugin_dir = tmp_path / "adapters"
        plugin_dir.mkdir()

        # Create test plugin
        (plugin_dir / "test_adapter.py").write_text(
            """
from pathlib import Path
from scripts.core.plugin_api import AdapterPlugin, PluginMetadata, Finding, adapter_plugin

@adapter_plugin(PluginMetadata(name="discover_test", version="1.0.0"))
class TestAdapter(AdapterPlugin):
    @property
    def metadata(self):
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path):
        return []
"""
        )

        # Override search paths
        loader = get_plugin_loader()
        loader.search_paths = [plugin_dir]

        # Discover adapters
        count = discover_adapters()
        assert count >= 1  # At least our test plugin
