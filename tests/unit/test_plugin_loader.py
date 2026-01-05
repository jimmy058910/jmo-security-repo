"""Unit tests for plugin loader (plugin_loader.py).

Tests cover:
- PluginRegistry: Basic registration and lookup
- PluginLoader: Lazy loading and hot-reload
- LazyPluginRegistry: On-demand adapter loading
- Global functions: preload_profile, get_available_adapters
"""

from pathlib import Path
import time


from scripts.core.plugin_api import AdapterPlugin, PluginMetadata, adapter_plugin
from scripts.core.plugin_loader import (
    PluginRegistry,
    PluginLoader,
    LazyPluginRegistry,
    get_plugin_registry,
    get_plugin_loader,
    get_available_adapters,
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

    def test_unregister_plugin(self):
        """Test unregistering a plugin."""
        registry = PluginRegistry()

        @adapter_plugin(PluginMetadata(name="test", version="1.0.0"))
        class TestAdapter(AdapterPlugin):
            @property
            def metadata(self):
                return self.__class__._plugin_metadata

            def parse(self, output_path: Path):
                return []

        registry.register("test", TestAdapter, TestAdapter._plugin_metadata)
        assert "test" in registry.list_plugins()

        result = registry.unregister("test")
        assert result is True
        assert "test" not in registry.list_plugins()
        assert registry.get("test") is None

    def test_unregister_nonexistent_plugin(self):
        """Test unregistering a plugin that doesn't exist."""
        registry = PluginRegistry()
        result = registry.unregister("nonexistent")
        assert result is False


class TestPluginLoader:
    """Test PluginLoader class."""

    def test_empty_loader(self):
        """Test PluginLoader with no plugins."""
        registry = PluginRegistry()
        loader = PluginLoader(registry)

        # Override search paths to empty directories
        loader.search_paths = []

        available = loader.get_available_adapters()
        assert available == []
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

    def test_discover_adapters_from_directory(self, tmp_path):
        """Test discovering adapter paths from directory."""
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

        # Discover available adapters (without loading)
        available = loader.get_available_adapters()

        assert len(available) == 2
        assert "plugin1" in available
        assert "plugin2" in available

        # Plugins should NOT be loaded yet (lazy loading)
        assert registry.list_plugins() == []

        # Now lazy-load them
        loader.get_adapter("plugin1")
        loader.get_adapter("plugin2")
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


class TestLazyLoading:
    """Test lazy loading functionality."""

    def test_discover_adapter_paths(self, tmp_path):
        """Test discovering adapter paths without loading modules."""
        registry = PluginRegistry()
        loader = PluginLoader(registry)

        # Create plugin directory with adapters
        plugin_dir = tmp_path / "adapters"
        plugin_dir.mkdir()

        (plugin_dir / "lazy1_adapter.py").write_text(
            """
from pathlib import Path
from scripts.core.plugin_api import AdapterPlugin, PluginMetadata, adapter_plugin

@adapter_plugin(PluginMetadata(name="lazy1", version="1.0.0"))
class Lazy1Adapter(AdapterPlugin):
    @property
    def metadata(self):
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path):
        return []
"""
        )

        (plugin_dir / "lazy2_adapter.py").write_text(
            """
from pathlib import Path
from scripts.core.plugin_api import AdapterPlugin, PluginMetadata, adapter_plugin

@adapter_plugin(PluginMetadata(name="lazy2", version="1.0.0"))
class Lazy2Adapter(AdapterPlugin):
    @property
    def metadata(self):
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path):
        return []
"""
        )

        loader.search_paths = [plugin_dir]

        # Get available adapters (discovers paths without loading)
        available = loader.get_available_adapters()

        assert "lazy1" in available
        assert "lazy2" in available
        # Plugins should NOT be loaded yet
        assert registry.list_plugins() == []

    def test_get_adapter_lazy_loads(self, tmp_path):
        """Test that get_adapter() lazy-loads adapters on demand."""
        registry = PluginRegistry()
        loader = PluginLoader(registry)

        # Create plugin directory
        plugin_dir = tmp_path / "adapters"
        plugin_dir.mkdir()

        (plugin_dir / "ondemand_adapter.py").write_text(
            """
from pathlib import Path
from scripts.core.plugin_api import AdapterPlugin, PluginMetadata, adapter_plugin

@adapter_plugin(PluginMetadata(name="ondemand", version="1.0.0"))
class OnDemandAdapter(AdapterPlugin):
    @property
    def metadata(self):
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path):
        return []
"""
        )

        loader.search_paths = [plugin_dir]

        # Registry should be empty before lazy load
        assert registry.list_plugins() == []

        # Get adapter (triggers lazy load)
        adapter = loader.get_adapter("ondemand")

        assert adapter is not None
        assert "ondemand" in registry.list_plugins()

    def test_get_adapter_returns_none_for_unknown(self, tmp_path):
        """Test that get_adapter() returns None for unknown adapters."""
        registry = PluginRegistry()
        loader = PluginLoader(registry)
        loader.search_paths = [tmp_path]

        adapter = loader.get_adapter("nonexistent")
        assert adapter is None

    def test_get_adapter_caches_result(self, tmp_path):
        """Test that get_adapter() caches loaded adapters."""
        registry = PluginRegistry()
        loader = PluginLoader(registry)

        # Create plugin directory
        plugin_dir = tmp_path / "adapters"
        plugin_dir.mkdir()

        (plugin_dir / "cached_adapter.py").write_text(
            """
from pathlib import Path
from scripts.core.plugin_api import AdapterPlugin, PluginMetadata, adapter_plugin

@adapter_plugin(PluginMetadata(name="cached", version="1.0.0"))
class CachedAdapter(AdapterPlugin):
    @property
    def metadata(self):
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path):
        return []
"""
        )

        loader.search_paths = [plugin_dir]

        # First call loads the adapter
        adapter1 = loader.get_adapter("cached")
        # Second call returns cached adapter
        adapter2 = loader.get_adapter("cached")

        assert adapter1 is adapter2

    def test_tool_to_adapter_name_mapping(self):
        """Test tool name to adapter name conversion."""
        registry = PluginRegistry()
        loader = PluginLoader(registry)

        # Test special mappings
        assert loader._tool_to_adapter_name("afl++") == "aflplusplus"
        assert loader._tool_to_adapter_name("dependency-check") == "dependency_check"
        assert loader._tool_to_adapter_name("semgrep-secrets") == "semgrep_secrets"
        assert loader._tool_to_adapter_name("trivy-rbac") == "trivy_rbac"
        assert loader._tool_to_adapter_name("checkov-cicd") == "checkov"

        # Test generic hyphen-to-underscore conversion
        assert loader._tool_to_adapter_name("some-tool") == "some_tool"

        # Test names without hyphens pass through
        assert loader._tool_to_adapter_name("trivy") == "trivy"
        assert loader._tool_to_adapter_name("semgrep") == "semgrep"


class TestLazyPluginRegistry:
    """Test LazyPluginRegistry class."""

    def test_lazy_registry_without_loader(self):
        """Test LazyPluginRegistry without a loader."""
        registry = LazyPluginRegistry()

        # Without a loader, get() should return None for unknown plugins
        assert registry.get("unknown") is None

    def test_lazy_registry_with_loader(self, tmp_path):
        """Test LazyPluginRegistry with loader for lazy loading."""
        registry = LazyPluginRegistry()
        loader = PluginLoader(registry)
        registry.set_loader(loader)

        # Create plugin directory
        plugin_dir = tmp_path / "adapters"
        plugin_dir.mkdir()

        (plugin_dir / "lazytest_adapter.py").write_text(
            """
from pathlib import Path
from scripts.core.plugin_api import AdapterPlugin, PluginMetadata, adapter_plugin

@adapter_plugin(PluginMetadata(name="lazytest", version="1.0.0"))
class LazyTestAdapter(AdapterPlugin):
    @property
    def metadata(self):
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path):
        return []
"""
        )

        loader.search_paths = [plugin_dir]

        # Registry get() should trigger lazy loading
        adapter = registry.get("lazytest")
        assert adapter is not None
        assert "lazytest" in registry.list_plugins()

    def test_list_all_available(self, tmp_path):
        """Test list_all_available() returns both loaded and discoverable."""
        registry = LazyPluginRegistry()
        loader = PluginLoader(registry)
        registry.set_loader(loader)

        # Create plugin directory
        plugin_dir = tmp_path / "adapters"
        plugin_dir.mkdir()

        (plugin_dir / "available1_adapter.py").write_text(
            """
from pathlib import Path
from scripts.core.plugin_api import AdapterPlugin, PluginMetadata, adapter_plugin

@adapter_plugin(PluginMetadata(name="available1", version="1.0.0"))
class Available1Adapter(AdapterPlugin):
    @property
    def metadata(self):
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path):
        return []
"""
        )

        (plugin_dir / "available2_adapter.py").write_text(
            """
from pathlib import Path
from scripts.core.plugin_api import AdapterPlugin, PluginMetadata, adapter_plugin

@adapter_plugin(PluginMetadata(name="available2", version="1.0.0"))
class Available2Adapter(AdapterPlugin):
    @property
    def metadata(self):
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path):
        return []
"""
        )

        loader.search_paths = [plugin_dir]

        # Load one adapter
        registry.get("available1")

        # list_all_available should show both loaded and discoverable
        all_available = registry.list_all_available()
        assert "available1" in all_available
        assert "available2" in all_available


class TestPreloadProfile:
    """Test profile preloading functionality."""

    def test_preload_unknown_profile(self):
        """Test preloading an unknown profile."""
        registry = PluginRegistry()
        loader = PluginLoader(registry)
        loader.search_paths = []

        count = loader.preload_profile("nonexistent_profile")
        assert count == 0

    def test_preload_profile_loads_adapters(self, tmp_path, monkeypatch):
        """Test that preload_profile loads adapters for the profile."""
        registry = PluginRegistry()
        loader = PluginLoader(registry)

        # Create plugin directory with adapters matching "fast" profile
        plugin_dir = tmp_path / "adapters"
        plugin_dir.mkdir()

        # Create some adapters that match the fast profile
        for tool_name in ["trivy", "semgrep", "syft"]:
            (plugin_dir / f"{tool_name}_adapter.py").write_text(
                f"""
from pathlib import Path
from scripts.core.plugin_api import AdapterPlugin, PluginMetadata, adapter_plugin

@adapter_plugin(PluginMetadata(name="{tool_name}", version="1.0.0"))
class {tool_name.title()}Adapter(AdapterPlugin):
    @property
    def metadata(self):
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path):
        return []
"""
            )

        loader.search_paths = [plugin_dir]

        # Preload fast profile
        count = loader.preload_profile("fast")

        # Should have loaded at least some adapters
        assert count >= 3
        assert "trivy" in registry.list_plugins()
        assert "semgrep" in registry.list_plugins()


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

    def test_get_available_adapters_function(self):
        """Test get_available_adapters() function."""
        available = get_available_adapters()
        assert isinstance(available, list)
        # In real environment, should find built-in adapters
        # In isolated test, might be empty depending on search paths


class TestLazyLoadingPerformance:
    """Performance tests for lazy loading.

    These tests verify that lazy loading provides performance benefits
    over eager loading.
    """

    def test_path_discovery_is_fast(self, tmp_path):
        """Test that path discovery is much faster than module loading."""
        registry = PluginRegistry()
        loader = PluginLoader(registry)

        # Create plugin directory with multiple adapters
        plugin_dir = tmp_path / "adapters"
        plugin_dir.mkdir()

        for i in range(10):
            (plugin_dir / f"perf{i}_adapter.py").write_text(
                f"""
from pathlib import Path
from scripts.core.plugin_api import AdapterPlugin, PluginMetadata, adapter_plugin

@adapter_plugin(PluginMetadata(name="perf{i}", version="1.0.0"))
class Perf{i}Adapter(AdapterPlugin):
    @property
    def metadata(self):
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path):
        return []
"""
            )

        loader.search_paths = [plugin_dir]

        # Time path discovery (should be fast)
        start = time.perf_counter()
        available = loader.get_available_adapters()
        discovery_time = time.perf_counter() - start

        # Path discovery should be fast (< 100ms)
        assert discovery_time < 0.1
        assert len(available) == 10

        # Modules should NOT be loaded yet
        assert len(registry.list_plugins()) == 0

    def test_lazy_loading_loads_on_demand(self, tmp_path):
        """Test that adapters are only loaded when accessed."""
        registry = PluginRegistry()
        loader = PluginLoader(registry)

        # Create plugin directory
        plugin_dir = tmp_path / "adapters"
        plugin_dir.mkdir()

        for name in ["first", "second", "third"]:
            (plugin_dir / f"{name}_adapter.py").write_text(
                f"""
from pathlib import Path
from scripts.core.plugin_api import AdapterPlugin, PluginMetadata, adapter_plugin

@adapter_plugin(PluginMetadata(name="{name}", version="1.0.0"))
class {name.title()}Adapter(AdapterPlugin):
    @property
    def metadata(self):
        return self.__class__._plugin_metadata

    def parse(self, output_path: Path):
        return []
"""
            )

        loader.search_paths = [plugin_dir]

        # Initially, no plugins loaded
        assert len(registry.list_plugins()) == 0

        # Load only "first"
        loader.get_adapter("first")
        assert len(registry.list_plugins()) == 1
        assert "first" in registry.list_plugins()

        # "second" and "third" should NOT be loaded
        assert "second" not in registry.list_plugins()
        assert "third" not in registry.list_plugins()
