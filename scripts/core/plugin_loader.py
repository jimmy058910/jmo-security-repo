"""Plugin loader with lazy loading for adapter discovery (INTERNAL USE).

This module provides plugin discovery and loading functionality for
JMo Security's internal adapter architecture. Features:

1. Lazy loading - adapters load on-demand when first accessed
2. Auto-discovery from multiple search paths
3. Hot-reload support for development iteration
4. Profile preloading for batch operations

Search order:
1. ~/.jmo/adapters/ (user adapters - hot-loadable)
2. scripts/core/adapters/ (built-in adapters)

Performance:
- Path discovery: ~1-5ms (scans filesystem without importing)
- Lazy loading: Each adapter loaded only when requested
- Use preload_profile() to batch-load adapters for a scan profile

Usage:
    # Get an adapter (loads on-demand)
    registry = get_plugin_registry()
    adapter = registry.get("trivy")  # Loads trivy adapter

    # List available adapters without loading
    available = get_available_adapters()

    # Batch-load for a profile
    preload_profile("fast")  # Loads all 8 fast-profile adapters
"""

from __future__ import annotations

import importlib.util
import sys
import time
from pathlib import Path
import logging
from typing import TYPE_CHECKING

from scripts.core.plugin_api import AdapterPlugin, PluginMetadata

if TYPE_CHECKING:
    pass


logger = logging.getLogger(__name__)


class PluginRegistry:
    """Registry of loaded adapter plugins.

    Maintains a central registry of all discovered and loaded plugins,
    providing lookup and metadata access.
    """

    def __init__(self):
        """Initialize empty plugin registry."""
        self._plugins: dict[str, type[AdapterPlugin]] = {}
        self._metadata: dict[str, PluginMetadata] = {}

    def register(
        self, name: str, plugin_class: type[AdapterPlugin], metadata: PluginMetadata
    ):
        """Register a plugin.

        Args:
            name: Plugin name (e.g., 'trivy')
            plugin_class: Plugin class (AdapterPlugin subclass)
            metadata: Plugin metadata
        """
        self._plugins[name] = plugin_class
        self._metadata[name] = metadata
        logger.debug(f"Registered adapter plugin: {name} v{metadata.version}")

    def unregister(self, name: str) -> bool:
        """Unregister a plugin.

        Args:
            name: Plugin name

        Returns:
            True if unregistered, False if not found
        """
        if name in self._plugins:
            del self._plugins[name]
            del self._metadata[name]
            logger.debug(f"Unregistered adapter plugin: {name}")
            return True
        return False

    def get(self, name: str) -> type[AdapterPlugin] | None:
        """Get plugin class by name.

        Args:
            name: Plugin name

        Returns:
            Plugin class or None if not found
        """
        return self._plugins.get(name)

    def get_metadata(self, name: str) -> PluginMetadata | None:
        """Get plugin metadata by name.

        Args:
            name: Plugin name

        Returns:
            Plugin metadata or None if not found
        """
        return self._metadata.get(name)

    def list_plugins(self) -> list[str]:
        """List all registered plugin names.

        Returns:
            List of plugin names
        """
        return list(self._plugins.keys())

    def get_all_metadata(self) -> dict[str, PluginMetadata]:
        """Get metadata for all plugins.

        Returns:
            Dictionary mapping plugin names to metadata
        """
        return self._metadata.copy()


class PluginLoader:
    """Load adapter plugins from multiple search paths with lazy loading.

    Adapters are loaded on-demand when first accessed via get_adapter().
    This reduces startup time from 200-500ms to ~10ms by:
    - Only discovering adapter paths at initialization (~1-5ms)
    - Loading adapter modules only when first accessed
    - Caching loaded adapters for subsequent calls

    Search order:
    1. ~/.jmo/adapters/ (user adapters - hot-loadable)
    2. scripts/core/adapters/ (built-in adapters)

    Plugins are discovered by globbing for *_adapter.py files and
    loading AdapterPlugin subclasses from them.
    """

    def __init__(self, registry: PluginRegistry | None = None):
        """Initialize plugin loader.

        Args:
            registry: Plugin registry (creates new if None)
        """
        self.registry = registry or PluginRegistry()
        self.search_paths = [
            Path.home() / ".jmo" / "adapters",  # User adapters (hot-reload)
            Path(__file__).parent / "adapters",  # Built-in adapters
        ]

        # Lazy loading state: maps adapter name to file path
        self._adapter_paths: dict[str, Path] = {}
        self._paths_discovered = False

    def _discover_adapter_paths(self) -> None:
        """Discover adapter file paths without loading modules.

        This is a fast operation that only scans directories for
        *_adapter.py files without importing them.

        Performance: ~1-5ms for 28 adapters
        """
        if self._paths_discovered:
            return

        for search_path in self.search_paths:
            if not search_path.exists():
                logger.debug(f"Search path does not exist: {search_path}")
                continue

            for plugin_file in search_path.glob("*_adapter.py"):
                # Skip base_adapter.py (abstract base class, not a plugin)
                if plugin_file.name == "base_adapter.py":
                    continue
                # Skip common.py (utility module, not a plugin)
                if plugin_file.name == "common.py":
                    continue

                # Extract adapter name from filename
                # e.g., "trivy_adapter.py" -> "trivy"
                # e.g., "semgrep_secrets_adapter.py" -> "semgrep_secrets"
                name = plugin_file.stem.replace("_adapter", "")

                # First match wins (user adapters override built-in)
                if name not in self._adapter_paths:
                    self._adapter_paths[name] = plugin_file
                    logger.debug(f"Discovered adapter path: {name} -> {plugin_file}")

        self._paths_discovered = True
        logger.debug(f"Discovered {len(self._adapter_paths)} adapter paths")

    def get_adapter(self, name: str) -> type[AdapterPlugin] | None:
        """Get adapter class by name, loading on-demand if needed.

        This is the preferred method for getting adapters. It:
        1. Returns cached adapter if already loaded
        2. Loads and caches adapter if not loaded
        3. Returns None if adapter not found

        Args:
            name: Adapter name (e.g., 'trivy', 'semgrep')

        Returns:
            Adapter plugin class, or None if not found
        """
        # Check if already loaded (use base class get to avoid recursion)
        plugin = self.registry._plugins.get(name)
        if plugin is not None:
            return plugin

        # Ensure paths are discovered
        self._discover_adapter_paths()

        # Check if adapter exists
        if name not in self._adapter_paths:
            logger.debug(f"Adapter not found: {name}")
            return None

        # Load the adapter
        try:
            start_time = time.perf_counter()
            self._load_plugin(self._adapter_paths[name])
            elapsed = (time.perf_counter() - start_time) * 1000
            logger.debug(f"Lazy-loaded adapter {name} in {elapsed:.1f}ms")
            # Use direct lookup to avoid recursion through LazyPluginRegistry.get()
            # Try both underscore and hyphenated variants since metadata.name may differ
            result = self.registry._plugins.get(name)
            if result is None:
                # Try hyphenated version (e.g., "dependency_check" -> "dependency-check")
                hyphenated_name = name.replace("_", "-")
                result = self.registry._plugins.get(hyphenated_name)
            return result
        except Exception as e:
            logger.warning(f"Failed to lazy-load adapter {name}: {e}")
            return None

    def get_available_adapters(self) -> list[str]:
        """List all available adapter names without loading them.

        Returns:
            List of adapter names that can be loaded
        """
        self._discover_adapter_paths()
        return list(self._adapter_paths.keys())

    def preload_profile(self, profile: str) -> int:
        """Preload all adapters needed for a scan profile.

        This batch-loads adapters for faster subsequent access during scans.
        Useful when you know which profile will be used upfront.

        Args:
            profile: Scan profile name ('fast', 'slim', 'balanced', 'deep')

        Returns:
            Number of adapters loaded

        Example:
            >>> loader.preload_profile('fast')  # Load 8 adapters at once
            8
        """
        # Import here to avoid circular import
        from scripts.core.tool_registry import PROFILE_TOOLS

        if profile not in PROFILE_TOOLS:
            logger.warning(f"Unknown profile: {profile}")
            return 0

        loaded_count = 0
        tools = PROFILE_TOOLS[profile]

        for tool_name in tools:
            # Handle special cases (binary name -> adapter name)
            adapter_name = self._tool_to_adapter_name(tool_name)

            if self.get_adapter(adapter_name) is not None:
                loaded_count += 1

        logger.info(
            f"Preloaded {loaded_count}/{len(tools)} adapters for {profile} profile"
        )
        return loaded_count

    def _tool_to_adapter_name(self, tool_name: str) -> str:
        """Convert tool binary name to adapter name.

        Some tools have different binary names than adapter names:
        - "afl++" -> "aflplusplus"
        - "dependency-check" -> "dependency_check"
        - "semgrep-secrets" -> "semgrep_secrets"
        - "trivy-rbac" -> "trivy_rbac"
        - "checkov-cicd" -> "checkov" (same adapter)

        Args:
            tool_name: Tool binary/command name

        Returns:
            Adapter name
        """
        # Special mappings from tool name to adapter name
        mappings = {
            "afl++": "aflplusplus",
            "dependency-check": "dependency_check",
            "semgrep-secrets": "semgrep_secrets",
            "trivy-rbac": "trivy_rbac",
            "checkov-cicd": "checkov",  # Uses same adapter
        }
        return mappings.get(tool_name, tool_name.replace("-", "_"))

    def _load_plugin(self, plugin_path: Path):
        """Load a single plugin file.

        Args:
            plugin_path: Path to plugin file

        Raises:
            ImportError: If plugin cannot be loaded
        """
        module_name = plugin_path.stem

        # Load module
        spec = importlib.util.spec_from_file_location(module_name, plugin_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load plugin: {plugin_path}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)

        # Find AdapterPlugin subclasses
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, AdapterPlugin)
                and attr is not AdapterPlugin
            ):

                # Get metadata
                if hasattr(attr, "_plugin_metadata"):
                    metadata = attr._plugin_metadata
                elif hasattr(attr, "metadata"):
                    # If using property, try to instantiate to get metadata
                    try:
                        instance = attr()
                        metadata = instance.metadata
                    except TypeError:
                        # Abstract class, skip
                        logger.warning(
                            f"Plugin {attr_name} missing metadata (abstract class)"
                        )
                        continue
                else:
                    logger.warning(f"Plugin {attr_name} missing metadata")
                    continue

                # Register
                self.registry.register(metadata.name, attr, metadata)
                logger.debug(f"Loaded plugin: {metadata.name} from {plugin_path}")
                return

        logger.warning(f"No AdapterPlugin subclass found in {plugin_path}")

    def reload_plugin(self, name: str) -> bool:
        """Reload a specific plugin (hot-reload for development).

        Args:
            name: Plugin name (e.g., 'trivy')

        Returns:
            True if reloaded, False if not found
        """
        # Find plugin file
        for search_path in self.search_paths:
            plugin_file = search_path / f"{name}_adapter.py"
            if plugin_file.exists():
                try:
                    # Unregister old plugin
                    self.registry.unregister(name)

                    # Remove from sys.modules to force reload
                    module_name = f"{name}_adapter"
                    if module_name in sys.modules:
                        del sys.modules[module_name]

                    # Reload
                    self._load_plugin(plugin_file)
                    logger.info(f"Reloaded plugin: {name}")
                    return True
                except Exception as e:
                    logger.error(f"Failed to reload plugin {name}: {e}")
                    return False

        logger.warning(f"Plugin not found: {name}")
        return False


class LazyPluginRegistry(PluginRegistry):
    """Registry with lazy loading support.

    Extends PluginRegistry to support on-demand loading of adapters.
    When an adapter is requested but not loaded, it triggers loading
    through the associated PluginLoader.
    """

    def __init__(self, loader: PluginLoader | None = None):
        """Initialize lazy registry.

        Args:
            loader: Plugin loader for lazy loading
        """
        super().__init__()
        self._loader = loader

    def set_loader(self, loader: PluginLoader) -> None:
        """Set the plugin loader for lazy loading.

        Args:
            loader: Plugin loader instance
        """
        self._loader = loader

    def get(self, name: str) -> type[AdapterPlugin] | None:
        """Get plugin class by name, lazy-loading if needed.

        Args:
            name: Plugin name

        Returns:
            Plugin class or None if not found
        """
        # Try cached first
        plugin = super().get(name)
        if plugin is not None:
            return plugin

        # Try lazy loading
        if self._loader is not None:
            return self._loader.get_adapter(name)

        return None

    def list_all_available(self) -> list[str]:
        """List all available adapters (loaded and discoverable).

        Returns:
            List of all adapter names that can be accessed
        """
        loaded = set(self.list_plugins())
        if self._loader is not None:
            available = set(self._loader.get_available_adapters())
            return sorted(loaded | available)
        return sorted(loaded)


# Global plugin registry (singleton) - now with lazy loading support
_global_registry = LazyPluginRegistry()
_global_loader = PluginLoader(_global_registry)
_global_registry.set_loader(_global_loader)


def get_plugin_registry() -> LazyPluginRegistry:
    """Get global plugin registry.

    Returns:
        Global plugin registry instance (with lazy loading support)
    """
    return _global_registry


def get_plugin_loader() -> PluginLoader:
    """Get global plugin loader.

    Returns:
        Global plugin loader instance
    """
    return _global_loader


def preload_profile(profile: str) -> int:
    """Preload adapters for a specific scan profile.

    This is useful when you know which profile will be used upfront
    and want to batch-load all required adapters for faster access.

    Args:
        profile: Profile name ('fast', 'slim', 'balanced', 'deep')

    Returns:
        Number of adapters loaded

    Example:
        >>> preload_profile('fast')  # Load 8 adapters for fast profile
        8
    """
    return _global_loader.preload_profile(profile)


def get_available_adapters() -> list[str]:
    """List all available adapter names without loading them.

    Returns:
        List of adapter names that can be loaded
    """
    return _global_loader.get_available_adapters()
