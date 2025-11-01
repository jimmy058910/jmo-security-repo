"""Plugin loader for auto-discovery and hot-reload (INTERNAL USE).

This module provides plugin discovery and loading functionality for
JMo Security's internal adapter architecture. Features:

1. Auto-discovery from multiple search paths
2. Hot-reload support for development iteration
3. Plugin registry for tracking loaded adapters
4. Version compatibility validation

Search order:
1. ~/.jmo/adapters/ (user adapters - hot-loadable)
2. scripts/core/adapters/ (built-in adapters)
"""

import importlib.util
import sys
from pathlib import Path
from typing import Dict, List, Type, Optional
import logging

from scripts.core.plugin_api import AdapterPlugin, PluginMetadata


logger = logging.getLogger(__name__)


class PluginRegistry:
    """Registry of loaded adapter plugins.

    Maintains a central registry of all discovered and loaded plugins,
    providing lookup and metadata access.
    """

    def __init__(self):
        """Initialize empty plugin registry."""
        self._plugins: Dict[str, Type[AdapterPlugin]] = {}
        self._metadata: Dict[str, PluginMetadata] = {}

    def register(
        self, name: str, plugin_class: Type[AdapterPlugin], metadata: PluginMetadata
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

    def get(self, name: str) -> Optional[Type[AdapterPlugin]]:
        """Get plugin class by name.

        Args:
            name: Plugin name

        Returns:
            Plugin class or None if not found
        """
        return self._plugins.get(name)

    def get_metadata(self, name: str) -> Optional[PluginMetadata]:
        """Get plugin metadata by name.

        Args:
            name: Plugin name

        Returns:
            Plugin metadata or None if not found
        """
        return self._metadata.get(name)

    def list_plugins(self) -> List[str]:
        """List all registered plugin names.

        Returns:
            List of plugin names
        """
        return list(self._plugins.keys())

    def get_all_metadata(self) -> Dict[str, PluginMetadata]:
        """Get metadata for all plugins.

        Returns:
            Dictionary mapping plugin names to metadata
        """
        return self._metadata.copy()


class PluginLoader:
    """Load adapter plugins from multiple search paths.

    Search order:
    1. ~/.jmo/adapters/ (user adapters - hot-loadable)
    2. scripts/core/adapters/ (built-in adapters)

    Plugins are discovered by globbing for *_adapter.py files and
    loading AdapterPlugin subclasses from them.
    """

    def __init__(self, registry: Optional[PluginRegistry] = None):
        """Initialize plugin loader.

        Args:
            registry: Plugin registry (creates new if None)
        """
        self.registry = registry or PluginRegistry()
        self.search_paths = [
            Path.home() / ".jmo" / "adapters",  # User adapters (hot-reload)
            Path(__file__).parent / "adapters",  # Built-in adapters
        ]

    def discover_plugins(self) -> int:
        """Discover and load all plugins from search paths.

        Returns:
            Number of plugins loaded
        """
        loaded_count = 0

        for search_path in self.search_paths:
            if not search_path.exists():
                logger.debug(f"Search path does not exist: {search_path}")
                continue

            for plugin_file in search_path.glob("*_adapter.py"):
                # Skip base_adapter.py (abstract base class, not a plugin)
                if plugin_file.name == "base_adapter.py":
                    continue
                try:
                    self._load_plugin(plugin_file)
                    loaded_count += 1
                except Exception as e:
                    logger.warning(f"Failed to load plugin {plugin_file.name}: {e}")

        logger.info(f"Loaded {loaded_count} adapter plugins")
        return loaded_count

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


# Global plugin registry (singleton)
_global_registry = PluginRegistry()
_global_loader = PluginLoader(_global_registry)


def get_plugin_registry() -> PluginRegistry:
    """Get global plugin registry.

    Returns:
        Global plugin registry instance
    """
    return _global_registry


def get_plugin_loader() -> PluginLoader:
    """Get global plugin loader.

    Returns:
        Global plugin loader instance
    """
    return _global_loader


def discover_adapters() -> int:
    """Discover and load all adapter plugins.

    Call this once at startup or when you need to refresh plugin list.

    Returns:
        Number of plugins loaded
    """
    return _global_loader.discover_plugins()
