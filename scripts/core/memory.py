#!/usr/bin/env python3
"""
Memory System for JMo Security

Lightweight JSON-based persistent memory system for caching analysis patterns,
reducing repeated research, and speeding up common workflows by 30-60%.

Architecture:
    - Namespace-scoped storage (.jmo/memory/{namespace}/)
    - JSON-based (human-readable, easily editable)
    - Schema-validated (see .jmo/memory/schemas.json)
    - Automatic timestamping and versioning
    - Local-only (gitignored, no cloud sync)

Namespaces:
    - adapters/      Tool adapter patterns
    - compliance/    CWE → framework mappings
    - profiles/      Performance optimization history
    - target-types/  Multi-target scan patterns
    - refactoring/   Code refactoring decisions
    - security/      Security fix patterns

Usage:
    from scripts.core.memory import query_memory, store_memory

    # Query memory before analysis
    cached = query_memory("adapters", "snyk")
    if cached:
        print(f"Exit codes: {cached['exit_codes']}")
        # Use cached patterns

    # Store memory after analysis
    store_memory("adapters", "snyk", {
        "tool": "snyk",
        "output_format": "results[].vulnerabilities[]",
        "exit_codes": {"0": "clean", "1": "findings", "2": "error"}
    })

See Also:
    - .jmo/memory/README.md - User-facing memory guide
    - .jmo/memory/schemas.json - JSON schemas for all namespaces
    - dev-only/hybrid-implementation-files/07-memory-integration-guide.md
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Configure module logger
logger = logging.getLogger(__name__)

# Memory base directory
MEMORY_DIR = Path(".jmo/memory")

# Schemas file
SCHEMAS_FILE = MEMORY_DIR / "schemas.json"

# Valid namespaces
VALID_NAMESPACES = {
    "adapters",
    "compliance",
    "profiles",
    "target-types",
    "refactoring",
    "security",
}

# Cache loaded schemas
_SCHEMAS_CACHE: Optional[Dict[str, Any]] = None


class MemoryError(Exception):
    """Base exception for memory system errors."""

    pass


class InvalidNamespaceError(MemoryError):
    """Raised when an invalid namespace is provided."""

    pass


class InvalidKeyError(MemoryError):
    """Raised when an invalid memory key is provided."""

    pass


class ValidationError(MemoryError):
    """Raised when memory data fails schema validation."""

    pass


def _validate_namespace(namespace: str) -> None:
    """
    Validate memory namespace.

    Args:
        namespace: Namespace to validate

    Raises:
        InvalidNamespaceError: If namespace is invalid
    """
    if namespace not in VALID_NAMESPACES:
        raise InvalidNamespaceError(
            f"Invalid namespace '{namespace}'. "
            f"Valid namespaces: {', '.join(sorted(VALID_NAMESPACES))}"
        )


def _validate_key(key: str) -> None:
    """
    Validate memory key (filename-safe).

    Args:
        key: Memory key to validate

    Raises:
        InvalidKeyError: If key contains invalid characters
    """
    if not key:
        raise InvalidKeyError("Memory key cannot be empty")

    # Check for path traversal attempts
    if ".." in key or "/" in key or "\\" in key:
        raise InvalidKeyError(
            f"Invalid memory key '{key}': cannot contain path separators"
        )

    # Check for filesystem-unsafe characters
    unsafe_chars = set('<>:"|?*')
    if any(c in key for c in unsafe_chars):
        raise InvalidKeyError(f"Invalid memory key '{key}': contains unsafe characters")


def _load_schemas() -> Dict[str, Any]:
    """
    Load and cache JSON schemas from .jmo/memory/schemas.json.

    Returns:
        Dictionary of schemas by namespace

    Raises:
        FileNotFoundError: If schemas.json doesn't exist
        json.JSONDecodeError: If schemas.json is invalid
    """
    global _SCHEMAS_CACHE

    if _SCHEMAS_CACHE is not None:
        return _SCHEMAS_CACHE

    if not SCHEMAS_FILE.exists():
        logger.warning(f"Schemas file not found: {SCHEMAS_FILE}")
        _SCHEMAS_CACHE = {}
        return _SCHEMAS_CACHE

    try:
        schemas_data = json.loads(SCHEMAS_FILE.read_text(encoding="utf-8"))
        _SCHEMAS_CACHE = schemas_data.get("definitions", {})
        logger.debug(f"Loaded {len(_SCHEMAS_CACHE)} memory schemas")
        return _SCHEMAS_CACHE
    except json.JSONDecodeError as e:
        logger.error(f"Invalid schemas file {SCHEMAS_FILE}: {e}")
        _SCHEMAS_CACHE = {}
        return _SCHEMAS_CACHE


def _validate_data(namespace: str, data: Dict[str, Any]) -> None:
    """
    Validate memory data against JSON schema.

    Args:
        namespace: Memory namespace
        data: Data to validate

    Raises:
        ValidationError: If data doesn't match schema
    """
    try:
        import jsonschema
    except ImportError:
        logger.debug("jsonschema not available, skipping validation")
        return

    schemas = _load_schemas()
    if namespace not in schemas:
        logger.debug(
            f"No schema defined for namespace '{namespace}', skipping validation"
        )
        return

    schema = schemas[namespace]

    try:
        jsonschema.validate(instance=data, schema=schema)
        logger.debug(f"Memory data validated successfully for {namespace}")
    except jsonschema.ValidationError as e:
        raise ValidationError(
            f"Memory data for '{namespace}' failed schema validation: {e.message}"
        )


def query_memory(
    namespace: str, key: str, default: Optional[Dict[str, Any]] = None
) -> Optional[Dict[str, Any]]:
    """
    Query memory for cached pattern.

    Args:
        namespace: Memory namespace (adapters, compliance, profiles, etc.)
        key: Memory key (tool name, CWE ID, profile name, etc.)
        default: Default value to return if not found

    Returns:
        Cached data dict if found, default otherwise

    Raises:
        InvalidNamespaceError: If namespace is invalid
        InvalidKeyError: If key is invalid

    Example:
        >>> cached = query_memory("adapters", "snyk")
        >>> if cached:
        ...     print(f"Exit codes: {cached['exit_codes']}")
    """
    _validate_namespace(namespace)
    _validate_key(key)

    memory_file = MEMORY_DIR / namespace / f"{key}.json"

    if not memory_file.exists():
        return default

    try:
        data = json.loads(memory_file.read_text(encoding="utf-8"))

        # Log retrieval
        last_updated = data.get("last_updated", "unknown")
        logger.debug(f"Memory retrieved: {namespace}/{key} (updated: {last_updated})")

        return data

    except json.JSONDecodeError as e:
        logger.warning(f"Error parsing memory {namespace}/{key}: {e}")
        return default

    except (FileNotFoundError, IOError, OSError) as e:
        logger.warning(f"Error loading memory {namespace}/{key}: {e}")
        return default


def store_memory(
    namespace: str,
    key: str,
    data: Dict[str, Any],
    overwrite: bool = True,
    validate: bool = False,
) -> bool:
    """
    Store analysis patterns in memory.

    Args:
        namespace: Memory namespace
        key: Memory key
        data: Pattern data (must match schema from .jmo/memory/schemas.json)
        overwrite: If False, raise error if key already exists
        validate: If True, validate data against schema (requires jsonschema package, default: False)

    Returns:
        True if stored successfully, False otherwise

    Raises:
        InvalidNamespaceError: If namespace is invalid
        InvalidKeyError: If key is invalid
        FileExistsError: If key exists and overwrite=False
        ValidationError: If validation enabled and data doesn't match schema

    Example:
        >>> store_memory("adapters", "snyk", {
        ...     "tool": "snyk",
        ...     "output_format": "results[].vulnerabilities[]",
        ...     "exit_codes": {"0": "clean", "1": "findings", "2": "error"}
        ... })
        True
    """
    _validate_namespace(namespace)
    _validate_key(key)

    # Validate data against schema if requested
    if validate:
        _validate_data(namespace, data)

    memory_dir = MEMORY_DIR / namespace
    memory_file = memory_dir / f"{key}.json"

    # Check if file exists and overwrite is disabled
    if memory_file.exists() and not overwrite:
        raise FileExistsError(
            f"Memory key '{namespace}/{key}' already exists. "
            f"Use overwrite=True to replace."
        )

    # Ensure directory exists
    memory_dir.mkdir(parents=True, exist_ok=True)

    # Add timestamp if not present
    if "last_updated" not in data:
        data["last_updated"] = datetime.now().strftime("%Y-%m-%d")

    try:
        # Write JSON with nice formatting
        memory_file.write_text(
            json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8"
        )

        logger.debug(f"Memory stored: {namespace}/{key}")
        return True

    except (IOError, OSError, PermissionError) as e:
        logger.error(f"Error storing memory {namespace}/{key}: {e}")
        return False


def update_memory(
    namespace: str,
    key: str,
    updates: Dict[str, Any],
    create_if_missing: bool = False,
    validate: bool = False,
) -> bool:
    """
    Update existing memory entry (merge updates with existing data).

    Args:
        namespace: Memory namespace
        key: Memory key
        updates: Updates to merge into existing data
        create_if_missing: If True, create new entry if not found
        validate: If True, validate merged data against schema (default: False)

    Returns:
        True if updated successfully, False otherwise

    Raises:
        InvalidNamespaceError: If namespace is invalid
        InvalidKeyError: If key is invalid
        FileNotFoundError: If key doesn't exist and create_if_missing=False
        ValidationError: If validation enabled and merged data doesn't match schema

    Example:
        >>> update_memory("adapters", "snyk", {
        ...     "version": "1.1290.0",  # Update version
        ...     "common_pitfalls": ["New pitfall discovered"]  # Append
        ... })
        True
    """
    _validate_namespace(namespace)
    _validate_key(key)

    # Get existing data
    existing = query_memory(namespace, key)

    if existing is None:
        if not create_if_missing:
            raise FileNotFoundError(
                f"Memory key '{namespace}/{key}' not found. "
                f"Use create_if_missing=True to create."
            )
        # Create new entry
        return store_memory(namespace, key, updates, validate=validate)

    # Merge updates
    merged = {**existing, **updates}

    # Update timestamp
    merged["last_updated"] = datetime.now().strftime("%Y-%m-%d")

    return store_memory(namespace, key, merged, overwrite=True, validate=validate)


def list_memory(namespace: str, pattern: Optional[str] = None) -> List[str]:
    """
    List all memory keys in a namespace.

    Args:
        namespace: Memory namespace
        pattern: Optional glob pattern to filter keys (e.g., "cwe-*")

    Returns:
        List of memory keys (without .json extension)

    Raises:
        InvalidNamespaceError: If namespace is invalid

    Example:
        >>> list_memory("adapters")
        ['snyk', 'trivy', 'semgrep']

        >>> list_memory("compliance", pattern="cwe-*")
        ['cwe-79', 'cwe-89', 'cwe-502']
    """
    _validate_namespace(namespace)

    memory_dir = MEMORY_DIR / namespace

    if not memory_dir.exists():
        return []

    # Get all JSON files
    if pattern:
        files = memory_dir.glob(f"{pattern}.json")
    else:
        files = memory_dir.glob("*.json")

    # Return keys without .json extension, sorted
    return sorted([f.stem for f in files if f.is_file()])


def delete_memory(namespace: str, key: str) -> bool:
    """
    Delete memory entry.

    Args:
        namespace: Memory namespace
        key: Memory key

    Returns:
        True if deleted successfully, False if not found

    Raises:
        InvalidNamespaceError: If namespace is invalid
        InvalidKeyError: If key is invalid

    Example:
        >>> delete_memory("adapters", "deprecated-tool")
        True
    """
    _validate_namespace(namespace)
    _validate_key(key)

    memory_file = MEMORY_DIR / namespace / f"{key}.json"

    if not memory_file.exists():
        logger.debug(f"Memory key '{namespace}/{key}' not found (nothing to delete)")
        return False

    try:
        memory_file.unlink()
        logger.debug(f"Memory deleted: {namespace}/{key}")
        return True

    except (IOError, OSError, PermissionError) as e:
        logger.error(f"Error deleting memory {namespace}/{key}: {e}")
        return False


def clear_namespace(namespace: str, confirm: bool = False) -> int:
    """
    Clear all memory entries in a namespace (dangerous operation).

    Args:
        namespace: Memory namespace to clear
        confirm: Must be True to actually delete files

    Returns:
        Number of entries deleted

    Raises:
        InvalidNamespaceError: If namespace is invalid
        RuntimeError: If confirm is False

    Example:
        >>> # Dry run (safe)
        >>> clear_namespace("adapters")
        RuntimeError: Must pass confirm=True to delete

        >>> # Actual deletion
        >>> clear_namespace("adapters", confirm=True)
        3  # Deleted 3 entries
    """
    _validate_namespace(namespace)

    if not confirm:
        raise RuntimeError(
            f"Clearing namespace '{namespace}' requires confirm=True. "
            f"This will delete all memory entries!"
        )

    memory_dir = MEMORY_DIR / namespace

    if not memory_dir.exists():
        return 0

    count = 0
    for memory_file in memory_dir.glob("*.json"):
        if memory_file.is_file():
            try:
                memory_file.unlink()
                count += 1
            except (IOError, OSError, PermissionError) as e:
                logger.error(f"Error deleting {memory_file.name}: {e}")

    logger.info(f"Cleared {count} memory entries from {namespace}/")
    return count


def memory_stats() -> Dict[str, Any]:
    """
    Get memory system statistics.

    Returns:
        Dict with statistics for each namespace

    Example:
        >>> stats = memory_stats()
        >>> print(stats)
        {
            'adapters': {'count': 3, 'total_size_kb': 12.5},
            'compliance': {'count': 5, 'total_size_kb': 8.2},
            ...
        }
    """
    stats = {}

    for namespace in VALID_NAMESPACES:
        memory_dir = MEMORY_DIR / namespace

        if not memory_dir.exists():
            stats[namespace] = {"count": 0, "total_size_kb": 0.0}
            continue

        files = list(memory_dir.glob("*.json"))
        total_size = sum(f.stat().st_size for f in files if f.is_file())

        stats[namespace] = {
            "count": len(files),
            "total_size_kb": round(total_size / 1024, 2),
        }

    return stats


# Convenience function for checking if memory exists
def has_memory(namespace: str, key: str) -> bool:
    """
    Check if memory entry exists without loading it.

    Args:
        namespace: Memory namespace
        key: Memory key

    Returns:
        True if memory exists, False otherwise

    Example:
        >>> if has_memory("adapters", "snyk"):
        ...     print("Snyk patterns already cached")
    """
    _validate_namespace(namespace)
    _validate_key(key)

    return (MEMORY_DIR / namespace / f"{key}.json").exists()
