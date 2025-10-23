#!/usr/bin/env python3
"""
Tests for Memory System (scripts/core/memory.py)

Test Coverage:
    - Query operations (exists, not exists, malformed JSON)
    - Store operations (new, overwrite, no-overwrite)
    - Update operations (merge, create-if-missing)
    - List operations (all, pattern matching)
    - Delete operations (single, namespace clear)
    - Validation (invalid namespace, invalid key, path traversal)
    - Statistics and utilities (has_memory, memory_stats)

Target Coverage: ≥85%
"""

import json
import pytest
from pathlib import Path
from scripts.core.memory import (
    query_memory,
    store_memory,
    update_memory,
    list_memory,
    delete_memory,
    clear_namespace,
    memory_stats,
    has_memory,
    InvalidNamespaceError,
    InvalidKeyError,
    VALID_NAMESPACES,
)


# Fixtures
@pytest.fixture
def memory_dir(tmp_path, monkeypatch):
    """Create temporary memory directory for testing."""
    test_memory = tmp_path / ".jmo" / "memory"
    test_memory.mkdir(parents=True, exist_ok=True)

    # Create namespace directories
    for namespace in VALID_NAMESPACES:
        (test_memory / namespace).mkdir(parents=True, exist_ok=True)

    # Patch MEMORY_DIR to use temp directory
    monkeypatch.setattr("scripts.core.memory.MEMORY_DIR", test_memory)

    return test_memory


@pytest.fixture
def sample_adapter_data():
    """Sample adapter memory data."""
    return {
        "tool": "snyk",
        "version": "1.1290.0",
        "output_format": "results[].vulnerabilities[]",
        "exit_codes": {"0": "clean", "1": "findings", "2": "error"},
        "common_pitfalls": ["Requires auth token", "Large repos timeout"],
        "test_fixtures": ['{"results": [{"vulnerabilities": [{"id": "TEST-001"}]}]}'],
    }


@pytest.fixture
def sample_compliance_data():
    """Sample compliance memory data."""
    return {
        "cwe_id": "CWE-79",
        "cwe_name": "Cross-site Scripting (XSS)",
        "frameworks": {
            "owasp_top10_2021": ["A03:2021"],
            "cwe_top25_2024": [{"rank": 2, "category": "Injection"}],
            "nist_csf_2_0": ["PR.DS-5"],
        },
        "rationale": "CWE-79 enables injection attacks by allowing unvalidated input",
    }


# Test: Query Operations
class TestQueryMemory:
    """Test memory query functionality."""

    def test_query_existing_memory(self, memory_dir, sample_adapter_data):
        """Test querying existing memory entry."""
        # Store data
        store_memory("adapters", "snyk", sample_adapter_data)

        # Query it back
        result = query_memory("adapters", "snyk")

        assert result is not None
        assert result["tool"] == "snyk"
        assert result["version"] == "1.1290.0"
        assert "last_updated" in result

    def test_query_nonexistent_memory(self, memory_dir):
        """Test querying non-existent memory entry."""
        result = query_memory("adapters", "nonexistent")
        assert result is None

    def test_query_with_default(self, memory_dir):
        """Test querying with default value."""
        default = {"tool": "default"}
        result = query_memory("adapters", "nonexistent", default=default)
        assert result == default

    def test_query_malformed_json(self, memory_dir):
        """Test querying memory with malformed JSON."""
        # Create malformed JSON file
        memory_file = memory_dir / "adapters" / "broken.json"
        memory_file.write_text("{ invalid json }")

        result = query_memory("adapters", "broken")
        assert result is None

    def test_query_invalid_namespace(self, memory_dir):
        """Test querying with invalid namespace."""
        with pytest.raises(InvalidNamespaceError):
            query_memory("invalid_namespace", "test")

    def test_query_invalid_key_path_traversal(self, memory_dir):
        """Test querying with path traversal attempt."""
        with pytest.raises(InvalidKeyError):
            query_memory("adapters", "../etc/passwd")

    def test_query_invalid_key_empty(self, memory_dir):
        """Test querying with empty key."""
        with pytest.raises(InvalidKeyError):
            query_memory("adapters", "")


# Test: Store Operations
class TestStoreMemory:
    """Test memory storage functionality."""

    def test_store_new_memory(self, memory_dir, sample_adapter_data):
        """Test storing new memory entry."""
        result = store_memory("adapters", "snyk", sample_adapter_data)

        assert result is True

        # Verify file exists
        memory_file = memory_dir / "adapters" / "snyk.json"
        assert memory_file.exists()

        # Verify content
        stored_data = json.loads(memory_file.read_text())
        assert stored_data["tool"] == "snyk"
        assert "last_updated" in stored_data

    def test_store_overwrite_existing(self, memory_dir, sample_adapter_data):
        """Test overwriting existing memory entry."""
        # Store initial data
        store_memory("adapters", "snyk", sample_adapter_data)

        # Update data
        updated_data = {**sample_adapter_data, "version": "2.0.0"}
        result = store_memory("adapters", "snyk", updated_data, overwrite=True)

        assert result is True

        # Verify updated
        stored = query_memory("adapters", "snyk")
        assert stored["version"] == "2.0.0"

    def test_store_no_overwrite_raises(self, memory_dir, sample_adapter_data):
        """Test storing with overwrite=False raises error if exists."""
        # Store initial data
        store_memory("adapters", "snyk", sample_adapter_data)

        # Attempt to store again with overwrite=False
        with pytest.raises(FileExistsError):
            store_memory("adapters", "snyk", sample_adapter_data, overwrite=False)

    def test_store_auto_timestamp(self, memory_dir):
        """Test automatic timestamp addition."""
        data = {"tool": "test"}
        store_memory("adapters", "test", data)

        stored = query_memory("adapters", "test")
        assert "last_updated" in stored
        assert len(stored["last_updated"]) == 10  # YYYY-MM-DD

    def test_store_creates_namespace_dir(self, memory_dir, tmp_path, monkeypatch):
        """Test store creates namespace directory if missing."""
        # Remove namespace directory
        (memory_dir / "adapters").rmdir()

        # Store should recreate it
        store_memory("adapters", "test", {"tool": "test"})

        assert (memory_dir / "adapters").exists()

    def test_store_invalid_namespace(self, memory_dir):
        """Test storing with invalid namespace."""
        with pytest.raises(InvalidNamespaceError):
            store_memory("invalid", "test", {})

    def test_store_invalid_key_unsafe_chars(self, memory_dir):
        """Test storing with unsafe characters in key."""
        with pytest.raises(InvalidKeyError):
            store_memory("adapters", "test<>key", {})


# Test: Update Operations
class TestUpdateMemory:
    """Test memory update functionality."""

    def test_update_existing_memory(self, memory_dir, sample_adapter_data):
        """Test updating existing memory entry."""
        # Store initial data
        store_memory("adapters", "snyk", sample_adapter_data)

        # Update version
        result = update_memory("adapters", "snyk", {"version": "2.0.0"})

        assert result is True

        # Verify merge
        updated = query_memory("adapters", "snyk")
        assert updated["version"] == "2.0.0"
        assert updated["tool"] == "snyk"  # Original field preserved

    def test_update_nonexistent_raises(self, memory_dir):
        """Test updating non-existent entry raises error."""
        with pytest.raises(FileNotFoundError):
            update_memory("adapters", "nonexistent", {"version": "1.0"})

    def test_update_create_if_missing(self, memory_dir):
        """Test updating with create_if_missing creates entry."""
        result = update_memory(
            "adapters",
            "new_tool",
            {"tool": "new_tool", "version": "1.0"},
            create_if_missing=True,
        )

        assert result is True

        # Verify created
        created = query_memory("adapters", "new_tool")
        assert created["tool"] == "new_tool"


# Test: List Operations
class TestListMemory:
    """Test memory listing functionality."""

    def test_list_all_keys(self, memory_dir):
        """Test listing all keys in namespace."""
        # Store multiple entries
        store_memory("adapters", "snyk", {"tool": "snyk"})
        store_memory("adapters", "trivy", {"tool": "trivy"})
        store_memory("adapters", "semgrep", {"tool": "semgrep"})

        keys = list_memory("adapters")

        assert len(keys) == 3
        assert "snyk" in keys
        assert "trivy" in keys
        assert "semgrep" in keys

    def test_list_with_pattern(self, memory_dir):
        """Test listing keys with glob pattern."""
        # Store multiple compliance entries
        store_memory("compliance", "cwe-79", {"cwe_id": "CWE-79"})
        store_memory("compliance", "cwe-89", {"cwe_id": "CWE-89"})
        store_memory("compliance", "owasp-a03", {"framework": "OWASP"})

        # List only CWE entries
        cwe_keys = list_memory("compliance", pattern="cwe-*")

        assert len(cwe_keys) == 2
        assert "cwe-79" in cwe_keys
        assert "cwe-89" in cwe_keys
        assert "owasp-a03" not in cwe_keys

    def test_list_empty_namespace(self, memory_dir):
        """Test listing empty namespace."""
        keys = list_memory("adapters")
        assert keys == []

    def test_list_nonexistent_namespace_dir(self, memory_dir):
        """Test listing namespace without directory."""
        # Remove directory
        (memory_dir / "adapters").rmdir()

        keys = list_memory("adapters")
        assert keys == []

    def test_list_invalid_namespace(self, memory_dir):
        """Test listing with invalid namespace."""
        with pytest.raises(InvalidNamespaceError):
            list_memory("invalid")


# Test: Delete Operations
class TestDeleteMemory:
    """Test memory deletion functionality."""

    def test_delete_existing_memory(self, memory_dir):
        """Test deleting existing memory entry."""
        # Store entry
        store_memory("adapters", "snyk", {"tool": "snyk"})

        # Delete it
        result = delete_memory("adapters", "snyk")

        assert result is True
        assert not has_memory("adapters", "snyk")

    def test_delete_nonexistent_returns_false(self, memory_dir):
        """Test deleting non-existent entry returns False."""
        result = delete_memory("adapters", "nonexistent")
        assert result is False

    def test_delete_invalid_namespace(self, memory_dir):
        """Test deleting with invalid namespace."""
        with pytest.raises(InvalidNamespaceError):
            delete_memory("invalid", "test")


# Test: Clear Namespace
class TestClearNamespace:
    """Test namespace clearing functionality."""

    def test_clear_namespace_requires_confirm(self, memory_dir):
        """Test clear namespace requires confirm=True."""
        # Store entries
        store_memory("adapters", "snyk", {"tool": "snyk"})

        # Attempt to clear without confirm
        with pytest.raises(RuntimeError):
            clear_namespace("adapters")

    def test_clear_namespace_with_confirm(self, memory_dir):
        """Test clearing namespace with confirm."""
        # Store multiple entries
        store_memory("adapters", "snyk", {"tool": "snyk"})
        store_memory("adapters", "trivy", {"tool": "trivy"})
        store_memory("adapters", "semgrep", {"tool": "semgrep"})

        # Clear namespace
        count = clear_namespace("adapters", confirm=True)

        assert count == 3
        assert list_memory("adapters") == []

    def test_clear_empty_namespace(self, memory_dir):
        """Test clearing empty namespace."""
        count = clear_namespace("adapters", confirm=True)
        assert count == 0

    def test_clear_invalid_namespace(self, memory_dir):
        """Test clearing with invalid namespace."""
        with pytest.raises(InvalidNamespaceError):
            clear_namespace("invalid", confirm=True)


# Test: Statistics and Utilities
class TestMemoryStats:
    """Test memory statistics functionality."""

    def test_memory_stats_all_namespaces(self, memory_dir):
        """Test memory_stats returns all namespaces."""
        # Store entries in multiple namespaces
        store_memory("adapters", "snyk", {"tool": "snyk"})
        store_memory("compliance", "cwe-79", {"cwe_id": "CWE-79"})

        stats = memory_stats()

        assert "adapters" in stats
        assert "compliance" in stats
        assert stats["adapters"]["count"] == 1
        assert stats["compliance"]["count"] == 1

    def test_memory_stats_empty_namespaces(self, memory_dir):
        """Test memory_stats handles empty namespaces."""
        stats = memory_stats()

        for namespace in VALID_NAMESPACES:
            assert stats[namespace]["count"] == 0
            assert stats[namespace]["total_size_kb"] == 0.0

    def test_has_memory_true(self, memory_dir):
        """Test has_memory returns True for existing entry."""
        store_memory("adapters", "snyk", {"tool": "snyk"})
        assert has_memory("adapters", "snyk") is True

    def test_has_memory_false(self, memory_dir):
        """Test has_memory returns False for non-existent entry."""
        assert has_memory("adapters", "nonexistent") is False

    def test_has_memory_invalid_namespace(self, memory_dir):
        """Test has_memory with invalid namespace."""
        with pytest.raises(InvalidNamespaceError):
            has_memory("invalid", "test")


# Test: Edge Cases
class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_concurrent_writes_same_key(self, memory_dir):
        """Test concurrent writes to same key (last write wins)."""
        # Simulate concurrent writes
        store_memory("adapters", "snyk", {"version": "1.0"})
        store_memory("adapters", "snyk", {"version": "2.0"})

        result = query_memory("adapters", "snyk")
        assert result["version"] == "2.0"

    def test_unicode_in_data(self, memory_dir):
        """Test storing and retrieving unicode data."""
        data = {
            "tool": "test",
            "description": "Unicode: 中文, Emoji: 🔒, Special: \u00e9",
        }

        store_memory("adapters", "unicode-test", data)
        result = query_memory("adapters", "unicode-test")

        assert result["description"] == data["description"]

    def test_large_data_storage(self, memory_dir):
        """Test storing large data structures."""
        large_data = {
            "tool": "test",
            "findings": [
                {"id": f"FINDING-{i:04d}", "severity": "HIGH"} for i in range(1000)
            ],
        }

        result = store_memory("adapters", "large-test", large_data)
        assert result is True

        retrieved = query_memory("adapters", "large-test")
        assert len(retrieved["findings"]) == 1000

    def test_special_characters_in_key(self, memory_dir):
        """Test keys with special (but valid) characters."""
        # Valid: alphanumeric, dash, underscore, dot
        valid_keys = ["tool-name", "tool_name", "tool.name", "tool123"]

        for key in valid_keys:
            result = store_memory("adapters", key, {"tool": key})
            assert result is True

    def test_path_traversal_attempts(self, memory_dir):
        """Test various path traversal attempts are blocked."""
        malicious_keys = [
            "../etc/passwd",
            "..\\..\\windows\\system32",
            "test/../../../etc/passwd",
            "test/../../file",
        ]

        for key in malicious_keys:
            with pytest.raises(InvalidKeyError):
                store_memory("adapters", key, {})


# Test: Integration Scenarios
class TestIntegrationScenarios:
    """Test realistic integration scenarios."""

    def test_adapter_workflow(self, memory_dir, sample_adapter_data):
        """Test complete adapter memory workflow."""
        # Step 1: Check if memory exists
        assert not has_memory("adapters", "snyk")

        # Step 2: Store initial research
        store_memory("adapters", "snyk", sample_adapter_data)

        # Step 3: Query for subsequent use
        cached = query_memory("adapters", "snyk")
        assert cached["tool"] == "snyk"

        # Step 4: Update with new version
        update_memory("adapters", "snyk", {"version": "2.0.0"})

        # Step 5: Verify update
        updated = query_memory("adapters", "snyk")
        assert updated["version"] == "2.0.0"
        assert updated["output_format"] == sample_adapter_data["output_format"]

    def test_compliance_workflow(self, memory_dir, sample_compliance_data):
        """Test complete compliance memory workflow."""
        # Map CWE-79
        store_memory("compliance", "cwe-79", sample_compliance_data)

        # Query for report generation
        mapping = query_memory("compliance", "cwe-79")
        assert "frameworks" in mapping
        assert "A03:2021" in mapping["frameworks"]["owasp_top10_2021"]

        # List all compliance mappings
        all_cwes = list_memory("compliance", pattern="cwe-*")
        assert "cwe-79" in all_cwes

    def test_profile_optimization_workflow(self, memory_dir):
        """Test profile optimization memory workflow."""
        # Store optimization results
        optimization_data = {
            "profile": "balanced",
            "original_duration": 900,
            "optimized_duration": 450,
            "speedup_percent": 50,
            "changes": ["Increased threads: 4 → 8", "Reduced timeout: 600s → 300s"],
        }

        store_memory("profiles", "balanced-optimization", optimization_data)

        # Query for future optimizations
        previous = query_memory("profiles", "balanced-optimization")
        assert previous["speedup_percent"] == 50


# Test: Coverage Edge Cases
class TestCoverageEdgeCases:
    """Additional tests to reach ≥85% coverage."""

    def test_query_memory_exception_handling(self, memory_dir, monkeypatch):
        """Test query_memory handles generic exceptions."""
        # Create valid file
        store_memory("adapters", "test", {"tool": "test"})

        # Mock read_text to raise exception
        def mock_read_text(*args, **kwargs):
            raise PermissionError("Access denied")

        monkeypatch.setattr(Path, "read_text", mock_read_text)

        result = query_memory("adapters", "test")
        assert result is None

    def test_store_memory_exception_handling(self, memory_dir, monkeypatch):
        """Test store_memory handles write exceptions."""

        # Mock write_text to raise exception
        def mock_write_text(*args, **kwargs):
            raise PermissionError("Access denied")

        monkeypatch.setattr(Path, "write_text", mock_write_text)

        result = store_memory("adapters", "test", {"tool": "test"})
        assert result is False

    def test_delete_memory_exception_handling(self, memory_dir, monkeypatch):
        """Test delete_memory handles unlink exceptions."""
        # Create file
        store_memory("adapters", "test", {"tool": "test"})

        # Mock unlink to raise exception
        def mock_unlink(*args, **kwargs):
            raise PermissionError("Access denied")

        monkeypatch.setattr(Path, "unlink", mock_unlink)

        result = delete_memory("adapters", "test")
        assert result is False

    def test_clear_namespace_partial_failure(self, memory_dir, monkeypatch):
        """Test clear_namespace continues after individual file errors."""
        # Create multiple files
        store_memory("adapters", "test1", {"tool": "test1"})
        store_memory("adapters", "test2", {"tool": "test2"})

        # Mock unlink to fail for first file only
        original_unlink = Path.unlink
        call_count = [0]

        def mock_unlink(self, *args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise PermissionError("Access denied")
            return original_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", mock_unlink)

        # Should delete test2 even if test1 fails
        count = clear_namespace("adapters", confirm=True)
        assert count == 1  # Only test2 deleted


if __name__ == "__main__":
    pytest.main(
        [__file__, "-v", "--cov=scripts.core.memory", "--cov-report=term-missing"]
    )
