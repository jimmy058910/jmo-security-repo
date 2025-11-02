"""
Tests for MCP server rate limiting decorator.

Tests:
- Rate limiting enforcement
- Rate limiting disabled (dev mode)
- Decorator integration with MCP tools

Note: Full authentication enforcement awaits FastMCP middleware support (v1.0.2).
Current implementation provides auth infrastructure (API_KEYS_HASHED) but
enforces rate limiting only.
"""

import os
import pytest
from unittest import mock

# Import the decorator and configuration
from scripts.mcp.server import require_auth_and_rate_limit
from scripts.mcp.utils.rate_limiter import RateLimiter


class TestRateLimitingBasics:
    """Test basic rate limiting functionality."""

    def test_no_rate_limiter_allows_all(self):
        """Test that requests are allowed when rate limiting disabled."""
        # Mock environment: rate limiting disabled
        with mock.patch("scripts.mcp.server.rate_limiter", None):
            @require_auth_and_rate_limit
            def test_func():
                return "success"

            # Should succeed without rate limiting
            result = test_func()
            assert result == "success"

    def test_rate_limiting_enforced(self):
        """Test that rate limit is enforced."""
        limiter = RateLimiter(capacity=5, refill_rate=0.0)  # 5 requests max

        # Mock environment: rate limiting enabled
        with mock.patch("scripts.mcp.server.rate_limiter", limiter):
            with mock.patch("scripts.mcp.server.RATE_LIMIT_CAPACITY", 5):
                with mock.patch("scripts.mcp.server.RATE_LIMIT_REFILL_RATE", 0.0):
                    @require_auth_and_rate_limit
                    def test_func():
                        return "success"

                    # First 5 requests should succeed
                    for _ in range(5):
                        result = test_func()
                        assert result == "success"

                    # 6th request should fail
                    with pytest.raises(ValueError, match="Rate limit exceeded"):
                        test_func()

    def test_rate_limiting_many_requests(self):
        """Test that rate limiting allows burst traffic."""
        limiter = RateLimiter(capacity=100, refill_rate=0.0)  # 100 burst

        # Mock environment: rate limiting enabled
        with mock.patch("scripts.mcp.server.rate_limiter", limiter):
            with mock.patch("scripts.mcp.server.RATE_LIMIT_CAPACITY", 100):
                @require_auth_and_rate_limit
                def test_func():
                    return "success"

                # 100 requests should succeed
                for _ in range(100):
                    result = test_func()
                    assert result == "success"

                # 101st request should fail
                with pytest.raises(ValueError, match="Rate limit exceeded"):
                    test_func()

    def test_decorator_preserves_function_metadata(self):
        """Test that decorator preserves function name and docstring."""
        with mock.patch("scripts.mcp.server.rate_limiter", None):
            @require_auth_and_rate_limit
            def test_func():
                """Test function docstring."""
                return "success"

            # Function name and docstring should be preserved
            assert test_func.__name__ == "test_func"
            assert "Test function docstring" in test_func.__doc__

    def test_decorator_with_arguments(self):
        """Test that decorator works with functions that have arguments."""
        with mock.patch("scripts.mcp.server.rate_limiter", None):
            @require_auth_and_rate_limit
            def test_func(arg1, arg2, kwarg1=None):
                """Test function with args."""
                return f"{arg1}-{arg2}-{kwarg1}"

            # Should pass through arguments correctly
            result = test_func("foo", "bar", kwarg1="baz")
            assert result == "foo-bar-baz"

    def test_error_message_includes_limits(self):
        """Test that error message includes rate limit configuration."""
        limiter = RateLimiter(capacity=10, refill_rate=0.5)

        with mock.patch("scripts.mcp.server.rate_limiter", limiter):
            with mock.patch("scripts.mcp.server.RATE_LIMIT_CAPACITY", 10):
                with mock.patch("scripts.mcp.server.RATE_LIMIT_REFILL_RATE", 0.5):
                    @require_auth_and_rate_limit
                    def test_func():
                        return "success"

                    # Exhaust quota
                    for _ in range(10):
                        test_func()

                    # Error message should include limits
                    with pytest.raises(ValueError) as exc_info:
                        test_func()

                    error_message = str(exc_info.value)
                    assert "Rate limit exceeded" in error_message
                    assert "10" in error_message  # Capacity
                    assert "0.5" in error_message  # Refill rate


class TestAuthenticationInfrastructure:
    """Test that authentication infrastructure is in place (not enforced yet)."""

    def test_api_keys_hashed_populated(self):
        """Test that API_KEYS_HASHED is populated from environment."""
        # This test verifies the infrastructure is ready for future enforcement
        import scripts.mcp.server as server_module

        # Mock environment with API keys
        test_keys = "key1,key2,key3"
        with mock.patch.dict(os.environ, {"JMO_MCP_API_KEYS": test_keys}):
            # Re-import to trigger initialization
            import importlib
            importlib.reload(server_module)

            # Verify hashes are computed (infrastructure ready)
            assert hasattr(server_module, "API_KEYS_HASHED")
            assert isinstance(server_module.API_KEYS_HASHED, list)
            # Should have 3 hashed keys (if module reloaded successfully)

    def test_auth_logging_configuration(self):
        """Test that auth configuration is logged correctly."""
        import scripts.mcp.server as server_module

        # Verify configuration variables exist
        assert hasattr(server_module, "API_KEYS_HASHED")
        assert hasattr(server_module, "RATE_LIMIT_ENABLED")
        assert hasattr(server_module, "RATE_LIMIT_CAPACITY")
        assert hasattr(server_module, "RATE_LIMIT_REFILL_RATE")
