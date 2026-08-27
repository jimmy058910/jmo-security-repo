"""
Tests for the MCP server's rate-limit decorator and its ABSENT authentication.

What this file used to be, and why it changed
---------------------------------------------
It had seven tests and a class named ``TestAuthenticationInfrastructure``, and
not one of them called a decorated tool without a credential to see whether it
was refused. ``test_api_keys_hashed_populated`` reloaded the module with three
keys set and asserted only ``isinstance(API_KEYS_HASHED, list)`` -- its own
trailing comment said "Should have 3 hashed keys" and there was no assertion for
it. ``test_auth_logging_configuration`` was named for logging and checked four
attributes' *existence*. Neither could fail while the module imported.

Meanwhile the server logged ``Authentication: enabled`` whenever
``JMO_MCP_API_KEYS`` was set and then served every unauthenticated caller, and
``docs/KNOWN_LIMITATIONS.md`` told users in bold to read that line before
exposing the server.

The tests below are deliberately written to fail if authentication is ever
implemented. That is the point: the absence is currently load-bearing for three
user-facing documents, and whoever implements it must update them in the same
change.
"""

import logging
import os
from unittest import mock

import pytest

from scripts.jmo_mcp.jmo_server import require_rate_limit
from scripts.jmo_mcp.utils.rate_limiter import RateLimiter


class TestRateLimitingBasics:
    """Test basic rate limiting functionality."""

    def test_no_rate_limiter_allows_all(self):
        """Test that requests are allowed when rate limiting disabled."""
        with mock.patch("scripts.jmo_mcp.jmo_server.rate_limiter", None):

            @require_rate_limit
            def test_func():
                return "success"

            result = test_func()
            assert result == "success"

    def test_rate_limiting_enforced(self):
        """Test that rate limit is enforced."""
        limiter = RateLimiter(capacity=5, refill_rate=0.0)  # 5 requests max

        with mock.patch("scripts.jmo_mcp.jmo_server.rate_limiter", limiter):
            with mock.patch("scripts.jmo_mcp.jmo_server.RATE_LIMIT_CAPACITY", 5):
                with mock.patch(
                    "scripts.jmo_mcp.jmo_server.RATE_LIMIT_REFILL_RATE", 0.0
                ):

                    @require_rate_limit
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

        with mock.patch("scripts.jmo_mcp.jmo_server.rate_limiter", limiter):
            with mock.patch("scripts.jmo_mcp.jmo_server.RATE_LIMIT_CAPACITY", 100):

                @require_rate_limit
                def test_func():
                    return "success"

                for _ in range(100):
                    result = test_func()
                    assert result == "success"

                with pytest.raises(ValueError, match="Rate limit exceeded"):
                    test_func()

    def test_decorator_preserves_function_metadata(self):
        """Test that decorator preserves function name and docstring."""
        with mock.patch("scripts.jmo_mcp.jmo_server.rate_limiter", None):

            @require_rate_limit
            def test_func():
                """Test function docstring."""
                return "success"

            assert test_func.__name__ == "test_func"
            assert "Test function docstring" in test_func.__doc__

    def test_decorator_with_arguments(self):
        """Test that decorator works with functions that have arguments."""
        with mock.patch("scripts.jmo_mcp.jmo_server.rate_limiter", None):

            @require_rate_limit
            def test_func(arg1, arg2, kwarg1=None):
                """Test function with args."""
                return f"{arg1}-{arg2}-{kwarg1}"

            result = test_func("foo", "bar", kwarg1="baz")
            assert result == "foo-bar-baz"

    def test_error_message_includes_limits(self):
        """Test that error message includes rate limit configuration."""
        limiter = RateLimiter(capacity=10, refill_rate=0.5)

        with mock.patch("scripts.jmo_mcp.jmo_server.rate_limiter", limiter):
            with mock.patch("scripts.jmo_mcp.jmo_server.RATE_LIMIT_CAPACITY", 10):
                with mock.patch(
                    "scripts.jmo_mcp.jmo_server.RATE_LIMIT_REFILL_RATE", 0.5
                ):

                    @require_rate_limit
                    def test_func():
                        return "success"

                    for _ in range(10):
                        test_func()

                    with pytest.raises(ValueError) as exc_info:
                        test_func()

                    error_message = str(exc_info.value)
                    assert "Rate limit exceeded" in error_message
                    assert "10" in error_message  # Capacity
                    assert "0.5" in error_message  # Refill rate


class TestTheBucketIsSharedNotPerClient:
    """Unauthenticated callers share one bucket, and that is now the *fallback*.

    `docs/MCP_SETUP.md` once claimed "Separate buckets for each client", which
    was false: every request was charged to a hardcoded ``anonymous`` bucket, so
    a second caller's first ever request was denied once the first had drained
    the budget. Chunk 20 corrected the docs; #952 then made the accounting real
    -- ``require_rate_limit`` now keys on the request's authenticated principal
    when the transport supplies one.

    These tests are unchanged and still pass, because they call the decorated
    functions with **no auth context installed** -- which is exactly what stdio
    does. So they now pin the fallback rather than the whole behaviour. The
    per-principal half lives in ``test_rate_limit_identity.py``.
    """

    def test_a_second_caller_inherits_the_first_callers_exhausted_budget(self):
        limiter = RateLimiter(capacity=2, refill_rate=0.0)

        with mock.patch("scripts.jmo_mcp.jmo_server.rate_limiter", limiter):

            @require_rate_limit
            def alice():
                return "alice"

            @require_rate_limit
            def bob():
                return "bob"

            # Alice burns the whole budget.
            assert alice() == "alice"
            assert alice() == "alice"

            # Bob has never called anything. He is refused anyway.
            with pytest.raises(ValueError, match="Rate limit exceeded"):
                bob()

    def test_only_one_bucket_is_ever_created(self):
        limiter = RateLimiter(capacity=10, refill_rate=0.0)

        with mock.patch("scripts.jmo_mcp.jmo_server.rate_limiter", limiter):

            @require_rate_limit
            def one():
                return 1

            @require_rate_limit
            def two():
                return 2

            one()
            two()

            assert list(limiter.buckets.keys()) == ["anonymous"], (
                "More than one bucket means per-client accounting arrived. "
                "Update docs/MCP_SETUP.md's rate-limiting section, which "
                "documents the shared bucket, and the require_rate_limit "
                "docstring."
            )


class TestAuthenticationIsNotEnforced:
    """Characterization tests for an access control that does not exist.

    These assert the *absence*. If authentication is implemented, they go red --
    which is the intended signal, because three user-facing documents currently
    describe the server as unauthenticated and must change with it:
    ``docs/KNOWN_LIMITATIONS.md``, ``docs/MCP_SETUP.md``, and the
    ``jmo mcp-server --help`` description in ``scripts/cli/jmo.py``.
    """

    def test_keys_are_hashed_but_never_compared(self, monkeypatch):
        """API_KEYS_HASHED is populated -- and referenced by no other code."""
        import importlib
        import inspect

        import scripts.jmo_mcp.jmo_server as server_module

        monkeypatch.setenv("JMO_MCP_API_KEYS", "key1,key2,key3")
        importlib.reload(server_module)
        try:
            # The count its predecessor's comment claimed and never asserted.
            assert len(server_module.API_KEYS_HASHED) == 3
            assert all(len(h) == 64 for h in server_module.API_KEYS_HASHED)

            # The decorator body must not consult them. This is the assertion
            # the old `test_auth.py` was missing entirely.
            decorator_src = inspect.getsource(server_module.require_rate_limit)
            assert "API_KEYS_HASHED" not in decorator_src.split('"""')[-1], (
                "The rate-limit decorator now references API_KEYS_HASHED. If "
                "authentication is enforced, rename it, drop this test, and "
                "update KNOWN_LIMITATIONS.md / MCP_SETUP.md / the CLI help."
            )
        finally:
            monkeypatch.delenv("JMO_MCP_API_KEYS", raising=False)
            importlib.reload(server_module)

    def test_a_caller_with_no_credential_is_served_even_with_keys_set(
        self, monkeypatch, mcp_env_with_findings
    ):
        """The whole point. Keys configured; unauthenticated call still served."""
        import importlib

        import scripts.jmo_mcp.jmo_server as server_module

        monkeypatch.setenv("JMO_MCP_API_KEYS", "supersecret")
        monkeypatch.setenv("JMO_MCP_RATE_LIMIT_ENABLED", "false")
        importlib.reload(server_module)
        try:
            info = server_module.get_server_info()
            assert info["total_findings"] >= 0
            assert info["authentication_enforced"] is False, (
                "get_server_info now reports authentication as enforced. "
                "Update the three user-facing documents named in this class's "
                "docstring in the same change."
            )
        finally:
            importlib.reload(server_module)

    def test_startup_never_claims_authentication_is_enabled(self, monkeypatch, caplog):
        """The log line KNOWN_LIMITATIONS.md tells users to read.

        It said ``Authentication: enabled`` while enforcing nothing. A security
        signal that reads positive for a control that does not exist is worse
        than no signal: it ends the reader's investigation with a confirmation.
        """
        import importlib

        import scripts.jmo_mcp.jmo_server as server_module

        monkeypatch.setenv("JMO_MCP_API_KEYS", "supersecret")
        with caplog.at_level(logging.INFO, logger="scripts.jmo_mcp.jmo_server"):
            importlib.reload(server_module)
        try:
            auth_lines = [
                r.getMessage()
                for r in caplog.records
                if "Authentication:" in r.getMessage()
            ]
            assert auth_lines, "no Authentication: line was logged at startup"
            line = auth_lines[-1]

            assert "NOT ENFORCED" in line
            assert line != "Authentication: enabled"
            # It must be a warning, not an info line, when keys are configured:
            # the user asked for a control they are not getting.
            warned = [
                r
                for r in caplog.records
                if "Authentication:" in r.getMessage() and r.levelno >= logging.WARNING
            ]
            assert warned, "keys configured but the notice was not a warning"
        finally:
            monkeypatch.delenv("JMO_MCP_API_KEYS", raising=False)
            importlib.reload(server_module)

    def test_startup_without_keys_does_not_call_itself_dev_mode(
        self, monkeypatch, caplog
    ):
        """'disabled (dev mode)' implied a non-dev mode that enforces. None exists."""
        import importlib

        import scripts.jmo_mcp.jmo_server as server_module

        monkeypatch.delenv("JMO_MCP_API_KEYS", raising=False)
        with caplog.at_level(logging.INFO, logger="scripts.jmo_mcp.jmo_server"):
            importlib.reload(server_module)

        auth_lines = [
            r.getMessage()
            for r in caplog.records
            if "Authentication:" in r.getMessage()
        ]
        assert auth_lines
        assert "dev mode" not in auth_lines[-1]
        assert "not enforced" in auth_lines[-1].lower()

    def test_api_keys_bind_at_import_not_at_call(self, monkeypatch):
        """Setting JMO_MCP_API_KEYS after import has no effect.

        Documented in the module and asserted here so the binding is a decision
        rather than a surprise.
        """
        import importlib

        import scripts.jmo_mcp.jmo_server as server_module

        monkeypatch.delenv("JMO_MCP_API_KEYS", raising=False)
        importlib.reload(server_module)
        assert server_module.API_KEYS_HASHED == []

        os.environ["JMO_MCP_API_KEYS"] = "set-after-import"
        try:
            assert server_module.API_KEYS_HASHED == [], (
                "API_KEYS_HASHED now tracks the environment at call time. "
                "Drop the module-level 'Bound at MODULE IMPORT' note."
            )
        finally:
            os.environ.pop("JMO_MCP_API_KEYS", None)
            importlib.reload(server_module)
