"""The rate limiter must charge each caller its own budget (#952).

`require_rate_limit` charged every request to one hardcoded bucket:

    client_id = _SHARED_BUCKET_ID   # "anonymous"

Measured end to end: with `capacity=2`, one caller spent both tokens and a
second caller was refused on its **first ever** request.

The issue said a real fix "needs a transport that supplies caller identity" and
that until then this was "a documented property, not a bug to patch". That is
**measured out of date for mcp 2.0**, which is what this repo pins:

    mcp.server.auth.middleware.auth_context.get_access_token()   <- a contextvar
    mcp.server.auth.provider.principal_components(token)
        -> (client_id, issuer, subject)

`get_access_token()` reads a `ContextVar`, so it is callable from inside the
decorator with no signature change and no request object threaded through. It
returns `None` on an unauthenticated transport -- which stdio is -- so the
shared bucket stops being a hardcoded constant and becomes the honest fallback
for "this transport carries no identity".

Under stdio the observable behaviour is unchanged, and correctly so: each
client spawns its own server subprocess, so one bucket per process *is* one
bucket per client. What changes is that the accounting is derived rather than
asserted, and that it becomes genuinely per-principal the moment a transport
supplies one -- `mcp.server` ships `sse`, `streamable_http` and
`streamable_http_manager`, so that is a configuration away, not a rewrite.

The bucket key is the (client_id, issuer, subject) triple, never the token
itself: `require_rate_limit` logs the client id at DEBUG, and a bearer token in
a log line would be a worse bug than the one being fixed.
"""

from __future__ import annotations

from unittest import mock

import pytest

from scripts.jmo_mcp.jmo_server import _SHARED_BUCKET_ID, require_rate_limit
from scripts.jmo_mcp.utils.rate_limiter import RateLimiter


def _authenticated_as(client_id: str, subject: str | None = None):
    """Context manager putting an authenticated principal in the contextvar.

    Uses mcp's own `AuthenticatedUser` and `AccessToken` rather than a stub, so
    the test exercises the real shape the runtime installs.
    """
    from mcp.server.auth.middleware.auth_context import (
        AuthenticatedUser,
        auth_context_var,
    )
    from mcp.server.auth.provider import AccessToken

    token = AccessToken(
        token="secret-bearer-value",
        client_id=client_id,
        scopes=[],
        subject=subject,
    )
    return _ContextVarToken(auth_context_var, AuthenticatedUser(token))


class _ContextVarToken:
    def __init__(self, var, value):
        self._var = var
        self._value = value
        self._token = None

    def __enter__(self):
        self._token = self._var.set(self._value)
        return self

    def __exit__(self, *_exc):
        self._var.reset(self._token)
        return False


@pytest.fixture
def limiter():
    """A two-token bucket, patched in for the duration of a test."""
    lim = RateLimiter(capacity=2, refill_rate=0.0)
    with mock.patch("scripts.jmo_mcp.jmo_server.rate_limiter", lim):
        yield lim


# ---------------------------------------------------------------------------
# The bug, stated as a property.
# ---------------------------------------------------------------------------


def test_two_principals_do_not_share_a_budget(limiter: RateLimiter) -> None:
    """One caller exhausting its budget must not deny a different caller."""

    @require_rate_limit
    def tool():
        return "ok"

    with _authenticated_as("alice"):
        assert tool() == "ok"
        assert tool() == "ok"
        with pytest.raises(ValueError, match="Rate limit exceeded"):
            tool()

    with _authenticated_as("bob"):
        assert tool() == "ok", "bob was charged for alice's requests"


def test_the_same_principal_is_still_limited(limiter: RateLimiter) -> None:
    """The negative control.

    Without it, "give everyone their own bucket" could be satisfied by a fresh
    bucket per *request*, which is no rate limit at all.
    """

    @require_rate_limit
    def tool():
        return "ok"

    with _authenticated_as("alice"):
        tool()
        tool()
        with pytest.raises(ValueError, match="Rate limit exceeded"):
            tool()


def test_two_users_of_one_oauth_client_are_distinct(limiter: RateLimiter) -> None:
    """Identity is the (client_id, issuer, subject) triple, not the client id.

    `principal_components` is mcp's own answer to "who is this token's
    principal", and it is what session ownership uses. Keying on `client_id`
    alone would pool every user of a shared OAuth client into one bucket --
    a smaller version of the same bug.
    """

    @require_rate_limit
    def tool():
        return "ok"

    with _authenticated_as("shared-client", subject="user-a"):
        tool()
        tool()
        with pytest.raises(ValueError, match="Rate limit exceeded"):
            tool()

    with _authenticated_as("shared-client", subject="user-b"):
        assert tool() == "ok"


def test_an_unauthenticated_transport_falls_back_to_the_shared_bucket(
    limiter: RateLimiter,
) -> None:
    """stdio supplies no principal, and the fallback must be explicit.

    Not a regression: under stdio each client spawns its own server process, so
    one bucket per process is one bucket per client. The point is that the
    shared bucket is now what happens when there is genuinely no identity,
    rather than what happens always.
    """

    @require_rate_limit
    def tool():
        return "ok"

    tool()
    tool()
    with pytest.raises(ValueError, match="Rate limit exceeded"):
        tool()

    assert list(limiter.buckets) == [_SHARED_BUCKET_ID]


def test_the_bearer_token_is_never_used_as_a_bucket_key(
    limiter: RateLimiter,
) -> None:
    """The key is logged at DEBUG, so it must not be a credential.

    `require_rate_limit` emits `Rate limit OK (client: {client_id})`. Keying on
    `token.token` would have put a bearer token into the log -- a worse bug
    than the one being fixed.
    """

    @require_rate_limit
    def tool():
        return "ok"

    with _authenticated_as("alice", subject="user-a"):
        tool()

    keys = list(limiter.buckets)
    assert keys, "no bucket was created"
    assert not any("secret-bearer-value" in key for key in keys), keys
