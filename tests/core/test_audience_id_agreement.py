"""`email_service` and `newsletter_broadcast` must target the same audience (#929).

Both modules are documented as pointing at the "JMo Updates" list, and both read
``RESEND_AUDIENCE_ID`` -- with different defaults. Unset (the normal case),
``email_service`` added CLI signups to a production audience hardcoded in source
while ``newsletter_broadcast`` had no audience at all and exited 1. Coupled by
intent, uncoupled by default value.

``email_service``'s own comment calls the pairing load-bearing:

    This is the load-bearing call that ensures CLI signups receive the
    broadcast newsletter sends emitted by newsletter_broadcast.py.

Resolved in the direction the issue recommended: **one shared default, and it is
the empty one.** With a production id baked into source, the only thing between
"someone exported RESEND_API_KEY to try the welcome path" and real subscribers
getting mail was a credential happening to be absent.

The guard asserts the two modules *agree*, not that their source text matches --
`from x import CONST` would bind a copy and quietly defeat the suite's
``patch("scripts.core.email_service.RESEND_AUDIENCE_ID", ...)``, so the property
is the thing worth pinning.
"""

from __future__ import annotations

import importlib

import pytest


def _reload_both():
    import scripts.core.email_service as es
    import scripts.core.newsletter_broadcast as nb

    return importlib.reload(es), importlib.reload(nb)


@pytest.mark.parametrize(
    "env_value",
    [None, "", "aud-from-the-environment", "fb900b6d-10de-4171-97df-e4e5eebf20fd"],
)
def test_both_modules_resolve_the_same_audience(monkeypatch, env_value):
    """The invariant, across every state the environment can be in."""
    if env_value is None:
        monkeypatch.delenv("RESEND_AUDIENCE_ID", raising=False)
    else:
        monkeypatch.setenv("RESEND_AUDIENCE_ID", env_value)

    es, nb = _reload_both()

    assert es.RESEND_AUDIENCE_ID == nb.RESEND_AUDIENCE_ID, (
        f"with RESEND_AUDIENCE_ID={env_value!r}, email_service targets "
        f"{es.RESEND_AUDIENCE_ID!r} and newsletter_broadcast targets "
        f"{nb.RESEND_AUDIENCE_ID!r}"
    )


def test_unset_means_no_audience_not_the_production_one(monkeypatch):
    """The specific regression. This was the production list."""
    monkeypatch.delenv("RESEND_AUDIENCE_ID", raising=False)
    es, _ = _reload_both()

    assert es.RESEND_AUDIENCE_ID == ""
    assert es.RESEND_AUDIENCE_ID != es.JMO_UPDATES_AUDIENCE_ID, (
        "the production audience is a source-code default again: exporting a "
        "Resend key to try the welcome path would mail real subscribers"
    )


def test_the_canonical_id_is_still_recorded(monkeypatch):
    """Dropping the default must not lose the record of WHICH audience is the
    right one -- that is the thing a maintainer exports."""
    monkeypatch.delenv("RESEND_AUDIENCE_ID", raising=False)
    es, _ = _reload_both()
    assert es.JMO_UPDATES_AUDIENCE_ID == "fb900b6d-10de-4171-97df-e4e5eebf20fd"


def test_the_environment_still_wins(monkeypatch):
    """Negative control: "make them agree" must not have been achieved by
    making both ignore the environment."""
    monkeypatch.setenv("RESEND_AUDIENCE_ID", "aud-explicit")
    es, nb = _reload_both()
    assert es.RESEND_AUDIENCE_ID == "aud-explicit"
    assert nb.RESEND_AUDIENCE_ID == "aud-explicit"


def test_no_audience_means_no_contact_is_added(monkeypatch):
    """The consequence that makes the empty default safe rather than merely
    consistent: with nothing to target, the add is refused rather than
    defaulted."""
    monkeypatch.delenv("RESEND_AUDIENCE_ID", raising=False)
    es, _ = _reload_both()
    monkeypatch.setattr(es, "RESEND_AVAILABLE", True)
    monkeypatch.setattr(es, "RESEND_API_KEY", "re_test_key")

    def _boom(*a, **k):
        raise AssertionError("a contact was sent to Resend with no audience set")

    monkeypatch.setattr(
        es,
        "resend",
        type("R", (), {"Contacts": type("C", (), {"create": staticmethod(_boom)})})(),
    )

    assert es.add_contact_to_audience("user@example.com") is False


@pytest.fixture(autouse=True)
def _restore_modules():
    """Leave both modules bound to the ambient environment for other tests.

    These tests reload modules, and a reload under a monkeypatched env would
    otherwise persist that env's values into every later test in the session.
    """
    yield
    _reload_both()
