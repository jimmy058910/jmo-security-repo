"""An uppercase hex digest is not tampering (#950).

``hashlib.hexdigest()`` is always lowercase and in-toto does not mandate a case
for hex digest values, so an attestation written with an uppercase sha256 failed
verification -- and failed it as ``TAMPER DETECTED - Subject has been
modified!``, naming a subject nothing had touched.

The direction was safe (it rejected rather than accepted), so this is not the
"verified without verifying" class. It is worse in a different way: a verifier
that accuses over a formatting difference is one an operator learns to override.

Only JMo's own generator emits lowercase, which is why the whole suite and every
local round trip missed it -- the same blind spot as #947, where a check could
not fire on this project's own output format. So the tests here deliberately do
NOT go through `jmo attest`.
"""

from __future__ import annotations

import hashlib

import pytest

from scripts.core.attestation.verifier import AttestationVerifier


@pytest.fixture
def subject(tmp_path):
    p = tmp_path / "findings.json"
    p.write_bytes(b'{"findings": [], "schema": "common_finding.v1"}')
    return p


@pytest.fixture
def verifier():
    return AttestationVerifier(enable_tamper_detection=False)


def _sha256(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --------------------------------------------------------------------------
# What was broken
# --------------------------------------------------------------------------


def test_uppercase_digest_verifies(subject, verifier):
    digest = _sha256(subject).upper()
    ok, reason = verifier._verify_subject_digest(str(subject), {"sha256": digest})
    assert ok, f"an uppercase sha256 of an unmodified subject was rejected: {reason}"
    assert reason is None


def test_mixed_case_digest_verifies(subject, verifier):
    raw = _sha256(subject)
    mixed = "".join(c.upper() if i % 2 else c for i, c in enumerate(raw))
    assert mixed != raw, "fixture bug: the mixed-case digest equals the lowercase one"
    ok, _ = verifier._verify_subject_digest(str(subject), {"sha256": mixed})
    assert ok


def test_surrounding_whitespace_is_tolerated(subject, verifier):
    ok, _ = verifier._verify_subject_digest(
        str(subject), {"sha256": f"  {_sha256(subject)}\n"}
    )
    assert ok


# --------------------------------------------------------------------------
# Negative controls -- without these the fix is just "compare less"
# --------------------------------------------------------------------------


def test_a_genuine_mismatch_still_fails(subject, verifier):
    """The assertion the issue insisted on. Case-folding must not widen what
    verifies -- only narrow what is reported as tampering."""
    wrong = hashlib.sha256(b"something else entirely").hexdigest()
    assert wrong != _sha256(subject)
    ok, reason = verifier._verify_subject_digest(str(subject), {"sha256": wrong})
    assert not ok
    assert reason == "Subject digest mismatch"


def test_an_uppercase_genuine_mismatch_still_fails(subject, verifier):
    """The case the fix could plausibly have broken: normalising both sides
    must not make two *different* digests compare equal."""
    wrong = hashlib.sha256(b"something else entirely").hexdigest().upper()
    ok, reason = verifier._verify_subject_digest(str(subject), {"sha256": wrong})
    assert not ok
    assert reason == "Subject digest mismatch"


def test_a_truncated_digest_still_fails(subject, verifier):
    """A prefix of the right answer is not the right answer."""
    ok, reason = verifier._verify_subject_digest(
        str(subject), {"sha256": _sha256(subject)[:-1]}
    )
    assert not ok
    assert reason == "Subject digest mismatch"


def test_internal_whitespace_still_fails(subject, verifier):
    """Only *surrounding* whitespace is stripped. A digest with a space in the
    middle of it is malformed, not merely formatted differently."""
    raw = _sha256(subject)
    ok, reason = verifier._verify_subject_digest(
        str(subject), {"sha256": raw[:32] + " " + raw[32:]}
    )
    assert not ok
    assert reason == "Subject digest mismatch"


def test_a_mismatch_on_the_second_algorithm_still_fails(subject, verifier):
    """A multi-hash attestation must not pass on the strength of one match."""
    ok, reason = verifier._verify_subject_digest(
        str(subject),
        {
            "sha256": _sha256(subject).upper(),
            "sha384": "00" * 48,
        },
    )
    assert not ok
    assert reason == "Subject digest mismatch"
