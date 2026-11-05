"""The reviewed list of rules that match a secret's value covers the bundle (#1585).

`scripts/core/secret_value_rules.py` classifies, once, every bundled opengrep rule
whose id `SECRET_LIKE_RULE_ID` catches. A bundle update that adds such a rule must
be classified before it ships: unlisted, its findings would quote whatever secret
it matched into `summaries/` and history. Read from the bundle itself, not restated.
"""

from __future__ import annotations

import re

import pytest
import yaml

from scripts.core.rule_bundle import BUNDLE_DIR
from scripts.core.secret_value_rules import (
    CREDENTIAL_CWES,
    MESSAGE_SECRET_METAVARS,
    MESSAGE_TEMPLATES,
    SECRET_LIKE_RULE_ID,
    SECRET_VALUE_RULES,
    is_secret_value_finding,
)


def _bundle_rules() -> dict[str, dict]:
    rules = {}
    for path in sorted(BUNDLE_DIR.glob("*.yaml")):
        for rule in (yaml.safe_load(path.read_bytes()) or {}).get("rules", []):
            rules[rule["id"]] = rule
    return rules


BUNDLE = _bundle_rules()
CAUGHT = sorted(i for i in BUNDLE if SECRET_LIKE_RULE_ID.search(i))


def _cwes(rule: dict) -> set[str]:
    cwes = (rule.get("metadata") or {}).get("cwe") or []
    cwes = cwes if isinstance(cwes, list) else [cwes]
    return {m.group(0) for c in cwes for m in re.finditer(r"CWE-\d+", str(c))}


def test_the_bundle_and_the_net_are_read() -> None:
    """Meta-guard: an empty bundle or net would pass the tests below."""
    assert len(BUNDLE) > 1000
    assert len(CAUGHT) >= 50


@pytest.mark.parametrize("rule_id", CAUGHT)
def test_every_rule_the_net_catches_is_classified(rule_id: str) -> None:
    assert rule_id in SECRET_VALUE_RULES, (
        f"{rule_id} may match a secret's value: read the rule and add it to "
        "SECRET_VALUE_RULES, True if what it matches holds one"
    )


def test_the_list_names_only_bundled_rules() -> None:
    assert sorted(set(SECRET_VALUE_RULES) - set(BUNDLE)) == []


def test_a_rule_listed_false_carries_no_credential_cwe() -> None:
    """A credential CWE counts on its own, so a False beside one would mislead."""
    contradicted = [
        i
        for i, value in SECRET_VALUE_RULES.items()
        if not value and _cwes(BUNDLE[i]) & CREDENTIAL_CWES
    ]
    assert contradicted == []


@pytest.mark.parametrize(
    ("rule_id", "cwes", "expected"),
    [
        (
            "javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret",
            [],
            True,
        ),
        (
            "python.lang.security.audit.md5-used-as-password.md5-used-as-password",
            [],
            False,
        ),
        ("a.rule.no.list.knows", ["CWE-798: Use of Hard-coded Credentials"], True),
        ("a.rule.no.list.knows", ["CWE-79"], False),
        ("a.rule.no.list.knows", "CWE-259", True),
    ],
)
def test_a_finding_is_secret_class_by_its_rule_or_its_cwe(
    rule_id: str, cwes: object, expected: bool
) -> None:
    assert is_secret_value_finding(rule_id, cwes) is expected


def _message_metavars(rule: dict) -> set[str]:
    return set(re.findall(r"\$[A-Z_][A-Z0-9_]*", str(rule.get("message", ""))))


@pytest.mark.parametrize(
    "rule_id", sorted(i for i, v in SECRET_VALUE_RULES.items() if v)
)
def test_a_listed_rule_whose_message_interpolates_says_which_metavariables_hold_it(
    rule_id: str,
) -> None:
    """opengrep fills `$NAME` in a rule's message with what it matched, so a
    message can carry the secret itself (measured: secrets-in-config-file's
    `$VALUE`, python-logger-credential-disclosure's `$FORMAT_STRING`). Each
    listed rule whose message interpolates says which of those hold the secret,
    () for none, so the adapter redacts exactly those."""
    interpolated = _message_metavars(BUNDLE[rule_id])
    if not interpolated:
        assert rule_id not in MESSAGE_SECRET_METAVARS
        return
    assert rule_id in MESSAGE_SECRET_METAVARS, (rule_id, sorted(interpolated))
    assert set(MESSAGE_SECRET_METAVARS[rule_id]) <= interpolated


def test_the_measured_interpolations_are_listed() -> None:
    """Meta-guard on the parse above: the three rules whose message carries the
    secret, each pinned, since `<=` alone would let `()` through."""
    assert {rule: held for rule, held in MESSAGE_SECRET_METAVARS.items() if held} == {
        "yaml.kubernetes.security.secrets-in-config-file.secrets-in-config-file": (
            "$VALUE",
        ),
        "python.lang.security.audit.logging.logger-credential-leak."
        "python-logger-credential-disclosure": ("$FORMAT_STRING",),
        "ruby.rails.security.brakeman.check-rails-secret-yaml."
        "check-rails-secret-yaml": ("$VALUE",),
    }


@pytest.mark.parametrize(
    "rule_id", sorted(r for r, held in MESSAGE_SECRET_METAVARS.items() if held)
)
def test_a_message_carrying_the_secret_is_rebuilt_from_the_rules_own_template(
    rule_id: str,
) -> None:
    """opengrep renders a metavariable into the message as the source spells
    it, while `abstract_content` normalises it (`"x %s" % y` becomes
    `"x %s"%y`), so replacing the value in the message misses (review of
    #1585). Such a message is rebuilt from the rule's template instead, which
    must be the bundle's own text."""
    assert MESSAGE_TEMPLATES[rule_id] == BUNDLE[rule_id]["message"]


def test_only_those_rules_have_a_template() -> None:
    assert set(MESSAGE_TEMPLATES) == {
        r for r, held in MESSAGE_SECRET_METAVARS.items() if held
    }
