"""`jmo.yml` keys that configure nothing must say so (#859).

Config used to discard every key it did not recognise in total silence. That is
how ``exclude_paths`` survived in ``docs/RESULTS_GUIDE.md`` as documented advice
for suppressing false positives: the real key is ``exclude``, so a user
following the docs got nothing suppressed, no warning, and no way to tell the
difference between "the setting did not apply" and "the setting found nothing".

Two guards live here, and they check different things:

* the loader warns, and names the offending key; and
* ``RECOGNISED_CONFIG_KEYS`` still matches what ``load_config`` actually reads,
  derived by walking its AST rather than by re-listing it. A hand-maintained
  allowlist beside a hand-maintained reader drifts, and the failure mode of
  drift here is a *false* warning about a key that works -- worse than the
  silence it replaced.
"""

from __future__ import annotations

import ast
import inspect
import logging
import textwrap
from pathlib import Path

import pytest

from scripts.core.config import RECOGNISED_CONFIG_KEYS, load_config


def _write(tmp_path: Path, body: str) -> str:
    p = tmp_path / "jmo.yml"
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return str(p)


# --------------------------------------------------------------------------
# The behaviour
# --------------------------------------------------------------------------


def test_unrecognised_key_is_named_in_a_warning(tmp_path, caplog):
    """The exact case that reached the docs: `exclude_paths` for `exclude`."""
    path = _write(
        tmp_path,
        """
        default_profile: fast
        exclude_paths:
          - vendor/
        """,
    )
    with caplog.at_level(logging.WARNING, logger="scripts.core.config"):
        cfg = load_config(path)

    messages = " ".join(r.getMessage() for r in caplog.records)
    assert "exclude_paths" in messages, (
        "the unrecognised key must be named -- a warning that does not say "
        f"which key is nearly as unhelpful as silence. Got: {messages!r}"
    )
    # And the setting still does nothing, which is the thing being warned about.
    assert not hasattr(cfg, "exclude_paths")


def test_warning_lists_the_recognised_keys(tmp_path, caplog):
    """A user who mistyped needs to see what the right spelling would have been."""
    path = _write(tmp_path, "totally_made_up_key: 1\n")
    with caplog.at_level(logging.WARNING, logger="scripts.core.config"):
        load_config(path)

    messages = " ".join(r.getMessage() for r in caplog.records)
    assert "exclude" in messages and "default_profile" in messages


def test_every_recognised_key_is_accepted_without_warning(tmp_path, caplog):
    """The negative control.

    Without this, "warn on anything unknown" could be satisfied by warning on
    everything, which would be a worse bug wearing the fix's clothes.
    """
    lines = []
    for key in sorted(RECOGNISED_CONFIG_KEYS):
        if key in ("tools", "outputs", "include", "exclude"):
            lines.append(f"{key}: []")
        elif key in ("profiles", "per_tool", "policy", "deduplication", "profiling"):
            lines.append(f"{key}: {{}}")
        elif key == "fail_on":
            lines.append("fail_on: HIGH")
        elif key == "log_level":
            lines.append("log_level: INFO")
        elif key == "default_profile":
            lines.append("default_profile: fast")
        else:  # threads, timeout, retries
            lines.append(f"{key}: 1")
    path = _write(tmp_path, "\n".join(lines) + "\n")

    with caplog.at_level(logging.WARNING, logger="scripts.core.config"):
        load_config(path)

    unrecognised = [
        r.getMessage() for r in caplog.records if "unrecognised" in r.getMessage()
    ]
    assert (
        not unrecognised
    ), f"a key the loader reads was reported as unrecognised: {unrecognised}"


def test_a_config_that_is_not_a_mapping_is_reported_not_crashed(tmp_path, caplog):
    """A YAML list reached `data.get(...)` and raised AttributeError.

    `load_config`'s docstring says it raises nothing, so this was both a crash
    and a broken contract -- and it is the same "input discarded without
    saying so" family, one layer up.
    """
    path = _write(tmp_path, "- a\n- b\n")
    with caplog.at_level(logging.WARNING, logger="scripts.core.config"):
        cfg = load_config(path)

    assert cfg.default_profile is None or isinstance(cfg.default_profile, str)
    messages = " ".join(r.getMessage() for r in caplog.records)
    assert "mapping" in messages.lower()


# --------------------------------------------------------------------------
# The allowlist cannot drift away from the loader
# --------------------------------------------------------------------------


def _keys_load_config_reads() -> set[str]:
    """AST-walk `load_config` for every top-level key it consults.

    Matches two shapes and nothing else:
        data.get("<key>")      ->  <key>
        "<key>" in data        ->  <key>

    Deliberately literal. Anything cleverer would need to model the function,
    and a guard that models its subject can be wrong in the same direction as
    the subject.
    """
    source = textwrap.dedent(inspect.getsource(load_config))
    tree = ast.parse(source)
    found: set[str] = set()

    for node in ast.walk(tree):
        # data.get("key")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "data"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            found.add(node.args[0].value)
        # "key" in data
        if (
            isinstance(node, ast.Compare)
            and len(node.ops) == 1
            and isinstance(node.ops[0], ast.In)
            and isinstance(node.left, ast.Constant)
            and isinstance(node.left.value, str)
            and isinstance(node.comparators[0], ast.Name)
            and node.comparators[0].id == "data"
        ):
            found.add(node.left.value)

    return found


def test_ast_derivation_finds_something():
    """Positive control for the derivation itself.

    A walk that silently matched nothing would make the two tests below pass
    for the worst possible reason. This is the assertion that a mutation
    harness needs: the instrument works before its reading is trusted.
    """
    assert len(_keys_load_config_reads()) >= 10


@pytest.mark.parametrize("key", sorted(RECOGNISED_CONFIG_KEYS))
def test_recognised_key_is_actually_read_by_the_loader(key: str):
    """No key may be allowlisted that the loader ignores.

    Such a key would be accepted in silence -- exactly the defect #859 fixes,
    reintroduced through the allowlist instead of through the reader.
    """
    assert (
        key in _keys_load_config_reads()
    ), f"{key!r} is in RECOGNISED_CONFIG_KEYS but load_config never reads it"


def test_no_key_the_loader_reads_is_missing_from_the_allowlist():
    """The other direction: a newly-read key must not warn users off itself."""
    missing = sorted(_keys_load_config_reads() - set(RECOGNISED_CONFIG_KEYS))
    assert not missing, (
        f"load_config reads {missing}, which RECOGNISED_CONFIG_KEYS omits -- a "
        f"user setting them would be warned that a working key configures nothing"
    )
