#!/usr/bin/env python3
"""Guard: every suppression key JMo documents is a key the engine honours.

#538 was exactly this drift. The shipped `jmo.suppress.yml`, its header, and
three docs advertised `path` / `ruleId` / `severity` / `line` selectors while
`load_suppressions()` read only `id`, so all eleven of the repo's own entries
loaded as zero rules.

The guard this replaces asserted that the strings ``path:``, ``ruleId:``,
``line:`` and ``severity:`` were *absent* from one section of one file. That
encoded the shape the bug had at the time rather than the property that
matters, and it covered `USER_GUIDE.md` only -- the one document that was
already correct. `RESULTS_GUIDE.md`, `RESULTS_QUICK_REFERENCE.md`,
`DOCKER_README.md` and `jmo.suppress.yml` all advertised the broken selectors
and were unguarded.

So this asserts the property instead: parse every suppression example JMo
ships, and require that each key is one the engine implements and that each
entry can actually match something.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from scripts.core.suppress import (
    METADATA_KEYS,
    SELECTOR_KEYS,
    Suppression,
    load_suppressions,
)

ROOT = Path(__file__).resolve().parents[2]

#: Everything that ships a suppression example a user might copy.
DOCUMENTED_SOURCES = [
    "jmo.suppress.yml",
    "docs/USER_GUIDE.md",
    "docs/RESULTS_GUIDE.md",
    "docs/RESULTS_QUICK_REFERENCE.md",
    "docs/DOCKER_README.md",
]


def _fenced_blocks(text: str) -> list[str]:
    """Yield the contents of each fenced code block.

    Deliberately toggles on any ``` line rather than matching an opening
    language tag to a matching closer: several of these files close a ```yaml
    block with ```text (#740), and a stricter reader silently swallows pages.
    """
    blocks: list[str] = []
    current: list[str] | None = None
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            if current is None:
                current = []
            else:
                blocks.append("\n".join(current))
                current = None
            continue
        if current is not None:
            current.append(line)
    return blocks


def _suppression_examples(path: Path) -> list[tuple[str, list]]:
    """Return (label, entries) for every suppression example in a file."""
    text = path.read_text(encoding="utf-8")
    candidates = [text] if path.suffix in {".yml", ".yaml"} else _fenced_blocks(text)

    found = []
    for index, block in enumerate(candidates):
        if "suppressions:" not in block and "suppress:" not in block:
            continue
        try:
            data = yaml.safe_load(block)
        except yaml.YAMLError:
            continue  # Not a YAML block; some fences hold shell or jq.
        if not isinstance(data, dict):
            continue
        entries = data.get("suppressions")
        if entries is None:
            entries = data.get("suppress")
        if isinstance(entries, list) and entries:
            found.append((f"{path.name} block {index}", entries))
    return found


ALL_EXAMPLES = [
    (label, entry)
    for source in DOCUMENTED_SOURCES
    for label, entries in _suppression_examples(ROOT / source)
    for entry in entries
    if isinstance(entry, dict)
]


def test_the_guard_actually_found_examples_to_check():
    """A parser change that silently found nothing would pass every test below."""
    assert len(ALL_EXAMPLES) >= 15, (
        f"only {len(ALL_EXAMPLES)} documented suppression entries were parsed; "
        "the extractor is probably broken, not the docs"
    )
    labels = {label.split(" block")[0] for label, _ in ALL_EXAMPLES}
    assert labels == {
        Path(s).name for s in DOCUMENTED_SOURCES
    }, f"no suppression example was parsed out of {
            {Path(s).name for s in DOCUMENTED_SOURCES} - labels
        }"


@pytest.mark.parametrize(
    ("label", "entry"),
    ALL_EXAMPLES,
    ids=[f"{i}-{lbl}" for i, (lbl, _) in enumerate(ALL_EXAMPLES)],
)
def test_documented_keys_are_keys_the_engine_implements(label: str, entry: dict):
    unknown = set(entry) - SELECTOR_KEYS - METADATA_KEYS

    assert not unknown, (
        f"{label} documents suppression key(s) {sorted(unknown)} that "
        f"load_suppressions() ignores. Implement them or drop them from the docs."
    )


@pytest.mark.parametrize(
    ("label", "entry"),
    ALL_EXAMPLES,
    ids=[f"{i}-{lbl}" for i, (lbl, _) in enumerate(ALL_EXAMPLES)],
)
def test_every_documented_entry_can_match_something(label: str, entry: dict):
    """An entry with no selector suppresses nothing and is skipped at load."""
    keys = set(entry)

    assert keys & SELECTOR_KEYS, (
        f"{label} shows an entry with no selector ({sorted(keys)}); "
        f"it would be reported at WARNING and ignored"
    )


def test_the_repos_own_suppression_config_loads_every_entry():
    """#538's sharpest symptom: all 11 shipped entries loaded as 0 rules."""
    raw = yaml.safe_load((ROOT / "jmo.suppress.yml").read_text(encoding="utf-8"))
    declared = len(raw["suppressions"])

    loaded = load_suppressions(str(ROOT / "jmo.suppress.yml"))

    assert (
        len(loaded) == declared
    ), f"jmo.suppress.yml declares {declared} entries but {len(loaded)} load"


def test_shipped_rule_ids_match_what_the_tools_actually_emit():
    """A ruleId written as a rule *name* never matches semgrep's dotted id.

    Measured: semgrep reports
    yaml.github-actions.security.run-shell-injection.run-shell-injection,
    so `ruleId: "run-shell-injection"` stayed inert even after selectors
    started working.
    """
    loaded = load_suppressions(str(ROOT / "jmo.suppress.yml"))
    long_form = {
        "run-shell-injection": (
            "yaml.github-actions.security.run-shell-injection.run-shell-injection"
        ),
        "detected-aws-access-key-id-value": (
            "generic.secrets.security.detected-aws-access-key-id-value"
            ".detected-aws-access-key-id-value"
        ),
    }

    for rule in loaded.values():
        if rule.rule_id is None:
            continue
        for short, dotted in long_form.items():
            if short in rule.rule_id:
                probe = Suppression(rule_id=rule.rule_id)
                assert probe.matches(
                    {"ruleId": dotted, "location": {}, "severity": "HIGH"}
                ), (
                    f"jmo.suppress.yml uses ruleId={rule.rule_id!r}, which does not "
                    f"match the id the tool emits ({dotted!r}); use a glob"
                )
