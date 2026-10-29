"""scripts/dev/build_rule_bundle.py: the offline opengrep rule bundle's builder.

Every test builds from `tests/fixtures/rule_bundle/sources/`, a synthetic tree
shaped like the four pinned sources (GitLab's `lgpl-cc`, the opengrep-rules
snapshot, 0xdea, elttam), and never touches the network. The real `SOURCES`
configuration runs against it, so a dropped exclusion fails a test here rather
than shipping a secret scanner's rules in a committed bundle.

Fixture contents (what each file is for is in its own `message:`):
  lgpl-cc          gl-r, gl-r2, gl-t, gl-p kept; notes.yml (not `rule-*.yml`) and
                   rules/gitlab (outside the rules root) never read
  opengrep-rules   r2, gen, s-pair, t1, t2, wf kept; r (body twin of gl-r) and
                   s-t (body twin of gl-t) and s-prop (twin of gl-p, in another language
                   file) dropped as duplicates; c (correctness),
                   nometa, a.test.yaml, not-rules.yaml, template.yaml, generic/secrets
                   and problem-based-packs contribute nothing
  0xdea            ok-rule kept; p-pair, p-t duplicates; raptor-use-after-free
                   (an excluded id) and noisy/ (an excluded directory) dropped
  elttam           e-ok kept; jsp-join (mode: join) and yaml/kubernetes dropped
"""

from __future__ import annotations

import dataclasses
import hashlib
import io
import json
import re
import shutil
import tarfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts.dev import build_rule_bundle as bb

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "rule_bundle" / "sources"

# 7 files, 12 rules: the fixture's expected bundle.
EXPECTED_FILES = {
    "c.yaml": 2,
    "generic.yaml": 1,
    "java.yaml": 2,
    "javascript.yaml": 3,
    "properties.yaml": 1,
    "python.yaml": 2,
    "yaml.yaml": 1,
}


# The repository's .gitignore drops every `*secret*` data file (a deliberate net),
# so this fixture cannot be committed under generic/secrets/ and is written into
# each test's copy of the tree instead.
SECRETS_RULE = b"""\
rules:
  - id: leak
    languages: [generic]
    severity: ERROR
    message: secret detection is gitleaks' and trufflehog's class
    metadata:
      category: security
    pattern: LEAKED
"""


@pytest.fixture
def trees(tmp_path: Path) -> dict[str, Path]:
    """A writable copy of the synthetic sources, keyed like SOURCES."""
    dest = tmp_path / "sources"
    shutil.copytree(FIXTURES, dest)
    leak = dest / "opengrep-rules" / "generic" / "secrets" / "leak.yaml"
    leak.parent.mkdir()
    leak.write_bytes(SECRETS_RULE)
    return {name: dest / name for name in bb.SOURCES}


def _rules_by_file(out: Path) -> dict[str, list[dict[str, Any]]]:
    return {
        p.name: yaml.safe_load(p.read_bytes().decode("utf-8"))["rules"]
        for p in sorted(out.glob("*.yaml"))
    }


def _ids(out: Path) -> set[str]:
    return {r["id"] for rules in _rules_by_file(out).values() for r in rules}


def _build(trees: dict[str, Path], tmp_path: Path, name: str = "out") -> Path:
    out = tmp_path / name
    bb.build(trees, out)
    return out


def _exclusions(manifest: dict[str, Any], kind: str) -> list[dict[str, Any]]:
    return [e for e in manifest["exclusions"] if e["kind"] == kind]


def test_the_fixture_builds_the_expected_bundle(trees, tmp_path):
    out = _build(trees, tmp_path)
    counts = {name: len(rules) for name, rules in _rules_by_file(out).items()}
    assert counts == EXPECTED_FILES


# --- what is kept -----------------------------------------------------------


def test_only_security_rules_are_kept(trees, tmp_path):
    ids = _ids(_build(trees, tmp_path))
    assert "javascript.express.security.a.r2" in ids
    # category: correctness, and a rule with no metadata at all
    assert "javascript.express.security.a.c" not in ids
    assert "javascript.express.security.a.nometa" not in ids


def test_test_targets_and_non_rule_yaml_are_skipped(trees, tmp_path):
    ids = _ids(_build(trees, tmp_path))
    assert not any("from-a-test-target" in i for i in ids)  # a.test.yaml
    assert not any("not-rules" in i for i in ids)  # YAML with no rules list
    assert not any("template-rule" in i for i in ids)  # a file at the root: no language
    # GitLab files are read only as rule-*.yml, and only under rules/lgpl-cc
    assert not any("not-a-rule-file" in i for i in ids)
    assert not any("outside-the-rules-root" in i for i in ids)


def test_generic_secrets_is_excluded(trees, tmp_path):
    assert (trees["opengrep-rules"] / "generic" / "secrets" / "leak.yaml").is_file()
    out = _build(trees, tmp_path)
    generic = [r["id"] for r in _rules_by_file(out)["generic.yaml"]]
    assert generic == ["generic.audit.gen.gen"]
    assert not any(i.startswith("generic.secrets.") for i in _ids(out))


def test_ids_are_namespaced_by_path(trees, tmp_path):
    ids = _ids(_build(trees, tmp_path))
    assert "javascript.express.security.a.r2" in ids  # the snapshot carries no prefix
    assert "lgpl-cc.javascript.express.rule-a.gl-r2" in ids
    assert "0xdea.c.ok.ok-rule" in ids
    assert "elttam.java.lang.e.e-ok" in ids  # a .yml file loses its extension too
    # joined with ".", never an os.sep: a Windows build must give the same ids
    assert not any("/" in i or "\\" in i for i in ids)


def test_a_rule_goes_to_the_file_named_by_its_top_directory(trees, tmp_path):
    by_file = _rules_by_file(_build(trees, tmp_path))
    assert {r["id"] for r in by_file["java.yaml"]} == {
        "lgpl-cc.java.rule-t.gl-t",  # GitLab's java merges into java.yaml
        "elttam.java.lang.e.e-ok",
    }
    assert {r["id"] for r in by_file["c.yaml"]} == {"c.s.s-pair", "0xdea.c.ok.ok-rule"}


def test_rules_within_a_file_are_sorted_by_id(trees, tmp_path):
    for rules in _rules_by_file(_build(trees, tmp_path)).values():
        ids = [r["id"] for r in rules]
        assert ids == sorted(ids)


# --- body duplicates (D5, D16) ----------------------------------------------


def test_rule_body_ignores_id_message_metadata_severity_and_key_order():
    a = {
        "id": "a",
        "message": "m",
        "severity": "ERROR",
        "metadata": {"x": 1},
        "pattern": "p",
        "languages": ["c"],
    }
    b = {
        "languages": ["c"],
        "pattern": "p",
        "id": "b",
        "severity": "INFO",
        "message": "other",
    }
    assert bb.rule_body(a) == bb.rule_body(b)
    assert bb.rule_body(a) != bb.rule_body({**a, "pattern": "q"})
    assert bb.rule_body(a) != bb.rule_body({**a, "languages": ["java"]})


def test_gitlab_wins_a_body_duplicate(trees, tmp_path):
    out = _build(trees, tmp_path)
    ids = _ids(out)
    assert "lgpl-cc.javascript.express.rule-a.gl-r" in ids
    assert (
        "javascript.express.security.a.r" not in ids
    )  # same body, different id and message
    # same first pattern but a different `patterns`: both rules stay
    assert "lgpl-cc.javascript.express.rule-a.gl-r2" in ids
    assert "javascript.express.security.a.r2" in ids


def test_a_dropped_duplicate_is_recorded_with_the_rule_that_won(trees, tmp_path):
    manifest = bb.build(trees, tmp_path / "out")
    dup = next(
        e
        for e in _exclusions(manifest, "body-duplicate")
        if e["id"] == "javascript.express.security.a.r"
    )
    assert dup["source"] == "opengrep-rules"
    assert dup["kept_id"] == "lgpl-cc.javascript.express.rule-a.gl-r"
    assert dup["kept_source"] == "lgpl-cc"
    assert dup["reason"]


def test_a_duplicate_is_found_across_language_files(trees, tmp_path):
    # GitLab's properties/ has no directory of that name in the snapshot, so the
    # snapshot's twin sits in java.yaml: duplicates are matched over the whole
    # bundle, not file by file (1 of the real 50 is of this kind: a properties rule).
    manifest = bb.build(trees, tmp_path / "out")
    by_file = _rules_by_file(tmp_path / "out")
    assert [r["id"] for r in by_file["properties.yaml"]] == [
        "lgpl-cc.properties.rule-p.gl-p"
    ]
    assert "java.lang.prop.s-prop" not in _ids(tmp_path / "out")
    dup = next(
        e
        for e in _exclusions(manifest, "body-duplicate")
        if e["id"] == "java.lang.prop.s-prop"
    )
    assert dup["kept_id"] == "lgpl-cc.properties.rule-p.gl-p"


def test_two_rules_of_one_source_with_one_body_are_both_kept(trees, tmp_path):
    # Only a HIGHER source's rule drops one; twins inside a source stay. The
    # measured 50 duplicates (and so the bundle's rule count) depend on it.
    ids = _ids(_build(trees, tmp_path))
    assert {"python.lang.twin.t1", "python.lang.twin.t2"} <= ids


def test_precedence_follows_the_source_order(trees, tmp_path):
    # `triple($X)` is in lgpl-cc, the snapshot and 0xdea; `pair($X)` in the snapshot and 0xdea
    manifest = bb.build(trees, tmp_path / "out")
    ids = _ids(tmp_path / "out")
    assert "lgpl-cc.java.rule-t.gl-t" in ids
    assert "java.lang.t.s-t" not in ids
    assert "0xdea.java.p-t.p-t" not in ids
    assert "c.s.s-pair" in ids
    assert "0xdea.c.p.p-pair" not in ids
    losers = {
        e["id"]: e["kept_source"] for e in _exclusions(manifest, "body-duplicate")
    }
    assert losers["0xdea.java.p-t.p-t"] == "lgpl-cc"
    assert losers["0xdea.c.p.p-pair"] == "opengrep-rules"


def test_reversing_the_sources_reverses_the_winners(trees, tmp_path, monkeypatch):
    # The order is SOURCES' own, not an accident of sorting ids or paths.
    monkeypatch.setattr(bb, "SOURCES", dict(reversed(list(bb.SOURCES.items()))))
    ids = _ids(_build(trees, tmp_path))
    assert "0xdea.java.p-t.p-t" in ids
    assert "lgpl-cc.java.rule-t.gl-t" not in ids
    assert "java.lang.t.s-t" not in ids


# --- ids (D14 and collisions) -----------------------------------------------


def test_a_colliding_id_fails_the_build(trees, tmp_path):
    target = trees["opengrep-rules"] / "javascript" / "express" / "security" / "a.yaml"
    target.write_bytes(
        target.read_bytes()
        + b"  - id: r2\n    languages: [javascript]\n    pattern: x\n    metadata: {category: security}\n"
    )
    with pytest.raises(ValueError, match=re.escape("javascript.express.security.a.r2")):
        bb.build(trees, tmp_path / "out")


def test_a_dotted_file_name_and_a_directory_collide_too(trees, tmp_path):
    # javascript/a.b.yaml and javascript/a/b.yaml both namespace to javascript.a.b.<id>
    rule = "rules:\n  - id: r\n    languages: [javascript]\n    pattern: {}\n    metadata: {{category: security}}\n"
    (trees["opengrep-rules"] / "javascript" / "a.b.yaml").write_bytes(
        rule.format("one").encode()
    )
    (trees["opengrep-rules"] / "javascript" / "a").mkdir()
    (trees["opengrep-rules"] / "javascript" / "a" / "b.yaml").write_bytes(
        rule.format("two").encode()
    )
    with pytest.raises(ValueError, match=re.escape("javascript.a.b.r")):
        bb.build(trees, tmp_path / "out")


def test_a_bare_on_key_stays_a_string(trees, tmp_path):
    source = bb.SOURCES["opengrep-rules"]
    rule = next(
        r
        for rs in bb.collect(trees["opengrep-rules"], source).values()
        for r in rs
        if r["id"] == "yaml.ci.on.wf"
    )
    assert "on" in rule  # a YAML 1.1 loader would have made this key True
    assert True not in rule
    assert rule["options"]["on"] is True  # `true` is still a boolean
    assert rule["options"]["Flag"] is True  # TRUE, True and true all are
    assert rule["options"]["other"] is False
    assert rule["options"]["off"] == "no"  # but off / no / on / yes are not

    out = _build(trees, tmp_path)
    text = (out / "yaml.yaml").read_bytes().decode("utf-8")
    assert "'on':" in text  # quoted, so no parser can read it back as a boolean
    # and both YAML 1.1's loader and the builder's read the written file the same way
    assert yaml.safe_load(text)["rules"] == [rule]


# --- D15: exclusions are data ----------------------------------------------


def test_join_rules_are_dropped_with_their_reason(trees, tmp_path):
    manifest = bb.build(trees, tmp_path / "out")
    (record,) = _exclusions(manifest, "mode")
    assert (record["source"], record["mode"]) == ("elttam", "join")
    assert record["id"] == "elttam.generic.jsp.jsp-join"
    assert "opengrep" in record["reason"]
    assert "elttam.generic.jsp.jsp-join" not in _ids(tmp_path / "out")


def test_an_excluded_id_is_dropped_with_its_reason(trees, tmp_path):
    manifest = bb.build(trees, tmp_path / "out")
    (record,) = _exclusions(manifest, "id")
    assert record["source"] == "0xdea"
    assert record["id"] == "0xdea.c.use-after-free.raptor-use-after-free"
    assert "stack" in record["reason"]
    assert not any("raptor-use-after-free" in i for i in _ids(tmp_path / "out"))


def test_a_proprietary_rule_is_dropped_with_its_reason(trees, tmp_path):
    # R9: a rule that declares a proprietary license in its own metadata is not
    # one the bundle's open-source notices cover. The guard is general (any
    # source, any casing), and a rule under another license is untouched.
    proprietary = {
        "lgpl-cc": "Proprietary",
        "opengrep-rules": "proprietary license - copyright \u00a9 Semgrep, Inc.",
        "0xdea": "PROPRIETARY",
        "elttam": "Commercial, all rights reserved (proprietary)",
    }
    assert set(proprietary) == set(bb.SOURCES)
    dropped: dict[str, str] = {}
    kept: set[str] = set()
    for name, text in proprietary.items():
        source = bb.SOURCES[name]
        for stem, license_text in (("prop", text), ("open", "MIT")):
            path = (
                trees[name]
                / source.rules_root
                / "java"
                / source.globs[0].replace("*", stem)
            )
            doc = {
                "rules": [
                    {
                        "id": "lic",
                        "languages": ["java"],
                        "pattern": f"{name}_{stem}()",
                        "message": "planted",
                        "severity": "ERROR",
                        "metadata": {"category": "security", "license": license_text},
                    }
                ]
            }
            path.write_bytes(yaml.safe_dump(doc, allow_unicode=True).encode("utf-8"))
            rule_id = ".".join(
                part for part in (source.prefix, "java", path.stem, "lic") if part
            )
            if stem == "prop":
                dropped[rule_id] = text
            else:
                kept.add(rule_id)

    manifest = bb.build(trees, tmp_path / "out")

    ids = _ids(tmp_path / "out")
    assert not set(dropped) & ids
    assert kept <= ids  # the same rule under another license stays
    records = _exclusions(manifest, "license")
    assert {e["id"] for e in records} == set(dropped)
    for record in records:
        assert record["source"] in bb.SOURCES
        assert dropped[record["id"]] in record["reason"]  # the license text, quoted
        assert "proprietary" in record["reason"]
    # a license given as a list is read too, and an absent one is not a finding
    assert bb._proprietary_license({"metadata": {"license": ["MIT", "Proprietary"]}})
    assert bb._proprietary_license({"metadata": {"license": ["MIT"]}}) is None
    assert bb._proprietary_license({"metadata": {"category": "security"}}) is None
    assert bb._proprietary_license({"id": "no-metadata"}) is None


CONFIGURED_DIRS = [
    pytest.param(source.name, directory, id=f"{source.name}:{directory}")
    for source in bb.SOURCES.values()
    for directory in source.skip_dirs
]


@pytest.mark.parametrize(("source_name", "directory"), CONFIGURED_DIRS)
def test_an_excluded_directory_is_dropped_with_its_reason(
    trees, tmp_path, source_name, directory
):
    # Plant a security rule in the directory and prove the builder leaves it out.
    source = bb.SOURCES[source_name]
    planted = (
        trees[source_name]
        / source.rules_root
        / directory
        / source.globs[0].replace("*", "planted")
    )
    planted.parent.mkdir(parents=True, exist_ok=True)
    planted.write_bytes(
        b"rules:\n  - id: planted\n    languages: [generic]\n    pattern: x\n    metadata: {category: security}\n"
    )
    manifest = bb.build(trees, tmp_path / "out")
    planted_id = ".".join(
        part
        for part in (source.prefix, *directory.split("/"), planted.stem, "planted")
        if part
    )
    assert planted_id not in _ids(tmp_path / "out")
    record = next(
        e
        for e in _exclusions(manifest, "directory")
        if (e["source"], e["path"]) == (source_name, directory)
    )
    assert record["reason"]
    assert record["rules"] >= 1


def test_a_tree_without_its_rules_root_fails_loudly(trees, tmp_path):
    shutil.rmtree(trees["lgpl-cc"] / "rules" / "lgpl-cc")
    with pytest.raises(ValueError, match="lgpl-cc"):
        bb.build(trees, tmp_path / "out")


def test_a_directory_is_excluded_by_its_whole_name(trees, tmp_path):
    # `noisy` is excluded; a sibling that merely starts with it is a language of its own
    sibling = trees["0xdea"] / "rules" / "noisy-extra" / "x.yaml"
    sibling.parent.mkdir()
    sibling.write_bytes(
        b"rules:\n  - id: kept\n    languages: [generic]\n    pattern: x\n    metadata: {category: security}\n"
    )
    bb.build(trees, tmp_path / "out")
    assert "0xdea.noisy-extra.x.kept" in _ids(tmp_path / "out")


def test_the_fixtures_excluded_directories_are_all_recorded(trees, tmp_path):
    manifest = bb.build(trees, tmp_path / "out")
    got = {
        (e["source"], e["path"]): e["rules"] for e in _exclusions(manifest, "directory")
    }
    assert got == {
        ("opengrep-rules", "generic/secrets"): 1,
        ("opengrep-rules", "problem-based-packs"): 1,
        ("0xdea", "noisy"): 1,
        ("elttam", "yaml/kubernetes"): 1,
    }


def test_the_configured_exclusions_are_the_decided_ones():
    assert list(bb.SOURCES) == [
        "lgpl-cc",
        "opengrep-rules",
        "0xdea",
        "elttam",
    ]  # D16's precedence
    assert "generic/secrets" in bb.SOURCES["opengrep-rules"].skip_dirs
    assert "yaml/kubernetes" in bb.SOURCES["elttam"].skip_dirs
    assert "noisy" in bb.SOURCES["0xdea"].skip_dirs
    assert (
        "0xdea.c.use-after-free.raptor-use-after-free" in bb.SOURCES["0xdea"].skip_ids
    )
    for source in bb.SOURCES.values():
        assert "join" in source.skip_modes, source.name
        for exclusion in (source.skip_dirs, source.skip_modes, source.skip_ids):
            assert all(reason.strip() for reason in exclusion.values()), source.name


def test_the_pins_are_exact():
    for source in bb.SOURCES.values():
        assert source.url.startswith("https://"), source.name
        assert re.fullmatch(r"[0-9a-f]{64}", source.sha256), source.name
        assert source.pin in source.url, source.name
    assert bb.SOURCES["lgpl-cc"].pin == "v2.10.1"
    assert (
        bb.SOURCES["opengrep-rules"].pin == "f1d2b562b414783763fd02a6ed2736eaed622efa"
    )
    assert bb.SOURCES["0xdea"].pin == "e0121ac19d9fa259a44f3a24d3e42c95719b17c7"
    assert bb.SOURCES["elttam"].pin == "244268562cc92d33f54b8a60a187df5520f91b26"
    assert bb.SOURCES["lgpl-cc"].globs == ("rule-*.yml",)


# --- output bytes -----------------------------------------------------------


def _bytes_of(directory: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in sorted(directory.iterdir())}


def test_two_builds_are_byte_identical(trees, tmp_path):
    first = _build(trees, tmp_path, "first")
    # a second tree at another path, written in another order
    other = tmp_path / "elsewhere"
    other.mkdir()
    moved = {}
    for name in reversed(list(trees)):
        moved[name] = other / name
        shutil.copytree(trees[name], moved[name])
    second = _build(moved, tmp_path, "second")
    assert _bytes_of(first) == _bytes_of(second)
    assert set(_bytes_of(first)) == {*EXPECTED_FILES, "SOURCES.json"}


def test_files_are_lf(trees, tmp_path):
    # a source file with CRLF endings, as a Windows checkout may carry
    crlf = trees["opengrep-rules"] / "javascript" / "crlf.yaml"
    crlf.write_bytes(
        b"rules:\r\n  - id: crlf\r\n    languages: [javascript]\r\n    pattern: |\r\n      a\r\n      b\r\n"
        b"    metadata:\r\n      category: security\r\n"
    )
    out = _build(trees, tmp_path)
    assert "javascript.crlf.crlf" in _ids(out)
    for name, data in _bytes_of(out).items():
        assert b"\r" not in data, name
        assert data.endswith(b"\n"), name


def test_a_rebuild_removes_a_file_the_sources_no_longer_produce(trees, tmp_path):
    out = _build(trees, tmp_path)
    stale = out / "ocaml.yaml"
    stale.write_bytes(b"rules: []\n")
    unrelated = out / "notes.txt"
    unrelated.write_bytes(b"keep me")
    bb.build(trees, out)
    assert not stale.exists()
    assert unrelated.read_bytes() == b"keep me"


# --- the license header (R15) -----------------------------------------------


_SOURCE_LINE = re.compile(r"^#   (\S+) +pinned at (\S+)  (.+)$")


def _header(path: Path) -> list[str]:
    """The comment lines a generated file opens with, up to its first non-comment line."""
    lines = []
    for line in path.read_bytes().decode("utf-8").splitlines():
        if not line.startswith("#"):
            break
        lines.append(line)
    return lines


def _header_sources(path: Path) -> dict[str, tuple[str, str]]:
    """source name -> (pin, license), as the header's source lines give them."""
    return {
        m.group(1): (m.group(2), m.group(3))
        for line in _header(path)
        if (m := _SOURCE_LINE.match(line))
    }


def test_each_file_names_the_sources_that_gave_it_rules_with_pin_and_license(
    trees, tmp_path
):
    # LGPL-2.1 section 1 asks that notices referring to the license stay with
    # the files; a file's header names the sources whose rules are in THAT file
    # (java.yaml holds GitLab's and elttam's, none from the snapshot or 0xdea),
    # each with its pin and the license THIRD_PARTY_LICENSES.md gives it.
    out = _build(trees, tmp_path)
    expected = {
        name: (source.pin, source.license) for name, source in bb.SOURCES.items()
    }
    assert expected["opengrep-rules"][1] == "LGPL-2.1 with the Commons Clause"
    assert expected["lgpl-cc"][1] == "LGPL-2.1 with the Commons Clause"
    assert expected["0xdea"][1] == expected["elttam"][1] == "MIT"

    assert _header_sources(out / "java.yaml") == {
        "lgpl-cc": expected["lgpl-cc"],
        "elttam": expected["elttam"],
    }
    assert _header_sources(out / "c.yaml") == {
        "opengrep-rules": expected["opengrep-rules"],
        "0xdea": expected["0xdea"],
    }
    assert _header_sources(out / "generic.yaml") == {
        "opengrep-rules": expected["opengrep-rules"]
    }
    assert _header_sources(out / "properties.yaml") == {"lgpl-cc": expected["lgpl-cc"]}

    # and for every file, exactly the sources its rule ids come from
    prefixes = {n: s.prefix for n, s in bb.SOURCES.items()}
    for name, rules in _rules_by_file(out).items():
        owners = {
            next(
                (
                    n
                    for n, prefix in prefixes.items()
                    if prefix and rule["id"].startswith(f"{prefix}.")
                ),
                "opengrep-rules",
            )
            for rule in rules
        }
        assert set(_header_sources(out / name)) == owners, name


def test_each_header_says_it_is_generated_what_changed_when_and_where_the_notices_are(
    trees, tmp_path
):
    # LGPL-2.1 section 2(b): a modified file carries a prominent notice that it
    # was changed, and the date. No build-time clock goes in: --check compares bytes.
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", bb.BUNDLE_DATE)
    out = _build(trees, tmp_path)
    for path in sorted(out.glob("*.yaml")):
        header = "\n".join(_header(path))
        assert path.read_bytes().startswith(
            b"# Generated by scripts/dev/build_rule_bundle.py"
        )
        assert "Do not edit by hand" in header, path.name
        assert f"on {bb.BUNDLE_DATE}" in header, path.name
        assert "metadata.category: security" in header, path.name
        for change in ("prefix", "excluded", "duplicates", "merged"):
            assert change in header, (path.name, change)
        assert "THIRD_PARTY_LICENSES.md" in header, path.name
        # the header is comments only: the file still loads as the same rules
        assert yaml.safe_load(path.read_bytes().decode("utf-8"))["rules"]


def test_the_header_changes_only_with_the_sources_and_the_date(
    trees, tmp_path, monkeypatch
):
    first = _build(trees, tmp_path, "first")
    second = _build(trees, tmp_path, "second")
    assert _bytes_of(first) == _bytes_of(second)  # nothing in it is a timestamp
    monkeypatch.setattr(bb, "BUNDLE_DATE", "2030-01-02")
    third = _build(trees, tmp_path, "third")
    assert b"on 2030-01-02" in (third / "c.yaml").read_bytes()
    assert b"2026-10-29" not in (third / "c.yaml").read_bytes()
    # the date is in the file bytes (so their hashes), never in the rules or the sources
    before = json.loads((first / "SOURCES.json").read_bytes())
    after = json.loads((third / "SOURCES.json").read_bytes())
    assert after["sources"] == before["sources"]
    assert after["exclusions"] == before["exclusions"]
    for name, entry in before["files"].items():
        assert after["files"][name]["rules"] == entry["rules"]
        assert after["files"][name]["sha256"] != entry["sha256"]


# --- the manifest -----------------------------------------------------------


def test_the_manifest_records_each_file(trees, tmp_path):
    manifest = bb.build(trees, tmp_path / "out")
    out = tmp_path / "out"

    assert {
        name: entry["rules"] for name, entry in manifest["files"].items()
    } == EXPECTED_FILES
    for name, entry in manifest["files"].items():
        assert entry["sha256"] == hashlib.sha256((out / name).read_bytes()).hexdigest()

    assert list(manifest["sources"]) == list(bb.SOURCES)
    for name, source in bb.SOURCES.items():
        recorded = manifest["sources"][name]
        assert (recorded["url"], recorded["sha256"], recorded["pin"]) == (
            source.url,
            source.sha256,
            source.pin,
        )
        assert (recorded["rules_root"], recorded["prefix"]) == (
            source.rules_root,
            source.prefix,
        )
    assert {n: s["rules"] for n, s in manifest["sources"].items()} == {
        "lgpl-cc": 4,
        "opengrep-rules": 6,
        "0xdea": 1,
        "elttam": 1,
    }

    assert {e["kind"] for e in manifest["exclusions"]} == {
        "directory",
        "mode",
        "id",
        "body-duplicate",
    }
    assert all(e["reason"] and e["source"] for e in manifest["exclusions"])
    assert len(_exclusions(manifest, "body-duplicate")) == 5


def test_sources_json_is_deterministic_json_matching_the_manifest(trees, tmp_path):
    manifest = bb.build(trees, tmp_path / "out")
    data = (tmp_path / "out" / "SOURCES.json").read_bytes()
    assert json.loads(data) == manifest
    assert data == (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode(
        "utf-8"
    )
    assert b"\r" not in data


# --- fetching and unpacking -------------------------------------------------


def _tarball(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


class _FakeUrlopen:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.calls: list[tuple[str, float | None]] = []

    def __call__(self, request: Any, timeout: float | None = None) -> io.BytesIO:
        self.calls.append((request.full_url, timeout))
        return io.BytesIO(self.payload)


def _fake_source(payload: bytes, sha256: str | None = None) -> bb.Source:
    return dataclasses.replace(
        bb.SOURCES["elttam"],
        url="https://example.invalid/pack.tar.gz",
        sha256=sha256 or hashlib.sha256(payload).hexdigest(),
    )


def test_fetch_downloads_verifies_and_caches(tmp_path, monkeypatch):
    payload = _tarball({"pack-1/rules/a.yaml": b"rules: []\n"})
    fake = _FakeUrlopen(payload)
    monkeypatch.setattr(bb.urllib.request, "urlopen", fake)
    source = _fake_source(payload)

    path = bb.fetch(source, tmp_path / "cache")
    assert path.read_bytes() == payload
    assert fake.calls == [
        (source.url, bb.FETCH_TIMEOUT_S)
    ]  # a timeout is always passed

    assert bb.fetch(source, tmp_path / "cache") == path
    assert len(fake.calls) == 1  # the verified cache is reused
    assert [p.name for p in (tmp_path / "cache").iterdir()] == [path.name]


def test_a_corrupt_cache_entry_is_downloaded_again(tmp_path, monkeypatch):
    payload = _tarball({"pack-1/a.yaml": b"x\n"})
    fake = _FakeUrlopen(payload)
    monkeypatch.setattr(bb.urllib.request, "urlopen", fake)
    source = _fake_source(payload)
    path = bb.fetch(source, tmp_path / "cache")
    path.write_bytes(b"truncated")

    assert bb.fetch(source, tmp_path / "cache").read_bytes() == payload
    assert len(fake.calls) == 2


def test_a_sha256_mismatch_names_the_url_and_both_hashes(tmp_path, monkeypatch):
    # GitLab builds its archives on demand, so a mismatch must be quick to diagnose.
    payload = _tarball({"pack-1/a.yaml": b"x\n"})
    monkeypatch.setattr(bb.urllib.request, "urlopen", _FakeUrlopen(payload))
    expected = "0" * 64
    source = _fake_source(payload, sha256=expected)

    with pytest.raises(ValueError) as caught:
        bb.fetch(source, tmp_path / "cache")
    message = str(caught.value)
    assert source.url in message
    assert expected in message
    assert hashlib.sha256(payload).hexdigest() in message
    assert (
        list((tmp_path / "cache").iterdir()) == []
    )  # nothing unverified is left to be reused


def test_extract_returns_the_single_top_directory(tmp_path):
    tarball = tmp_path / "t.tar.gz"
    tarball.write_bytes(_tarball({"pack-abc/rules/a.yaml": b"rules: []\n"}))
    root = bb.extract(tarball, tmp_path / "work")
    assert root == tmp_path / "work" / "pack-abc"
    assert (root / "rules" / "a.yaml").read_bytes() == b"rules: []\n"


def test_extract_refuses_a_path_that_leaves_the_directory(tmp_path):
    tarball = tmp_path / "evil.tar.gz"
    tarball.write_bytes(_tarball({"../escaped.txt": b"x"}))
    with pytest.raises(tarfile.TarError):
        bb.extract(tarball, tmp_path / "work")
    assert not (tmp_path / "escaped.txt").exists()


# --- the command line --------------------------------------------------------


@pytest.fixture
def cli(trees, tmp_path, monkeypatch) -> Callable[..., int]:
    monkeypatch.setattr(bb, "fetch_trees", lambda cache, work: trees)

    def run(*extra: str) -> int:
        return bb.main(
            [
                "--out",
                str(tmp_path / "bundle"),
                "--cache",
                str(tmp_path / "cache"),
                *extra,
            ]
        )

    return run


def test_main_builds_into_out(cli, tmp_path, capsys):
    assert cli() == 0
    assert set(_bytes_of(tmp_path / "bundle")) == {*EXPECTED_FILES, "SOURCES.json"}
    assert "7 files, 12 rules" in capsys.readouterr().out


def test_check_passes_on_an_unchanged_bundle(cli, tmp_path):
    cli()
    before = _bytes_of(tmp_path / "bundle")
    assert cli("--check") == 0
    assert _bytes_of(tmp_path / "bundle") == before  # --check never writes


def test_check_names_a_hand_edited_file(cli, tmp_path, capsys):
    cli()
    edited = tmp_path / "bundle" / "java.yaml"
    edited.write_bytes(edited.read_bytes().replace(b"triple", b"tripled"))
    capsys.readouterr()
    assert cli("--check") == 1
    err = capsys.readouterr().err
    assert "java.yaml" in err
    assert "c.yaml" not in err  # only what differs


def test_check_names_a_missing_and_an_unexpected_file(cli, tmp_path, capsys):
    cli()
    (tmp_path / "bundle" / "python.yaml").unlink()
    (tmp_path / "bundle" / "ocaml.yaml").write_bytes(b"rules: []\n")
    (tmp_path / "bundle" / "SOURCES.json").unlink()
    capsys.readouterr()
    assert cli("--check") == 1
    err = capsys.readouterr().err
    assert "python.yaml" in err
    assert "ocaml.yaml" in err
    assert "SOURCES.json" in err


def test_check_on_a_missing_directory_fails(cli, capsys):
    assert cli("--check") == 1
    assert "c.yaml" in capsys.readouterr().err


def test_main_reports_a_failed_fetch_and_exits_2(tmp_path, monkeypatch, capsys):
    def boom(cache: Path, work: Path) -> dict[str, Path]:
        raise ValueError("lgpl-cc: sha256 mismatch for https://example.invalid/x")

    monkeypatch.setattr(bb, "fetch_trees", boom)
    assert (
        bb.main(["--out", str(tmp_path / "bundle"), "--cache", str(tmp_path / "cache")])
        == 2
    )
    assert "sha256 mismatch for https://example.invalid/x" in capsys.readouterr().err
