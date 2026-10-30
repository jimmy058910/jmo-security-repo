"""scripts/core/rule_bundle.py: which of the bundle's rule files a repository needs.

opengrep loads every rule of every `--config` file into memory before it scans
a byte, so a scan hands it only the files of the languages the repository has
(plus `generic`). The selection reads file NAMES, from the same walk the scan
already made; it never opens a file.

The language table is data, taken from the extensions opengrep itself assigns
each language (measured on 1.32.0 with one `pattern-regex` rule per language
and `paths.scanned`), so a name here is a file opengrep would scan with that
language's rules. A name it would not scan selects a rule file for nothing; a
name it would scan and the table lacks drops that language's rules silently.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.cli.scan_jobs.tool_loop import collect_files, iter_repo_files
from scripts.core import rule_bundle
from scripts.core.rule_bundle import BUNDLE_DIR, LANGUAGE_PATTERNS, select_configs

GENERIC = BUNDLE_DIR / "generic.yaml"


def _stems(files) -> list[str]:
    return [config.stem for config in select_configs(files)]


def test_typescript_selects_javascript_too():
    """opengrep runs `languages: [javascript]` rules on `.ts` and `.tsx`: all 31
    hits on a TypeScript app (2026-10-22) were JavaScript rules. Choosing only
    typescript.yaml would drop the 177-rule JavaScript file from every TS repo."""
    assert _stems([Path("web/app.ts")]) == ["generic", "javascript", "typescript"]
    assert _stems([Path("web/App.tsx")]) == ["generic", "javascript", "typescript"]


def test_every_typescript_pattern_is_a_javascript_pattern():
    """Decision 6 as an invariant: a TypeScript file always selects javascript.yaml
    too. A `.mts` added to the typescript row alone would give that repository
    typescript.yaml and none of the JavaScript rules opengrep runs on it."""
    missing = set(LANGUAGE_PATTERNS["typescript"]) - set(
        LANGUAGE_PATTERNS["javascript"]
    )
    assert not missing, (
        f"typescript patterns the javascript row lacks: {sorted(missing)}"
    )


def test_generic_is_always_selected():
    """generic.yaml carries the rules that match by file name, whatever the
    language (nginx and apache configs, Bicep, Handlebars), so no file
    extension stands for it and a repository of any kind gets it."""
    for files in ([], [Path("LICENSE")], [Path("a.py"), Path("b.go")]):
        assert GENERIC in select_configs(files), files


def test_a_python_repo_gets_python_and_generic_only():
    """Every file a repository has that no language owns selects nothing, so the
    memory a scan pays is the languages it has, not the bundle's 25 files."""
    files = [
        Path("pkg/__init__.py"),
        Path("pkg/app.py"),
        Path("tests/test_app.py"),
        Path("README.md"),
        Path("requirements.txt"),
        Path("setup.cfg"),
        Path("LICENSE"),
    ]

    assert _stems(files) == ["generic", "python"]


def test_every_bundle_file_has_patterns():
    """The table's keys ARE the bundle's file stems. A rebuilt bundle that gains
    a language fails here until the table learns its file names; a stem the
    table lacks would be a rule file no repository could ever select."""
    stems = {config.stem for config in BUNDLE_DIR.glob("*.yaml")}

    assert stems, f"no rule file under {BUNDLE_DIR}"
    assert set(LANGUAGE_PATTERNS) == stems
    # generic is chosen by no file name (above), every other language by some.
    assert [s for s in stems - {"generic"} if not LANGUAGE_PATTERNS[s]] == []


def test_no_files_selects_nothing_but_generic():
    assert select_configs([]) == [GENERIC]
    assert select_configs(iter(())) == [GENERIC]


def test_the_patterns_are_bare_names_because_only_the_name_is_matched():
    """`select_configs` matches a file's last component. A pattern with a
    separator in it could never match, and would select nothing without a word.
    The scan's walk adds its own `**/` in front (the way every descriptor row
    writes its file patterns), so the table keeps none. Except generic's, which
    are opengrep's own include globs and read the path (below)."""
    patterns = [
        p
        for stem, group in LANGUAGE_PATTERNS.items()
        if stem != "generic"
        for p in group
    ]

    assert patterns
    assert [p for p in patterns if "/" in p or "\\" in p] == []
    # The only separator generic's carry is the `<directory>/*` form, which the
    # trigger reads as a directory name.
    assert [
        p
        for p in LANGUAGE_PATTERNS["generic"]
        if ("/" in p or "\\" in p) and not (p.count("/") == 1 and p.endswith("/*"))
    ] == []


def test_a_directory_named_like_a_language_selects_nothing():
    """The name decides, not the path above it: `Dockerfile/` and `tests.py/`
    are directories, and the files inside them are notes."""
    files = [Path("Dockerfile/README.md"), Path("docs.py/index.txt")]

    assert _stems(files) == ["generic"]


def test_it_takes_the_str_paths_the_walk_hands_over():
    """`collect_files` returns `str`, and `ScanContext.files` is a tuple of
    them: the caller never holds a `Path`."""
    assert _stems(["src/main.rs", "Cargo.toml"]) == ["generic", "rust"]


@pytest.mark.parametrize(
    "name", ["a.c", "a.h", "a.cpp", "a.cc", "a.cxx", "a.hpp", "a.hh", "a.hxx", "a.C"]
)
def test_the_c_and_cpp_extensions_select_c_yaml(name):
    """0xdea's rules are `languages: [c, cpp]` and live in c.yaml, the one file
    for both, so a C++-only repository still needs it."""
    assert "c" in _stems([Path("src") / name])


@pytest.mark.parametrize(
    ("name", "stem"),
    [
        ("images/app/Dockerfile", "dockerfile"),
        ("service.Dockerfile", "dockerfile"),
        ("infra/main.tf", "terraform"),
        ("infra/prod.hcl", "terraform"),
        ("app/build.gradle.kts", "kotlin"),
        ("conf/app.properties", "properties"),
        ("deploy/ci.yml", "yaml"),
    ],
)
def test_the_names_the_plan_spells_out(name, stem):
    assert stem in _stems([Path(name)])


def test_every_pattern_selects_its_own_file():
    """Each pattern, written out as a file name, selects its own language. A
    stem whose later patterns never matched (a loop that stops at the first)
    would pass the tests above and leave those names unscanned."""
    wrong = []
    for stem, patterns in LANGUAGE_PATTERNS.items():
        for pattern in patterns:
            name = pattern.replace("*", "x")
            if stem not in _stems([Path(name)]):
                wrong.append((stem, pattern))

    assert wrong == []


def test_the_selected_files_are_the_bundles_own_and_sorted():
    files = [Path(p.replace("*", "x")) for g in LANGUAGE_PATTERNS.values() for p in g]
    chosen = select_configs(files)

    assert chosen == sorted(chosen)
    assert {config.parent for config in chosen} == {BUNDLE_DIR}
    assert all(config.is_file() for config in chosen)


@pytest.mark.parametrize("case_sensitive", [True, False])
def test_where_case_is_ignored_the_pattern_is_folded_with_the_name(
    monkeypatch, case_sensitive
):
    """A pattern spelled with capitals (`Dockerfile`) must still match its name
    on a platform that ignores case, where the name is folded to lowercase: the
    table's own capitalised patterns each have a lowercase twin, so the real
    table cannot show it. A one-language table can."""
    monkeypatch.setattr(rule_bundle, "GLOB_CASE_SENSITIVE", case_sensitive)
    monkeypatch.setattr(
        rule_bundle, "LANGUAGE_PATTERNS", {"python": ("Special.PY",), "generic": ()}
    )

    assert ("python" in _stems([Path("special.py")])) is (not case_sensitive)
    assert "python" in _stems([Path("Special.PY")])


@pytest.mark.parametrize("case_sensitive", [True, False])
def test_names_are_matched_by_the_case_rule_collect_files_uses(
    tmp_path, monkeypatch, case_sensitive
):
    """One rule decides what the scan's walk calls a TypeScript file and which
    rule file that file selects. The walk's glob ignores case on Windows only;
    were `select_configs` always case-sensitive, a walked `App.TS` there would
    reach opengrep (its row's file patterns found it) and select no TypeScript
    rules. Both are driven by the one constant, flipped both ways."""
    monkeypatch.setattr(rule_bundle, "GLOB_CASE_SENSITIVE", case_sensitive)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "App.TS").write_text("export {};\n", encoding="utf-8")

    globbed = collect_files(
        repo, tuple(f"**/{p}" for p in LANGUAGE_PATTERNS["typescript"]), "opengrep"
    )
    selected = _stems(iter_repo_files(repo))

    expected = not case_sensitive
    assert bool(globbed) is expected
    assert ("typescript" in selected) is expected
    assert ("javascript" in selected) is expected
    # What the walk handed back, as `ctx.files` carries it, selects the same.
    assert ("typescript" in _stems(globbed)) is expected


# --- generic.yaml's own file patterns (F3) ----------------------------------------


def _generic_include_globs() -> set[str]:
    """Every `paths.include` glob of every rule in generic.yaml: the files
    opengrep reads those rules on."""
    import yaml

    rules = yaml.safe_load(GENERIC.read_text(encoding="utf-8"))["rules"]
    return {
        glob for rule in rules for glob in (rule.get("paths") or {}).get("include", [])
    }


def test_generics_patterns_are_its_rules_include_globs():
    """The table's `generic` row IS the union of the include globs of the rules in
    generic.yaml. A rebuilt bundle that adds a rule for another file name fails
    here until the row learns it; one the row lists and no rule reads would keep
    a repository of nothing else from being skipped, for no reason."""
    assert _generic_include_globs()
    assert set(LANGUAGE_PATTERNS["generic"]) == _generic_include_globs()


@pytest.mark.parametrize(
    "path",
    [
        "nginx.conf",
        "conf.d/default.conf",
        "infra/main.bicep",
        "views/layout.hbs",
        "views/layout.mustache",
        "force-app/Foo.page",
        "force-app/Foo.component",
        "force-app/Foo.page-meta.xml",
        "app/build.gradle",
        "app/mobile-build.gradle",
        "hosts/site.vhost",
        # Measured on opengrep 1.32.0: the globs read the whole path, so a file
        # with no extension is read when a directory above it is named for one.
        "etc/nginx/sites-enabled/default",
        "sites-available/example.com",
        "etc/nginx/plain",
        "conf/app",
        "vhosts/example",
    ],
)
def test_a_file_only_generic_reads_has_rules(path):
    """A repository of nothing but an nginx or Visualforce file is read by the
    rules generic.yaml carries, so it must not be skipped as having no language."""
    assert rule_bundle.has_rules_for([Path(path)])
    assert rule_bundle.has_rules_for([path])


@pytest.mark.parametrize(
    "path",
    [
        "README.md",
        "LICENSE",
        "notes.txt",
        "docs/guide.md",
        # `*build.gradle` ends the name; Kotlin's script is kotlin.yaml's.
        "build.gradle.backup",
        "pkg/sites/enabled/default",
    ],
)
def test_a_file_no_rule_reads_has_no_rules(path):
    assert not rule_bundle.has_rules_for([Path(path)])


def test_a_language_file_has_rules_and_nothing_walked_has_none():
    assert rule_bundle.has_rules_for([Path("a.py")])
    assert rule_bundle.has_rules_for(iter([Path("README.md"), Path("a.go")]))
    assert not rule_bundle.has_rules_for([])
    assert not rule_bundle.has_rules_for(iter(()))


def test_generic_is_still_always_selected_and_selects_no_other_file():
    """`select_configs` names generic.yaml for any repository, an nginx one
    included, and gives it no language's file."""
    assert select_configs([Path("nginx.conf")]) == [GENERIC]
    assert select_configs([Path("README.md")]) == [GENERIC]


@pytest.mark.parametrize("case_sensitive", [True, False])
def test_generic_patterns_follow_the_case_rule_too(monkeypatch, case_sensitive):
    """Where case is ignored (Windows), `NGINX.CONF` is a `*.conf`, as it is to
    the walk's own glob; where it counts, it is not."""
    monkeypatch.setattr(rule_bundle, "GLOB_CASE_SENSITIVE", case_sensitive)

    assert rule_bundle.has_rules_for([Path("etc/NGINX.CONF")]) is (not case_sensitive)
    assert rule_bundle.has_rules_for([Path("X.BICEP")]) is (not case_sensitive)
    assert rule_bundle.has_rules_for([Path("SITES-ENABLED/default")]) is (
        not case_sensitive
    )
