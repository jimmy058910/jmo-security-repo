"""Which rule files of the committed bundle a repository needs (v2.0.0 Phase 5).

opengrep loads every rule of every ``--config`` file before it scans a file, so
a scan hands it the files of the languages the repository has, plus
``generic.yaml`` (rules matched by file name, whatever the language), and not
all 25. ``select_configs`` reads the names of the files the scan's walk found;
it never opens one. ``has_rules_for`` says whether any of them is a file the
bundle has a rule for at all, generic.yaml's own included: the row is skipped
when none is.

``LANGUAGE_PATTERNS`` is data: for each bundle file (named by its language
stem), the file names that select it. They are the extensions opengrep itself
assigns the language, measured on 1.32.0 with one ``pattern-regex`` rule per
language and ``paths.scanned``: a name listed here is a file opengrep scans
with that language's rules, and one it does not scan is not listed. A name
missing from the table would drop that language's rules without a word, so the
table keeps every spelling opengrep takes. Shebang-only scripts are not among
them: opengrep did not scan one.

This module is ``core``: it imports the standard library and nothing from
``scripts.cli``, so ``tool_descriptors`` can import it.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from fnmatch import fnmatchcase
from pathlib import Path

BUNDLE_DIR = Path(__file__).resolve().parent.parent / "jmo_rules"

# The scan's walk matches file names with the platform's own case rule,
# pathlib's default, passed explicitly. Given none, Python 3.13 matches a
# pattern's wildcard-free part (the `Dockerfile` of `**/Dockerfile`) with a
# stat, which follows the filesystem, and returns it spelled as the PATTERN
# spells it: where the filesystem ignores case (Windows, macOS), a file named
# `sub/dockerfile` came back as `sub/Dockerfile`, and every exact-name test
# accepted it (#1421). Given a rule, 3.13 lists each directory, as 3.12 always
# did, so a path it returns is spelled as it is on disk.
#
# Defined here, and imported by `tool_loop`, because `select_configs` must apply
# the same rule to the same files and cannot import it from `tool_loop`: `core`
# imports nothing from `scripts.cli`. Both read it as
# `rule_bundle.GLOB_CASE_SENSITIVE` at call time, so one patch moves both.
GLOB_CASE_SENSITIVE = os.path.normcase("Aa") == "Aa"

# Bare file-name patterns, matched against a file's last path component. The
# scan's walk puts `**/` in front of each to find the files.
LANGUAGE_PATTERNS: dict[str, tuple[str, ...]] = {
    "apex": ("*.cls", "*.trigger"),
    # Not `*.ksh`, which shellcheck's row reads: opengrep scans no Korn script.
    "bash": ("*.sh", "*.bash"),
    # 0xdea's rules are `[c, cpp]` and live here, so every C++ spelling
    # opengrep scans selects this file. `.C` is C++ in its own right, where
    # case counts.
    "c": (
        *("*.c", "*.h", "*.C"),
        *("*.cc", "*.cpp", "*.cxx", "*.c++", "*.pcc", "*.tpp"),
        *("*.hh", "*.hpp", "*.hxx", "*.inl", "*.ipp"),
    ),
    # `.edn` is data, which opengrep reads as Clojure.
    "clojure": ("*.clj", "*.cljs", "*.cljc", "*.edn"),
    "csharp": ("*.cs",),
    # The first three are `DOCKERFILE_PATTERNS` without its `**/` (hadolint's
    # row), which `tool_descriptors` cannot lend: it imports this module.
    # opengrep scans `Dockerfile` and `*.Dockerfile` and their lowercase
    # spellings, which a match that counts case does not fold into them, and
    # scans no `Dockerfile.dev`, which `Dockerfile.*` still names.
    "dockerfile": (
        *("Dockerfile", "Dockerfile.*", "*.Dockerfile"),
        *("dockerfile", "*.dockerfile"),
    ),
    # generic.yaml is always loaded (below), so these choose nothing. They say
    # which files its rules read, for `has_rules_for`: a repository of nothing
    # but an nginx config has no language and is still read. They are the
    # union of the `paths.include` globs of the rules in generic.yaml, and a
    # test keeps them so. opengrep matches an include glob against the whole
    # path (measured on 1.32.0): `*conf*` reads `conf/app` and `etc/nginx/plain`
    # as it reads `my.conf`, and `sites-enabled/*` reads a file under such a
    # directory at any depth. So these are not file names, and are matched
    # against each name and each directory above it; a pattern ending `/*`
    # names a directory. They are broad on purpose (`*conf*` reads `config.txt`).
    # Two rules have no include at all and read any file (a reverse shell, a
    # bidirectional character): no pattern stands for them, so they alone do
    # not make a tree worth scanning.
    "generic": (
        *("*.bicep", "*.component", "*.conf", "*.hbs", "*.html", "*.mustache"),
        *("*.page", "*.page-meta.xml", "*.vhost", "*build.gradle"),
        *("*conf*", "*nginx*", "*vhost*", "sites-available/*", "sites-enabled/*"),
    ),
    "go": ("*.go",),
    "html": ("*.html", "*.htm"),
    "java": ("*.java",),
    # opengrep runs JavaScript rules on TypeScript too (31 of 31 hits on a
    # TypeScript app, 2026-10-22), so `.ts` and `.tsx` select this file as
    # well as typescript.yaml.
    "javascript": ("*.js", "*.jsx", "*.cjs", "*.mjs", "*.ts", "*.tsx"),
    # `.ipynb` is JSON to opengrep.
    "json": ("*.json", "*.ipynb"),
    # `.kts` is Gradle's Kotlin script; `.ktm` a Kotlin module.
    "kotlin": ("*.kt", "*.kts", "*.ktm"),
    "ocaml": ("*.ml", "*.mli"),
    # opengrep reads `.phtml` and `.tpl` as PHP.
    "php": ("*.php", "*.phtml", "*.tpl"),
    # Not a language of opengrep's: its one rule is `generic` and reads
    # `*properties` (Spring's), so the file name is what selects it.
    "properties": ("*.properties",),
    "python": ("*.py", "*.pyi"),
    "ruby": ("*.rb",),
    "rust": ("*.rs",),
    "scala": ("*.scala",),
    "solidity": ("*.sol",),
    "swift": ("*.swift",),
    # opengrep reads `.hcl` and `.tfvars` as Terraform too.
    "terraform": ("*.tf", "*.hcl", "*.tfvars"),
    "typescript": ("*.ts", "*.tsx"),
    "yaml": ("*.yaml", "*.yml"),
}


def _fold(
    patterns: dict[str, tuple[str, ...]], names: set[str], dirs: set[str]
) -> tuple[dict[str, tuple[str, ...]], set[str], set[str]]:
    """The patterns and the names to match them against, folded to lowercase
    where the platform ignores case (see `GLOB_CASE_SENSITIVE`)."""
    if GLOB_CASE_SENSITIVE:
        return patterns, names, dirs
    return (
        {stem: tuple(p.lower() for p in group) for stem, group in patterns.items()},
        {name.lower() for name in names},
        {d.lower() for d in dirs},
    )


def _language_stems(files: Iterable[str | Path]) -> set[str]:
    """The stems of the languages whose file names match one of these files
    (`generic` is not a language: it is chosen by no name)."""
    patterns, names, _ = _fold(LANGUAGE_PATTERNS, {Path(f).name for f in files}, set())
    return {
        stem
        for stem, group in patterns.items()
        if stem != "generic"
        and any(fnmatchcase(name, pattern) for pattern in group for name in names)
    }


def _reads_generic(files: Iterable[str | Path]) -> bool:
    """Whether a rule in generic.yaml reads one of these files: a name or a
    directory above it matches a pattern of its row, or the file is under a
    directory a `<dir>/*` pattern names. `files` are relative to the scan root,
    or an ancestor of the target would match (`~/nginx/` and a README)."""
    names: set[str] = set()
    dirs: set[str] = set()
    for f in files:
        path = Path(f)
        names.add(path.name)
        dirs.update(path.parts[:-1])
    patterns, names, dirs = _fold(LANGUAGE_PATTERNS, names, dirs)
    anywhere = names | dirs
    for pattern in patterns.get("generic", ()):
        if pattern.endswith("/*"):
            if any(fnmatchcase(d, pattern[:-2]) for d in dirs):
                return True
        elif any(fnmatchcase(part, pattern) for part in anywhere):
            return True
    return False


def has_rules_for(files: Iterable[str | Path]) -> bool:
    """Whether the bundle has a rule for at least one of these files: one has
    the name of a language it covers, or is one only generic.yaml reads. A
    repository with none is nothing to scan (the row is skipped), whatever
    ``select_configs`` names for it.

    ``files`` are the scan's walked files **relative to the scan root**."""
    files = list(files)
    return bool(_language_stems(files)) or _reads_generic(files)


def select_configs(files: Iterable[str | Path]) -> list[Path]:
    """The bundle files for these files' languages, ``generic.yaml`` always, sorted.

    ``files`` are the scan's walked files, as ``Path`` or as the ``str`` the
    walk's ``collect_files`` returns. Only each file's name is read.
    """
    stems = {"generic"} | _language_stems(files)
    return sorted(BUNDLE_DIR / f"{stem}.yaml" for stem in stems)
