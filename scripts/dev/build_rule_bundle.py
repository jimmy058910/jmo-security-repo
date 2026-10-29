#!/usr/bin/env python3
"""Build the offline opengrep rule bundle, `scripts/jmo_rules/`, from four pinned sources.

The bundle is generated and committed, so a scan never fetches a rule. This
script is the only thing that writes it; a hand edit shows up as a diff under
`--check`.

Sources, in precedence order (a rule whose body equals a higher source's is
dropped, so GitLab wins over the snapshot, and the snapshot over the packs):

    lgpl-cc          GitLab sast-rules, `rules/lgpl-cc/**/rule-*.yml`
    opengrep-rules   the opengrep-rules snapshot, every language directory
    0xdea            0xdea/semgrep-rules `rules/` (MIT)
    elttam           elttam/semgrep-rules `rules/` (MIT)

Each source is one tarball at a fixed commit or tag, fetched by URL and checked
against its pinned sha256 before it is unpacked.

What is kept: rules with `metadata.category: security`, from `*.yaml` / `*.yml`
files that are not `*.test.yaml` test targets and have a `rules` list (the
GitLab glob is `rule-*.yml` only). A rule's language is the top directory under
its source's rules root, and it goes to `<language>.yaml`; sources that share a
language directory merge into one file. The one exception is configured per
source (`route_by_languages`): opengrep-rules' `problem-based-packs/` is laid out
by problem, so its top directory names no language, and a rule there goes to the
file named by the first entry of its own `languages:` list (`[javascript,
typescript]` goes to `javascript.yaml`, which a TypeScript scan reads too). Ids
are namespaced by path so that ids repeating across frameworks stay distinct: the
path under the rules root, minus the extension, with its parts joined by "."
(never the OS separator, so a Windows build gives the same ids), then the rule's
own id, with the source's prefix in front when it has one. A repeated namespaced
id fails the build.

What is left out is recorded with its reason in the manifest: whole directories,
rules by `mode`, single namespaced ids (all three configured in each `Source`),
body duplicates, and proprietary licenses. A rule's body is the rule minus `id`,
`message`, `metadata` and `severity`, as canonical JSON. Twins inside one source
both stay. The license guard is general, not configured: a rule whose
`metadata.license` contains "proprietary" (any casing), from any source, is not
shipped, because the bundle's notices (`THIRD_PARTY_LICENSES.md`) grant only the
open-source licenses of its sources. The reason quotes the license text. The match
is a deliberately broad substring, so a "non-proprietary" license would be dropped
too; that is the conservative direction.

YAML is read with 1.2 booleans (only true/false, in their three casings), so a
bare `on:` key stays the string "on" and not True. It is written with
`yaml.safe_dump`, which quotes such a key. Files are sorted by rule id, written
as UTF-8 with LF endings, byte for byte, so two builds are identical.

Each rule file begins with a fixed comment header (`file_header`): that the file
is generated, which sources gave it rules (each with its pin and license), how many
of a source's rules in it name another license in their own source files (a
`metadata.license`, else the file's head `# License:` comment, spelled differently
from the source's `declared_license`), what the builder changed and on what date
(`BUNDLE_DATE`), and a pointer to `THIRD_PARTY_LICENSES.md`. LGPL-2.1 asks that
notices referring to the license stay with the files (section 1) and that a
modified file say that it was changed, and when (section 2(b)). The header has no
build-time input, so `--check` still compares byte for byte.

`SOURCES.json`, the manifest (JSON, sorted keys, indent 2, trailing newline):

    version              schema version, 1
    files                {"<language>.yaml": {"sha256": str, "rules": int}}
    sources              {"<name>": {"url", "sha256" (of the tarball), "pin"
                         (commit or tag), "rules_root", "prefix", "rules" (kept)}}
    exclusions           a list, sorted by (kind, source, path or id), each with
                         "kind", "source" and "reason", and by kind:
        directory        "path" (under rules_root), "rules" (security rules in it)
        mode             "mode", "id"
        id               "id"
        license          "id" (the reason quotes the rule's `metadata.license`)
        body-duplicate   "id" (dropped), "kept_id", "kept_source"

Usage:
    build_rule_bundle.py --out scripts/jmo_rules [--cache ~/.cache/jmo-rule-sources]
    build_rule_bundle.py --out scripts/jmo_rules --check    # exit 1 naming any file that differs

Exit code 0 = built (or identical under --check), 1 = --check found differences,
2 = a source could not be fetched, verified or unpacked, or its rules could not be read.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import http.client
import json
import re
import sys
import tarfile
import tempfile
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

MANIFEST = "SOURCES.json"
MANIFEST_VERSION = 1
# The date the bundle's rules were last changed from the sources, written into
# every file's header (LGPL-2.1 section 2(b)). Bump it with the pins.
BUNDLE_DATE = "2026-10-29"
FETCH_TIMEOUT_S = 120
DEFAULT_CACHE = Path.home() / ".cache" / "jmo-rule-sources"

_JOIN_REASON = (
    'opengrep scan --validate rejects mode: join rules ("Rule parse error ... missing '
    'languages") on 1.31.0 and 1.32.0, and every bundle file must validate; a scan itself '
    "loads and runs the one measured (elttam's jsp-likely-xss)"
)


@dataclass(frozen=True)
class Source:
    """One pinned tarball and how its rules are read.

    `sha256` is the tarball's; `pin` is the commit or tag the URL names;
    `rules_root` is a POSIX path inside the tarball's one top directory ("" is
    that directory); `globs` match rule file names; `prefix` goes in front of
    every namespaced id ("" for none); `license` is the name
    `THIRD_PARTY_LICENSES.md` gives the license, written into the header of every
    file this source contributes to; `declared_license` is how this source's own
    files spell it (in a `# License:` head comment or `metadata.license`), so
    a rule that names anything else can be told apart. The three `skip_` maps give each
    exclusion its reason: a directory under `rules_root`, a rule's `mode:`, and
    a namespaced id. `route_by_languages` lists directories under `rules_root`
    whose rules are filed by their own `languages:` key, not by the directory.
    """

    name: str
    url: str
    sha256: str
    pin: str
    rules_root: str
    globs: tuple[str, ...]
    prefix: str
    license: str
    declared_license: str
    skip_dirs: dict[str, str] = field(default_factory=dict)
    skip_modes: dict[str, str] = field(default_factory=dict)
    skip_ids: dict[str, str] = field(default_factory=dict)
    route_by_languages: tuple[str, ...] = ()


SOURCES: dict[str, Source] = {
    source.name: source
    for source in (
        Source(
            name="lgpl-cc",
            url="https://gitlab.com/gitlab-org/security-products/sast-rules/-/archive/v2.10.1/sast-rules-v2.10.1.tar.gz",
            sha256="627a73135374fdb9122eb3dcca268ea0fbb11d889d1126c6c52fd28b9df2236b",
            pin="v2.10.1",
            rules_root="rules/lgpl-cc",
            globs=("rule-*.yml",),
            prefix="lgpl-cc",
            license="LGPL-2.1 with the Commons Clause",
            declared_license="Commons Clause License Condition v1.0[LGPL-2.1-only]",
            skip_modes={"join": _JOIN_REASON},
        ),
        Source(
            name="opengrep-rules",
            url="https://github.com/opengrep/opengrep-rules/archive/f1d2b562b414783763fd02a6ed2736eaed622efa.tar.gz",
            sha256="9a5f1cd5c625418cc1c776120123e2d4371df9bb66e099426b17c3488e13619d",
            pin="f1d2b562b414783763fd02a6ed2736eaed622efa",
            rules_root="",
            globs=("*.yaml", "*.yml"),
            prefix="",
            license="LGPL-2.1 with the Commons Clause",
            declared_license="Commons Clause License Condition v1.0[LGPL-2.1-only]",
            skip_dirs={
                "generic/secrets": (
                    "secret detection is gitleaks' and trufflehog's class; with these rules the "
                    "bundle trips JMo's own secret scanning (private-key and Slack-webhook patterns)"
                ),
                "scripts": "repository tooling, not rules",
                "stats": "coverage statistics, not rules",
                ".github": "the rules repository's CI workflows, not rules",
            },
            skip_modes={"join": _JOIN_REASON},
            skip_ids={
                "problem-based-packs.insecure-transport.js-node.using-http-server.using-http-server": (
                    "matches any call on Node's http module, so it flags every plaintext server behind "
                    "a TLS-terminating proxy, and double-reports the line http-request reports "
                    "(measured on probes, 2026-10-29)"
                ),
            },
            route_by_languages=("problem-based-packs",),
        ),
        Source(
            name="0xdea",
            url="https://github.com/0xdea/semgrep-rules/archive/e0121ac19d9fa259a44f3a24d3e42c95719b17c7.tar.gz",
            sha256="3a0095ef737f4413883e85201f06a66028e6f6173c711e89cb9ff5237667be32",
            pin="e0121ac19d9fa259a44f3a24d3e42c95719b17c7",
            rules_root="rules",
            globs=("*.yaml", "*.yml"),
            prefix="0xdea",
            license="MIT",
            declared_license="MIT",
            skip_dirs={
                "noisy": "the pack's own noisy tier, 'potentially too noisy and unsuitable for general use' (its README)",
            },
            skip_modes={"join": _JOIN_REASON},
            skip_ids={
                "0xdea.c.use-after-free.raptor-use-after-free": "overflows opengrep 1.31.0's stack on its own test file",
            },
        ),
        Source(
            name="elttam",
            url="https://github.com/elttam/semgrep-rules/archive/244268562cc92d33f54b8a60a187df5520f91b26.tar.gz",
            sha256="4a1c064f24391ec8423e53b9d423c5ba2cdedd5b481a0c73237ca32d6cd9d748",
            pin="244268562cc92d33f54b8a60a187df5520f91b26",
            rules_root="rules",
            globs=("*.yaml", "*.yml"),
            prefix="elttam",
            license="MIT",
            declared_license="MIT",
            skip_dirs={
                "yaml/kubernetes": (
                    "anchors on different lines from the snapshot's same-named Kubernetes rules, so one "
                    "pod spec would report twice; the snapshot's Kubernetes rules, checkov and trivy "
                    "already cover manifests"
                ),
            },
            skip_modes={"join": _JOIN_REASON},
        ),
    )
}

_BODY_IGNORED = frozenset({"id", "message", "metadata", "severity"})
_BOOL_TAG = "tag:yaml.org,2002:bool"


class _Yaml12Loader(yaml.SafeLoader):
    """SafeLoader whose booleans are YAML 1.2's: `on`, `off`, `yes` and `no` stay strings."""


_Yaml12Loader.yaml_implicit_resolvers = {
    first: [(tag, regexp) for tag, regexp in resolvers if tag != _BOOL_TAG]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_Yaml12Loader.add_implicit_resolver(
    _BOOL_TAG, re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF")
)


def rule_body(rule: dict[str, Any]) -> str:
    """The rule minus id, message, metadata and severity, as canonical JSON.

    A value JSON cannot hold, such as a YAML date, is bad input: ValueError, naming the rule.
    """
    try:
        return json.dumps(
            {k: v for k, v in rule.items() if k not in _BODY_IGNORED}, sort_keys=True
        )
    except TypeError as exc:
        raise ValueError(f"rule {rule.get('id')!r}: {exc}") from exc


def _is_security(rule: dict[str, Any]) -> bool:
    metadata = rule.get("metadata")
    return isinstance(metadata, dict) and metadata.get("category") == "security"


def _license_text(rule: dict[str, Any]) -> str | None:
    """The rule's `metadata.license` as text, or None when it has none."""
    metadata = rule.get("metadata")
    value = metadata.get("license") if isinstance(metadata, dict) else None
    if value is None or isinstance(value, str):
        return value
    # Only a substring or a spelling is compared, so a value JSON cannot hold (a YAML
    # date) is stringified rather than refused.
    return json.dumps(value, sort_keys=True, default=str)


def _proprietary_license(rule: dict[str, Any]) -> str | None:
    """The rule's `metadata.license` text when it declares a proprietary license."""
    text = _license_text(rule)
    return text if text is not None and "proprietary" in text.lower() else None


_HEAD_LICENSE = re.compile(r"#\s*License:\s*(.+)", re.IGNORECASE)


def _head_license(text: str) -> str | None:
    """The `# License:` comment in a rule file's head, before its first YAML line."""
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            return None
        if match := _HEAD_LICENSE.fullmatch(line):
            return match.group(1).strip()
    return None


def _spelling(text: str) -> str:
    """A license's name with its case and spacing ignored, to compare spellings."""
    return "".join(text.split()).casefold()


def _load_rules(
    path: Path, label: str
) -> tuple[list[dict[str, Any]], str | None] | None:
    """A rule file's `rules` list and head `# License:`, or None for a YAML file with no rules."""
    try:
        text = path.read_bytes().decode("utf-8")
        doc: Any = yaml.load(text, Loader=_Yaml12Loader)
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        raise ValueError(f"{label}: cannot read as YAML: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
        return None
    rules: list[dict[str, Any]] = doc["rules"]
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
            raise ValueError(f"{label}: a rule without a string id")
    return rules, _head_license(text)


def _under(parts: tuple[str, ...], directory: str) -> bool:
    wanted = tuple(directory.split("/"))
    return parts[: len(wanted)] == wanted


def _language(
    rule: dict[str, Any], parts: tuple[str, ...], source: Source, label: str
) -> str:
    """The language file a rule goes to: its top directory, or its first `languages:` entry."""
    if not any(_under(parts, directory) for directory in source.route_by_languages):
        return parts[0]
    languages = rule.get("languages")
    if not (
        isinstance(languages, list) and languages and isinstance(languages[0], str)
    ):
        raise ValueError(
            f"{label}: rule {rule['id']!r} has no `languages:` list to file it by"
        )
    return languages[0]


def collect(
    root: Path,
    source: Source,
    exclusions: list[dict[str, Any]] | None = None,
    other_licenses: dict[str, str] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """The kept rules of one extracted tree, by language, with namespaced ids.

    `exclusions`, when given, receives a record for each directory, mode and id
    the source's configuration dropped. `other_licenses`, when given, receives
    rule id -> license text for each kept rule that names a license other than the
    source's: in its `metadata.license`, else in its file's head `# License:` comment.
    """
    base = root / source.rules_root
    if not base.is_dir():  # a moved rules root must not read as a source with no rules
        raise ValueError(f"{source.name}: no directory {source.rules_root!r} in {root}")
    dropped = exclusions if exclusions is not None else []
    dir_rules = dict.fromkeys(source.skip_dirs, 0)
    by_language: dict[str, list[dict[str, Any]]] = defaultdict(list)

    files = sorted(
        (p for p in base.rglob("*") if p.is_file()),
        key=lambda p: p.relative_to(base).as_posix(),
    )
    for path in files:
        rel = path.relative_to(base)
        name = rel.name
        if (
            len(rel.parts) < 2  # a file at the root has no language directory
            or name.endswith((".test.yaml", ".test.yml"))
            or not any(fnmatch.fnmatchcase(name, glob) for glob in source.globs)
        ):
            continue
        label = f"{source.name}:{rel.as_posix()}"
        loaded = _load_rules(path, label)
        if loaded is None:
            continue
        rules, head_license = loaded
        skipped_dir = next((d for d in source.skip_dirs if _under(rel.parts, d)), None)
        if skipped_dir is not None:
            dir_rules[skipped_dir] += sum(_is_security(r) for r in rules)
            continue
        namespace = ".".join((*rel.parts[:-1], Path(name).stem))
        if source.prefix:
            namespace = f"{source.prefix}.{namespace}"
        for rule in rules:
            if not _is_security(rule):
                continue
            rule_id = f"{namespace}.{rule['id']}"
            mode = rule.get("mode")
            if isinstance(mode, str) and mode in source.skip_modes:
                dropped.append(
                    {
                        "kind": "mode",
                        "source": source.name,
                        "mode": mode,
                        "id": rule_id,
                        "reason": source.skip_modes[mode],
                    }
                )
            elif rule_id in source.skip_ids:
                dropped.append(
                    {
                        "kind": "id",
                        "source": source.name,
                        "id": rule_id,
                        "reason": source.skip_ids[rule_id],
                    }
                )
            elif (proprietary := _proprietary_license(rule)) is not None:
                dropped.append(
                    {
                        "kind": "license",
                        "source": source.name,
                        "id": rule_id,
                        "reason": (
                            f'metadata.license declares a proprietary license, "{proprietary}", '
                            "which the bundle's notices do not grant"
                        ),
                    }
                )
            else:
                by_language[_language(rule, rel.parts, source, label)].append(
                    {**rule, "id": rule_id}
                )
                declared = _license_text(rule) or head_license
                if (
                    other_licenses is not None
                    and declared is not None
                    and _spelling(declared) != _spelling(source.declared_license)
                ):
                    other_licenses[rule_id] = " ".join(declared.split())

    for directory, count in dir_rules.items():
        if (base / directory).is_dir():
            dropped.append(
                {
                    "kind": "directory",
                    "source": source.name,
                    "path": directory,
                    "rules": count,
                    "reason": source.skip_dirs[directory],
                }
            )
    return dict(by_language)


def file_header(
    sources: list[Source], other_licenses: dict[str, list[str]] | None = None
) -> str:
    """The comment block that opens a generated rule file.

    `sources` are the ones that gave the file a rule, in precedence order.
    `other_licenses` maps a source name to the license text of each of its rules in
    this file that names a license other than the source's; the header says how
    many, which licenses, and where they are listed. The text depends on these and
    on `BUNDLE_DATE` alone, so a rebuild reproduces it.
    """
    width = max(len(source.name) for source in sources)
    notes = [
        f"# {source.name} rules in this file that name another license in their own "
        f"source file: {len(found)} ({'; '.join(sorted(set(found)))})."
        for source in sources
        if (found := (other_licenses or {}).get(source.name))
    ]
    lines = [
        "# Generated by scripts/dev/build_rule_bundle.py. Do not edit by hand: the next",
        "# rebuild replaces this file, and CI's rule-bundle-reproducible job rejects an edit.",
        "#",
        "# The rules in this file come from these sources, under these licenses:",
        *(
            f"#   {source.name:<{width}}  pinned at {source.pin}  {source.license}"
            for source in sources
        ),
        *(["#", *notes, "# THIRD_PARTY_LICENSES.md lists them."] if notes else []),
        "#",
        f"# Changed from those sources on {BUNDLE_DATE}. The builder kept only the rules with",
        "# `metadata.category: security`, put the path of the file a rule came from (and its",
        "# source's prefix, where it has one) in front of the rule's id, left out the rules",
        "# SOURCES.json lists as excluded and those whose body duplicates a rule from a source",
        "# it ranks higher, merged the rest into this one file for the language, and wrote it",
        "# again as YAML, which leaves out the sources' comments. A kept rule's pattern,",
        "# message and metadata are as its source has them.",
        "#",
        "# The licenses, their texts and the notices to keep with these rules are in",
        "# THIRD_PARTY_LICENSES.md, at the repository root. Pins and archive hashes: SOURCES.json.",
        "",
    ]
    return "\n".join(lines) + "\n"


def build(trees: dict[str, Path], out_dir: Path) -> dict[str, Any]:
    """Write the bundle and its manifest into `out_dir`; return the manifest.

    `trees` maps each source name to its extracted tree. The manifest records the
    pinned url and sha256 of each source, which `fetch` verified.
    """
    missing = [name for name in SOURCES if name not in trees]
    if missing:
        raise ValueError(f"no extracted tree for: {', '.join(missing)}")

    exclusions: list[dict[str, Any]] = []
    other_licenses: dict[str, str] = {}  # rule id -> a license other than its source's
    collected = {
        name: collect(trees[name], source, exclusions, other_licenses)
        for name, source in SOURCES.items()
    }

    owners: dict[str, str] = {}
    for name, by_language in collected.items():
        for rules in by_language.values():
            for rule in rules:
                if rule["id"] in owners:
                    raise ValueError(
                        f"rule id {rule['id']!r} is defined twice (in {owners[rule['id']]} and {name})"
                    )
                owners[rule["id"]] = name

    # Duplicates are found across all languages: a GitLab language directory can
    # have no counterpart in the snapshot, so its twin lives in another file.
    # body -> (source, id) of the highest source that has it
    winners: dict[str, tuple[str, str]] = {}
    kept: dict[str, list[dict[str, Any]]] = defaultdict(list)
    contributors: dict[str, list[str]] = defaultdict(list)  # language -> source names
    # language -> source name -> the other license of each kept rule that has one
    elsewhere: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    kept_per_source: dict[str, int] = {}
    for name, by_language in collected.items():
        own: dict[str, tuple[str, str]] = {}
        kept_per_source[name] = 0
        entries = sorted(
            (
                (language, rule)
                for language, rules in by_language.items()
                for rule in rules
            ),
            key=lambda entry: entry[1]["id"],
        )
        for language, rule in entries:
            body = rule_body(rule)
            if body in winners:
                kept_source, kept_id = winners[body]
                exclusions.append(
                    {
                        "kind": "body-duplicate",
                        "source": name,
                        "id": rule["id"],
                        "kept_id": kept_id,
                        "kept_source": kept_source,
                        "reason": f"same rule body as {kept_source}'s {kept_id}, a higher-precedence source",
                    }
                )
                continue
            kept[language].append(rule)
            if name not in contributors[language]:
                contributors[language].append(name)
            if rule["id"] in other_licenses:
                elsewhere[language][name].append(other_licenses[rule["id"]])
            kept_per_source[name] += 1
            own.setdefault(body, (name, rule["id"]))
        # Only a later source is compared with this one's bodies, so twins inside
        # one source both stay.
        for body, winner in own.items():
            winners.setdefault(body, winner)

    out_dir.mkdir(parents=True, exist_ok=True)
    # In a previous bundle, drop a language the sources no longer give.
    if (out_dir / MANIFEST).is_file():
        for stale in out_dir.glob("*.yaml"):
            if stale.stem not in kept:
                stale.unlink()

    files: dict[str, dict[str, Any]] = {}
    for language in sorted(kept):
        rules = sorted(kept[language], key=lambda rule: rule["id"])
        header = file_header(
            [SOURCES[name] for name in contributors[language]], elsewhere[language]
        )
        data = (
            header
            + yaml.safe_dump({"rules": rules}, sort_keys=False, allow_unicode=True)
        ).encode("utf-8")
        (out_dir / f"{language}.yaml").write_bytes(data)
        files[f"{language}.yaml"] = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "rules": len(rules),
        }

    manifest: dict[str, Any] = {
        "version": MANIFEST_VERSION,
        "files": files,
        "sources": {
            name: {
                "url": source.url,
                "sha256": source.sha256,
                "pin": source.pin,
                "rules_root": source.rules_root,
                "prefix": source.prefix,
                "rules": kept_per_source[name],
            }
            for name, source in SOURCES.items()
        },
        "exclusions": sorted(
            exclusions,
            key=lambda e: (e["kind"], e["source"], e.get("path", e.get("id", ""))),
        ),
    }
    text = json.dumps(manifest, sort_keys=True, indent=2) + "\n"
    (out_dir / MANIFEST).write_bytes(text.encode("utf-8"))
    return manifest


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fetch(source: Source, cache: Path) -> Path:
    """The source's tarball in `cache`, downloaded when absent or when it no longer verifies."""
    cache.mkdir(parents=True, exist_ok=True)
    dest = cache / f"{source.name}-{source.sha256[:12]}.tar.gz"
    if dest.is_file() and _sha256_file(dest) == source.sha256:
        return dest
    part = dest.with_name(dest.name + ".part")
    digest = hashlib.sha256()
    request = urllib.request.Request(
        source.url, headers={"User-Agent": "jmo-security rule bundle builder"}
    )
    try:
        # The URL is a constant https URL from SOURCES, never user input.
        with (
            urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_S) as response,  # nosec B310
            part.open("wb") as handle,
        ):
            while chunk := response.read(1 << 20):
                digest.update(chunk)
                handle.write(chunk)
        actual = digest.hexdigest()
        if actual != source.sha256:
            raise ValueError(
                f"{source.name}: sha256 mismatch for {source.url}: expected {source.sha256}, got {actual}"
            )
        part.replace(dest)
    finally:
        part.unlink(missing_ok=True)
    return dest


def extract(tarball: Path, dest: Path) -> Path:
    """Unpack `tarball` into `dest` with the `data` filter; return its one top directory."""
    with tarfile.open(tarball, "r:gz") as archive:
        archive.extractall(dest, filter="data")
    tops = sorted(dest.iterdir())
    if len(tops) != 1 or not tops[0].is_dir():
        raise ValueError(
            f"{tarball.name}: expected one top-level directory, found {[t.name for t in tops]}"
        )
    return tops[0]


def fetch_trees(cache: Path, work: Path) -> dict[str, Path]:
    """Every source's verified tarball, unpacked under `work`; name -> tree."""
    return {
        name: extract(fetch(source, cache), work / name)
        for name, source in SOURCES.items()
    }


def diff_bundle(built: Path, existing: Path) -> list[str]:
    """One line per bundle file that differs between two directories."""

    def names(directory: Path) -> set[str]:
        if not directory.is_dir():
            return set()
        return {
            p.name
            for p in directory.iterdir()
            if p.is_file() and (p.suffix == ".yaml" or p.name == MANIFEST)
        }

    expected, present = names(built), names(existing)
    problems = []
    for name in sorted(expected | present):
        if name not in present:
            problems.append(f"{name}: missing")
        elif name not in expected:
            problems.append(f"{name}: not produced by this build")
        elif (built / name).read_bytes() != (existing / name).read_bytes():
            problems.append(f"{name}: differs")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build the offline opengrep rule bundle."
    )
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="bundle directory, e.g. scripts/jmo_rules",
    )
    parser.add_argument(
        "--cache",
        type=Path,
        default=DEFAULT_CACHE,
        help="where the source tarballs are kept (default %(default)s)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="build into a temporary directory and exit 1 naming any file that differs",
    )
    args = parser.parse_args(argv)

    try:
        args.cache.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=args.cache, prefix="work-") as work:
            trees = fetch_trees(args.cache, Path(work) / "trees")
            if args.check:
                manifest = build(trees, Path(work) / "built")
                problems = diff_bundle(Path(work) / "built", args.out)
            else:
                manifest = build(trees, args.out)
                problems = []
    except (
        ValueError,  # includes a rule value JSON cannot hold (rule_body)
        OSError,  # covers URLError
        http.client.HTTPException,  # a truncated download is IncompleteRead, not an OSError
        tarfile.TarError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if problems:
        print(f"{args.out} differs from a fresh build:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    total = sum(entry["rules"] for entry in manifest["files"].values())
    verb = "matches a fresh build:" if args.check else "built"
    print(f"{verb} {len(manifest['files'])} files, {total} rules in {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
