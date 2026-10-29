"""scripts/jmo_rules/: the committed opengrep rule bundle, read offline.

`scripts/dev/build_rule_bundle.py` is the only writer of the bundle, and its
`--check` mode (the `rule-bundle-reproducible` job) proves the committed copy
still equals a rebuild from the four pinned sources. These tests need neither
the network nor the builder. They read the committed files and `SOURCES.json`
and hold the properties a scan depends on, so a hand edit, a stray file or a
rule that should never have shipped fails on every shard, not only in that job.

Nothing here parametrizes over the bundle's contents. A bundle that is missing
would make that zero tests, which pytest reports as a skip, and the guard would
read green exactly when it matters. Each test loads the bundle in its body.

The counts (25 files, 1,420 rules) are the builder's output for today's pins.
They appear in no assertion: a source bump changes both, and `--check` is the
guard that the numbers are the sources'. The manifest is the reference here.
"""

from __future__ import annotations

import glob
import hashlib
import json
import re
import shutil
import subprocess
import tomllib
from collections import Counter
from functools import cache
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
BUNDLE = REPO_ROOT / "scripts" / "jmo_rules"
MANIFEST = BUNDLE / "SOURCES.json"


def _manifest() -> dict[str, Any]:
    return json.loads(MANIFEST.read_bytes())


def _bundle_files() -> list[Path]:
    """Every rule file on disk, so a file the manifest does not list is read too."""
    files = sorted(BUNDLE.glob("*.yaml"))
    assert files, f"no rule file under {BUNDLE}"
    return files


@cache
def _rules(name: str) -> list[dict[str, Any]]:
    return yaml.safe_load((BUNDLE / name).read_bytes().decode("utf-8"))["rules"]


def test_the_directory_holds_exactly_the_manifest_files() -> None:
    """Per-file hashes cannot see a file that is not in the manifest, and the
    package-data pattern `jmo_rules/*.yaml` would ship it anyway."""
    on_disk = {p.name for p in _bundle_files()}
    listed = set(_manifest()["files"])
    assert on_disk == listed, (
        f"on disk only: {sorted(on_disk - listed)}; "
        f"in the manifest only: {sorted(listed - on_disk)}"
    )
    stray = sorted(
        p.name
        for p in BUNDLE.iterdir()
        if p.name != MANIFEST.name and p.suffix != ".yaml"
    )
    assert not stray, f"files that are neither a rule file nor the manifest: {stray}"


def test_every_file_matches_its_manifest_entry() -> None:
    """The bytes (sha256) and the rule count each file was recorded with."""
    manifest = _manifest()["files"]
    assert manifest, "the manifest lists no file"
    wrong = []
    for name, entry in sorted(manifest.items()):
        data = (BUNDLE / name).read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != entry["sha256"]:
            wrong.append(f"{name}: sha256 {digest} != {entry['sha256']}")
        count = len(_rules(name))
        if count != entry["rules"]:
            wrong.append(f"{name}: {count} rules != {entry['rules']}")
    assert not wrong, "\n".join(wrong)


def test_the_sources_account_for_every_rule() -> None:
    """The per-source counts and the per-file counts are two tallies of one set."""
    manifest = _manifest()
    by_file = sum(e["rules"] for e in manifest["files"].values())
    by_source = sum(s["rules"] for s in manifest["sources"].values())
    assert by_file == by_source, f"{by_file} rules in files, {by_source} in sources"


def test_every_rule_is_security() -> None:
    """The bundle is the security tier only (spec §4.1); the engine's
    correctness and best-practice rules are the noise the filter removes."""
    wrong = [
        f"{p.name}: {rule.get('id')}"
        for p in _bundle_files()
        for rule in _rules(p.name)
        if (rule.get("metadata") or {}).get("category") != "security"
    ]
    assert not wrong, f"{len(wrong)} rule(s) without category: security:\n" + "\n".join(
        wrong[:20]
    )


def test_ids_are_unique_across_the_bundle() -> None:
    """Every file is merged into one scan, and the engine is run with
    `--no-rewrite-rule-ids`, so an id is the finding's identity and two rules
    with one id would be one."""
    ids = Counter(rule["id"] for p in _bundle_files() for rule in _rules(p.name))
    assert ids, "the bundle holds no rule"
    repeated = sorted(i for i, n in ids.items() if n > 1)
    assert not repeated, f"{len(repeated)} repeated id(s): {repeated[:10]}"


# What `generic/secrets/` held, as the secret scanners' own hits: a private-key
# header and a Slack webhook URL, written out in rules that detect them.
_PRIVATE_KEY_HEADER = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY")
_SLACK_WEBHOOK = re.compile(rb"hooks\.slack\.com/services/", re.IGNORECASE)


def test_no_generic_secrets_rule_ships() -> None:
    """Secret detection is gitleaks' and trufflehog's class. With these rules
    in it the bundle cannot be committed past JMo's own secret hooks (225 of
    the snapshot's 248 generic security rules, measured), so the directory is
    excluded by the builder, with its reason, and nothing from it may appear."""
    manifest = _manifest()
    excluded = [
        e
        for e in manifest["exclusions"]
        if e["kind"] == "directory" and e["path"] == "generic/secrets"
    ]
    assert excluded and excluded[0]["reason"], (
        "the manifest no longer records generic/secrets as excluded, with a reason"
    )

    ids = [rule["id"] for p in _bundle_files() for rule in _rules(p.name)]
    from_secrets = sorted(i for i in ids if i.startswith("generic.secrets."))
    assert not from_secrets, f"generic/secrets rules in the bundle: {from_secrets[:10]}"

    for p in _bundle_files():
        data = p.read_bytes()
        assert not _PRIVATE_KEY_HEADER.search(data), (
            f"{p.name} holds a private-key header"
        )
        assert not _SLACK_WEBHOOK.search(data), f"{p.name} holds a Slack webhook URL"


def test_no_rule_declares_a_proprietary_license() -> None:
    """The bundle's notices (THIRD_PARTY_LICENSES.md) grant the open-source
    licenses of its four sources and nothing proprietary. One snapshot rule
    declared `proprietary license - copyright (c) Semgrep, Inc.` in its own
    metadata, so the builder drops any rule whose `metadata.license` says
    "proprietary", from any source, and records it as a `license` exclusion."""
    wrong = [
        f"{p.name}: {rule['id']}: {(rule.get('metadata') or {}).get('license')!r}"
        for p in _bundle_files()
        for rule in _rules(p.name)
        if "proprietary"
        in json.dumps((rule.get("metadata") or {}).get("license")).lower()
    ]
    assert not wrong, f"{len(wrong)} rule(s) with a proprietary license:\n" + "\n".join(
        wrong[:20]
    )


def test_the_wheel_carries_the_bundle() -> None:
    """The wheel collects Python packages and their declared package data only,
    and `scripts/jmo_rules/` has no `__init__.py`. Without the pyproject entry a
    pip-installed `jmo` would have no rule to scan with (the dashboard's
    `index.html` was in the same position, #862).

    This resolves the declared patterns the way setuptools does, against the
    `scripts` package directory, and wants every bundle file covered. It never
    runs setuptools; the check on a built wheel is `dashboard-smoke`'s step
    "Verify the wheel carries the built dashboard and the rule bundle". This is
    the half that runs on every shard.
    """
    config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    patterns = config["tool"]["setuptools"]["package-data"]["scripts"]
    package_dir = REPO_ROOT / "scripts"
    shipped = {
        Path(match).as_posix()
        for pattern in patterns
        for match in glob.glob(pattern, root_dir=package_dir, recursive=True)
    }
    wanted = {f"jmo_rules/{p.name}" for p in _bundle_files()} | {
        f"jmo_rules/{MANIFEST.name}"
    }
    missing = sorted(wanted - shipped)
    assert not missing, (
        f"[tool.setuptools.package-data] scripts = {patterns} does not carry: {missing}"
    )


def test_the_wheel_ships_the_third_party_notices() -> None:
    """The wheel ships the rules, so it ships their notices (R10). setuptools
    copies each `license-files` match into `*.dist-info/licenses/`; without the
    entry a pip-installed JMo carries the rules and none of the LGPL-2.1,
    Commons Clause or MIT texts they came under. The entry needs the file at the
    repository root to match anything."""
    config = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    listed = config["tool"]["setuptools"]["license-files"]
    assert "THIRD_PARTY_LICENSES.md" in listed, (
        f"[tool.setuptools] license-files = {listed} does not name THIRD_PARTY_LICENSES.md"
    )
    notices = REPO_ROOT / "THIRD_PARTY_LICENSES.md"
    assert notices.is_file(), f"{notices} does not exist, so the entry matches nothing"


def test_the_bundle_keeps_its_line_endings_on_checkout() -> None:
    """`.gitattributes` marks `scripts/jmo_rules/**` as `-text`. GitHub's Windows
    runners check out with `core.autocrlf=true`, which would rewrite every
    file's LF to CRLF and change the bytes the manifest hashes. If the line is
    deleted, the only failure is on the `windows-2022` shard, which is
    `continue-on-error` and reports green over failures, so it is asserted here
    on every shard, from git's own resolution of the attribute."""
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not on PATH")
    if not (REPO_ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    result = subprocess.run(
        [git, "check-attr", "text", "--", "scripts/jmo_rules/SOURCES.json"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "scripts/jmo_rules/SOURCES.json: text: unset", (
        f"`text` is not unset for the bundle, so a CRLF checkout would change its "
        f"bytes; check the scripts/jmo_rules/** line in .gitattributes: {result.stdout!r}"
    )


@pytest.mark.requires_tools
@pytest.mark.timeout(600)
def test_every_file_validates() -> None:
    """Against the engine, not the YAML: a rule that parses can still be one
    opengrep refuses (a `mode: join` rule, a bad pattern), and one bad rule in
    a merged file fails the whole file. Each file is checked on its own and
    must report its manifest's rule count, so a rule the engine silently drops
    is a failure here too."""
    opengrep = shutil.which("opengrep")
    if opengrep is None:
        pytest.skip("opengrep is not on PATH")
    manifest = _manifest()["files"]
    assert manifest, "the manifest lists no file"
    wrong = []
    for name, entry in sorted(manifest.items()):
        result = subprocess.run(
            [opengrep, "scan", "--validate", "--config", str(BUNDLE / name)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        said = result.stdout + result.stderr
        want = f"found 0 configuration error(s), and {entry['rules']} rule(s)"
        if result.returncode != 0 or want not in said:
            wrong.append(
                f"{name}: rc {result.returncode}, wanted {want!r}:\n{said[-400:]}"
            )
    assert not wrong, "\n".join(wrong)
