"""The descriptor table is the one place a scanner is declared (v2.0.0 Phase 3).

Before it, one tool was spread over eleven tables in four modules and eighteen
hand-written blocks in six scan jobs, and nothing checked that they agreed:
nuclei was "valid" for GitLab targets in `TOOL_SCAN_TYPES` while the GitLab
job had no code path for it, so a failed GitLab scan blamed nuclei (measured
2026-09-25). Every table below is now **derived** from `DESCRIPTORS`.

Each derived table is compared with the literal it replaced, copied here
from `origin/dev` at 025edd01 before the literal was deleted. Where the two
differ, the difference is a decision of Phase 3 and is named beside it; any
other difference is a descriptor typo.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

from scripts.cli import scan_utils, tool_manager
from scripts.core import tool_registry
from scripts.core.tool_descriptors import (
    DESCRIPTORS,
    REMOVED_TOOLS,
    VENDORED_DIRS,
    ExclusionStyle,
    ScanContext,
    UnknownToolError,
    parse_tool_names,
)

# --- the literals, as they stood at 025edd01 ---------------------------------

OLD_REPO_TOOLS = {
    "trufflehog",
    "semgrep",
    "syft",
    "trivy",
    "checkov",
    "hadolint",
    "shellcheck",
    "gosec",
    "yara",
    "grype",
    "zap",
}
OLD_TOOL_SCAN_TYPES = {
    "repo": set(OLD_REPO_TOOLS),
    "image": {"trivy", "syft"},
    "url": {"nuclei", "zap"},
    "k8s": {"trivy"},
    "iac": {"trivy", "checkov"},
    "gitlab": set(OLD_REPO_TOOLS) | {"nuclei"},
}
OLD_TOOL_BINARY_NAMES = {"zap": "zap.sh"}
OLD_TOOL_EXECUTION_COMMANDS = {
    "zap": ["zap.sh", "java"],
    "nuclei": ["nuclei"],
    "gosec": ["gosec"],
}
OLD_VENDOR_NOISE_TOOLS = {"semgrep", "trivy", "checkov"}
OLD_TOOL_EXCLUSION_FLAG = {
    "semgrep": ("--exclude", "inline"),
    "trivy": ("--skip-dirs", "separate"),
    "checkov": ("--skip-path", "regex"),
}
OLD_TOOL_TIMEOUT_DEFAULTS = {"semgrep": 900, "zap": 900}
OLD_STUBS = {
    "trufflehog": [],
    "semgrep": {"results": []},
    "syft": {"artifacts": []},
    "trivy": {"Results": []},
    "grype": {"matches": []},
    "hadolint": [],
    "checkov": {"results": {"failed_checks": []}},
    "zap": {"site": []},
    "nuclei": "",
}
OLD_VERSION_PATTERNS = {
    "default": (r"v?(\d+\.\d+(?:\.\d+)?(?:-[\w.]+)?)", 0),
    "trivy": (r"Version:\s*v?(\d+\.\d+\.\d+)", 0),
    "grype": (r"Version:\s*v?(\d+\.\d+\.\d+)", 0),
    "syft": (r"Version:\s*v?(\d+\.\d+\.\d+)", 0),
    "nuclei": (r"Version:\s*v?(\d+\.\d+\.\d+)", 0),
    "trufflehog": (r"trufflehog\s+v?(\d+\.\d+\.\d+)", 0),
    "shellcheck": (r"(?:version:?\s*)?(\d+\.\d+\.\d+)", re.IGNORECASE),
    "gosec": (r"Version:\s*v?(\d+\.\d+\.\d+)", 0),
    "hadolint": (r"Haskell Dockerfile Linter\s+v?(\d+\.\d+\.\d+)", 0),
    "checkov": (r"(?:checkov\s+)?(\d+\.\d+\.\d+)", re.IGNORECASE),
    "semgrep": (r"^(\d+\.\d+\.\d+)$", re.MULTILINE),
    "zap": (
        r"(?<!version )(?<!\d)(?<!\.)(?:(?:OWASP\s+)?(?:ZAP|Zed Attack Proxy)\s+)?"
        r"v?(\d+\.\d+\.\d+)(?!\d|\.jar|\.\d)",
        re.IGNORECASE,
    ),
    "yara": (r"v?(\d+\.\d+\.\d+)", 0),
    "opa": (r"Version:\s*v?(\d+\.\d+\.\d+)", 0),
}
OLD_VERSION_COMMANDS = {
    "grype": ["grype", "version"],
    "syft": ["syft", "version"],
    "opa": ["opa", "version"],
    "nuclei": ["nuclei", "-version"],
    "zap": {"windows": ["zap.bat", "-version"], "default": ["zap.sh", "-version"]},
    "yara": [sys.executable, "-c", "import yara; print(yara.YARA_VERSION)"],
}
OLD_VERSION_TIMEOUTS = {"zap": 30, "checkov": 30}


def test_the_table_is_the_matrix() -> None:
    assert set(DESCRIPTORS) == set(tool_registry.TOOL_MATRIX)
    # Order too: docs, the wizard and `jmo tools check` list the matrix in it.
    assert tuple(DESCRIPTORS) == tool_registry.TOOL_MATRIX
    assert all(name == d.name for name, d in DESCRIPTORS.items())


def test_gitleaks_joined_beside_the_other_secret_scanner() -> None:
    """PR C (decided 2026-09-24): gitleaks is wired in Phase 3 for G1, so the
    matrix is 13. Listed after trufflehog, so the two secret scanners read
    together wherever the matrix is printed."""
    assert len(DESCRIPTORS) == 13
    names = list(DESCRIPTORS)
    assert names[names.index("trufflehog") + 1] == "gitleaks"


def test_target_types_differ_from_the_old_literal_only_by_the_url_tools() -> None:
    """zap left `repo` and nuclei left `gitlab`: both are URL-only (Phase 3
    decision: "zap and nuclei on a non-URL target are skipped:needs --url").
    gitleaks (PR C) reads a repository, and so a GitLab clone."""
    expected = {k: set(v) for k, v in OLD_TOOL_SCAN_TYPES.items()}
    expected["repo"].discard("zap")
    expected["repo"].add("gitleaks")
    expected["gitlab"] = set(expected["repo"])

    assert expected == tool_registry.TOOL_SCAN_TYPES


def test_binary_and_execution_tables_are_derived_unchanged() -> None:
    assert tool_registry.TOOL_BINARY_NAMES == OLD_TOOL_BINARY_NAMES
    assert tool_registry.TOOL_EXECUTION_COMMANDS == OLD_TOOL_EXECUTION_COMMANDS


def test_timeout_floors_are_derived_unchanged() -> None:
    assert scan_utils.TOOL_TIMEOUT_DEFAULTS == OLD_TOOL_TIMEOUT_DEFAULTS


def test_stub_shapes_are_derived_unchanged_plus_the_three_empty_ones() -> None:
    """shellcheck, gosec and yara had no entry and fell back to `{}`; they are
    declared now, with the value they already got. gitleaks (PR C) writes
    SARIF, so its empty result is an empty SARIF document."""
    derived = {name: d.stub for name, d in DESCRIPTORS.items()}
    assert derived == {
        **OLD_STUBS,
        "shellcheck": {},
        "gosec": {},
        "yara": {},
        "gitleaks": {"version": "2.1.0", "runs": []},
    }


# gitleaks (PR C): `gitleaks version` prints the bare version, `8.30.1`
# (measured, the release's windows_x64 binary).
NEW_VERSION_PATTERNS = {"gitleaks": (r"^v?(\d+\.\d+\.\d+)$", re.MULTILINE)}
NEW_VERSION_COMMANDS = {"gitleaks": ["gitleaks", "version"]}


@pytest.mark.parametrize(
    "name", sorted({**OLD_VERSION_PATTERNS, **NEW_VERSION_PATTERNS})
)
def test_version_patterns_are_derived_unchanged(name: str) -> None:
    pattern, flags = {**OLD_VERSION_PATTERNS, **NEW_VERSION_PATTERNS}[name]
    got = tool_manager.VERSION_PATTERNS[name]
    assert (got.pattern, got.flags & ~re.UNICODE) == (pattern, flags)


def test_version_tables_have_no_extra_keys() -> None:
    assert set(tool_manager.VERSION_PATTERNS) == set(OLD_VERSION_PATTERNS) | set(
        NEW_VERSION_PATTERNS
    )
    assert tool_manager.VERSION_COMMANDS == {
        **OLD_VERSION_COMMANDS,
        **NEW_VERSION_COMMANDS,
    }
    assert tool_manager.VERSION_TIMEOUTS == OLD_VERSION_TIMEOUTS


def test_the_gitleaks_probe_reads_what_gitleaks_version_prints() -> None:
    pattern = tool_manager.VERSION_PATTERNS["gitleaks"]
    assert pattern.search("8.30.1\n").group(1) == "8.30.1"
    # Not a version buried in some other line: the whole line is the version.
    assert pattern.search("built with go1.24.6\n") is None


def test_exclusions_old_flags_survive_and_the_new_tools_gain_one() -> None:
    """#1235: syft, grype and gosec had no exclusion at all. trivy's style keeps
    its old name; syft and grype share it, measured (bare names are fatal)."""
    assert {
        k: v
        for k, v in scan_utils.TOOL_EXCLUSION_FLAG.items()
        if k in OLD_TOOL_EXCLUSION_FLAG
    } == OLD_TOOL_EXCLUSION_FLAG
    assert scan_utils.TOOL_EXCLUSION_FLAG["syft"] == ("--exclude", "separate")
    assert scan_utils.TOOL_EXCLUSION_FLAG["grype"] == ("--exclude", "separate")
    # A regex, bounded to whole segments: a bare `.git` also dropped `.github`.
    assert scan_utils.TOOL_EXCLUSION_FLAG["gosec"] == ("-exclude-dir", "inline_regex")


def test_vendored_tier_is_the_old_set_plus_the_readers_that_walked_anyway() -> None:
    """Phase 3: the secret scanner joins the tier (trufflehog on a Next.js app,
    295.8 s and 222 of 253 findings in node_modules, measured), and so do the
    tools whose walk already skipped VENDORED_DIRS. syft and grype stay out
    (#1205): a vendored tree is their subject."""
    assert (
        OLD_VENDOR_NOISE_TOOLS
        | {
            "trufflehog",
            "hadolint",
            "shellcheck",
            "gosec",
            "yara",
            # PR C: the second secret scanner, for the same reason as the first.
            "gitleaks",
        }
        == scan_utils.VENDOR_NOISE_TOOLS
    )
    assert DESCRIPTORS["syft"].excluded_vendored == ()
    assert DESCRIPTORS["grype"].excluded_vendored == (".venv", "venv")


def test_every_descriptor_declares_an_exclusion_style() -> None:
    """ "none" is not a style: a tool that cannot exclude says why (#1235)."""
    for d in DESCRIPTORS.values():
        assert isinstance(d.exclusion_style, ExclusionStyle), d.name
        if d.exclusion_style in (
            ExclusionStyle.INLINE,
            ExclusionStyle.SEPARATE,
            ExclusionStyle.REGEX,
            ExclusionStyle.CONFIG_FILE,
        ):
            assert d.exclusion_flag, d.name
        if "repo" in d.target_types:
            assert d.exclusion_style is not ExclusionStyle.NOT_FILESYSTEM, d.name


def test_vendored_dirs_is_one_list() -> None:
    """yara_runner carried its own copy; the walk and the flags read this one."""
    from scripts.core import yara_runner

    assert scan_utils.VENDORED_DIRS is VENDORED_DIRS
    assert set(yara_runner.SKIP_DIRS) == set(VENDORED_DIRS)


class TestToolNames:
    """Decision 4 (#1279): split commas, reject unknowns."""

    def test_commas_and_spaces_split(self) -> None:
        assert parse_tool_names(["trivy,syft", "semgrep"]) == [
            "trivy",
            "syft",
            "semgrep",
        ]
        assert parse_tool_names(["trivy, syft ,", " grype "]) == [
            "trivy",
            "syft",
            "grype",
        ]

    def test_duplicates_collapse_in_order(self) -> None:
        assert parse_tool_names(["syft", "trivy,syft"]) == ["syft", "trivy"]

    def test_an_unknown_name_is_named(self) -> None:
        with pytest.raises(UnknownToolError) as exc:
            parse_tool_names(["trivy", "trivvy"])
        assert "trivvy" in str(exc.value)
        assert "removed" not in str(exc.value)

    @pytest.mark.parametrize("name", sorted(REMOVED_TOOLS))
    def test_a_removed_name_says_so(self, name: str) -> None:
        with pytest.raises(UnknownToolError) as exc:
            parse_tool_names([name])
        assert f"{name}" in str(exc.value)
        assert "removed in v2.0.0" in str(exc.value)

    def test_sixteen_were_removed(self) -> None:
        """docs/TOOLS.md "Removed in v2.0.0" lists sixteen; falco's companion
        falcoctl is accepted as a spelling of the same removal."""
        assert len(REMOVED_TOOLS - {"falcoctl"}) == 16
        assert not REMOVED_TOOLS & set(DESCRIPTORS)


# --- exclusions reach only a tree (#1318) -------------------------------------
#
# `--skip-dirs **/vendor` on an image scan drops the image's vulnerabilities
# under any `vendor` path; a `--skip-path` on checkov's file mode is meaningless
# at best. Two layers keep them off: `run_tools` hands exclusion arguments only
# to a repository target, and each non-repository builder ignores what it is
# handed (`excl=False`). Either alone suffices, so each is tested alone: a
# mutation of one layer is invisible through the other (measured: with `excl`
# flipped on `_trivy("image")`, `run_tools` still built no `--skip-dirs`).

NOT_A_TREE = {
    "image": "nginx:latest",
    "iac": Path("main.tf"),
    "url": "http://a.test/app",
    "k8s": {"context": "ctx", "namespace": "ns"},
}
NON_TREE_INVOCATIONS = sorted(
    (name, key)
    for name, d in DESCRIPTORS.items()
    for key in d.invocations
    if key != "repo"
)


def test_the_non_tree_invocations_include_the_two_with_an_excl_switch() -> None:
    assert ("trivy", "image") in NON_TREE_INVOCATIONS
    assert ("checkov", "iac") in NON_TREE_INVOCATIONS
    assert {key for _, key in NON_TREE_INVOCATIONS} == set(NOT_A_TREE)


@pytest.mark.parametrize(("tool", "key"), NON_TREE_INVOCATIONS)
def test_a_builder_for_a_non_tree_drops_exclusions_it_is_handed(
    tool, key, tmp_path
) -> None:
    ctx = ScanContext(
        tool=tool,
        target_type=key,
        target=NOT_A_TREE[key],
        out_dir=tmp_path,
        binary=tool,
        exclusion_args=("--EXCLUDED", "sentinel"),
    )

    for invocation in DESCRIPTORS[tool].invocations[key](ctx):
        assert "--EXCLUDED" not in invocation.command, invocation.command


@pytest.mark.parametrize(
    ("target_type", "target"), [*NOT_A_TREE.items(), ("repo", None)]
)
def test_run_tools_hands_exclusions_to_a_repository_only(
    tmp_path, monkeypatch, target_type, target
) -> None:
    """A builder that would render whatever it is handed. The repository is
    the positive control: without it, "never hand exclusions to anything"
    passes too."""
    from scripts.cli.scan_jobs import tool_loop

    handed: list[tuple[str, ...]] = []

    def recording_builder(ctx: ScanContext) -> list:
        handed.append(ctx.exclusion_args)
        return []

    monkeypatch.setitem(
        DESCRIPTORS["trivy"].invocations, target_type, recording_builder
    )
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_bytes(b"x = 1\n")
    out = tmp_path / "out"
    out.mkdir()

    tool_loop.run_tools(
        tools=["trivy"],
        target_type=target_type,
        target=repo if target is None else target,
        target_label="t",
        out_dir=out,
        timeout=60,
        retries=0,
        per_tool_config={},
        allow_missing_tools=False,
        runner_cls=lambda **kw: type("R", (), {"run_all_parallel": lambda s: []})(),
        find_tool_func=lambda name: "/usr/bin/" + name,
        repo_root=repo if target is None else None,
    )

    assert len(handed) == 1
    assert bool(handed[0]) is (target_type == "repo"), handed
