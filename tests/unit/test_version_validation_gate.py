"""The pre-build version gate must be able to pass, and must never fail open.

Two issues, tested together because the second is only observable once the
first is fixed -- `jmo build` could not complete this check at all.

**#935**: `jmo build` runs `update_versions.py --validate` before every build
and aborts if it fails. On a clean `dev` checkout it failed, so the only way to
use `jmo build` was `--skip-validate`, which disables the check for the other 27
tools at the same time. Measured with the three network probes stubbed:

    27 passed, 2 failed   ->   cdxgen, falco

Two data causes, plus one the issue did not name:

1. `cdxgen` is an npm package with its scoped name filed under `pypi_package`,
   so it was checked against PyPI and could never be found.
2. `falco` carries `version: 0.0.0`, a placeholder for a MANUAL_INSTALL tool
   that ships in no image. The validator read it as a claim that release 0.0.0
   exists.
3. `update_versions.py` already contained a dedicated npm block for cdxgen --
   and it was **unreachable in every configuration**. It guards on
   ``if tool in passed or tool in failed: continue``, and the `python_tools`
   loop always claims cdxgen first: into `failed` when `pypi_package` is
   present (not on PyPI), into `passed` as "skipped - no PyPI package" when it
   is absent. So renaming the key in place would have turned a loud false
   failure into a silent vacuous pass, which is the failure class this campaign
   keeps finding, and the guard written to prevent exactly that could not fire.

**#939**: `_validate_versions` returns `True` -- read by its callers as
"validation passed" -- on three separate failure paths: script not found,
timeout, and any exception. The issue names one caller; there are **two**, and
the one it omits is `jmo build validate`, whose entire purpose is to report
validation status and which printed "Validation passed" and exited 0 on all
three.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

from scripts.cli.build_commands import _validate_versions
from scripts.dev.update_versions import MANUAL_INSTALL_TOOLS, validate_all_versions

REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# #935: the gate must be able to pass on the shipped versions.yaml.
# ---------------------------------------------------------------------------


@pytest.fixture
def stub_registries(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[str]]:
    """Replace the three registry probes, recording which one each tool hit.

    Stubbed rather than mocked away entirely: the point is *which* registry a
    tool is checked against, and that is only observable by recording the
    calls. Each stub answers as the real registry would for a well-formed
    request -- a scoped npm name is not on PyPI, and there is no 0.0.0 release.

    The probes return EXISTS/ABSENT/UNKNOWN, not a bool: "I could not check"
    used to collapse into "it does not exist", which is how a Windows box
    reported cdxgen 12.0.0 missing from npm when it is published there.
    """
    import scripts.dev.update_versions as uv

    seen: dict[str, list[str]] = {"pypi": [], "npm": [], "github": []}

    def pypi(pkg: str, _ver: str) -> str:
        seen["pypi"].append(pkg)
        return uv.ABSENT if pkg.startswith("@") else uv.EXISTS

    def npm(pkg: str, _ver: str) -> str:
        seen["npm"].append(pkg)
        return uv.EXISTS if pkg.startswith("@") or "/" not in pkg else uv.ABSENT

    def github(repo: str, ver: str) -> str:
        seen["github"].append(repo)
        # "nonexistent" is the marker the negative-control tests use for a
        # version that is genuinely not published. Without it the stub answered
        # "exists" for every version except 0.0.0, which made
        # test_a_manual_install_tool_with_a_real_version_is_still_validated
        # unable to fail -- a stub too permissive to distinguish the case the
        # test exists to check.
        if ver == "0.0.0" or "nonexistent" in ver:
            return uv.ABSENT
        return uv.EXISTS

    monkeypatch.setattr(uv, "check_pypi_version_exists", pypi)
    monkeypatch.setattr(uv, "check_npm_version_exists", npm)
    monkeypatch.setattr(uv, "check_github_release_exists", github)
    return seen


def test_validation_passes_on_the_shipped_versions_yaml(
    stub_registries: dict[str, list[str]],
) -> None:
    """The gate must be usable without --skip-validate.

    This is the whole of #935 stated as a property: a check whose only working
    mode is "turn it off" is not a check.
    """
    _passed, failed, _unpinned = validate_all_versions()

    assert failed == [], f"versions.yaml still fails validation for {failed}"


def test_cdxgen_is_checked_against_npm_not_pypi(
    stub_registries: dict[str, list[str]],
) -> None:
    """The registry a tool is checked against must follow its package, not its section.

    `cdxgen` lives in `python_tools` because that is how it is *installed* in
    this file's taxonomy; it is published on npm. Dispatching on the section
    is what sent a scoped npm name to PyPI.
    """
    validate_all_versions()

    assert "@cyclonedx/cdxgen" in stub_registries["npm"], (
        "cdxgen was never checked against npm; "
        f"npm calls were {stub_registries['npm']}"
    )
    assert (
        "@cyclonedx/cdxgen" not in stub_registries["pypi"]
    ), "cdxgen is still being checked against PyPI"


def test_no_scoped_npm_name_is_filed_as_a_pypi_package() -> None:
    """The data defect, asserted against versions.yaml directly.

    A structural guard rather than a cdxgen-specific one: the next npm tool
    added to `python_tools` must not repeat this, and a test naming only
    cdxgen would not notice.
    """
    versions = yaml.safe_load((REPO_ROOT / "versions.yaml").read_text(encoding="utf-8"))

    offenders = []
    for section in ("python_tools", "binary_tools", "special_tools"):
        for tool, info in (versions.get(section) or {}).items():
            pkg = info.get("pypi_package")
            if pkg and pkg.startswith("@"):
                offenders.append(f"{section}.{tool} -> {pkg}")

    assert not offenders, (
        f"scoped npm names filed under pypi_package: {offenders}. "
        f"Use `npm_package:` -- PyPI has no scoped names, so these can never "
        f"validate."
    )


def test_a_manual_install_tool_at_the_sentinel_is_reported_as_unpinned(
    stub_registries: dict[str, list[str]],
) -> None:
    """`0.0.0` on a MANUAL_INSTALL tool means "unpinned", not "release 0.0.0".

    `falco` ships in no image by design -- it is one of the four
    MANUAL_INSTALL_TOOLS -- so it carries a placeholder rather than a version.
    The validator had no notion of that and reported it as a missing release.

    Reported as a distinct third state rather than folded into "passed",
    following the precedent #373 set for `jmo tools check`: MANUAL renders
    differently from both OK and MISSING, because a user needs to be able to
    tell "we deliberately do not pin this" from "this validated".
    """
    _passed, failed, unpinned = validate_all_versions()

    assert "falco" not in failed
    assert "falco" in unpinned
    assert (
        "falcosecurity/falco" not in stub_registries["github"]
    ), "an unpinned tool should not be looked up upstream at all"


def test_the_sentinel_is_only_honoured_for_manual_install_tools(
    stub_registries: dict[str, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A `0.0.0` on a tool that DOES ship must still fail.

    The negative control. Without it, "treat 0.0.0 as unpinned" is a blanket
    escape hatch that would hide a genuinely unset version on a tool baked into
    an image -- trading the false failure for a false pass.
    """
    import scripts.dev.update_versions as uv

    versions = yaml.safe_load((REPO_ROOT / "versions.yaml").read_text(encoding="utf-8"))
    assert "trivy" not in MANUAL_INSTALL_TOOLS
    versions["binary_tools"]["trivy"]["version"] = "0.0.0"
    monkeypatch.setattr(uv, "load_versions", lambda: versions)

    _passed, failed, _unpinned = validate_all_versions()

    assert "trivy" in failed, (
        "0.0.0 on a tool that ships in an image must fail -- the sentinel is "
        "only meaningful for MANUAL_INSTALL_TOOLS"
    )


def test_a_manual_install_tool_with_a_real_version_is_still_validated(
    stub_registries: dict[str, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other negative control: MANUAL is not a blanket exemption.

    "Skip MANUAL_INSTALL_TOOLS" was one of the options on the table and this is
    why it was not taken -- `afl++`, `mobsf` and `akto` all carry real pinned
    versions today, and exempting the whole set would stop checking three
    tools that are checkable.
    """
    import scripts.dev.update_versions as uv

    versions = yaml.safe_load((REPO_ROOT / "versions.yaml").read_text(encoding="utf-8"))
    versions["special_tools"]["falco"]["version"] = "9.9.9-nonexistent"
    monkeypatch.setattr(uv, "load_versions", lambda: versions)

    _passed, failed, unpinned = validate_all_versions()

    assert "falco" not in unpinned
    assert (
        "falco" in failed
    ), "a MANUAL_INSTALL tool carrying a real version must still be checked"


def test_every_tool_is_accounted_for_exactly_once(
    stub_registries: dict[str, list[str]],
) -> None:
    """Meta-guard: the three buckets must partition the registry.

    An entry that falls through every branch is invisible -- neither passed nor
    failed, and nothing counts it. That is how the unreachable npm block hid:
    its work was silently done by another loop, so the totals still looked
    right.
    """
    versions = yaml.safe_load((REPO_ROOT / "versions.yaml").read_text(encoding="utf-8"))
    declared = {
        tool
        for section in ("python_tools", "binary_tools", "special_tools")
        for tool in (versions.get(section) or {})
    }

    passed, failed, unpinned = validate_all_versions()
    reported = [*passed, *failed, *unpinned]

    assert sorted(set(reported)) == sorted(declared), (
        f"reported set differs from versions.yaml: "
        f"missing={sorted(declared - set(reported))} "
        f"extra={sorted(set(reported) - declared)}"
    )
    assert len(reported) == len(
        set(reported)
    ), f"a tool was counted twice: {sorted({t for t in reported if reported.count(t) > 1})}"


# ---------------------------------------------------------------------------
# #939: the gate must not report success on a check it did not complete.
# ---------------------------------------------------------------------------


def test_a_missing_validation_script_does_not_report_success(tmp_path: Path) -> None:
    """An absent script means the gate is absent, not satisfied."""
    assert _validate_versions(tmp_path) is False


def test_a_timeout_does_not_report_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A gate that never completed has not passed.

    Not theoretical: `--validate` makes ~29 network calls to PyPI, npm and the
    GitHub API against a 120s budget, and the GitHub calls are rate-limited
    without a GITHUB_TOKEN.
    """
    script = tmp_path / "scripts" / "dev" / "update_versions.py"
    script.parent.mkdir(parents=True)
    script.write_text("", encoding="utf-8")

    def boom(*_a: object, **_k: object) -> None:
        raise subprocess.TimeoutExpired(cmd="update_versions.py", timeout=120)

    monkeypatch.setattr(subprocess, "run", boom)

    assert _validate_versions(tmp_path) is False


def test_an_unexpected_exception_does_not_report_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A gate that crashed has not passed."""
    script = tmp_path / "scripts" / "dev" / "update_versions.py"
    script.parent.mkdir(parents=True)
    script.write_text("", encoding="utf-8")

    def boom(*_a: object, **_k: object) -> None:
        raise OSError("no interpreter")

    monkeypatch.setattr(subprocess, "run", boom)

    assert _validate_versions(tmp_path) is False


@pytest.mark.parametrize(
    ("returncode", "expected"), [(0, True), (1, False)], ids=["clean", "failed"]
)
def test_a_completed_run_is_reported_by_its_exit_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    expected: bool,
) -> None:
    """The negative control: a gate that always returns False is not a fix.

    Both directions, so "make the error paths strict" cannot be satisfied by
    making the function useless.
    """
    script = tmp_path / "scripts" / "dev" / "update_versions.py"
    script.parent.mkdir(parents=True)
    script.write_text("", encoding="utf-8")

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_a, **_k: subprocess.CompletedProcess([], returncode, "", ""),
    )

    assert _validate_versions(tmp_path) is expected


def test_jmo_build_validate_reports_the_failure_it_could_not_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The caller the issue did not name.

    `jmo build validate` exists to answer "are the pinned versions real?". On a
    timeout it printed "Validation passed" and exited 0 -- an answer it had not
    obtained, from the one command whose entire output is that answer.
    """
    from scripts.cli import build_commands
    from scripts.cli.jmo import build_parser

    (tmp_path / "versions.yaml").write_text("", encoding="utf-8")
    (tmp_path / "Dockerfile.deep").write_text("", encoding="utf-8")
    script = tmp_path / "scripts" / "dev" / "update_versions.py"
    script.parent.mkdir(parents=True)
    script.write_text("", encoding="utf-8")

    monkeypatch.setattr(build_commands, "_find_repo_root", lambda: tmp_path)

    def boom(*_a: object, **_k: object) -> None:
        raise subprocess.TimeoutExpired(cmd="update_versions.py", timeout=120)

    monkeypatch.setattr(subprocess, "run", boom)

    args = build_parser().parse_args(["build", "validate"])
    rc = build_commands.cmd_build(args)

    out = capsys.readouterr()
    assert rc != 0, "jmo build validate reported success on a check it never completed"
    assert "Validation passed" not in out.out


# ---------------------------------------------------------------------------
# The fail-closed twin, found while verifying #935 end to end.
# ---------------------------------------------------------------------------


def test_a_scoped_npm_name_is_percent_encoded_for_the_registry() -> None:
    """`@cyclonedx/cdxgen` must not be split on its slash.

    The registry path for a scoped package is `@scope%2Fname`; sending the raw
    slash asks for a package inside a scope path that does not exist.
    """
    import scripts.dev.update_versions as uv

    seen: list[str] = []

    def fake(url: str) -> dict:
        seen.append(url)
        return {"versions": {"12.0.0": {}}}

    original = uv._registry_json
    uv._registry_json = fake  # type: ignore[assignment]
    try:
        assert uv.check_npm_version_exists("@cyclonedx/cdxgen", "12.0.0") == uv.EXISTS
    finally:
        uv._registry_json = original  # type: ignore[assignment]

    assert seen == ["https://registry.npmjs.org/@cyclonedx%2Fcdxgen"], seen


@pytest.mark.parametrize(
    "checker",
    ["check_npm_version_exists", "check_pypi_version_exists"],
)
def test_an_unreachable_registry_is_unknown_not_absent(
    checker: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A network failure must not be reported as a missing release.

    This is the defect that kept `jmo build validate` red after the routing fix
    was already correct: `subprocess.run(["npm", ...])` cannot resolve
    `npm.CMD` on Windows (list form does not apply PATHEXT), the checker caught
    FileNotFoundError and returned False, and the caller printed
    "NOT FOUND on npm" for a version that is published. Measured: cdxgen 12.0.0
    is one of 236 versions on the npm registry.
    """
    import scripts.dev.update_versions as uv

    monkeypatch.setattr(uv, "_registry_json", lambda _url: None)

    assert getattr(uv, checker)("anything", "1.0.0") == uv.UNKNOWN


def test_a_404_from_the_registry_is_absent_not_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The negative control: a real answer must stay a real answer.

    Without it, "treat failures as unknown" could be satisfied by never
    reporting ABSENT at all -- which would make the gate incapable of failing,
    the exact shape #939 is about.
    """
    import scripts.dev.update_versions as uv

    monkeypatch.setattr(uv, "_registry_json", lambda _url: {})

    assert uv.check_npm_version_exists("@scope/gone", "1.0.0") == uv.ABSENT
    assert uv.check_pypi_version_exists("gone", "1.0.0") == uv.ABSENT


def test_could_not_check_is_reported_as_a_failure_not_a_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """UNKNOWN must land in `failed`, and say so distinctly.

    Same rule #939 applies to the build gate: a check that could not run has
    not passed. The wording has to differ from NOT FOUND, or a network outage
    reads as a bad version pin.
    """
    import scripts.dev.update_versions as uv

    monkeypatch.setattr(uv, "check_npm_version_exists", lambda *_a: uv.UNKNOWN)

    bucket, message = uv._validate_one(
        "cdxgen", {"version": "12.0.0", "npm_package": "@cyclonedx/cdxgen"}
    )

    assert bucket == "failed"
    assert "COULD NOT CHECK" in message
    assert "NOT FOUND" not in message


def test_registry_json_distinguishes_a_404_from_a_network_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The distinction the whole fix rests on, tested at its source.

    Added because two mutations survived: every test above stubs
    `_registry_json` itself, so its two branches -- a 404 is an *answer*
    ("absent"), any other failure is *no answer* ("unknown") -- were never
    executed. A mutation collapsing them was invisible. That is information
    about the tests, not a licence to move on.
    """
    import urllib.error

    import scripts.dev.update_versions as uv

    def raise_http(*_a: object, **_k: object) -> None:
        raise urllib.error.HTTPError("u", 404, "Not Found", {}, None)  # type: ignore[arg-type]

    def raise_url(*_a: object, **_k: object) -> None:
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(uv.urllib.request, "urlopen", raise_http)
    assert (
        uv._registry_json("https://example.test/x") == {}
    ), "a 404 is an answer -- the package or version is genuinely absent"

    monkeypatch.setattr(uv.urllib.request, "urlopen", raise_url)
    assert (
        uv._registry_json("https://example.test/x") is None
    ), "a transport failure is NOT an answer -- it must surface as unknown"


def test_registry_json_reports_a_non_404_http_error_as_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 500 or a 429 is the registry failing, not the version being absent.

    Rate limiting is the realistic case: npm and PyPI both throttle anonymous
    clients, and ~29 lookups in a row is exactly the shape that trips it.
    """
    import urllib.error

    import scripts.dev.update_versions as uv

    for code in (429, 500, 503):

        def raise_http(*_a: object, _code: int = code, **_k: object) -> None:
            raise urllib.error.HTTPError("u", _code, "err", {}, None)  # type: ignore[arg-type]

        monkeypatch.setattr(uv.urllib.request, "urlopen", raise_http)
        assert (
            uv._registry_json("https://example.test/x") is None
        ), f"HTTP {code} was read as a definitive answer"
