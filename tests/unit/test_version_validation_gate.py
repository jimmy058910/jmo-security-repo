"""The pre-build version gate must be able to pass, and must never fail open.

Two issues, tested together because the second is only observable once the
first is fixed -- `jmo build` could not complete this check at all.

**#935**: `jmo build` runs `update_versions.py --validate` before every build
and aborts if it fails. On a clean `dev` checkout it failed, so the only way to
use `jmo build` was `--skip-validate`, which disables the check for every other
tool at the same time. The causes were a scoped npm name filed under
`pypi_package` (cdxgen) and a `0.0.0` placeholder read as a release (falco);
both tools, npm and the placeholder left in v2.0.0. What stays is the rule the
fix established: the registry a pin is checked against follows the package
field the entry carries, not the section it sits in.

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
from scripts.dev.update_versions import validate_all_versions

REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# #935: the gate must be able to pass on the shipped versions.yaml.
# ---------------------------------------------------------------------------


@pytest.fixture
def stub_registries(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[str]]:
    """Replace the registry probes, recording which one each tool hit.

    Stubbed rather than mocked away entirely: the point is *which* registry a
    tool is checked against, and that is only observable by recording the
    calls. Each stub answers as the real registry would for a well-formed
    request -- there is no 0.0.0 release.

    The probes return EXISTS/ABSENT/UNKNOWN, not a bool: "I could not check"
    used to collapse into "it does not exist".
    """
    import scripts.dev.update_versions as uv

    seen: dict[str, list[str]] = {"pypi": [], "github": []}

    # "nonexistent" is the marker the negative-control tests use for a version
    # that is genuinely not published. Without it a stub answers "exists" for
    # every version, which makes a test of the failing path unable to fail.
    def pypi(pkg: str, ver: str) -> str:
        seen["pypi"].append(pkg)
        return uv.ABSENT if "nonexistent" in ver else uv.EXISTS

    def github(repo: str, ver: str) -> str:
        seen["github"].append(repo)
        if ver == "0.0.0" or "nonexistent" in ver:
            return uv.ABSENT
        return uv.EXISTS

    monkeypatch.setattr(uv, "check_pypi_version_exists", pypi)
    monkeypatch.setattr(uv, "check_github_release_exists", github)
    return seen


def test_validation_passes_on_the_shipped_versions_yaml(
    stub_registries: dict[str, list[str]],
) -> None:
    """The gate must be usable without --skip-validate.

    This is the whole of #935 stated as a property: a check whose only working
    mode is "turn it off" is not a check.
    """
    _passed, failed = validate_all_versions()

    assert failed == [], f"versions.yaml still fails validation for {failed}"


def test_yara_is_checked_against_pypi_not_github(
    stub_registries: dict[str, list[str]],
) -> None:
    """The registry a tool is checked against must follow its package, not its section.

    `yara` lives in `special_tools`, a section whose other entries are GitHub
    releases; it is published on PyPI as `yara-python`. Dispatching on the
    section is what once sent a package to a registry it was never on.
    """
    passed, _failed = validate_all_versions()

    assert "yara-python" in stub_registries["pypi"], (
        f"yara was never checked against PyPI; PyPI calls were {stub_registries['pypi']}"
    )
    assert "yara" in passed


def test_a_0_0_0_version_fails_validation(
    stub_registries: dict[str, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A `0.0.0` placeholder is not an exemption.

    It was honoured as "unpinned" for manual-install tools until v2.0.0 removed
    them. Nothing may treat it as one now, or a genuinely unset version on a
    tool baked into the image would pass the gate.
    """
    import scripts.dev.update_versions as uv

    versions = yaml.safe_load((REPO_ROOT / "versions.yaml").read_text(encoding="utf-8"))
    versions["binary_tools"]["trivy"]["version"] = "0.0.0"
    monkeypatch.setattr(uv, "load_versions", lambda: versions)

    _passed, failed = validate_all_versions()

    assert "trivy" in failed, "0.0.0 on a tool that ships in the image must fail"


def test_a_pypi_pin_to_an_unpublished_version_fails(
    stub_registries: dict[str, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The PyPI path can fail too.

    The negative control for `test_validation_passes_on_the_shipped_versions_yaml`
    on the PyPI side: without it, a PyPI branch that never reported a failure
    would pass every other test in this file.
    """
    import scripts.dev.update_versions as uv

    versions = yaml.safe_load((REPO_ROOT / "versions.yaml").read_text(encoding="utf-8"))
    versions["python_tools"]["semgrep"]["version"] = "9.9.9-nonexistent"
    monkeypatch.setattr(uv, "load_versions", lambda: versions)

    _passed, failed = validate_all_versions()

    assert "semgrep" in failed
    assert "semgrep" in stub_registries["pypi"]


def test_every_tool_is_accounted_for_exactly_once(
    stub_registries: dict[str, list[str]],
) -> None:
    """Meta-guard: the two buckets must partition the registry.

    An entry that falls through every branch is invisible -- neither passed nor
    failed, and nothing counts it. That is how an unreachable npm block once
    hid: its work was silently done by another loop, so the totals still
    looked right.
    """
    versions = yaml.safe_load((REPO_ROOT / "versions.yaml").read_text(encoding="utf-8"))
    declared = {
        tool
        for section in ("python_tools", "binary_tools", "special_tools")
        for tool in (versions.get(section) or {})
    }

    passed, failed = validate_all_versions()
    reported = [*passed, *failed]

    assert sorted(set(reported)) == sorted(declared), (
        f"reported set differs from versions.yaml: "
        f"missing={sorted(declared - set(reported))} "
        f"extra={sorted(set(reported) - declared)}"
    )
    assert len(reported) == len(set(reported)), (
        f"a tool was counted twice: {sorted({t for t in reported if reported.count(t) > 1})}"
    )


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

    Not theoretical: `--validate` makes one network call per versions.yaml
    entry, to PyPI or the GitHub API, against a 120s budget, and the GitHub
    calls are rate-limited without a GITHUB_TOKEN.
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
    (tmp_path / "Dockerfile").write_text("", encoding="utf-8")
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


def test_an_unreachable_registry_is_unknown_not_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A network failure must not be reported as a missing release.

    This is the defect that kept `jmo build validate` red after the routing fix
    was already correct: a checker that could not reach its registry returned
    False, and the caller printed "NOT FOUND" for a version that is published.
    """
    import scripts.dev.update_versions as uv

    monkeypatch.setattr(uv, "_registry_json", lambda _url: None)

    assert uv.check_pypi_version_exists("anything", "1.0.0") == uv.UNKNOWN


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

    monkeypatch.setattr(uv, "check_pypi_version_exists", lambda *_a: uv.UNKNOWN)

    bucket, message = uv._validate_one(
        "semgrep", {"version": "1.175.0", "pypi_package": "semgrep"}
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
    assert uv._registry_json("https://example.test/x") == {}, (
        "a 404 is an answer -- the package or version is genuinely absent"
    )

    monkeypatch.setattr(uv.urllib.request, "urlopen", raise_url)
    assert uv._registry_json("https://example.test/x") is None, (
        "a transport failure is NOT an answer -- it must surface as unknown"
    )


def test_registry_json_reports_a_non_404_http_error_as_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 500 or a 429 is the registry failing, not the version being absent.

    Rate limiting is the realistic case: PyPI throttles anonymous clients, and
    one lookup per versions.yaml entry in a row is exactly the shape that trips
    it.
    """
    import urllib.error

    import scripts.dev.update_versions as uv

    for code in (429, 500, 503):

        def raise_http(*_a: object, _code: int = code, **_k: object) -> None:
            raise urllib.error.HTTPError("u", _code, "err", {}, None)  # type: ignore[arg-type]

        monkeypatch.setattr(uv.urllib.request, "urlopen", raise_http)
        assert uv._registry_json("https://example.test/x") is None, (
            f"HTTP {code} was read as a definitive answer"
        )
