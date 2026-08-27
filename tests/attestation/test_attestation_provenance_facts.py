"""An attestation must be readable by other people's verifiers, and say which
commit was scanned.

**#946**: JMo emitted in-toto Statement **v0.1** carrying a SLSA Provenance
**v1** predicate. `constants.py` called v0.1 "the current version for in-toto
attestations"; it is not, and SLSA Provenance v1 is specified to travel in a v1
Statement. Generator and verifier agreed with each other, so nothing was broken
*inside* JMo -- and that is the whole cost: the entire point of publishing SLSA
provenance is that somebody else's verifier reads it, and `cosign` /
`slsa-verifier` expect v1.

Measured, and not stated in the issue: `verifier.py` did not read
`INTOTO_VERSION` at all. It compared against the **literal** string, so flipping
the constant alone would have made JMo unable to verify its own output.

**#945**: `MetadataCapture` was 183 lines with 23 tests and zero callers. Its
own docstring said "Used by ProvenanceGenerator"; `ProvenanceGenerator` did not
import it. The cost is not the dead code -- it is that
`capture_git_context()` reads the commit SHA, branch and tag and **none of it
reached the attestation**, so JMo's provenance could not answer "which commit
was scanned", the field a consumer would most want to pin a result to.

Wired in rather than deleted. Which repo was the open question: the subject's
directory is not the scanned tree (`findings.json` lives in the results
directory, which need not be a repo at all), so the context is captured from the
**scanned target** and only when there is exactly one -- attributing one commit
to a multi-repo scan would be a fresh false statement in the one document whose
purpose is to be believed.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scripts.core.attestation.constants import INTOTO_VERSION, SLSA_VERSION
from scripts.core.attestation.provenance import ProvenanceGenerator
from scripts.core.attestation.verifier import AttestationVerifier

V1 = "https://in-toto.io/Statement/v1"
V0_1 = "https://in-toto.io/Statement/v0.1"


@pytest.fixture
def findings(tmp_path: Path) -> Path:
    path = tmp_path / "findings.json"
    path.write_text(json.dumps({"findings": []}), encoding="utf-8")
    return path


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """A real one-commit repository, or skip.

    A real repo rather than a mocked `subprocess.run`: the thing under test is
    that a *commit SHA* reaches the document, and a mock that returns a
    hardcoded SHA would pass whether or not git was ever consulted.
    """
    repo = tmp_path / "scanned-repo"
    repo.mkdir()
    try:
        for cmd in (
            ["git", "init", "-q", "-b", "main"],
            # Repo-local identity, so the fixture does not depend on -- or
            # touch -- the developer's global git config.
            ["git", "config", "user.email", "t@example.test"],
            ["git", "config", "user.name", "T"],
            ["git", "commit", "-q", "--allow-empty", "-m", "initial"],
        ):
            subprocess.run(cmd, cwd=repo, check=True, capture_output=True, timeout=30)
    except (
        FileNotFoundError,
        subprocess.CalledProcessError,
    ) as exc:  # pragma: no cover
        pytest.skip(f"git unavailable: {exc}")
    return repo


def _head(repo: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    ).stdout.strip()


# ---------------------------------------------------------------------------
# #946: the statement version.
# ---------------------------------------------------------------------------


def test_the_statement_version_matches_the_predicate_version(findings: Path) -> None:
    """A SLSA Provenance v1 predicate travels in an in-toto Statement v1."""
    statement = ProvenanceGenerator().generate(
        findings_path=findings, profile="fast", tools=[], targets=[]
    )

    assert statement["predicateType"] == SLSA_VERSION
    assert statement["_type"] == V1, (
        f"emitted {statement['_type']} with a {statement['predicateType']} "
        f"predicate -- external verifiers expect the versions to agree"
    )


def test_the_constant_is_what_the_generator_emits() -> None:
    """The constant must be the single source, not a parallel literal."""
    assert INTOTO_VERSION == V1


def test_the_verifier_reads_the_constant_rather_than_a_literal() -> None:
    """`verifier.py` hardcoded the v0.1 string instead of the constant.

    That is why "flip the constant" was never a one-line fix: the generator and
    the verifier would have disagreed, and JMo would have been unable to verify
    its own freshly written attestation. Asserted structurally so the two cannot
    drift again.
    """
    source = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "core"
        / "attestation"
        / "verifier.py"
    ).read_text(encoding="utf-8")

    assert V0_1 not in source, (
        "verifier.py still carries the v0.1 literal; accepted versions belong "
        "in constants.py so the generator and verifier cannot disagree"
    )


def test_a_freshly_generated_attestation_verifies(
    findings: Path, tmp_path: Path
) -> None:
    """End to end: what JMo writes, JMo must accept."""
    statement = ProvenanceGenerator().generate(
        findings_path=findings, profile="fast", tools=[], targets=[]
    )
    att = tmp_path / "att.json"
    att.write_text(json.dumps(statement), encoding="utf-8")

    result = AttestationVerifier().verify(str(findings), str(att))

    assert result.error_message != "Invalid attestation format"


def test_an_attestation_written_before_the_migration_still_verifies(
    findings: Path, tmp_path: Path
) -> None:
    """v0.1 documents keep verifying.

    Not backward compatibility for its own sake -- this is a *security*
    component, and refusing to read a document JMo itself issued turns a
    version bump into an inability to check anything already published. The
    accepted set is explicit and lives beside the emitted version.
    """
    statement = ProvenanceGenerator().generate(
        findings_path=findings, profile="fast", tools=[], targets=[]
    )
    statement["_type"] = V0_1
    att = tmp_path / "old.json"
    att.write_text(json.dumps(statement), encoding="utf-8")

    result = AttestationVerifier().verify(str(findings), str(att))

    assert result.error_message != "Invalid attestation format"


def test_a_genuinely_unknown_statement_type_is_still_rejected(
    findings: Path, tmp_path: Path
) -> None:
    """The negative control.

    "Accept both versions" must not become "accept anything" -- the format
    check is the first gate the verifier applies.
    """
    statement = ProvenanceGenerator().generate(
        findings_path=findings, profile="fast", tools=[], targets=[]
    )
    statement["_type"] = "https://example.test/NotAStatement/v9"
    att = tmp_path / "bogus.json"
    att.write_text(json.dumps(statement), encoding="utf-8")

    result = AttestationVerifier().verify(str(findings), str(att))

    assert result.is_valid is False
    assert result.error_message == "Invalid attestation format"


# ---------------------------------------------------------------------------
# #945: the commit the attestation is about.
# ---------------------------------------------------------------------------


def test_the_scanned_commit_reaches_the_attestation(
    findings: Path, git_repo: Path
) -> None:
    """The single most useful provenance field for a security scan.

    Recorded as a SLSA ResourceDescriptor under `resolvedDependencies` with a
    `gitCommit` digest -- the spec's own shape for "the exact source this was
    built from", and what an external verifier looks for. Not a free-text field
    in externalParameters.
    """
    statement = ProvenanceGenerator().generate(
        findings_path=findings,
        profile="fast",
        tools=[],
        targets=[str(git_repo)],
    )

    deps = statement["predicate"]["buildDefinition"]["resolvedDependencies"]
    commits = [
        d["digest"]["gitCommit"] for d in deps if "gitCommit" in (d.get("digest") or {})
    ]

    assert commits == [
        _head(git_repo)
    ], f"expected the scanned repo's HEAD in resolvedDependencies, got {deps}"


def test_the_branch_is_recorded_too(findings: Path, git_repo: Path) -> None:
    """Branch and tag are not digests, so they belong in externalParameters."""
    statement = ProvenanceGenerator().generate(
        findings_path=findings,
        profile="fast",
        tools=[],
        targets=[str(git_repo)],
    )

    external = statement["predicate"]["buildDefinition"]["externalParameters"]

    assert external["source"]["branch"] == "main"


def test_a_target_that_is_not_a_repository_degrades_cleanly(
    findings: Path, tmp_path: Path
) -> None:
    """Outside a repo: no crash, and no invented commit.

    The acceptance criterion the issue wrote. Fabricating a value here would be
    the same defect chunk 19 removed when `threads=4, timeout=600` were written
    into every attestation as though measured.
    """
    plain = tmp_path / "not-a-repo"
    plain.mkdir()

    statement = ProvenanceGenerator().generate(
        findings_path=findings, profile="fast", tools=[], targets=[str(plain)]
    )

    deps = statement["predicate"]["buildDefinition"]["resolvedDependencies"]
    assert not [d for d in deps if "gitCommit" in (d.get("digest") or {})]
    assert (
        "source" not in statement["predicate"]["buildDefinition"]["externalParameters"]
    )


def test_a_multi_repo_scan_claims_no_single_commit(
    findings: Path, git_repo: Path, tmp_path: Path
) -> None:
    """Two targets means no one commit describes the scan.

    This is why the capture keys off the scan's targets and requires exactly
    one, rather than defaulting to the subject file's directory or to cwd --
    both of which would have produced a confident, wrong answer.
    """
    other = tmp_path / "second-repo"
    other.mkdir()

    statement = ProvenanceGenerator().generate(
        findings_path=findings,
        profile="fast",
        tools=[],
        targets=[str(git_repo), str(other)],
    )

    deps = statement["predicate"]["buildDefinition"]["resolvedDependencies"]
    assert not [d for d in deps if "gitCommit" in (d.get("digest") or {})]


def test_metadata_capture_has_a_caller() -> None:
    """The structural half of #945.

    183 lines and 23 tests describing a caller that did not exist read to a
    maintainer as a working feature. This fails if the wiring is removed but the
    module is left behind.
    """
    source = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "core"
        / "attestation"
        / "provenance.py"
    ).read_text(encoding="utf-8")

    assert "MetadataCapture" in source, (
        "provenance.py no longer uses MetadataCapture -- either wire it back in "
        "or delete the module and its tests; a fully tested module nothing runs "
        "is worse than an absent one"
    )
