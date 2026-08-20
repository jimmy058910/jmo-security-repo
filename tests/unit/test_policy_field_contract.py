#!/usr/bin/env python3
"""Every field a builtin policy reads must be a field findings actually carry.

Chunk 16 found two shipped policies that were structurally inert -- they could
not fire on any input, and said PASS for every one:

* ``zero-secrets.rego`` gated on ``finding.raw.verified``. TruffleHog writes
  ``Verified`` (capital V) and ``trufflehog_adapter`` stores its record verbatim
  (``raw=f``), so the lowercase key has never existed. A findings file holding
  one verified AWS secret, produced by the real adapter from a real TruffleHog
  record, evaluated to ``allow = true`` with the message "No verified secrets
  detected".
* ``hipaa-compliance.rego`` computed ``sprintf("CWE-%d", [finding.risk.cwe])``
  where ``risk.cwe`` is an array of strings, so ``allow`` was unconditionally
  true.

Neither is visible to the existing tests. ``tests/cli/test_policy_commands.py``
mocks ``PolicyEngine`` and *supplies* the verdict, and the only tests that run
real OPA were skipped by a resolver that disagreed with the product's own.

So the guard here is structural rather than example-based, in the shape of
``test_trend_payload_contract.py`` from chunk 15: extract every field reference
out of the ``.rego`` sources, then check each one against findings built by
**real adapters from real tool records** and put through the **real compliance
enricher**. It needs no OPA binary, so unlike the behavioural tests in
``tests/integration/test_builtin_policy_decisions.py`` it runs everywhere --
including CI, which does not install OPA.

The extractor carries its own meta-guard. An extractor that silently traces
nothing passes every assertion built on top of it, which is exactly how chunk
15's first AST probe reported zero absent keys for the file containing the
headline defect.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from scripts.core.adapters.nuclei_adapter import NucleiAdapter
from scripts.core.adapters.semgrep_adapter import SemgrepAdapter
from scripts.core.adapters.trufflehog_adapter import TruffleHogAdapter
from scripts.core.compliance_mapper import enrich_findings_with_compliance

BUILTIN_DIR = Path(__file__).parent.parent.parent / "policies" / "builtin"

# Paths the extractor must find, named individually. A floor alone does not
# prove the extractor reached the *interesting* parts of each file.
MUST_EXTRACT = {
    "tool.name",  # zero-secrets, production-hardening
    "severity",  # all five
    "raw.Verified",  # zero-secrets -- the field the defect was about
    "risk.cwe",  # hipaa-compliance
    "compliance.owaspTop10_2021",  # owasp-top-10
    "compliance.pciDss4_0",  # pci-dss
    "location.startLine",  # zero-secrets
}

# `finding.<path>` and `<local> := <set>[_]` aliases both appear, so match the
# dereference itself rather than trying to resolve Rego's bindings.
_DEREF = re.compile(
    r"\bfinding\.((?:[A-Za-z_][A-Za-z0-9_]*)(?:\.[A-Za-z_][A-Za-z0-9_]*)*)"
)

# `object.get(finding, "remediation", "")` and
# `object.get(finding.location, "startLine", 0)` read a field just as much as a
# bare dereference does -- they are how an *optional* field is read safely. If
# the extractor did not see them, the guarded reads would drop out of the
# contract entirely, and the fix for one silent-drop class would create another.
_OBJECT_GET = re.compile(
    r"\bobject\.get\(\s*finding((?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s*,\s*\"([A-Za-z_][A-Za-z0-9_]*)\""
)


def _policy_files() -> list[Path]:
    return sorted(BUILTIN_DIR.glob("*.rego"))


def _strip_comments(text: str) -> str:
    """Drop Rego comments, respecting string literals.

    Necessary, not cosmetic: the fixes in these policies carry comments naming
    the dead field they replaced (``finding.raw.verified``). Matching prose
    would make this suite fail on its own explanation of why it exists.
    """
    out = []
    for line in text.splitlines():
        in_str = False
        cut = len(line)
        for i, ch in enumerate(line):
            if ch == '"' and (i == 0 or line[i - 1] != "\\"):
                in_str = not in_str
            elif ch == "#" and not in_str:
                cut = i
                break
        out.append(line[:cut])
    return "\n".join(out)


def _extract_field_paths(text: str) -> set[str]:
    """Every dotted path a policy's *code* reads off a finding.

    Covers both spellings: the bare `finding.a.b` dereference and the
    `object.get(finding.a, "b", <default>)` guarded read.
    """
    code = _strip_comments(text)
    paths = {m.group(1) for m in _DEREF.finditer(code)}
    for m in _OBJECT_GET.finditer(code):
        prefix = m.group(1).lstrip(".")
        paths.add(f"{prefix}.{m.group(2)}" if prefix else m.group(2))
    return paths


def _real_findings() -> list[dict[str, Any]]:
    """Findings built by real adapters from real tool records, then enriched.

    Deliberately not hand-written. A hand-authored finding is written to match
    whatever the policy reads, so it confirms any field name at all -- which is
    how ``test_policy_evaluation_with_violations_performance`` came to supply
    ``raw: {"verified": True}``, the exact shape nothing produces, and would
    have passed against the broken policy.
    """
    import tempfile

    findings: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        # TruffleHog NDJSON -- a verified AWS key. Supplies raw.Verified and the
        # normalised "verified" tag.
        th = tmp / "trufflehog.json"
        th.write_bytes(
            (
                json.dumps(
                    {
                        "SourceMetadata": {
                            "Data": {"Filesystem": {"file": "config/prod.env"}}
                        },
                        "DetectorName": "AWS",
                        "Verified": True,
                        "Raw": "AKIAIOSFODNN7EXAMPLE",
                        "StartLine": 3,
                    }
                )
                + "\n"
            ).encode("utf-8")
        )
        findings += [f.to_dict() for f in TruffleHogAdapter().parse(th)]

        # Semgrep -- supplies risk.cwe and a CWE the compliance mapper maps.
        sg = tmp / "semgrep.json"
        sg.write_bytes(
            json.dumps(
                {
                    "results": [
                        {
                            "check_id": "python.lang.security.audit.exec-detected",
                            "path": "app.py",
                            "start": {"line": 12},
                            "end": {"line": 12},
                            "extra": {
                                "message": "exec detected",
                                "severity": "ERROR",
                                "metadata": {
                                    "cwe": [
                                        "CWE-79: Improper Neutralization of Input "
                                        "During Web Page Generation"
                                    ],
                                    "owasp": ["A03:2021 - Injection"],
                                },
                            },
                        }
                    ],
                    "errors": [],
                }
            ).encode("utf-8")
        )
        findings += [f.to_dict() for f in SemgrepAdapter().parse(sg)]

        # Nuclei -- a second shape, and a tool whose remediation is defaulted.
        nu = tmp / "nuclei.json"
        nu.write_bytes(
            (
                json.dumps(
                    {
                        "template-id": "CVE-2021-44228",
                        "info": {
                            "name": "Apache Log4j RCE",
                            "severity": "critical",
                            "description": "Log4Shell",
                        },
                        "matched-at": "https://example.com/api",
                        "type": "http",
                    }
                )
                + "\n"
            ).encode("utf-8")
        )
        findings += [f.to_dict() for f in NucleiAdapter().parse(nu)]

    return enrich_findings_with_compliance(findings)


def _has_path(finding: dict[str, Any], dotted: str) -> bool:
    cur: Any = finding
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return False
        cur = cur[part]
    return True


@pytest.fixture(scope="module")
def real_findings() -> list[dict[str, Any]]:
    findings = _real_findings()
    # Meta-guard on the corpus itself: if the adapters stop producing, every
    # "field is present" assertion below would fail for the wrong reason, and
    # every "field is absent" one would pass for the wrong reason.
    assert len(findings) >= 3, f"only {len(findings)} findings built from adapters"
    assert any(f["tool"]["name"] == "trufflehog" for f in findings)
    assert any(f.get("compliance") for f in findings), "enrichment produced nothing"
    return findings


def test_extractor_actually_traces_dereferences():
    """The extractor must reach the interesting parts of every policy.

    Without this, a regex that quietly matches nothing turns
    ``test_every_policy_field_exists_in_real_findings`` into a test that cannot
    fail.
    """
    files = _policy_files()
    assert len(files) == 5, f"expected 5 builtin policies, found {len(files)}"

    found: set[str] = set()
    per_file: dict[str, set[str]] = {}
    for p in files:
        paths = _extract_field_paths(p.read_text(encoding="utf-8"))
        assert paths, f"extractor found no finding dereferences in {p.name}"
        per_file[p.name] = paths
        found |= paths

    assert len(found) >= 8, f"extractor found only {len(found)} distinct paths: {found}"
    missing = MUST_EXTRACT - found
    assert not missing, f"extractor failed to reach known dereferences: {missing}"

    # The comment stripper must strip, and must not strip code. Both halves
    # matter: a stripper that ate everything would empty `found` (caught above),
    # one that ate nothing would resurrect the historical `raw.verified` these
    # policies name in their own comments.
    assert "raw.verified" not in found, (
        "extractor is matching prose: `raw.verified` appears only in the comment "
        "explaining the defect, never in code"
    )
    assert "raw.Verified" in per_file["zero-secrets.rego"]


def test_extractor_rejects_the_field_that_was_broken():
    """Negative control: the checker must still reject the pre-fix source.

    Without this, "every path resolves" could mean the checker resolves
    everything, which is the failure mode an oracle is supposed to rule out.
    """
    pre_fix = """
    verified_secrets contains finding if {
        finding := input.findings[_]
        finding.raw.verified == true
    }
    """
    paths = _extract_field_paths(pre_fix)
    assert "raw.verified" in paths

    findings = _real_findings()
    assert not any(
        _has_path(f, "raw.verified") for f in findings
    ), "raw.verified is produced by something now -- update this control"


def test_every_policy_field_exists_in_real_findings(real_findings):
    """No builtin policy may gate on a field no adapter produces.

    This is the whole class the chunk was about. A policy that reads a field
    nothing writes does not error -- Rego makes the expression undefined, the
    rule silently does not match, and the policy answers PASS.
    """
    unresolvable: dict[str, list[str]] = {}
    for p in _policy_files():
        for dotted in sorted(_extract_field_paths(p.read_text(encoding="utf-8"))):
            if not any(_has_path(f, dotted) for f in real_findings):
                unresolvable.setdefault(p.name, []).append(dotted)

    assert not unresolvable, (
        "policies dereference fields that no real adapter produces "
        f"(these silently never match, so the policy always PASSES): {unresolvable}"
    )


def test_hipaa_safeguard_map_covers_every_listed_cwe():
    """A CWE in ``hipaa_cwes`` with no safeguard drops its finding silently.

    ``hipaa_violations`` builds an object containing
    ``hipaa_safeguard(cwe)``. If the map has no entry, that call is undefined,
    the whole object is undefined and the violation disappears -- while
    ``allow`` still reports false. The two lists are coupled by hand and
    nothing else checks them.
    """
    text = (BUILTIN_DIR / "hipaa-compliance.rego").read_text(encoding="utf-8")

    listed = set(re.findall(r'"(CWE-\d+)",\s*#', text))
    mapped = set(re.findall(r'"(CWE-\d+)":\s*"16[0-9.()a-z\s\-/]+', text))

    assert len(listed) >= 10, f"only {len(listed)} CWEs parsed out of hipaa_cwes"
    assert len(mapped) >= 10, f"only {len(mapped)} CWEs parsed out of safeguard_map"
    assert listed == mapped, (
        "hipaa_cwes and safeguard_map disagree; a listed CWE with no safeguard "
        f"silently drops its violation. only-listed={listed - mapped} "
        f"only-mapped={mapped - listed}"
    )


def test_optional_fields_are_read_defensively():
    """Fields the schema marks optional must go through ``object.get``.

    ``Finding.to_dict()`` drops ``None`` values, so an optional field that is
    unset is *absent*, not null. A bare dereference inside a violation object
    then makes the whole object undefined and the violation vanishes from the
    report while ``allow`` still fails. Measured: two findings both breaching
    ``owasp-top-10``, one without ``remediation``, produced ``violations = 1``
    and the message "Found 1 OWASP Top 10 violations".
    """
    # Optional per docs/schemas/common_finding.v1.json: required is
    # schemaVersion, id, ruleId, severity, tool, location, message; within
    # location only `path` is required.
    optional = {
        "remediation",
        "location.startLine",
        "location.endLine",
        "title",
        "description",
        "cvss",
        "context",
    }

    offenders: dict[str, list[str]] = {}
    for p in _policy_files():
        code = _strip_comments(p.read_text(encoding="utf-8"))
        for dotted in sorted(_extract_field_paths(code)):
            if dotted not in optional:
                continue
            bare = re.search(
                rf"(?<!object\.get\()\bfinding\.{re.escape(dotted)}\b", code
            )
            guarded = f'object.get(finding, "{dotted}"' in code or (
                "." in dotted
                and f'object.get(finding.{dotted.rsplit(".", 1)[0]}, '
                f'"{dotted.rsplit(".", 1)[1]}"' in code
            )
            if bare and not guarded:
                offenders.setdefault(p.name, []).append(dotted)

    assert not offenders, (
        "optional fields dereferenced without object.get(); when absent these "
        f"silently drop the whole violation: {offenders}"
    )


def test_every_policy_emoji_has_an_ascii_fallback():
    """Policy-authored text reaches a console, so its glyphs need fallbacks.

    Derived from the ``.rego`` sources rather than restating a list, so adding
    an emoji to a policy is what makes this fail -- the same reasoning as
    ``MUST_EXTRACT`` above. Chunk 16 measured 7 distinct non-ASCII codepoints
    across the five files, of which U+1F6AB and U+1F6A8 were absent from the
    table and rendered as a bare "?".

    ``[?]`` is excluded deliberately (#921): it is indistinguishable from the
    bare "?" that ``errors="replace"`` emits, which is the failure this table
    exists to make visible.
    """
    from scripts.core.unicode_utils import UNICODE_FALLBACKS

    used: dict[str, set[str]] = {}
    for p in _policy_files():
        for ch in p.read_text(encoding="utf-8"):
            if ord(ch) > 127:
                used.setdefault(ch, set()).add(p.name)

    assert len(used) >= 5, f"only {len(used)} non-ASCII codepoints found: {used.keys()}"

    # VARIATION SELECTOR-16 is handled per-emoji, by giving the two-character
    # sequence its own key (see the "warning sign" entries), never on its own.
    variation_selector = "\ufe0f"
    missing = {
        f"U+{ord(ch):04X}": sorted(files)
        for ch, files in used.items()
        if ch != variation_selector and ch not in UNICODE_FALLBACKS
    }
    assert not missing, f"policy emoji with no ASCII fallback: {missing}"

    placeholder = {
        f"U+{ord(ch):04X}" for ch in used if UNICODE_FALLBACKS.get(ch) == "[?]"
    }
    assert (
        not placeholder
    ), f"policy emoji mapped to the ambiguous '[?]' token: {placeholder}"
