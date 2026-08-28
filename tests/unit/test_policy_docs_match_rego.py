#!/usr/bin/env python3
"""Guard: policy documentation may only quote controls its policy enforces.

Regression for #923.

``docs/POLICY_AS_CODE.md`` and ``policies/README.md`` both described the
``hipaa-compliance`` gate in **NIST CSF** terms -- "Data encryption (NIST CSF
PR.DS-1, PR.DS-2)", "Access controls (PR.AC-1, PR.AC-3, PR.AC-4)", "Audit
logging (DE.AE-3, DE.CM-1)", "Vulnerability management (ID.RA-1, DE.CM-8)".

``policies/builtin/hipaa-compliance.rego`` does none of that and never reads
``compliance.nistCsf2_0``. It gates on ten CWEs at CRITICAL/HIGH and maps each
to a 45 CFR 164.312 technical safeguard. So a HIGH finding tagged ``ID.RA-1``
with no CWE **passed**, and a HIGH finding carrying ``CWE-79`` with no NIST
mapping **failed** -- the opposite of what a user choosing that policy from the
documentation would predict, in both directions.

It stayed invisible because until chunk 16 the policy's ``allow`` was
unconditionally true (it applied Go's ``%d`` verb to an array of strings), so
neither set of criteria was being applied to anything.

**The same defect was in the ``pci-dss`` docs**, which #923 flagged for
re-checking. Both files said "FAIL: Any HIGH/CRITICAL finding mapped to PCI DSS
requirements". The policy fails on five specific requirements only -- 2.2.4,
3.5.1, 4.2.1, 6.2.4, 8.3.6 -- and its warning rule matches ``MEDIUM`` and
``LOW``, so a HIGH finding mapped to any other requirement produces neither a
violation nor a warning. ``policies/README.md`` additionally named "Requirement
11", which appears nowhere in the policy.

## What this asserts

Every compliance identifier quoted in a policy's documentation section must be
one that policy can actually act on. Whether it can is derived from the Rego,
not declared here, and the distinction matters: ``owasp-top-10.rego`` gates on a
non-empty ``compliance.owaspTop10_2021`` **without naming a single category**, so
listing all ten in its documentation is accurate, while ``pci-dss.rego`` names
exactly five requirements and listing a sixth is not. A first version required
the literal identifier in every case and reddened on all ten OWASP categories --
asserting the pattern instead of the property.

Only unambiguously-shaped identifiers are extracted. A PCI requirement number
is indistinguishable from a version string in prose ("PCI DSS 4.0", "OPA 1.0+",
"version 1.1.0"), so those are read only from the leading cell of a table row,
where the shape is unambiguous.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = REPO_ROOT / "policies" / "builtin"
POLICY_DOCS = ("docs/POLICY_AS_CODE.md", "policies/README.md")

# A framework the docs can cite: how its identifiers are spelled, and the
# CommonFinding field a policy reads to consult it. `None` means the framework
# has no enrichment field -- 45 CFR safeguards are the policy's own output, not
# an input it could match generically.
_FRAMEWORKS = (
    ("CWE", re.compile(r"\bCWE-\d+\b"), "risk.cwe"),
    ("NIST CSF", re.compile(r"\b(?:GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d+\b"), "nistCsf2_0"),
    ("45 CFR 164.312", re.compile(r"\b164\.312\([a-z0-9)(]*\)"), None),
    ("OWASP Top 10", re.compile(r"\bA\d{2}:\d{4}\b"), "owaspTop10_2021"),
    # A PCI requirement is indistinguishable from a version string in prose
    # ("PCI DSS 4.0", "OPA 1.0+"), so in documentation it is read only from a
    # table's leading cell. In Rego it is always a quoted list member.
    ("PCI DSS", re.compile(r"\b\d{1,2}\.\d{1,2}\.\d{1,2}\b"), "pciDss4_0"),
)
_DOC_ONLY_FROM_TABLE = {"PCI DSS"}
_TABLE_CELL = re.compile(r"^\|\s*([^|]+?)\s*\|")
_HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
_SLUG_IN_HEADING = re.compile(r"`([a-z0-9-]+)(?:\.rego)?`")


def _policy_slugs() -> set[str]:
    return {p.stem for p in POLICY_DIR.glob("*.rego")}


def _sections(text: str, slugs: set[str]) -> dict[str, list[str]]:
    """Map policy slug -> the lines of the section documenting it."""
    found: dict[str, list[str]] = {}
    current: str | None = None
    level = 0
    for line in text.splitlines():
        heading = _HEADING.match(line)
        if heading:
            this_level = len(heading.group(1))
            if current is not None and this_level <= level:
                current = None
            match = _SLUG_IN_HEADING.search(heading.group(2))
            if match and match.group(1) in slugs:
                current = match.group(1)
                level = this_level
                found.setdefault(current, [])
            continue
        if current is not None:
            found[current].append(line)
    return found


def _cited(lines: list[str], framework: str, pattern: re.Pattern[str]) -> set[str]:
    """Identifiers of one framework cited in a documentation section."""
    if framework in _DOC_ONLY_FROM_TABLE:
        cells = [_TABLE_CELL.match(ln.strip()) for ln in lines]
        return {
            cell.group(1) for cell in cells if cell and pattern.fullmatch(cell.group(1))
        }
    return {m for line in lines for m in pattern.findall(line)}


@pytest.mark.parametrize("doc", POLICY_DOCS)
def test_policy_doc_quotes_only_controls_the_policy_enforces(doc: str) -> None:
    """Regression for #923: hipaa docs described a NIST CSF gate.

    Three verdicts per (policy, framework) pair, derived from the Rego rather
    than declared here:

    * the policy names some of that framework's identifiers -> it is
      **selective**, and the docs may cite only those. This is what stops
      ``policies/README.md`` re-adding "Requirement 11" to a gate whose five
      critical requirements are 2.2.4, 3.5.1, 4.2.1, 6.2.4 and 8.3.6.
    * the policy names none but reads the framework's enrichment field -> it is
      **category-agnostic**, and any identifier is fair to cite.
      ``owasp-top-10.rego`` gates on a non-empty ``compliance.owaspTop10_2021``
      without ever naming a category, so documenting all ten is accurate.
    * neither -> the policy does not consult that framework at all, and citing
      it describes a gate that does not exist. That is the #923 defect.
    """
    slugs = _policy_slugs()
    assert len(slugs) >= 5, f"policy discovery looks wrong: {sorted(slugs)}"

    text = (REPO_ROOT / doc).read_text(encoding="utf-8")
    sections = _sections(text, slugs)

    # Meta-guard: an extractor that silently finds nothing passes everything.
    assert set(sections) == slugs, (
        f"{doc}: expected a documented section for every builtin policy; "
        f"missing {sorted(slugs - set(sections))}, "
        f"unexpected {sorted(set(sections) - slugs)}"
    )

    offenders: list[str] = []
    for slug, lines in sorted(sections.items()):
        rego = (POLICY_DIR / f"{slug}.rego").read_text(encoding="utf-8")
        for framework, pattern, field in _FRAMEWORKS:
            enforced = set(pattern.findall(rego))
            agnostic = not enforced and field is not None and field in rego
            for ident in sorted(_cited(lines, framework, pattern)):
                if agnostic or ident in enforced:
                    continue
                why = (
                    f"enforces only {sorted(enforced)}"
                    if enforced
                    else f"never consults {framework}"
                )
                offenders.append(
                    f"{doc} :: {slug} cites {ident}, but {slug}.rego {why}"
                )

    assert not offenders, (
        "policy documentation names controls the policy does not enforce, so a "
        "user picking a policy from the docs gets a different gate (#923):\n"
        + "\n".join(offenders)
    )


def test_hipaa_section_documents_the_cwe_gate_it_actually_has() -> None:
    """The ten gating CWEs must all reach the reader (#923).

    The check above is one-directional -- it catches a quoted control the policy
    lacks, not a gating control the docs omit. Without this, deleting the whole
    criteria block would pass.
    """
    rego = (POLICY_DIR / "hipaa-compliance.rego").read_text(encoding="utf-8")
    gating = set(re.findall(r'"(CWE-\d+)"', rego.split("hipaa_cwes")[1].split("]")[0]))
    assert len(gating) == 10, f"expected 10 gating CWEs, parsed {sorted(gating)}"

    for doc in POLICY_DOCS:
        text = (REPO_ROOT / doc).read_text(encoding="utf-8")
        section = "\n".join(_sections(text, _policy_slugs())["hipaa-compliance"])
        documented = set(re.findall(r"\bCWE-\d+\b", section))
        assert gating <= documented, (
            f"{doc}: the hipaa-compliance section omits gating CWEs "
            f"{sorted(gating - documented)}"
        )
