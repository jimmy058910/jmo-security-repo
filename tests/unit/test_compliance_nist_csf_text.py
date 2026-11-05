"""Every NIST CSF entry quotes CSF 2.0's own words for its subcategory (#1572).

The mapper's `NIST_CSF_2_0` and `CWE_TO_NIST_CSF_2_0` carried CSF 1.1: four of
their subcategory ids (PR.AC-1, PR.IP-1, PR.PT-3, DE.CM-8) do not exist in CSF
2.0, and `GV.SC-3` carried 1.1's ID.SC-1 text, so a report paired a control id
with words that were not that control's.

`CSF_2_0` below quotes "The NIST Cybersecurity Framework (CSF) 2.0", NIST CSWP 29
(February 26, 2024), https://doi.org/10.6028/NIST.CSWP.29, read 2026-11-05: the
subcategory list after the Core overview. CSF 2.0 writes ids with two digits.
"""

from __future__ import annotations

import re

import pytest

from scripts.core.compliance_mapper import CWE_TO_NIST_CSF_2_0, NIST_CSF_2_0

CSF_2_0 = {
    "GV.SC-03": "Cybersecurity supply chain risk management is integrated into "
    "cybersecurity and enterprise risk management, risk assessment, and "
    "improvement processes",
    "ID.RA-01": "Vulnerabilities in assets are identified, validated, and recorded",
    "PR.AA-01": "Identities and credentials for authorized users, services, and "
    "hardware are managed by the organization",
    "PR.DS-01": "The confidentiality, integrity, and availability of data-at-rest "
    "are protected",
    "PR.DS-02": "The confidentiality, integrity, and availability of "
    "data-in-transit are protected",
    "PR.PS-01": "Configuration management practices are established and applied",
}

FUNCTIONS = {
    "GV": "GOVERN",
    "ID": "IDENTIFY",
    "PR": "PROTECT",
    "DE": "DETECT",
    "RS": "RESPOND",
    "RC": "RECOVER",
}

ENTRIES = [
    (f"{table}[{key}]", entry)
    for table, mapping in (
        ("NIST_CSF_2_0", NIST_CSF_2_0),
        ("CWE_TO_NIST_CSF_2_0", CWE_TO_NIST_CSF_2_0),
    )
    for key, entries in mapping.items()
    for entry in entries
]


def test_the_tables_are_read() -> None:
    """Meta-guard: an empty walk would pass every test below."""
    assert len(ENTRIES) >= 10
    assert {"secrets", "sast", "sca", "iac", "dast"} <= set(NIST_CSF_2_0)


@pytest.mark.parametrize(("where", "entry"), ENTRIES, ids=[w for w, _ in ENTRIES])
def test_an_entry_names_a_csf_2_0_subcategory_in_its_own_words(
    where: str, entry: dict[str, str]
) -> None:
    subcategory = entry["subcategory"]
    assert re.fullmatch(r"[A-Z]{2}\.[A-Z]{2}-\d{2}", subcategory), subcategory
    assert subcategory in CSF_2_0, f"{where}: {subcategory} is not quoted here"
    assert entry["description"] == CSF_2_0[subcategory]
    assert entry["category"] == subcategory.split("-")[0]
    assert entry["function"] == FUNCTIONS[subcategory[:2]]


@pytest.mark.parametrize("table", [NIST_CSF_2_0, CWE_TO_NIST_CSF_2_0])
def test_no_key_lists_one_subcategory_twice(table: dict) -> None:
    """Two CSF 1.1 ids that map to one 2.0 id must leave one entry."""
    for key, entries in table.items():
        ids = [e["subcategory"] for e in entries]
        assert len(ids) == len(set(ids)), (key, ids)
