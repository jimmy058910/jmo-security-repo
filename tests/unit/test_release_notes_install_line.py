"""The release notes' install command installs the documented extra.

A GitHub release told readers `pip install jmo-security==X`, which since
#1577 installs JMo without the YARA-X engine. Handed over 2026-11-05: the
notes name the install the docs name, `jmo-security[yara]`.
"""

from __future__ import annotations

from unittest.mock import patch

from scripts.dev import generate_release_notes as notes_module


def test_the_release_notes_install_the_yara_extra() -> None:
    with (
        patch.object(notes_module, "extract_changelog_section", return_value=""),
        patch.object(
            notes_module, "get_contributors_since_last_release", return_value=[]
        ),
    ):
        notes = notes_module.format_release_notes("2.0.1", "v2.0.1")

    assert 'pip install "jmo-security[yara]==2.0.1"' in notes
    assert "pip install jmo-security==" not in notes
