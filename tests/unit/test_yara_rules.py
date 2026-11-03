"""signature-base keeps only the rules JMo may redistribute (v2.0.0 Phase 6,
PR Y, Task Y1, decision 6).

signature-base's LICENSE is the Detection Rule License 1.1, but not every rule
in it is DRL. Some say so in their own `license` metadata; about 18 files at
`36ab7042` say so only in a header comment (Apache-2.0, CC BY-NC, GPL, ...),
and about 3,000 rules carry no license line at all, the npm supply-chain rules
among them. So a rule's license is read from its metadata, a file that is
ambiguous must be on a reviewed list, and an unreviewed ambiguous file fails
the fetch rather than shipping.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.core.yara_rules import Dropped, UnreviewedRuleFile, filter_rules

DRL = (
    "Detection Rule License 1.1 "
    "https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
)
CC_BY_NC = "https://creativecommons.org/licenses/by-nc/4.0/"


def _rule(name: str, license: str | None = None, *, key: str = "license") -> str:
    meta = f'        {key} = "{license}"\n' if license else ""
    return (
        f"rule {name} {{\n"
        f"    meta:\n"
        f'        author = "someone"\n'
        f"{meta}"
        f"    condition:\n"
        f"        true\n"
        f"}}\n"
    )


def _write(root: Path, name: str, text: str) -> Path:
    path = root / name
    path.write_bytes(text.encode("utf-8"))
    return path


def _read(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def test_a_rule_licensed_otherwise_is_dropped_and_named(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "a.yar",
        'import "pe"\n\n' + _rule("Kept", DRL) + _rule("NonCommercial", CC_BY_NC),
    )

    result = filter_rules(tmp_path, reviewed={})

    text = _read(path)
    assert 'import "pe"' in text
    assert "rule Kept" in text
    assert "NonCommercial" not in text
    assert Dropped("a.yar", "NonCommercial", CC_BY_NC) in result.dropped


def test_the_license_key_is_matched_in_any_case(tmp_path: Path) -> None:
    # apt_prikormka.yar spells it `License = "BSD 2-Clause"`.
    path = _write(
        tmp_path,
        "b.yar",
        _rule("Kept", DRL) + _rule("Eset", "BSD 2-Clause", key="License"),
    )

    result = filter_rules(tmp_path, reviewed={})

    assert "Eset" not in _read(path)
    assert [d.rule for d in result.dropped] == ["Eset"]


def test_a_rule_with_no_license_line_is_drl(tmp_path: Path) -> None:
    # The repository's LICENSE covers it: the npm supply-chain rules are such rules.
    path = _write(tmp_path, "c.yara", _rule("Plain") + _rule("Tagged", DRL))
    before = _read(path)

    result = filter_rules(tmp_path, reviewed={})

    assert _read(path) == before
    assert result.dropped == []
    assert result.kept_rules == 2


def test_a_commented_out_rule_is_neither_dropped_nor_counted(tmp_path: Path) -> None:
    # 61 block comments in signature-base hold whole disabled rules. One read as
    # a rule would count 2 here. (A disabled rule's non-DRL license line is a
    # license comment like any other: its file needs review, as below.)
    disabled = (
        "/*\nrule Disabled {\n    meta:\n"
        '        author = "someone"\n    condition:\n        true\n}\n*/\n'
    )
    path = _write(tmp_path, "d.yar", disabled + _rule("Live", DRL))
    before = _read(path)

    result = filter_rules(tmp_path, reviewed={})

    assert _read(path) == before
    assert result.dropped == []
    assert result.kept_rules == 1


def test_braces_in_strings_regexes_and_hex_do_not_end_a_rule(tmp_path: Path) -> None:
    tricky = (
        "rule Tricky {\n"
        "    meta:\n"
        f'        license = "{DRL}"\n'
        "    strings:\n"
        '        $a = "}"\n'
        "        $b = /a\\}{2}/\n"
        "        $c = { 4D 5A [2] ( 90 | 91 ) } // a hex string\n"
        '        $d = "//not a comment {"\n'
        "        $e = /https?:\\/\\/x/\n"
        "    condition:\n"
        "        any of them\n"
        "}\n"
    )
    path = _write(tmp_path, "e.yar", tricky + _rule("Gone", CC_BY_NC))

    result = filter_rules(tmp_path, reviewed={})

    assert _read(path).strip() == tricky.strip()
    assert [d.rule for d in result.dropped] == ["Gone"]


def test_a_file_whose_rules_all_drop_is_removed(tmp_path: Path) -> None:
    path = _write(tmp_path, "f.yar", 'import "pe"\n' + _rule("Gone", CC_BY_NC))

    result = filter_rules(tmp_path, reviewed={})

    assert not path.exists()
    assert Dropped("f.yar", "Gone", CC_BY_NC) in result.dropped


def test_an_unreviewed_license_comment_fails_naming_the_file(tmp_path: Path) -> None:
    # gen_loaders.yar: "License: GPL" in its header, DRL in its rules' metadata.
    _write(tmp_path, "gpl.yar", "/*\n   License: GPL\n*/\n" + _rule("Mine", DRL))

    with pytest.raises(UnreviewedRuleFile, match="gpl.yar"):
        filter_rules(tmp_path, reviewed={})


def test_a_drl_comment_needs_no_review(tmp_path: Path) -> None:
    # SigmaHQ's files, typo and all.
    header = (
        "/*\n   License: Detetction Rule License 1.1 "
        "(https://github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection.Rules.md)\n*/\n"
    )
    path = _write(tmp_path, "sigma.yar", header + _rule("Mine"))

    result = filter_rules(tmp_path, reviewed={})

    assert path.exists()
    assert result.kept_rules == 1


def test_a_license_mention_inside_a_rule_body_needs_no_review(tmp_path: Path) -> None:
    # The vulnerable-driver files annotate a hex pattern with the driver's own
    # copyright string; it is not the rule's license.
    rule = (
        "rule Driver {\n    strings:\n"
        "        $ = { 4C 00 69 00 } /* LegalCopyright LicensedundertheGNUGPLv */\n"
        "    condition:\n        any of them\n}\n"
    )
    path = _write(tmp_path, "drivers.yar", rule)

    filter_rules(tmp_path, reviewed={})

    assert _read(path) == rule


def test_a_reviewed_drop_removes_the_whole_file(tmp_path: Path) -> None:
    # The header wins over the rules' own DRL metadata (decided 2026-11-03).
    path = _write(tmp_path, "gpl.yar", "/*\n   License: GPL\n*/\n" + _rule("Mine", DRL))

    result = filter_rules(tmp_path, reviewed={"gpl.yar": ("drop", "GPL header")})

    assert not path.exists()
    assert result.dropped == [Dropped("gpl.yar", "Mine", "GPL header")]


def test_a_reviewed_keep_stays_whole(tmp_path: Path) -> None:
    # apt_apt10.yar disables a rule whose strings name license.shenajou.com.
    text = "// c2 seen: license.example.com\n" + _rule("Mine")
    path = _write(tmp_path, "c2.yar", text)

    filter_rules(tmp_path, reviewed={"c2.yar": ("keep", "a C2 domain, not a license")})

    assert _read(path) == text


def test_a_mixed_file_must_be_reviewed(tmp_path: Path) -> None:
    # Third-party rules beside unlabelled ones: whose are the unlabelled ones?
    _write(tmp_path, "mixed.yar", _rule("Theirs", CC_BY_NC) + _rule("Unlabelled"))

    with pytest.raises(UnreviewedRuleFile, match="mixed.yar"):
        filter_rules(tmp_path, reviewed={})


def test_a_mixed_file_kept_on_review_drops_only_the_labelled_rule(
    tmp_path: Path,
) -> None:
    # thor-hacktools.yar: the author's own file with one third-party rule in it.
    path = _write(tmp_path, "own.yar", _rule("Theirs", CC_BY_NC) + _rule("Unlabelled"))

    result = filter_rules(tmp_path, reviewed={"own.yar": ("keep", "author's own file")})

    assert "rule Unlabelled" in _read(path)
    assert [d.rule for d in result.dropped] == ["Theirs"]
