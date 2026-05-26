from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
USER_GUIDE = ROOT / "docs" / "USER_GUIDE.md"


def _handling_false_positives_section() -> str:
    text = USER_GUIDE.read_text(encoding="utf-8")
    start = text.index("## Handling False Positives")
    end = text.index("\n## ", start + 1)
    return text[start:end]


def test_false_positive_suppression_examples_match_id_only_behavior():
    section = _handling_false_positives_section()

    assert 'expires: "<FUTURE_DATE>"' in section
    assert 'expires: "2025-12-31"' not in section
    assert 'expires: "2025-09-30"' not in section

    assert "Current behavior is exact `id` matching only" in section
    assert "load_suppressions()" in section
    assert "filter_suppressed()" in section

    example = section.split("```yaml", 1)[1].split("```", 1)[0]
    assert "path:" not in example
    assert "ruleId:" not in example
    assert "line:" not in example
    assert "severity:" not in example
