from scripts.core.common_finding import normalize_severity, fingerprint
from scripts.core.reporters.sarif_reporter import _severity_to_level


def test_normalize_severity_variants():
    assert normalize_severity("error") == "HIGH"
    assert normalize_severity("warn") == "MEDIUM"
    assert normalize_severity(None) == "INFO"
    assert normalize_severity("CRIT") == "CRITICAL"


def test_fingerprint_stability_changes_with_inputs():
    a = fingerprint("t", "R1", "p", 10, "msg")
    b = fingerprint("t", "R1", "p", 11, "msg")
    assert a != b


def test_sarif_level_mapping():
    assert _severity_to_level("CRITICAL") == "error"
    assert _severity_to_level("HIGH") == "error"
    assert _severity_to_level("MEDIUM") == "warning"
    assert _severity_to_level("LOW") == "note"
    assert _severity_to_level(None) == "note"
