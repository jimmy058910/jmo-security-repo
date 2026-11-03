import importlib.metadata
import json
from pathlib import Path

from scripts.core.adapters.yara_x_adapter import YaraXAdapter


def write(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def test_yara_x_adapter_webshell_detection(tmp_path: Path):
    """Test the yara-x adapter with web shell detection."""
    data = {
        "rule": "webshell_php_generic",
        "namespace": "default",
        "tags": ["webshell", "php"],
        "meta": {
            "description": "Generic PHP web shell patterns",
            "author": "Florian Roth",
            "severity": "HIGH",
            "reference": "https://github.com/Neo23x0/signature-base",
        },
        "strings": [
            {"identifier": "$s1", "offset": 42, "data": "eval($_POST"},
            {"identifier": "$s2", "offset": 108, "data": "base64_decode"},
        ],
        "file": "/var/www/html/upload/shell.php",
    }
    f = tmp_path / "yara-x.json"
    write(f, data)
    adapter = YaraXAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "webshell_php_generic"
    assert items[0].severity == "HIGH"
    assert "malware-detection" in items[0].tags
    assert "yara-x" in items[0].tags
    assert "webshell" in items[0].tags
    assert "php" in items[0].tags
    assert items[0].context["rule_name"] == "webshell_php_generic"
    assert items[0].context["author"] == "Florian Roth"
    assert items[0].context["matched_strings_count"] == 2
    assert items[0].location["path"] == "/var/www/html/upload/shell.php"


def test_yara_x_adapter_apt_detection(tmp_path: Path):
    """Test the yara-x adapter with APT detection."""
    data = {
        "rule": "APT_Cozy_Bear",
        "namespace": "apt",
        "tags": ["apt", "backdoor", "critical"],
        "meta": {
            "description": "Cozy Bear APT indicators",
            "author": "CISA",
            "severity": "CRITICAL",
            "reference": "https://www.cisa.gov/apt29",
        },
        "strings": [{"identifier": "$magic", "offset": 0, "data": "MZ"}],
        "file": "/tmp/suspicious.exe",
    }
    f = tmp_path / "yara-x.json"
    write(f, data)
    adapter = YaraXAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].severity == "CRITICAL"
    assert "apt" in items[0].tags
    assert "backdoor" in items[0].tags
    assert items[0].context["namespace"] == "apt"


def test_yara_x_adapter_ransomware_detection(tmp_path: Path):
    """Test the yara-x adapter with ransomware detection."""
    data = {
        "rule": "ransomware_wannacry",
        "namespace": "default",
        "tags": ["ransomware", "critical"],
        "meta": {
            "description": "WannaCry ransomware indicators",
            "author": "Security Researcher",
            "severity": "CRITICAL",
        },
        "strings": [],
        "file": "/downloads/malware.bin",
    }
    f = tmp_path / "yara-x.json"
    write(f, data)
    adapter = YaraXAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].severity == "CRITICAL"
    assert "ransomware" in items[0].tags


def test_yara_x_adapter_multiple_matches(tmp_path: Path):
    """Test the yara-x adapter with multiple matches."""
    data = [
        {
            "rule": "webshell_aspx",
            "namespace": "default",
            "tags": ["webshell"],
            "meta": {"description": "ASPX web shell", "severity": "HIGH"},
            "strings": [
                {"identifier": "$s1", "offset": 10, "data": "ProcessStartInfo"}
            ],
            "file": "/inetpub/wwwroot/shell.aspx",
        },
        {
            "rule": "cryptominer_xmrig",
            "namespace": "default",
            "tags": ["cryptominer", "medium"],
            "meta": {"description": "XMRig cryptominer", "severity": "MEDIUM"},
            "strings": [],
            "file": "/usr/bin/xmrig",
        },
        {
            "rule": "trojan_generic",
            "namespace": "default",
            "tags": ["trojan"],
            "meta": {"description": "Generic trojan patterns"},
            "strings": [],
            "file": "/tmp/trojan.exe",
        },
    ]
    f = tmp_path / "yara-x.json"
    write(f, data)
    adapter = YaraXAdapter()
    items = adapter.parse(f)

    assert len(items) == 3
    assert items[0].ruleId == "webshell_aspx"
    assert items[1].ruleId == "cryptominer_xmrig"
    assert items[2].ruleId == "trojan_generic"
    assert items[0].severity == "HIGH"
    assert items[1].severity == "MEDIUM"
    assert items[2].severity == "HIGH"  # trojan inferred as HIGH


def test_yara_x_adapter_severity_inference(tmp_path: Path):
    """Test the yara-x adapter severity inference from tags when no explicit severity."""
    data = [
        {"rule": "rule_critical", "tags": ["apt"], "meta": {}, "strings": []},
        {"rule": "rule_high", "tags": ["webshell"], "meta": {}, "strings": []},
        {"rule": "rule_medium", "tags": ["suspicious"], "meta": {}, "strings": []},
        {"rule": "rule_default", "tags": [], "meta": {}, "strings": []},
    ]
    f = tmp_path / "yara-x.json"
    write(f, data)
    adapter = YaraXAdapter()
    items = adapter.parse(f)

    assert len(items) == 4
    assert items[0].severity == "CRITICAL"  # APT tag
    assert items[1].severity == "HIGH"  # webshell tag
    assert items[2].severity == "MEDIUM"  # suspicious tag
    assert items[3].severity == "HIGH"  # default for malware


def test_yara_x_adapter_namespace_tagging(tmp_path: Path):
    """Test the yara-x adapter namespace tagging."""
    data = {
        "rule": "custom_rule",
        "namespace": "custom_rules",
        "tags": ["test"],
        "meta": {"description": "Test rule"},
        "strings": [],
    }
    f = tmp_path / "yara-x.json"
    write(f, data)
    adapter = YaraXAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert "namespace:custom_rules" in items[0].tags


def test_yara_x_adapter_no_file_path(tmp_path: Path):
    """Test the yara-x adapter handles missing file path gracefully."""
    data = {
        "rule": "test_rule",
        "namespace": "default",
        "tags": [],
        "meta": {"description": "Test"},
        "strings": [],
    }
    f = tmp_path / "yara-x.json"
    write(f, data)
    adapter = YaraXAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Should use fallback format
    assert items[0].location["path"] == "malware:test_rule"


def test_yara_x_adapter_empty_matches(tmp_path: Path):
    """Test the yara-x adapter with empty matches array."""
    data = []
    f = tmp_path / "yara-x.json"
    write(f, data)
    adapter = YaraXAdapter()
    items = adapter.parse(f)

    assert items == []


def test_yara_x_adapter_empty_file(tmp_path: Path):
    """Test the yara-x adapter handles empty JSON file."""
    f = tmp_path / "yara-x.json"
    f.write_text("", encoding="utf-8")
    adapter = YaraXAdapter()
    items = adapter.parse(f)

    assert items == []


def test_yara_x_adapter_compliance_enrichment(tmp_path: Path):
    """Test that YARA findings are enriched with compliance mappings."""
    data = {
        "rule": "malware_test",
        "namespace": "default",
        "tags": ["malware"],
        "meta": {"description": "Test malware rule"},
        "strings": [],
    }
    f = tmp_path / "yara-x.json"
    write(f, data)
    adapter = YaraXAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Compliance field should exist (enriched by compliance_mapper)
    assert hasattr(items[0], "compliance")


def test_yara_x_adapter_names_the_rule_author(tmp_path: Path):
    """DRL 1.1 requires a rule's author, and its reference when it has one,
    with what it detects (decision 5): in the context and in the message the
    reporters show."""
    data = {
        "rule": "SUSP_Example",
        "namespace": "gen_example",
        "tags": [],
        "meta": {
            "description": "Example detection",
            "author": "Florian Roth",
            "reference": "https://example.invalid/ref",
        },
        "strings": ["$a"],
        "file": "src/app.js",
    }
    f = tmp_path / "yara-x.json"
    write(f, data)

    (item,) = YaraXAdapter().parse(f)

    assert item.context["author"] == "Florian Roth"
    assert item.context["reference"] == "https://example.invalid/ref"
    assert "Florian Roth" in item.message
    assert "https://example.invalid/ref" in item.message


def test_yara_x_adapter_a_rule_with_no_author(tmp_path: Path):
    """A user's own rule may carry neither; the message names no one."""
    data = {"rule": "mine", "meta": {"description": "Mine"}, "strings": []}
    f = tmp_path / "yara-x.json"
    write(f, data)

    (item,) = YaraXAdapter().parse(f)

    assert item.context["author"] is None
    assert item.context["reference"] is None
    assert item.message == "YARA rule 'mine' matched: Mine"


def test_yara_x_adapter_names_its_engine(tmp_path: Path):
    """The tool is yara-x at the version installed beside JMo, not a
    hardcoded libyara version."""
    f = tmp_path / "yara-x.json"
    write(f, {"rule": "r", "meta": {}, "strings": []})

    (item,) = YaraXAdapter().parse(f)

    assert item.tool == {
        "name": "yara-x",
        "version": importlib.metadata.version("yara-x"),
    }


def test_yara_x_adapter_keeps_every_reference(tmp_path: Path):
    """The runner hands a repeated key over as a list (5 signature-base rules
    name two references); every one reaches the finding."""
    data = {
        "rule": "r",
        "meta": {
            "author": "A. Author",
            "reference": ["https://one.invalid/a", "https://two.invalid/b"],
        },
        "strings": [],
    }
    f = tmp_path / "yara-x.json"
    write(f, data)

    (item,) = YaraXAdapter().parse(f)

    assert item.references == ["https://one.invalid/a", "https://two.invalid/b"]
    assert item.context["reference"] == "https://one.invalid/a, https://two.invalid/b"
    assert "https://two.invalid/b" in item.message
