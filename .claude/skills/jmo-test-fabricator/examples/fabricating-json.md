# Fabricating Realistic JSON Fixtures

When creating sample JSON, follow these guidelines to match real tool output formats.

## Step 1: Research Real Tool Output

Before fabricating JSON, understand the tool's actual output format:

1. **Check tool documentation** for JSON schema examples
   - Search for "JSON output" or "JSON format" in docs
   - Look for schema definitions or TypeScript interfaces

2. **Run tool locally** (if available) and capture output

   ```bash
   # Example: Run tool and save output
   <tool> scan . -o json > sample_output.json
   ```

3. **Search GitHub** for example outputs

   ```text
   "<tool>" filetype:json
   "<tool> scan" filetype:json
   ```

4. **Use existing adapters** as reference
   - Check `tests/adapters/` for similar tools
   - Reuse patterns for secrets/SAST/vuln scanners

## Step 2: Identify Output Pattern

Tools typically follow one of these patterns:

### Pattern 1: Results Array (Semgrep, Bandit, Checkov)

**Structure:** Top-level object with `results` array

```json
{
  "version": "1.0.0",
  "results": [
    {
      "check_id": "rule-id",
      "path": "file.py",
      "start": {"line": 10, "col": 5},
      "end": {"line": 10, "col": 20},
      "extra": {
        "message": "Finding description",
        "severity": "ERROR",
        "metadata": {
          "cwe": ["CWE-79"],
          "confidence": "HIGH"
        }
      }
    }
  ]
}
```

**Adapter Considerations:**

- Check for `results` key existence
- Handle nested `extra` or `metadata` objects
- Map `check_id` -> `ruleId`
- Extract `message` from nested location

### Pattern 2: Flat Array (Gitleaks, TruffleHog NDJSON)

**Structure:** Top-level array or newline-delimited JSON

```json
[
  {
    "DetectorName": "AWS",
    "Verified": true,
    "Raw": "AKIAIOSFODNN7EXAMPLE",
    "SourceMetadata": {
      "Data": {
        "Filesystem": {
          "file": "config.yaml",
          "line": 7
        }
      }
    }
  }
]
```

**Adapter Considerations:**

- Handle both JSON array and NDJSON formats
- Extract path from nested `SourceMetadata`
- Use `DetectorName` as `ruleId`
- Map `Verified` to severity (HIGH if true, MEDIUM if false)

### Pattern 3: SARIF Format (Trivy, Checkov, Some Tools)

**Structure:** SARIF 2.1.0 schema

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {"driver": {"name": "Tool", "version": "1.0.0"}},
      "results": [
        {
          "ruleId": "CWE-79",
          "level": "error",
          "message": {"text": "XSS vulnerability"},
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {"uri": "file.py"},
              "region": {"startLine": 10, "endLine": 15}
            }
          }]
        }
      ]
    }
  ]
}
```

**Adapter Considerations:**

- Navigate nested `runs[0].results` structure
- Extract `message.text` (not just `message`)
- Map `level` (error/warning/note) to severity
- Extract location from `physicalLocation.artifactLocation.uri`

### Pattern 4: Nested Targets (Trivy, Snyk, Vuln Scanners)

**Structure:** Results grouped by target (file, package, image)

```json
{
  "Results": [
    {
      "Target": "package-lock.json",
      "Type": "npm",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-12345",
          "PkgName": "lodash",
          "InstalledVersion": "4.17.15",
          "Severity": "HIGH",
          "Title": "Prototype pollution",
          "References": ["https://nvd.nist.gov/vuln/detail/CVE-2023-12345"]
        }
      ]
    }
  ]
}
```

**Adapter Considerations:**

- Iterate over `Results` array
- For each target, iterate over `Vulnerabilities`
- Use target name as context (e.g., `location.path = target`)
- Map `VulnerabilityID` -> `ruleId`

## Step 3: Create Minimal and Complete Samples

**Minimal Sample** (for `test_basic`):

- Only required fields
- Single finding
- Use for smoke test

```python
minimal = {
    "results": [
        {
            "ruleId": "R1",
            "message": "Test",
            "severity": "HIGH",
            "path": "file.py",
            "line": 10,
        }
    ]
}
```

**Complete Sample** (for edge case tests):

- All optional fields
- Multiple findings
- Use for comprehensive testing

```python
complete = {
    "version": "1.2.3",
    "scanDate": "2024-01-15T10:30:00Z",
    "results": [
        {
            "ruleId": "R1",
            "message": "Detailed finding",
            "severity": "HIGH",
            "path": "app.py",
            "line": 42,
            "column": 10,
            "endLine": 45,
            "endColumn": 20,
            "cwe": ["CWE-79", "CWE-20"],
            "owasp": ["A03:2021"],
            "confidence": "HIGH",
            "likelihood": "MEDIUM",
            "impact": "HIGH",
            "fix": "Apply this patch",
            "fixSteps": ["Step 1", "Step 2"],
            "references": ["https://example.com/advisory"],
            "custom_metadata": {"key": "value"},
        }
    ]
}
```

---

## Real-World Test Suite Examples

### Example 1: Snyk (Vulnerability Scanner)

Complete test suite for Snyk adapter with all 5 categories:

```python
import json
from pathlib import Path

from scripts.core.adapters.snyk_adapter import load_snyk


def write_tmp(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


# ========== Category 1: Basic Valid Input ==========

def test_snyk_basic(tmp_path: Path):
    """Test basic Snyk vulnerability finding."""
    sample = {
        "vulnerabilities": [
            {
                "id": "SNYK-JS-LODASH-590103",
                "title": "Prototype Pollution",
                "severity": "high",
                "packageName": "lodash",
                "version": "4.17.15",
                "from": ["myapp@1.0.0", "lodash@4.17.15"],
                "CVSSv3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
                "identifiers": {"CWE": ["CWE-1321"]},
            }
        ]
    }
    path = write_tmp(tmp_path, "snyk.json", json.dumps(sample))
    out = load_snyk(path)
    assert len(out) == 1

    item = out[0]
    assert item["ruleId"] == "SNYK-JS-LODASH-590103"
    assert item["severity"] == "HIGH"
    assert "lodash" in item["message"]
    assert item["location"]["path"] == "lodash@4.17.15"


# ========== Category 2: Error Handling ==========

def test_snyk_empty_and_malformed(tmp_path: Path):
    """Test error handling for empty and malformed inputs."""
    p1 = write_tmp(tmp_path, "empty.json", "")
    assert load_snyk(p1) == []

    p2 = write_tmp(tmp_path, "bad.json", "{not json}")
    assert load_snyk(p2) == []

    p3 = write_tmp(tmp_path, "noresults.json", json.dumps({}))
    assert load_snyk(p3) == []


def test_snyk_nonexistent_file(tmp_path: Path):
    """Test loading from non-existent file."""
    result = load_snyk(tmp_path / "nonexistent.json")
    assert result == []


# ========== Category 3: v1.1.0 Features ==========

def test_snyk_v110_cwe_metadata(tmp_path: Path):
    """Test v1.1.0 CWE metadata extraction."""
    sample = {
        "vulnerabilities": [
            {
                "id": "SNYK-001",
                "title": "XSS Vulnerability",
                "severity": "high",
                "identifiers": {"CWE": ["CWE-79"]},
            }
        ]
    }
    path = write_tmp(tmp_path, "snyk_cwe.json", json.dumps(sample))
    out = load_snyk(path)
    assert len(out) == 1

    item = out[0]
    assert "risk" in item
    assert item["risk"]["cwe"] == ["CWE-79"]


def test_snyk_v110_cvss_score(tmp_path: Path):
    """Test v1.1.0 CVSS score extraction."""
    sample = {
        "vulnerabilities": [
            {
                "id": "SNYK-002",
                "title": "High CVSS Vuln",
                "severity": "critical",
                "cvssScore": 9.8,
                "CVSSv3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }
        ]
    }
    path = write_tmp(tmp_path, "snyk_cvss.json", json.dumps(sample))
    out = load_snyk(path)
    assert len(out) == 1

    item = out[0]
    assert "cvss" in item
    assert item["cvss"]["score"] == 9.8
    assert "CVSS:3.1" in item["cvss"]["vector"]


# ========== Category 4: v1.2.0 Compliance ==========

def test_snyk_compliance_enrichment(tmp_path: Path):
    """Test compliance enrichment for CWE findings."""
    sample = {
        "vulnerabilities": [
            {
                "id": "SNYK-003",
                "title": "SQL Injection",
                "severity": "high",
                "identifiers": {"CWE": ["CWE-89"]},
            }
        ]
    }
    path = write_tmp(tmp_path, "snyk_compliance.json", json.dumps(sample))
    out = load_snyk(path)
    assert len(out) == 1

    item = out[0]
    assert item["schemaVersion"] in ["1.1.0", "1.2.0"]

    if "compliance" in item:
        compliance = item["compliance"]
        # CWE-89 should map to OWASP A03:2021 (Injection)
        if "owaspTop10_2021" in compliance:
            assert any("A03" in cat for cat in compliance["owaspTop10_2021"])


# ========== Category 5: Tool-Specific Edge Cases ==========

def test_snyk_license_issues(tmp_path: Path):
    """Test handling license issues (not vulnerabilities)."""
    sample = {
        "vulnerabilities": [],  # No vulns
        "licenses": [
            {
                "id": "snyk:lic:npm:lodash:GPL-2.0",
                "title": "GPL-2.0 license",
                "severity": "medium",
                "packageName": "lodash",
            }
        ],
    }
    path = write_tmp(tmp_path, "snyk_license.json", json.dumps(sample))
    out = load_snyk(path)

    # Adapter should handle license issues (or skip them)
    # Check adapter implementation to see if licenses are included
    assert isinstance(out, list)


def test_snyk_dependency_path(tmp_path: Path):
    """Test extraction of dependency path (transitive deps)."""
    sample = {
        "vulnerabilities": [
            {
                "id": "SNYK-004",
                "title": "Transitive Vuln",
                "severity": "low",
                "packageName": "vulnerable-dep",
                "from": [
                    "myapp@1.0.0",
                    "express@4.17.1",
                    "vulnerable-dep@2.0.0",
                ],
            }
        ]
    }
    path = write_tmp(tmp_path, "snyk_transitive.json", json.dumps(sample))
    out = load_snyk(path)
    assert len(out) == 1

    item = out[0]
    # Path should show transitive dependency chain
    assert "express" in item["location"]["path"] or "vulnerable-dep" in item["location"]["path"]


def test_snyk_remediation(tmp_path: Path):
    """Test remediation advice extraction."""
    sample = {
        "vulnerabilities": [
            {
                "id": "SNYK-005",
                "title": "Fixable Vuln",
                "severity": "medium",
                "upgradePath": ["lodash@4.17.15", "lodash@4.17.21"],
                "isUpgradable": True,
            }
        ]
    }
    path = write_tmp(tmp_path, "snyk_remediation.json", json.dumps(sample))
    out = load_snyk(path)
    assert len(out) == 1

    item = out[0]
    if "remediation" in item:
        assert "4.17.21" in str(item["remediation"])
```

### Example 2: Semgrep (SAST)

Complete test suite for Semgrep adapter:

```python
import json
from pathlib import Path

from scripts.core.adapters.semgrep_adapter import load_semgrep


def write_tmp(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


# ========== Category 1: Basic Valid Input ==========

def test_semgrep_basic(tmp_path: Path):
    """Test basic Semgrep finding."""
    sample = {
        "results": [
            {
                "check_id": "python.django.security.injection.sql.sql-injection-db-cursor-execute",
                "path": "views.py",
                "start": {"line": 15, "col": 4},
                "end": {"line": 15, "col": 30},
                "extra": {
                    "message": "Potential SQL injection vulnerability",
                    "severity": "ERROR",
                    "metadata": {
                        "cwe": ["CWE-89"],
                        "owasp": ["A03:2021"],
                        "confidence": "HIGH",
                    },
                },
            }
        ]
    }
    path = write_tmp(tmp_path, "semgrep.json", json.dumps(sample))
    out = load_semgrep(path)
    assert len(out) == 1

    item = out[0]
    assert "sql-injection" in item["ruleId"]
    assert item["severity"] == "HIGH"  # ERROR maps to HIGH
    assert item["location"]["path"] == "views.py"
    assert item["location"]["startLine"] == 15


# ========== Category 2: Error Handling ==========

def test_semgrep_empty_and_malformed(tmp_path: Path):
    p1 = write_tmp(tmp_path, "empty.json", "")
    assert load_semgrep(p1) == []

    p2 = write_tmp(tmp_path, "bad.json", "{broken}")
    assert load_semgrep(p2) == []


# ========== Category 3: v1.1.0 Features ==========

def test_semgrep_v110_autofix(tmp_path: Path):
    """Test autofix extraction from Semgrep."""
    sample = {
        "results": [
            {
                "check_id": "python.lang.security.audit.insecure-random",
                "path": "crypto.py",
                "start": {"line": 10, "col": 1},
                "end": {"line": 10, "col": 20},
                "extra": {
                    "message": "Use secrets module",
                    "severity": "WARNING",
                    "fix": "import secrets\ntoken = secrets.token_hex(16)",
                },
            }
        ]
    }
    path = write_tmp(tmp_path, "semgrep_fix.json", json.dumps(sample))
    out = load_semgrep(path)
    assert len(out) == 1

    item = out[0]
    assert isinstance(item["remediation"], dict)
    assert "secrets" in item["remediation"]["fix"]


# ========== Category 4: v1.2.0 Compliance ==========

def test_semgrep_compliance_enrichment(tmp_path: Path):
    """Test compliance enrichment."""
    sample = {
        "results": [
            {
                "check_id": "python.xss",
                "path": "app.py",
                "start": {"line": 20, "col": 1},
                "end": {"line": 20, "col": 50},
                "extra": {
                    "message": "XSS vulnerability",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-79"]},
                },
            }
        ]
    }
    path = write_tmp(tmp_path, "semgrep_compliance.json", json.dumps(sample))
    out = load_semgrep(path)
    assert len(out) == 1
    assert out[0]["schemaVersion"] in ["1.1.0", "1.2.0"]


# ========== Category 5: Tool-Specific Edge Cases ==========

def test_semgrep_multiline_finding(tmp_path: Path):
    """Test multiline code finding."""
    sample = {
        "results": [
            {
                "check_id": "test.multiline",
                "path": "test.py",
                "start": {"line": 10, "col": 1},
                "end": {"line": 15, "col": 20},  # Spans 5 lines
                "extra": {"message": "Multiline issue", "severity": "INFO"},
            }
        ]
    }
    path = write_tmp(tmp_path, "semgrep_multiline.json", json.dumps(sample))
    out = load_semgrep(path)
    assert len(out) == 1

    item = out[0]
    assert item["location"]["startLine"] == 10
    assert item["location"]["endLine"] == 15
```
