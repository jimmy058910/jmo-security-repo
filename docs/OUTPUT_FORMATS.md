# Output Formats

JMo Security supports 6 output formats for security findings, all following the v1.0.0 metadata wrapper structure.

## Overview

All output formats (JSON, YAML, CSV, Markdown, HTML, SARIF) now use a standardized metadata envelope:

```json
{
  "meta": {
    "output_version": "1.0.0",
    "jmo_version": "0.9.0",
    "schema_version": "1.2.0",
    "timestamp": "2025-11-04T12:34:56Z",
    "scan_id": "scan-abc123",
    "profile": "balanced",
    "tools": ["trivy", "semgrep", "trufflehog"],
    "target_count": 5,
    "finding_count": 42,
    "platform": "Linux"
  },
  "findings": [
    {
      "schemaVersion": "1.2.0",
      "id": "trivy|CVE-2024-1234|package.json|0|abc123",
      "ruleId": "CVE-2024-1234",
      "severity": "HIGH",
      "message": "Vulnerability in lodash",
      "tool": {"name": "trivy", "version": "0.68.0"},
      "location": {"path": "package.json", "startLine": 0}
    }
  ]
}
```

## Metadata Fields

| Field | Type | Description |
|-------|------|-------------|
| `output_version` | string | Output format version (v1.0.0) |
| `jmo_version` | string | JMo Security version that generated output |
| `schema_version` | string | CommonFinding schema version (v1.2.0) |
| `timestamp` | string | ISO 8601 timestamp of scan completion |
| `scan_id` | string | Unique scan identifier |
| `profile` | string | Profile used (fast/balanced/deep) |
| `tools` | array | List of tools that ran successfully |
| `target_count` | integer | Number of targets scanned |
| `finding_count` | integer | Total number of findings |
| `platform` | string | OS platform (Linux/Darwin/Windows) |

## Format Details

### 1. JSON (`findings.json`)

**Primary machine-readable format with metadata wrapper.**

```json
{
  "meta": {
    "output_version": "1.0.0",
    "jmo_version": "0.9.0",
    "schema_version": "1.2.0",
    "timestamp": "2025-11-04T12:34:56Z",
    "scan_id": "scan-abc123",
    "profile": "balanced",
    "tools": ["trivy", "semgrep", "trufflehog"],
    "target_count": 5,
    "finding_count": 42,
    "platform": "Linux"
  },
  "findings": [
    {
      "schemaVersion": "1.2.0",
      "id": "trivy|CVE-2024-1234|package.json|0|abc123",
      "ruleId": "CVE-2024-1234",
      "severity": "HIGH",
      "message": "Vulnerability in lodash",
      "tool": {"name": "trivy", "version": "0.68.0"},
      "location": {"path": "package.json", "startLine": 0},
      "cvss": {
        "v3": {"baseScore": 7.5, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}
      },
      "compliance": {
        "owaspTop10_2021": ["A06:2021"],
        "cweTop25_2024": [{"cwe": "CWE-79", "rank": 1, "category": "Cross-Site Scripting"}]
      }
    }
  ]
}
```

**Use Cases:**
- Machine parsing and automation
- CI/CD pipeline integration
- Data science analysis
- API consumption

---

### 2. YAML (`findings.yaml`)

**Human-readable structured format with metadata wrapper.**

```yaml
meta:
  output_version: 1.0.0
  jmo_version: 0.9.0
  schema_version: 1.2.0
  timestamp: '2025-11-04T12:34:56Z'
  scan_id: scan-abc123
  profile: balanced
  tools:
    - trivy
    - semgrep
    - trufflehog
  target_count: 5
  finding_count: 42
  platform: Linux

findings:
  - schemaVersion: 1.2.0
    id: trivy|CVE-2024-1234|package.json|0|abc123
    ruleId: CVE-2024-1234
    severity: HIGH
    message: Vulnerability in lodash
    tool:
      name: trivy
      version: 0.68.0
    location:
      path: package.json
      startLine: 0
```

**Use Cases:**
- Configuration management
- GitOps workflows
- Documentation generation
- Human review

**Note:** Requires PyYAML (`pip install -e ".[reporting]"`)

---

### 3. CSV (`findings.csv`)

**Spreadsheet-friendly format with metadata header.**

```csv
# JMo Security Findings Report - v1.0.0
# Generated: 2025-11-04T12:34:56Z
# Scan ID: scan-abc123
# Profile: balanced
# Tools: trivy, semgrep, trufflehog
# Targets: 5
# Findings: 42
# Platform: Linux

Severity,RuleID,Message,Location,Line,Tool,Version,ID
HIGH,CVE-2024-1234,Vulnerability in lodash,package.json,0,trivy,0.68.0,trivy|CVE-2024-1234|package.json|0|abc123
CRITICAL,github,GitHub Personal Access Token detected,config.py,15,trufflehog,3.63.0,trufflehog|github|config.py|15|def456
MEDIUM,python.lang.security.audit.dangerous-code-exec,Use of exec() detected,app.py,42,semgrep,1.45.0,semgrep|exec|app.py|42|ghi789
```

**Use Cases:**
- Excel/Google Sheets analysis
- Non-technical stakeholder reports
- Compliance auditing
- Data visualization (pivot tables, charts)

**Features:**
- Metadata in comment header rows (lines starting with `#`)
- Standard CSV format (RFC 4180 compliant)
- UTF-8 encoding
- Column headers: Severity, RuleID, Message, Location, Line, Tool, Version, ID

---

### 4. Markdown (`SUMMARY.md`)

**Human-readable summary with metadata table.**

```markdown
# Security Scan Summary

## Scan Metadata

| Field | Value |
|-------|-------|
| Output Version | 1.0.0 |
| JMo Version | 0.9.0 |
| Scan ID | scan-abc123 |
| Profile | balanced |
| Timestamp | 2025-11-04T12:34:56Z |
| Targets Scanned | 5 |
| Total Findings | 42 |
| Platform | Linux |

## Severity Breakdown

| Severity | Count |
|----------|-------|
| CRITICAL | 5 |
| HIGH | 12 |
| MEDIUM | 15 |
| LOW | 8 |
| INFO | 2 |

## Top 10 Rules

| Rule ID | Count | Severity | Tool |
|---------|-------|----------|------|
| CVE-2024-1234 | 8 | HIGH | trivy |
| CWE-79 | 6 | MEDIUM | semgrep |
| github | 4 | CRITICAL | trufflehog |
```

**Use Cases:**
- GitHub/GitLab README display
- Documentation sites
- Email reports
- Quick human review

---

### 5. HTML (`dashboard.html`)

**Interactive dashboard with dual-mode support.**

#### Inline Mode (≤1000 findings)

```html
<!DOCTYPE html>
<html>
<head>
  <title>Security Dashboard v2.2</title>
  <!-- Embedded CSS -->
</head>
<body>
  <div id="app">
    <!-- Dashboard UI -->
  </div>

  <script>
    // Metadata
    const meta = {
      output_version: "1.0.0",
      jmo_version: "0.9.0",
      scan_id: "scan-abc123",
      profile: "balanced",
      tools: ["trivy", "semgrep", "trufflehog"],
      target_count: 5,
      finding_count: 42,
      platform: "Linux"
    };

    // Inline data (XSS-escaped)
    let data = [
      {
        "schemaVersion": "1.2.0",
        "id": "trivy|CVE-2024-1234|package.json|0|abc123",
        "severity": "HIGH",
        "message": "Vulnerability in lodash"
      }
    ];

    // Dashboard logic
    updateSummaryCards();
    render();
  </script>
</body>
</html>
```

**File Size:** ~84 KB for 100 findings (self-contained)

**Benefits:**
- Self-contained (no external dependencies)
- Works offline
- Easy to share (single file)
- Fast loading (<100ms)

#### External Mode (>1000 findings)

```html
<!DOCTYPE html>
<html>
<head>
  <title>Security Dashboard v2.2</title>
  <!-- Embedded CSS -->
</head>
<body>
  <!-- Loading spinner -->
  <div id="loading" style="display:block;">
    <div class="spinner"></div>
    <h2>Loading Security Findings...</h2>
  </div>

  <!-- Error message (hidden initially) -->
  <div id="loadError" style="display:none;">
    <h2>⚠️ Loading Failed</h2>
    <p>Could not load findings.json</p>
  </div>

  <!-- Dashboard (hidden until loaded) -->
  <div id="app" style="display:none;">
    <!-- Dashboard UI -->
  </div>

  <script>
    const useExternal = true;
    let data = [];

    // Async loading
    (async function() {
      const loadingEl = document.getElementById('loading');
      const appEl = document.getElementById('app');
      const errorEl = document.getElementById('loadError');

      loadingEl.style.display = 'block';

      try {
        const response = await fetch('findings.json');
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const json = await response.json();
        data = json.findings;  // v1.0.0: Extract findings from metadata wrapper

        loadingEl.style.display = 'none';
        appEl.style.display = 'block';

        updateSummaryCards();
        render();
      } catch (err) {
        console.error('Failed to load findings.json:', err);
        loadingEl.style.display = 'none';
        errorEl.style.display = 'block';
      }
    })();
  </script>
</body>
</html>
```

**File Sizes:**
- `dashboard.html`: ~63 KB (minimal HTML + JS)
- `findings.json`: ~448 KB for 1500 findings

**Benefits:**
- Prevents browser freeze (async loading)
- Smaller HTML file
- Supports massive datasets (10,000+ findings)
- Professional loading UX

**Features:**
- Priority Intelligence (EPSS, KEV, priority scores)
- Compliance frameworks (OWASP, CWE, CIS, NIST CSF, PCI DSS, ATT&CK)
- Dark mode toggle
- Severity filtering
- Grouping (severity/tool/location/priority)
- Triage workflow (accept/suppress/fix)
- Export to JSON/CSV
- Responsive design

**Use Cases:**
- Executive dashboards
- Security team reviews
- Compliance audits
- Stakeholder presentations

---

### 6. SARIF (`findings.sarif`)

**Static Analysis Results Interchange Format (SARIF 2.1.0).**

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "JMo Security",
          "version": "0.9.0",
          "informationUri": "https://jmotools.com",
          "rules": [
            {
              "id": "CVE-2024-1234",
              "shortDescription": {"text": "Vulnerability in lodash"},
              "fullDescription": {"text": "CVE-2024-1234: Prototype pollution in lodash"},
              "helpUri": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
              "defaultConfiguration": {"level": "error"},
              "properties": {
                "tags": ["security", "vulnerability", "cve"],
                "precision": "high",
                "security-severity": "7.5"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "CVE-2024-1234",
          "message": {"text": "Vulnerability in lodash"},
          "level": "error",
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {"uri": "package.json"},
                "region": {"startLine": 0}
              }
            }
          ],
          "properties": {
            "tool": "trivy",
            "toolVersion": "0.68.0",
            "cvss": {
              "v3": {
                "baseScore": 7.5,
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
              }
            }
          }
        }
      ]
    }
  ]
}
```

**Use Cases:**
- GitHub Code Scanning
- GitLab Security Dashboard
- Azure DevOps Pipelines
- Code quality platforms (SonarQube, CodeClimate)

**Features:**
- Severity mapping (CRITICAL/HIGH → error, MEDIUM → warning, LOW/INFO → note)
- Full rule metadata
- Location mapping
- Multi-tool support (each tool = separate run)
- CVSS scores in properties

---

## Format Comparison

| Format | Use Case | Size (1000 findings) | Parsing | Human-Readable |
|--------|----------|---------------------|---------|----------------|
| JSON | Machine parsing | ~500 KB | Fast | Medium |
| YAML | Configuration | ~600 KB | Medium | High |
| CSV | Spreadsheets | ~200 KB | Fast | Medium |
| Markdown | Documentation | ~100 KB | N/A | High |
| HTML (inline) | Dashboard (≤1000) | ~800 KB | Instant | High |
| HTML (external) | Dashboard (>1000) | 60 KB + 450 KB JSON | Async | High |
| SARIF | Code scanning | ~700 KB | Medium | Low |

## Configuration

Enable/disable formats in `jmo.yml`:

```yaml
outputs:
  - json       # Always included (primary format)
  - md         # Summary markdown
  - yaml       # Optional (requires PyYAML)
  - html       # Interactive dashboard
  - sarif      # Code scanning platforms
  - csv        # Spreadsheet analysis (v1.0.0+)
```

**Default:** All formats except YAML (requires extra dependency)

## Examples

### Accessing Metadata

```bash
# Extract metadata with jq
jq '.meta' findings.json

# Get scan timestamp
jq -r '.meta.timestamp' findings.json

# Get tool list
jq -r '.meta.tools | join(", ")' findings.json

# Get finding count
jq '.meta.finding_count' findings.json
```

### Processing Findings

```bash
# Extract findings array
jq '.findings' findings.json

# Filter by severity
jq '.findings[] | select(.severity == "CRITICAL")' findings.json

# Count by tool
jq '[.findings[] | .tool.name] | group_by(.) | map({tool: .[0], count: length})' findings.json
```

### Converting Formats

```bash
# JSON → YAML
jmo report results/ --outputs yaml

# JSON → CSV
jmo report results/ --outputs csv

# JSON → HTML
jmo report results/ --outputs html

# All formats
jmo report results/ --outputs json,md,yaml,html,sarif,csv
```

## See Also

- [CommonFinding Schema](schemas/common_finding.v1.json) - Finding structure specification
- [USER_GUIDE.md](USER_GUIDE.md) - Complete user guide
- [CHANGELOG.md](../CHANGELOG.md) - Version history
