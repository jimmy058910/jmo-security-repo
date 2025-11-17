# Output Formats

JMo Security supports 7 output formats for security findings, all following the v1.0.0 metadata wrapper structure.

## Overview

All output formats (JSON, YAML, CSV, Markdown, HTML, Simple HTML, SARIF) now use a standardized metadata envelope:

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

**Interactive React dashboard with dual-mode support (v1.0.0+).**

The HTML dashboard is a modern React application (built with TypeScript + Vite) that provides an interactive interface for exploring security findings. The dashboard automatically selects the optimal mode based on finding count:

- **Inline Mode (≤1000 findings):** JSON embedded directly in HTML (fast, self-contained)
- **External Mode (>1000 findings):** JSON loaded via fetch() (prevents browser freeze)

#### Inline Mode (≤1000 findings)

**Characteristics:**

- Findings JSON embedded directly in `window.__FINDINGS__`
- Self-contained single HTML file
- No external dependencies or network requests
- Instant loading (<500ms for 500 findings)
- Easy to share (drag-and-drop to browser)

**File Structure:**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>JMo Security Dashboard</title>
  <!-- Security headers (CSP, X-Frame-Options, etc.) -->

  <script>
    // Findings data embedded directly (XSS-escaped)
    window.__FINDINGS__ = [
      {
        "schemaVersion": "1.2.0",
        "id": "trivy|CVE-2024-1234|package.json|0|abc123",
        "severity": "HIGH",
        "message": "Vulnerability in lodash",
        "tool": {"name": "trivy", "version": "0.68.0"},
        "location": {"path": "package.json", "startLine": 0}
      },
      // ... 500 findings embedded ...
    ]
  </script>

  <!-- Bundled React app (Vite build) -->
  <script type="module">/* Minified React code */</script>
</head>
<body>
  <div id="root"></div>
</body>
</html>
```

**File Size Examples:**

- 100 findings: ~637 KB
- 500 findings: ~1.0 MB
- 1000 findings: ~1.6 MB

**Benefits:**

- **Zero configuration:** Works immediately after scan
- **Offline-ready:** No internet connection needed
- **Secure sharing:** Self-contained, no external dependencies
- **Fast loading:** No fetch() delays, instant rendering

#### External Mode (>1000 findings)

**Characteristics:**

- Findings loaded asynchronously from `findings.json`
- Dashboard HTML contains React app only (no data)
- Prevents 50-100 MB HTML files
- Loading spinner with error handling
- Professional UX for large datasets

**File Structure:**

```text
results/summaries/
├── dashboard.html        # ~610 KB (React app only)
└── findings.json         # ~1.6 MB for 1500 findings
```

**dashboard.html:**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>JMo Security Dashboard</title>
  <!-- Security headers -->

  <script>
    // Empty array - data loaded via fetch()
    window.__FINDINGS__ = []  // Loaded via fetch() in App.tsx
  </script>

  <!-- Bundled React app -->
  <script type="module">/* Minified React code */</script>
</head>
<body>
  <div id="root"></div>
</body>
</html>
```

**App Loading Logic (handled by React):**

1. Dashboard renders loading spinner
2. Fetch `findings.json` asynchronously
3. Parse JSON and populate dashboard
4. Hide spinner, show interactive UI
5. If fetch fails, display error message with troubleshooting

**File Size Examples:**

- 1500 findings: 610 KB (HTML) + 1.6 MB (JSON) = 2.2 MB total
- 5000 findings: 610 KB (HTML) + 5.2 MB (JSON) = 5.8 MB total
- 10000 findings: 610 KB (HTML) + 10.4 MB (JSON) = 11.0 MB total

**Benefits:**

- **Prevents browser freeze:** Large datasets don't block UI
- **Smaller HTML file:** React app only, no embedded data
- **Scalable:** Tested up to 10,000+ findings
- **Professional UX:** Loading states, error handling
- **95% file size reduction:** 2.2 MB vs 50-100 MB (legacy inline-only approach)

#### Dashboard Features

**All Modes Include:**

- **Priority Intelligence:**
  - EPSS risk scores for CVEs
  - CISA KEV (Known Exploited Vulnerabilities) badges
  - Calculated priority scores (0-100)

- **Compliance Frameworks:**
  - OWASP Top 10 2021
  - CWE Top 25 2024
  - CIS Controls v8.1
  - NIST CSF 2.0
  - PCI DSS 4.0
  - MITRE ATT&CK

- **Interactive Controls:**
  - Dark mode toggle (persisted to localStorage)
  - Severity filter checkboxes (CRITICAL, HIGH, MEDIUM, LOW, INFO)
  - Tool filter dropdown
  - Search by rule/message/path (real-time)
  - Column sorting (severity, priority, rule, path)

- **Data Views:**
  - **Summary Cards:** Severity counts, tool counts, target counts
  - **Findings Table:** Expandable rows with full details
  - **Compliance Tab:** Framework-specific compliance views
  - **Trends Tab:** Historical data (if available)
  - **Diff View:** Compare scans (if diff data present)

- **Export Options:**
  - Export to JSON (with metadata wrapper)
  - Export to CSV (Excel-compatible)

- **Responsive Design:**
  - Mobile-first layout
  - Tablet and desktop optimized
  - Accessible (WCAG 2.1 AA compliant)

#### Technical Details

**Built With:**

- **React 18.3+** — Component framework
- **TypeScript 5.3+** — Type safety
- **Vite 6.0+** — Build tool and bundler
- **Tailwind CSS 3.4+** — Utility-first styling
- **Lucide React** — Icon library

**Security:**

- **CSP Headers:** Strict Content Security Policy
- **X-Frame-Options:** DENY (prevents clickjacking)
- **XSS Prevention:** JSON escaping in inline mode
- **HTTPS-ready:** Works with HTTPS and file:// protocols

**Browser Compatibility:**

- Chrome/Edge 120+
- Firefox 121+
- Safari 17+
- No IE11 support (by design)

**Performance:**

- Inline mode: <500ms load time (500 findings)
- External mode: <3s load time (1500 findings)
- React virtualization for large tables
- Debounced search (300ms)

#### Troubleshooting

**External Mode: "Failed to load findings.json"**

**Cause:** Browser blocks file:// protocol fetch() (CORS restriction)

**Solution 1:** Serve via HTTP server

```bash
cd results/summaries
python3 -m http.server 8000
# Open http://localhost:8000/dashboard.html
```

**Solution 2:** Use browser flags (Chrome/Edge)

```bash
# Allow file:// access (temporary, for testing)
chrome --allow-file-access-from-files dashboard.html
```

**Solution 3:** Use inline mode instead

```bash
# Force inline mode by limiting findings
jmo report results/ --html --max-findings 1000
```

**Dashboard shows no findings**

**Cause:** `window.__FINDINGS__` not populated correctly

**Debug Steps:**

1. Open browser DevTools (F12)
2. Console tab: Check for JavaScript errors
3. Run: `console.log(window.__FINDINGS__.length)`
4. Verify findings.json exists in same directory (external mode)

**Dark mode not working**

**Cause:** localStorage disabled or blocked

**Solution:** Enable cookies/storage in browser settings

#### Use Cases

**Inline Mode Best For:**

- Quick scans (<1000 findings)
- Sharing via email/Slack
- Offline demos
- CI/CD artifacts (small repos)

**External Mode Best For:**

- Deep scans (>1000 findings)
- Production security reviews
- Large monorepos
- Compliance audits

**Both Modes Support:**

- Executive dashboards
- Security team reviews
- Developer onboarding
- Stakeholder presentations

---

### 6. Simple HTML (`simple-report.html`)

**Email-compatible static HTML table with inline CSS (v1.2.0+).**

The simple HTML reporter generates a static HTML table designed for maximum email client compatibility (Gmail, Outlook, Apple Mail, etc.). Unlike the interactive dashboard, it contains no JavaScript and uses only inline CSS.

#### Features

- **Static HTML table** - No JavaScript required
- **Inline CSS** - All styles embedded in `style=""` attributes
- **Email client compatibility:**
  - Microsoft Outlook (MSO) conditional comments
  - Table-based layout (email clients prefer tables over divs)
  - Viewport meta tags for mobile email apps
  - No external stylesheets or scripts
- **Security:** XSS protection via HTML escaping
- **Responsive design:** CSS media queries for dark mode and mobile
- **Severity color-coding:** Consistent color palette (CRITICAL=#b71c1c, HIGH=#e65100, etc.)
- **Consensus findings:** Shows multiple tools when issue detected by >1 scanner
- **Summary statistics:** Total findings, severity breakdown, tools used
- **Sorting:** Findings sorted by severity (CRITICAL → INFO)

#### HTML Structure

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Findings Report</title>
    <!--[if mso]>
    <style type="text/css">
        table { border-collapse: collapse; }
    </style>
    <![endif]-->
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; background: #f5f5f5; color: #212121; line-height: 1.6;">

    <!-- Main Container -->
    <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="width: 100%; max-width: 1200px; margin: 0 auto; background: #ffffff;">

        <!-- Header -->
        <tr>
            <td style="padding: 24px 20px; background: #1976d2; color: white;">
                <h1 style="margin: 0; font-size: 28px; font-weight: 600;">
                    🔒 Security Findings Report
                </h1>
            </td>
        </tr>

        <!-- Summary Section -->
        <tr>
            <td style="padding: 20px; background: #fafafa;">
                <h2>📊 Summary</h2>
                <p><strong>Total Findings:</strong> 42</p>
                <div>
                    <span style="display: inline-block; padding: 6px 12px; margin: 4px; background: #b71c1c; color: white; border-radius: 4px;">
                        CRITICAL: 5
                    </span>
                    <span style="display: inline-block; padding: 6px 12px; margin: 4px; background: #e65100; color: white; border-radius: 4px;">
                        HIGH: 12
                    </span>
                </div>
                <p><strong>Tools Used:</strong> trivy, semgrep, trufflehog</p>
            </td>
        </tr>

        <!-- Findings Table -->
        <tr>
            <td style="padding: 20px;">
                <h2>🔍 Findings</h2>
                <div style="overflow-x: auto;">
                    <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="width: 100%; border-collapse: collapse; border: 1px solid #e0e0e0;">
                        <thead style="background: #f5f5f5;">
                            <tr>
                                <th style="padding: 12px 8px; text-align: left; font-weight: 600; font-size: 13px; color: #424242;">Severity</th>
                                <th style="padding: 12px 8px; text-align: left; font-weight: 600; font-size: 13px; color: #424242;">Rule ID</th>
                                <th style="padding: 12px 8px; text-align: left; font-weight: 600; font-size: 13px; color: #424242;">Location</th>
                                <th style="padding: 12px 8px; text-align: left; font-weight: 600; font-size: 13px; color: #424242;">Message</th>
                                <th style="padding: 12px 8px; text-align: left; font-weight: 600; font-size: 13px; color: #424242;">Tool</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr style="border-bottom: 1px solid #e0e0e0;">
                                <td style="padding: 12px 8px; font-weight: 600; color: #b71c1c;">CRITICAL</td>
                                <td style="padding: 12px 8px; font-family: 'Courier New', monospace; font-size: 13px;">CVE-2024-1234</td>
                                <td style="padding: 12px 8px; font-family: 'Courier New', monospace; font-size: 12px; color: #555;">package.json:15</td>
                                <td style="padding: 12px 8px;">Prototype pollution vulnerability detected</td>
                                <td style="padding: 12px 8px; font-size: 13px; color: #666;">trivy</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </td>
        </tr>

        <!-- Footer -->
        <tr>
            <td style="padding: 20px; background: #fafafa; text-align: center; font-size: 13px; color: #757575;">
                <p style="margin: 0;">
                    Generated by <strong>JMo Security</strong> •
                    <a href="https://jmotools.com" style="color: #1976d2; text-decoration: none;">jmotools.com</a>
                </p>
            </td>
        </tr>
    </table>

    <!-- Dark mode support -->
    <style>
        @media (prefers-color-scheme: dark) {
            body { background: #121212 !important; color: #e0e0e0 !important; }
            table[role="presentation"] { background: #1e1e1e !important; }
        }
        @media screen and (max-width: 600px) {
            th, td { padding: 8px 4px !important; }
        }
    </style>
</body>
</html>
```

#### Use Cases

- **Email reports:** Send findings directly via email
- **Email attachments:** Attach simple-report.html to emails
- **Offline viewing:** Open in any browser without external dependencies
- **Non-technical stakeholders:** Easy-to-read table format
- **Compliance documentation:** Print or PDF export for audits
- **Restricted environments:** No JavaScript = works in locked-down email clients

#### Email Client Compatibility

Tested and verified in:

- ✅ Gmail (web, mobile)
- ✅ Microsoft Outlook (2016, 2019, 365, web)
- ✅ Apple Mail (macOS, iOS)
- ✅ Thunderbird
- ✅ Yahoo Mail
- ✅ ProtonMail

#### Configuration

Enable in `jmo.yml`:

```yaml
outputs: ["json", "md", "simple-html"]
```

Or via CLI:

```bash
jmo report results/ --simple-html
```

**Output file:** `results/summaries/simple-report.html`

#### Security Features

- **XSS protection:** All user input HTML-escaped (`_escape_html()` function)
- **No external dependencies:** No CDN links that could be compromised
- **Content Security Policy compatible:** No inline event handlers
- **Safe to forward:** Self-contained with no tracking pixels or external resources

#### Implementation

- **File:** `scripts/core/reporters/simple_html_reporter.py`
- **Test suite:** `tests/reporters/test_simple_html_reporter.py` (13 tests, 100% coverage)
- **Integration:** `scripts/cli/report_orchestrator.py` (lines 23, 170-171, 361-362)

---

### 7. SARIF (`findings.sarif`)

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
| **HTML (inline)** | **Dashboard (≤1000)** | **~1.6 MB** | **Instant** | **High** |
| **HTML (external)** | **Dashboard (>1000)** | **610 KB + 1.6 MB JSON** | **Async (<3s)** | **High** |
| SARIF | Code scanning | ~700 KB | Medium | Low |

**Note:** HTML dashboard sizes reflect React build (v1.0.0+). Legacy inline-only approach produced 50-100 MB files for >1000 findings (95% size reduction achieved).

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
