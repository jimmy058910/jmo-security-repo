# JMo Security - Immediate Action Plan

**Created:** 2025-10-15
**Status:** Active
**Purpose:** Consolidate business strategy and technical roadmap updates

---

## ✅ Completed

### 1. Apache 2.0 License Added
- ✅ Created LICENSE-APACHE
- ✅ Created LICENSE-MIT
- ✅ Updated LICENSE (dual license explanation)
- ✅ Updated pyproject.toml (`license = { text = "MIT OR Apache-2.0" }`)

**Remaining:** Update README.md badge to show dual license

---

## 📋 To-Do: Business Documentation Consolidation

### Task: Merge 3 business docs into single BUSINESS_PLAN.md

**Current files:**
- BUSINESS_PLAN.md (762 lines)
- BUSINESS_MODEL.md (1,343 lines)
- MONETIZATION_STRATEGY.md (508 lines)

**Action:** You should manually consolidate these using this structure:

```markdown
# BUSINESS_PLAN.md (New Structure)

## 1. Executive Summary
   - Mission, vision, market opportunity
   - Open source first approach
   - Revenue target: $2K/month by Month 12

## 2. Open Source Philosophy
   - CLI stays 100% free forever
   - Charge for convenience, not features
   - Community-driven development

## 3. Market Analysis
   - [Keep from existing BUSINESS_PLAN.md]
   - 6 critical market gaps
   - Competitive landscape

## 4. Product Strategy
   - [Keep from existing BUSINESS_PLAN.md]
   - Three-phase roadmap
   - Feature gating strategy

## 5. Monetization Strategy (Year 1 Focus)

   ### 5.1 Ko-Fi Memberships
   - [From MONETIZATION_STRATEGY.md]
   - 4 tiers: $5, $25, $100, $500/month
   - Goal: $1,000/month by Month 12

   ### 5.2 Email Collection (Mailjet)
   - [From MONETIZATION_STRATEGY.md]
   - Free tier: Up to 6,000 emails/month, 1,500 contacts
   - Multi-touch collection strategy
   - Goal: 3,000+ subscribers by Month 12

   ### 5.3 Hosted GitHub App
   - [From MONETIZATION_STRATEGY.md]
   - Launch: Months 6-12
   - Pricing: Free (10 scans), Pro ($29/month)
   - Goal: $1,500/month by Month 12

## 6. Target Audiences
   - [From BUSINESS_MODEL.md]
   - Phase 1: Platform Engineers (Months 1-6)
   - Phase 2: SMBs via GitHub App (Months 6-12)
   - Phase 3: Enterprises (Year 2)
   - Phase 4: MSPs (Year 2)

## 7. Financial Plan

   ### 7.1 Year 1 Projections
   - [From MONETIZATION_STRATEGY.md]
   - Month 6: $400/month
   - Month 12: $3,000/month
   - Email list: 3,000+ subscribers

   ### 7.2 Cost Structure
   - [From BUSINESS_MODEL.md]
   - Year 1: <$5K/month burn
   - Bootstrap-friendly

   ### 7.3 Future Revenue Streams
   - [From BUSINESS_MODEL.md]
   - Year 2: Premium Cloud SaaS
   - Year 3: White-label, MSP partnerships

## 8. Go-To-Market Strategy
   - [Keep from existing BUSINESS_PLAN.md]
   - Sequential audience targeting
   - Marketing channels

## 9. Execution Roadmap
   - [Keep from existing BUSINESS_PLAN.md]
   - Month-by-month milestones
   - Technical + business deliverables

## 10. Success Metrics
   - [Keep from existing BUSINESS_PLAN.md]
   - Product, usage, growth, financial KPIs

## 11. Risk Mitigation
   - [Keep from existing BUSINESS_PLAN.md]
   - Technical, business, market risks

## 12. Exit Strategy
   - [Keep from existing BUSINESS_PLAN.md]
   - Acquisition targets, valuations
```

**After consolidation:**
```bash
rm BUSINESS_MODEL.md
rm MONETIZATION_STRATEGY.md
```

---

## 📋 To-Do: Update README.md for Dual License

**Current:**
```markdown
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## 📝 License
MIT License. See LICENSE.
```

**Change to:**
```markdown
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)

## 📝 License
Dual licensed under your choice of MIT OR Apache 2.0. See [LICENSE](LICENSE), [LICENSE-MIT](LICENSE-MIT), and [LICENSE-APACHE](LICENSE-APACHE).
```

---

## 📋 To-Do: ROADMAP.md Technical Updates

### Missing Features to Add:

#### 1. Intelligent Prioritization (EPSS/KEV)

**Add as new section (before #1 Tool Version Consistency):**

```markdown
## 0. Intelligent Prioritization (EPSS/KEV Integration)

**Status:** 📋 Planned
**Priority:** 🔴 CRITICAL (reduce noise by 60-70%)
**Target:** v0.7.0 - Q1 2026
**Effort:** 2-3 weeks (solo dev friendly - API integrations only)

### Problem

Security scanners produce 20-40% false positive rates. Teams waste time investigating findings that aren't exploitable in practice. Need smart prioritization to focus on real threats.

### Solution: Dual-Layer Prioritization

#### Layer 1: EPSS + CISA KEV (Exploit Intelligence)

**EPSS (Exploit Prediction Scoring System):**
- API: https://api.first.org/data/v1/epss
- Provides probability (0-1) that a CVE will be exploited in next 30 days
- Example: EPSS score 0.85 = 85% chance of exploit

**CISA KEV (Known Exploited Vulnerabilities):**
- Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CVEs actively exploited in the wild
- Mandated for US federal agencies (BOD 22-01)

**Implementation:**

```python
# scripts/core/prioritization.py

import requests
from datetime import datetime

def get_epss_score(cve_id):
    """Fetch EPSS score for a CVE."""
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    response = requests.get(url, timeout=5)
    data = response.json()
    if data.get("data"):
        return float(data["data"][0].get("epss", 0))
    return 0.0

def is_cisa_kev(cve_id):
    """Check if CVE is in CISA KEV catalog."""
    # Cache KEV catalog locally (update weekly)
    kev_catalog = load_kev_catalog()  # Download once, cache
    return cve_id in kev_catalog

def calculate_priority(finding):
    """Calculate priority score (0-10)."""
    severity_weight = {
        "CRITICAL": 4.0,
        "HIGH": 3.0,
        "MEDIUM": 2.0,
        "LOW": 1.0,
        "INFO": 0.5,
    }

    base_score = severity_weight.get(finding["severity"], 1.0)

    # EPSS multiplier (0.1 to 2.0x)
    if cve := finding.get("cve_id"):
        epss = get_epss_score(cve)
        epss_multiplier = 1.0 + epss  # 1.0 to 2.0x
        base_score *= epss_multiplier

        # CISA KEV boost (+3.0)
        if is_cisa_kev(cve):
            base_score += 3.0

    return min(base_score, 10.0)  # Cap at 10
```

**Output Format:**

```json
{
  "id": "abc123",
  "severity": "HIGH",
  "cve_id": "CVE-2024-1234",
  "priority": 9.2,
  "priority_factors": {
    "epss_score": 0.85,
    "cisa_kev": true,
    "base_severity": "HIGH"
  }
}
```

**CLI Display:**

```
CRITICAL | SQL Injection | Priority: 9.2/10 🔥
├─ CVE-2024-1234
├─ EPSS: 0.85 (85% exploit probability in 30 days)
├─ CISA KEV: Yes 🔥 (actively exploited in the wild)
└─ Recommendation: PATCH IMMEDIATELY
```

#### Layer 2: Reachability Analysis (Future - v0.8.0)

**Goal:** Determine if vulnerable code path is actually reachable from entry points.

**Phase 1 (Python only, simple AST traversal):**

```python
# scripts/core/reachability.py

import ast

def is_function_reachable(target_func, entry_points):
    """
    Simple reachability check using AST.
    Returns: "reachable" | "potentially_reachable" | "not_reachable"
    """
    # Parse all Python files
    call_graph = build_call_graph(entry_points)

    # Check if target function is in call graph
    if target_func in call_graph:
        return "reachable"
    elif has_indirect_path(target_func, call_graph):
        return "potentially_reachable"
    else:
        return "not_reachable"
```

**Future (v0.9.0+):** Integrate CodeQL for advanced dataflow analysis.

### Benefits

- **60-70% noise reduction** (30% from EPSS/KEV + 40% from reachability)
- **Rebuild developer trust** (show only actionable findings)
- **Compliance alignment** (CISA BOD 22-01 requires KEV tracking)
- **Solo-dev friendly** (just API calls, no ML training needed)

### Dependencies

- None (standalone feature)

### Testing

```bash
# Unit tests
pytest tests/unit/test_prioritization.py

# Integration test with real CVEs
jmo scan --repo samples/fixtures/vulnerable-app --prioritize
```

### Rollout

- v0.7.0: EPSS + KEV integration (default enabled)
- v0.8.0: Basic reachability (Python only, opt-in with `--reachability`)
- v0.9.0: Advanced reachability (CodeQL integration)
```

---

#### 2. AI Remediation Orchestration (MCP Server)

**Add as new section:**

```markdown
## X. AI Remediation Orchestration (MCP Server Integration)

**Status:** 📋 Planned
**Priority:** 🟡 HIGH (developer experience improvement)
**Target:** v0.8.0 - Q2 2026
**Effort:** 3-4 weeks (MCP server + CLI integration)

### Problem

AI-powered code fixes are emerging (GitHub Copilot Autofix, Google CodeMender, Semgrep Assistant), but:
- Teams use multiple AI tools (no single winner)
- Manual fix application is tedious (copy-paste from AI chat)
- No batch processing (fix 50 findings one by one)
- No policy controls (which AI tool for which language?)

**We should NOT compete with AI tools.** Instead, **orchestrate them**.

### Solution: MCP Server for AI Fix Aggregation

**Architecture:**

```
jmo-security CLI
    ↓
jmo-ai-remediation MCP Server (open source)
    ↓
├─ GitHub Copilot Autofix API
├─ Semgrep Assistant API
├─ Google CodeMender API (when available)
├─ Amazon CodeWhisperer
└─ Custom AI tools (extensible)
```

**MCP Server Tools:**

```typescript
// mcp-server-jmo-ai/src/index.ts

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "get_ai_fix",
      description: "Get AI-suggested fix for a security finding",
      inputSchema: {
        type: "object",
        properties: {
          finding_id: { type: "string" },
          tool: {
            type: "string",
            enum: ["copilot", "semgrep", "codemender", "auto"]
          },
          code_context: { type: "string" },
          language: { type: "string" }
        },
        required: ["finding_id", "code_context"]
      }
    },
    {
      name: "apply_fix",
      description: "Apply AI-suggested fix to code",
      inputSchema: {
        type: "object",
        properties: {
          finding_id: { type: "string" },
          fix_source: { type: "string" },
          dry_run: { type: "boolean" }
        },
        required: ["finding_id", "fix_source"]
      }
    },
    {
      name: "batch_fix",
      description: "Apply fixes to multiple findings",
      inputSchema: {
        type: "object",
        properties: {
          finding_ids: { type: "array", items: { type: "string" } },
          confidence_threshold: { type: "number", minimum: 0, maximum: 1 },
          create_pr: { type: "boolean" }
        },
        required: ["finding_ids"]
      }
    }
  ]
}));
```

**CLI Integration:**

```bash
# Show AI fixes (read-only, always free)
jmo scan --repo . --ai-fixes

# Output:
Finding: SQL Injection in /api/users.ts:45
├─ Severity: HIGH
├─ AI Fixes Available (3):
│  ├─ GitHub Copilot: Use parameterized query (confidence: 95%)
│  ├─ Semgrep Assistant: Add input validation (confidence: 87%)
│  └─ CodeMender: Rewrite with ORM (confidence: 78%)
└─ Apply: jmo fix apply --finding-id abc123 --source copilot

# Apply single fix
jmo fix apply --finding-id abc123 --source copilot

# Batch apply (with policy)
jmo fix batch --confidence-threshold 0.9 --create-pr

# Policy example (jmo.yml):
ai_remediation:
  routing:
    python: semgrep      # Use Semgrep for Python
    javascript: copilot  # Use Copilot for JS
    default: auto        # Auto-select best
  batch_apply:
    confidence_min: 0.9  # Only auto-apply if 90%+ confidence
    create_pr: true      # Always create PR (never commit directly)
```

**Pricing Strategy:**

- **Free tier (CLI):** Show AI suggestions (read-only)
- **Paid tier (Cloud):** Batch apply, smart routing, policy controls
- **No AI training:** We just integrate existing AI tools

### Benefits

- **Don't compete with AI tools** (integrate them instead)
- **Developer-friendly** (one command for all AI tools)
- **Open source** (MCP server code is public)
- **Monetize orchestration** (not AI itself)

### Dependencies

- MCP SDK (https://github.com/modelcontextprotocol/sdk)
- GitHub Copilot API (when available)
- Semgrep Assistant API

### Implementation

**Phase 1 (v0.8.0): MCP Server + Semgrep**
- Build MCP server (TypeScript)
- Integrate Semgrep Assistant API
- CLI shows AI suggestions (read-only)

**Phase 2 (v0.9.0): Batch Apply**
- Add `jmo fix apply` command
- Add `jmo fix batch` command
- Policy controls (jmo.yml)

**Phase 3 (v1.0.0): Multi-Tool**
- Add GitHub Copilot (when API available)
- Add CodeMender (when released)
- Smart routing based on language
```

---

#### 3. Cross-Tool Deduplication Enhancement

**Add as new section OR enhance existing deduplication mentions:**

```markdown
## Y. Cross-Tool Deduplication (Similarity Matching)

**Status:** 📋 Planned
**Priority:** 🟡 MEDIUM (reduces noise, improves UX)
**Target:** v0.7.0 - Q1 2026
**Effort:** 2 weeks (string similarity, no ML needed)

### Current Status

✅ **We already have:** Fingerprint-based deduplication
- Each finding has stable ID: `hash(tool + ruleId + path + line + message)`
- Works great when same tool reports same issue twice
- Used in `normalize_and_report.py`

### Problem

Different tools report **same vulnerability** with **different IDs**:

```
Semgrep:  "SQL Injection in /api/users.ts:45" (rule: python.lang.security.audit.sqli)
Bandit:   "B608: Possible SQL injection vulnerability" (rule: B608)
CodeQL:   "CWE-89: Improper Neutralization of SQL" (rule: py/sql-injection)

→ Three separate findings, but SAME issue
→ Developer wastes time investigating same thing 3x
```

### Solution: Similarity-Based Clustering

**Algorithm:**

```python
# scripts/core/deduplication.py

from difflib import SequenceMatcher

def normalize_message(msg):
    """Normalize message for comparison."""
    # Lowercase, remove tool-specific prefixes
    msg = msg.lower()
    msg = re.sub(r'^(cwe-\d+:|b\d+:)', '', msg)
    msg = re.sub(r'\s+', ' ', msg).strip()
    return msg

def are_findings_similar(f1, f2, threshold=0.7):
    """Check if two findings are similar."""
    # Must be in same file
    if f1["location"]["path"] != f2["location"]["path"]:
        return False

    # Must be within 5 lines
    line_diff = abs(f1["location"]["startLine"] - f2["location"]["startLine"])
    if line_diff > 5:
        return False

    # Message similarity (70%+ threshold)
    msg1 = normalize_message(f1["message"])
    msg2 = normalize_message(f2["message"])
    similarity = SequenceMatcher(None, msg1, msg2).ratio()

    return similarity >= threshold

def cluster_findings(findings):
    """Group similar findings into clusters."""
    clusters = []

    for finding in findings:
        matched = False
        for cluster in clusters:
            # Check similarity with cluster representative
            if are_findings_similar(finding, cluster[0]):
                cluster.append(finding)
                matched = True
                break

        if not matched:
            # New cluster
            clusters.append([finding])

    return clusters

def merge_cluster(cluster):
    """Merge findings in a cluster into single representative."""
    # Use finding with highest severity as representative
    representative = max(cluster, key=lambda f: severity_rank(f["severity"]))

    # Add metadata about sources
    representative["detected_by"] = [f["tool"]["name"] for f in cluster]
    representative["detection_confidence"] = len(cluster) / 3.0  # More tools = higher confidence
    representative["duplicate_count"] = len(cluster) - 1

    return representative
```

**Output Format:**

```json
{
  "id": "abc123",
  "severity": "HIGH",
  "message": "SQL Injection vulnerability",
  "detected_by": ["semgrep", "bandit", "codeql"],
  "detection_confidence": 1.0,
  "duplicate_count": 2
}
```

**CLI Display:**

```
HIGH | SQL Injection | Confidence: 100% (3 tools agree)
├─ Detected by: Semgrep, Bandit, CodeQL
├─ Location: /api/users.ts:45
└─ 2 duplicates suppressed (view with --show-duplicates)
```

### Benefits

- **Reduce noise by 30-40%** (no more duplicate findings)
- **Increase confidence** (3 tools agree = probably real)
- **Solo-dev friendly** (just string similarity, no ML)

### Dependencies

- None (uses Python stdlib `difflib`)

### Testing

```bash
# Create test with 3 tools reporting same issue
pytest tests/unit/test_deduplication.py::test_cross_tool_clustering
```

### Rollout

- v0.7.0: Basic similarity matching (default enabled)
- v0.8.0: ML-powered clustering (optional, for cloud version)
```

---

## 📧 Email Service Recommendation: Mailjet

**Best for developers with free tier:**

- **Free Tier:** 6,000 emails/month, 1,500 contacts, 200 emails/day
- **API Access:** ✅ Full REST API + Webhooks
- **Developer-Friendly:** Python SDK, SMTP relay
- **Pricing:** Free forever, $15/month for 15K emails (when you scale)

**Setup:**
1. Sign up: https://www.mailjet.com
2. Get API keys
3. Install Python SDK: `pip install mailjet-rest`

**Integration:**

```python
# scripts/core/email_service.py

from mailjet_rest import Client

mailjet = Client(auth=(API_KEY, API_SECRET), version='v3.1')

def send_to_email_list(email, source="cli"):
    """Add email to Mailjet contact list."""
    data = {
        'Messages': [{
            "From": {"Email": "noreply@jmotools.com", "Name": "JMo Security"},
            "To": [{"Email": email}],
            "TemplateID": 1234567,  # Welcome email template
            "Variables": {"source": source}
        }]
    }
    result = mailjet.send.create(data=data)
    return result.status_code == 200
```

---

## 🌐 jmotools.com Update Checklist

**Every time you update the product, update the website:**

### Content to Keep in Sync:

1. **Homepage:**
   - [ ] Tool count (currently 11+, update if you add/remove tools)
   - [ ] Feature list (add AI remediation, EPSS/KEV when released)
   - [ ] GitHub stars count
   - [ ] Ko-Fi sponsor count

2. **Documentation:**
   - [ ] CLI command examples (sync with README.md)
   - [ ] ROADMAP.md link (ensure it's current)
   - [ ] Quick Start guide (sync with QUICKSTART.md)

3. **Pricing Page:** (when you add paid features)
   - [ ] Ko-Fi tier descriptions
   - [ ] GitHub App pricing
   - [ ] Email newsletter signup form (Mailjet)

4. **Blog:** (recommended)
   - [ ] Release announcements (v0.6.0, v0.7.0, etc.)
   - [ ] Feature deep-dives ("How EPSS reduces false positives by 60%")
   - [ ] Security tips ("Top 10 secrets found by jmo-security")

### Automation Idea:

```yaml
# .github/workflows/update-website.yml

name: Update Website Stats

on:
  release:
    types: [published]
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday

jobs:
  update-stats:
    runs-on: ubuntu-latest
    steps:
      - name: Get GitHub Stars
        run: |
          STARS=$(gh api repos/jimmy058910/jmo-security-repo | jq .stargazers_count)
          echo "STARS=$STARS" >> $GITHUB_ENV

      - name: Get Ko-Fi Supporters
        run: |
          # Call Ko-Fi API (if available) or manually update
          echo "SUPPORTERS=12" >> $GITHUB_ENV

      - name: Update Website
        run: |
          # Update jmotools.com via API or commit to website repo
          gh api --method PATCH repos/jimmy058910/jmotools-website \
            -f content="GitHub Stars: $STARS, Supporters: $SUPPORTERS"
```

---

## Next Steps (Priority Order)

### This Week:
1. ✅ Manually consolidate BUSINESS_PLAN.md (use outline above)
2. ✅ Delete BUSINESS_MODEL.md and MONETIZATION_STRATEGY.md
3. ✅ Update README.md to show dual license
4. ✅ Set up Mailjet account
5. ✅ Update ROADMAP.md (add 3 new sections above)

### Next Week:
1. Implement Ko-Fi integration in README/CLI/dashboard
2. Implement email collection (first-run prompt)
3. Update jmotools.com with latest info

### Month 1:
1. Build EPSS/KEV prioritization (v0.7.0)
2. Launch Ko-Fi membership tiers
3. Email newsletter setup (Mailjet welcome sequence)

---

**Last Updated:** 2025-10-15
