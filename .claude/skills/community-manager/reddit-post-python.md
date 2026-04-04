# Revised r/Python Showcase Post

**Account Status:** New account (needs karma building first)

**Strategy:** Conservative approach - minimal links, technical focus, conversational tone

---

## Version 1: Conservative (Safest - Recommended for New Accounts)

### Title

```text
Built a Python CLI to normalize output from 11 security scanners
```

### Body

```markdown
I built an open-source Python CLI that orchestrates multiple security tools (Trivy, Semgrep, TruffleHog, OWASP ZAP, Falco, etc.) and converts their different JSON formats into a unified schema.

## The Problem

Running multiple security scanners means dealing with:
- 11 different JSON output formats
- Duplicate findings across tools (same vulnerability reported by Trivy AND Semgrep)
- Manual compliance mapping (which CVE maps to OWASP Top 10?)
- Fragmented results (repos scanned separately from containers, IaC, web apps)

## Technical Approach

**Unified schema with deterministic fingerprinting:**

```python
def generate_fingerprint(finding: Dict[str, Any]) -> str:
    """Generate deterministic ID for cross-run deduplication."""
    components = [
        finding["tool"]["name"],
        finding["ruleId"],
        finding["location"]["path"],
        str(finding["location"]["startLine"]),
        finding["message"][:120]
    ]
    raw = "|".join(components)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
```

This fingerprint stays stable across scans, so re-running on the same codebase shows only NEW findings (not 500 duplicates).

**Type-safe severity enum with comparison operators:**

```python
class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def __lt__(self, other):
        order = {Severity.CRITICAL: 5, Severity.HIGH: 4, ...}
        return order[self] < order[other]

# Filter findings by severity
critical = [f for f in findings if f.severity >= Severity.HIGH]
```

**Parallel scanning with ThreadPoolExecutor:**

```python
def scan_targets(targets, scan_func, max_workers=4):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_func, t): t for t in targets}
        for future in as_completed(futures):
            try:
                name, statuses = future.result()
                results.append((name, statuses))
            except Exception as e:
                print(f"Error scanning {target}: {e}")
```

**Adapter pattern for tool integration:**

Each scanner has an adapter that maps its output to CommonFinding schema. Testing uses pytest fixtures with fabricated JSON:

```python
@pytest.fixture
def sample_trivy_output(tmp_path: Path) -> Path:
    output = {
        "Results": [{
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2023-12345",
                "Severity": "HIGH"
            }]
        }]
    }
    file_path = tmp_path / "trivy.json"
    file_path.write_text(json.dumps(output))
    return file_path

def test_trivy_adapter(sample_trivy_output):
    findings = load_trivy(sample_trivy_output)
    assert findings[0]["ruleId"] == "CVE-2023-12345"
```

## What It Does

- **Multi-target scanning:** Scan repos, containers, IaC files, web apps, GitLab repos, and K8s clusters in one command
- **Compliance auto-enrichment:** Maps findings to OWASP Top 10, CWE Top 25, NIST CSF 2.0, PCI DSS 4.0, CIS Controls, MITRE ATT&CK
- **Multiple output formats:** Interactive HTML dashboard, SARIF 2.1.0, JSON, Markdown, YAML
- **Profile-based config:** Fast (3 tools, 5 mins) / Balanced (8 tools, 15 mins) / Deep (11 tools, 30 mins)

## Quick Start

```bash
pip install jmo-security

# Interactive wizard
jmo wizard

# Manual scan
jmo scan --repo . --profile balanced

# Multi-target scan
jmo scan --repo ./app --image myapp:latest --url https://myapp.com
```

## Stats

- 91% test coverage (272 passing tests)
- Multi-platform: Linux/macOS/Windows (via Docker)
- Type hints throughout
- Supports Python 3.10, 3.11, 3.12

## Feedback Wanted

I'd love input from experienced Python developers on:

1. **Architecture:** Is the adapter pattern appropriate for tool integration? Better alternatives?
2. **Type hints:** Any places where types could be more precise?
3. **Testing:** Using pytest with fabricated JSON fixtures. Better approaches for integration testing?
4. **Performance:** ThreadPoolExecutor for subprocess calls. Would asyncio be better?
5. **CLI design:** Using argparse with subcommands. Should I switch to Click or Typer?

Built as my cybersecurity bootcamp capstone after transitioning from operational management. First major Python project, so eager to learn from the community!

GitHub and PyPI links in my profile. Issues, PRs, and feedback welcome!

```text

---

## Version 2: No Links (Maximum Safety)

### Title
```

Built an open-source CLI to unify 11 security scanners with deduplication

```text

### Body
```markdown
I spent the last few months building a Python CLI that solves a problem I kept hitting: running multiple security scanners (Trivy, Semgreg, TruffleHog, etc.) produces tons of duplicate findings and incompatible JSON formats.

## The Challenge

When scanning a codebase with multiple tools:
- Trivy finds CVE-2023-12345 in package.json
- Semgrep finds the same CVE via dependency analysis
- TruffleHog flags a potential secret
- OWASP ZAP finds a web vulnerability

You end up with 4 different JSON formats, duplicate findings, and no easy way to track "is this new since last scan?"

## Technical Solution

I built an adapter layer that normalizes everything into a unified CommonFinding schema with deterministic fingerprinting:

```python
def generate_fingerprint(finding: Dict[str, Any]) -> str:
    """Stable ID for deduplication across scans."""
    components = [
        finding["tool"]["name"],
        finding["ruleId"],
        finding["location"]["path"],
        str(finding["location"]["startLine"]),
        finding["message"][:120]
    ]
    return hashlib.sha256("|".join(components).encode()).hexdigest()[:16]
```

This means:

- ✅ Same finding = same ID across scans
- ✅ Deduplication across tools (Trivy + Semgrep reporting same CVE = 1 finding)
- ✅ Incremental scanning (only show NEW findings)

## Implementation Patterns

**Type-safe severity with comparison:**

```python
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def __lt__(self, other):
        order = {Severity.CRITICAL: 5, Severity.HIGH: 4, ...}
        return order[self] < order[other]

# Usage
high_and_above = [f for f in findings if f.severity >= Severity.HIGH]
```

**Parallel scanning with error handling:**

```python
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_all(targets, max_workers=4):
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan, t): t for t in targets}
        for future in as_completed(futures):
            target = futures[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                logging.error(f"Failed to scan {target}: {e}")
    return results
```

**Testing with fabricated fixtures:**

```python
import pytest
from pathlib import Path

@pytest.fixture
def trivy_json(tmp_path: Path) -> Path:
    """Fabricate Trivy output for testing adapter."""
    data = {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2023-1"}]}]}
    path = tmp_path / "trivy.json"
    path.write_text(json.dumps(data))
    return path

def test_trivy_adapter(trivy_json):
    findings = load_trivy(trivy_json)
    assert findings[0]["ruleId"] == "CVE-2023-1"
```

## Features

- Scans 6 target types: repos, containers, IaC, web apps, GitLab, Kubernetes
- Integrates 11 tools: Trivy, Semgrep, TruffleHog, Syft, Checkov, Hadolint, OWASP ZAP, Nuclei, Falco, Bandit, Nosey Parker
- Auto-maps findings to compliance frameworks (OWASP, CWE, NIST CSF, PCI DSS, CIS, MITRE ATT&CK)
- Outputs: Interactive HTML dashboard, SARIF 2.1.0, JSON, Markdown
- 91% test coverage, supports Python 3.10-3.12

## Install

```bash
pip install jmo-security
jmo wizard  # Interactive setup
```

Or search "jmo-security" on PyPI.

## Questions for the Community

1. **Adapters:** I use the adapter pattern for tool integration. Each tool has a `load_<tool>(path) -> List[Finding]` function. Is this appropriate, or would a plugin system be better?

2. **Type hints:** Everything is type-hinted, but should I use Protocol for the adapter interface instead of just following a convention?

3. **AsyncIO vs ThreadPoolExecutor:** Currently using threads for subprocess calls. Would asyncio.create_subprocess_exec() be better for I/O-bound scanner invocations?

4. **CLI framework:** Using argparse. Should I migrate to Click or Typer for better subcommand handling?

5. **Packaging:** Using pyproject.toml + setuptools. Worth switching to hatch or poetry?

This is my first major Python project after transitioning from operational management (cybersecurity bootcamp capstone). Eager to learn from experienced developers!

Comment if you'd like GitHub/docs links. Feedback, issues, and PRs welcome!

```text

---

## Version 3: Balanced (Moderate Links - Use After Building Karma)

### Title
```

Showcase: CLI to normalize 11 security scanners into unified reports

```text

### Body
```markdown
I built a Python CLI that orchestrates multiple security tools and normalizes their outputs into a unified schema with automatic deduplication and compliance mapping.

## Problem Statement

When running security scans with multiple tools:
- Each tool outputs a different JSON format (Trivy != Semgrep != TruffleHog)
- Same vulnerability reported by multiple tools = duplicates
- No easy way to track "what's NEW since last scan?"
- Manual compliance mapping (CVE → OWASP/NIST/PCI)

## Technical Implementation

**Unified schema with deterministic fingerprinting:**

```python
def generate_fingerprint(finding: Dict[str, Any]) -> str:
    """Generate stable ID for cross-run deduplication."""
    components = [
        finding["tool"]["name"],
        finding["ruleId"],
        finding["location"]["path"],
        str(finding["location"]["startLine"]),
        finding["message"][:120]
    ]
    raw = "|".join(components)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
```

Same finding = same ID across scans → deduplication works.

**Type-safe severity enum:**

```python
class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def __lt__(self, other):
        order = {Severity.CRITICAL: 5, Severity.HIGH: 4, ...}
        return order[self] < order[other]

# Filter findings
critical_findings = [f for f in findings if f.severity >= Severity.HIGH]
```

**Parallel scanning with ThreadPoolExecutor:**

```python
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_targets(targets, scan_func, max_workers=4):
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_func, t): t for t in targets}
        for future in as_completed(futures):
            target = futures[future]
            try:
                results.append(future.result())
            except Exception as e:
                print(f"Error scanning {target}: {e}")
    return results
```

**Testing with fabricated fixtures:**

```python
@pytest.fixture
def sample_trivy_output(tmp_path: Path) -> Path:
    output = {
        "Results": [{
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2023-12345",
                "Severity": "HIGH"
            }]
        }]
    }
    path = tmp_path / "trivy.json"
    path.write_text(json.dumps(output))
    return path

def test_trivy_adapter(sample_trivy_output):
    findings = load_trivy(sample_trivy_output)
    assert findings[0]["ruleId"] == "CVE-2023-12345"
```

## Features

- **Multi-target scanning:** Repos, containers, IaC files, web apps, GitLab repos, K8s clusters
- **11 integrated tools:** Trivy, Semgrep, TruffleHog, Syft, Checkov, Hadolint, OWASP ZAP, Nuclei, Falco, Bandit, Nosey Parker
- **Compliance auto-mapping:** OWASP Top 10, CWE Top 25, NIST CSF 2.0, PCI DSS 4.0, CIS Controls v8.1, MITRE ATT&CK
- **Multiple outputs:** Interactive HTML dashboard, SARIF 2.1.0, JSON, Markdown, YAML
- **Profile-based config:** fast (3 tools) / balanced (8 tools) / deep (11 tools)

## Quick Start

```bash
pip install jmo-security

# Interactive wizard
jmo wizard

# Manual scan
jmo scan --repo . --profile balanced

# Multi-target
jmo scan --repo ./app --image myapp:latest --url https://myapp.com
```

## Stats

- 91% test coverage (272 passing tests)
- Type hints throughout
- Python 3.10, 3.11, 3.12
- Multi-platform (Linux/macOS/Windows via Docker)

## Feedback Wanted

1. **Architecture:** Adapter pattern for tool integration appropriate? Better alternatives?
2. **Type hints:** Should I use Protocol for adapter interface instead of convention?
3. **Performance:** ThreadPoolExecutor for subprocess calls. Worth switching to asyncio?
4. **CLI framework:** Using argparse. Should I migrate to Click or Typer?
5. **Testing:** Fabricated JSON fixtures. Better approaches for integration tests?

Built as my cybersecurity bootcamp capstone. First major Python project, so eager to learn!

**Links:**

- GitHub: https://github.com/jimmy058910/jmo-security-repo
- PyPI: https://pypi.org/project/jmo-security

Issues and PRs welcome! 🐍

```text

---

## Posting Strategy for New Accounts

### Phase 1: Build Karma (Weeks 1-2)

**DO:**
- Comment on 15-20 r/Python posts
- Answer questions in r/learnpython
- Share helpful insights on threads
- Ask thoughtful questions
- Upvote quality content

**DON'T:**
- Post about your project yet
- Link to your GitHub in comments
- Mention your package name

**Goal:** Get 100+ comment karma, 30+ day account age

---

### Phase 2: Soft Introduction (Week 3)

**DO:**
- Comment on a relevant thread with a technical insight
- Casually mention "I built a tool that does X" (no links)
- If people ask, say "happy to share via DM"
- Collect interested users via DM

**DON'T:**
- Post links in comments
- Be overly promotional
- Spam multiple threads

**Goal:** Gauge interest, build relationships

---

### Phase 3: Official Showcase (Week 4+)

**DO:**
- Use Version 1 (Conservative) format
- Post on a weekday (Tuesday-Thursday)
- Morning US Eastern time (10am-12pm ET)
- Respond to ALL comments within 1 hour
- Be humble and appreciative

**DON'T:**
- Repost if removed (wait 7 days)
- Argue with critics
- Delete and repost
- Crosspost to multiple subs same day

---

### Phase 4: Follow-Up (After Post)

**DO:**
- Engage with every comment
- Answer technical questions in depth
- Accept criticism gracefully
- Update post with "Edit: addressing feedback on X"
- Thank people for trying it

**DON'T:**
- Abandon the thread
- Get defensive
- Ignore negative feedback
- Self-promote in other threads

---

## Alternative: Build Karma First

**Before posting your showcase, contribute to r/Python:**

### Week 1-2: Active Participation

**Comment on these types of threads:**
- "What are you working on?" weekly threads
- "Beginner questions" threads (answer if you can)
- Technical discussions (share insights)
- Tool comparisons (thoughtful analysis)
- Best practices debates

**Example comment:**
```

I've been using ThreadPoolExecutor for parallel subprocess calls in a CLI tool.
One gotcha I hit: make sure to handle exceptions in the future.result() calls,
or failed subprocesses silently disappear. Using as_completed() with try/except
around each result() call fixed it for me.

```text

### Week 3-4: Establish Presence

**Types of comments to make:**
- Answer beginner questions
- Share code snippets that helped you
- Recommend tools/libraries you've used
- Participate in architectural discussions

**Avoid:**
- Mentioning your project
- Linking to your GitHub
- Promotional language

### Week 5+: Ready to Post

**Checklist before posting:**
- [ ] Account age: 30+ days
- [ ] Comment karma: 100+
- [ ] Post karma: 10+
- [ ] Recent comment history: 20+ comments in last 2 weeks
- [ ] No self-promotional comments in history
- [ ] Active in r/Python community

---

## Recommended Version by Account Status

| Account Age | Karma | Version | Links |
|-------------|-------|---------|-------|
| 0-14 days | <50 | **DON'T POST** | Build karma first |
| 15-29 days | 50-100 | Version 2 (No Links) | Links in profile only |
| 30-60 days | 100-200 | Version 1 (Conservative) | 2 links max |
| 60+ days | 200+ | Version 3 (Balanced) | 2-3 links OK |

---

## Red Flags to Avoid

**These will trigger instant filter:**
- [ ] More than 3 external links
- [ ] Price comparisons or commercial language
- [ ] Comparison tables with competitors
- [ ] "Better than X" framing
- [ ] Package name in title
- [ ] Marketing template format
- [ ] Account age <7 days
- [ ] First post on account
- [ ] No comment history
- [ ] Previous removed posts

**Safest approach for NEW accounts:**
1. Build 100+ karma over 30 days
2. Post Version 2 (No Links)
3. Add links in comments AFTER post is live
4. Engage heavily in comments

---

## Contact Mods (If Post Removed)

**Wait 24 hours**, then message r/Python moderators:

```

Subject: Question about removed Showcase post

Hi mods,

I posted a Python CLI showcase earlier today and it appears to have been filtered.
I'm a new account and understand there may be karma/age requirements I don't meet yet.

Could you let me know:

1. What requirements I need to meet to post?
2. If my post violated any rules?
3. How long I should wait before trying again?

Happy to build karma and wait if needed. Just want to make sure I'm following
the rules correctly.

Thanks for your time!

```text

**Be polite, patient, and understanding.** Mods are volunteers.

---

## Next Steps

**Immediate (Today):**
1. Check your account age and karma
2. If <30 days or <50 karma: START Phase 1 (build karma)
3. If >30 days and >100 karma: Use Version 1 (Conservative)

**This Week:**
- Comment on 5-10 r/Python posts
- Answer questions in r/learnpython
- Build relationships, don't promote

**Next Month:**
- Post your showcase using recommended version
- Engage actively in comments
- Build on community feedback

---

## Summary: Why Original Post Was Filtered

**Primary issues:**
1. ❌ 7 links (Reddit limit ~2-3)
2. ❌ New account (likely <30 days)
3. ❌ Low karma (likely <100)
4. ❌ Commercial comparison table
5. ❌ Marketing template format
6. ❌ Price comparisons ($50k/year language)

**Fix:**
1. ✅ Build karma to 100+ over 30 days
2. ✅ Use Version 1 or 2 (max 2 links or no links)
3. ✅ Remove commercial language
4. ✅ Conversational tone, not marketing copy
5. ✅ Focus on technical decisions, not competitive positioning
6. ✅ Engage heavily in community first

**Expected timeline:**
- Weeks 1-4: Build karma and presence
- Week 5: Post showcase
- Week 6+: Engage with feedback, iterate on project

Good luck! 🐍
