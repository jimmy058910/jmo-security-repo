# Community Manager Response Templates

Templates for consistent, professional community engagement across all platforms.

---

## 1. GitHub Issue Response

When user says "respond to issue #N" or "how should I respond to this issue":

**Process:**

1. **Read the issue** (use mcp__github__get_issue)
2. **Read issue comments** (use mcp__github__get_issue_comments)
3. **Search docs** for relevant info (grep, read docs/)
4. **Check for similar issues** (use mcp__github__search_issues)
5. **Draft response**

**Response Template:**

```markdown
Hi @username,

Thanks for reporting this! [Acknowledge the issue/suggestion]

[If bug]
I can reproduce this on my end. It looks like [explanation].

**Workaround for now:**
[Temporary fix if available]

**Fix plan:**
I'll [what you'll do] and target this for [version/timeframe].

[If feature request]
This is a great idea! It aligns with our goal to [project goal].

**Questions before I implement:**
- [Clarifying question 1]
- [Clarifying question 2]

[If question]
Here's how to [answer]:

[Code example or link to docs]

**Related docs:**
- [Link to USER_GUIDE.md section]

[Always end with]
Let me know if this helps! Feel free to follow up here or in [Discussions/Discord].

[If first-time contributor]
P.S. Thanks for being part of the JMo Security community!
```

**Suggested Labels:** [enhancement, bug, question, good-first-issue, etc.]
**Priority:** [high/medium/low]

---

## 2. Thank Contributors

When user says "thank this week's contributors" or "draft Ko-Fi thank you":

### For GitHub Contributors

```markdown
# Public GitHub Comment (on PR)

@username — Thank you for this contribution!

[Specific praise: "This fixes a critical bug" / "Great documentation improvement" / "Love the test coverage"]

[If first PR]
This is your first contribution to JMo Security — welcome to the community!

[Always]
Your work helps make security scanning better for everyone.

---
*If you found this project useful, consider [supporting development](https://ko-fi.com/jmogaming).*
```

### For Ko-Fi Supporters

```markdown
# Personal Email (via Resend)

Subject: Thank you for supporting JMo Security!

Hi [Name],

I just saw your support on Ko-Fi — thank you so much!

[If message included]
I saw your note about [topic]. [Response to their message].

[Always]
Your support directly enables:
- [Current focus, e.g., "Building the policy-as-code integration"]
- [Maintenance, e.g., "Keeping all 11 security tools up to date"]
- [Community, e.g., "Creating tutorials and guides"]

As a supporter, you're welcome to:
- Request priority features
- Get early access to releases
- Ask technical questions directly

[If recurring]
I'll keep you updated monthly on what your support helped build.

Thanks again for believing in this project.

— James

P.S. Have feedback or requests? Reply anytime!
```

### For Social Media Shoutouts

```markdown
# X/Twitter Thread

Huge thanks to this week's JMo Security contributors:

@user1 — Fixed critical dashboard bug (#52)
@user2 — Added Kubernetes scanning support (#48)
@user3 — Improved documentation clarity

And to our 3 new Ko-Fi supporters — you're making full-time open source possible!

[If milestone]
We just hit [X stars / Y supporters] — grateful for this community.
```

---

## 3. Track & Categorize Feedback

When user says "categorize recent feedback" or "what are users asking for":

**Process:**

1. Scan last 30 days of issues (mcp__github__list_issues)
2. Scan discussions
3. Check Ko-Fi messages
4. Categorize by type and sentiment

**Output:**

```markdown
# Feedback Analysis — Last 30 Days

## Feature Requests (X total)
### High Demand (3+ votes)
1. **GitLab CI integration** (5 votes) — [Issue #N]
2. **Policy-as-Code (OPA)** (4 votes) — [Issue #M]

### Medium Demand (1-2 votes)
1. **SLSA attestation** (2 votes) — [Issue #P]

### Individual Requests (1 vote each)
- Custom report templates
- Jira integration
- VS Code extension

## Bug Reports (X total)
### Critical (Blocking users)
- **Dashboard crash on large repos** (3 reports) — [Issue #N]

### High (Major inconvenience)
- **Trivy timeout on slow networks** (2 reports) — [Issue #M]

### Medium (Workarounds available)
- CLI help text typo
- Docker alpine image size

## Questions/Confusion (X total)
### Documentation Gaps
- "How do I use custom profiles?" (3 asks) — Need USER_GUIDE.md section
- "What's the difference between fast/balanced/deep?" (2 asks) — Need comparison table

### Installation Issues
- WSL Python version conflict (1 report)
- macOS ARM Docker compatibility (1 report)

## Praise & Success Stories (X total)
- "Saved us 10 hours/week consolidating scanner outputs"
- "Only tool that does compliance mapping automatically"
- "Docker image made setup trivial"

## Sentiment Summary
- Positive: 65% (13 comments)
- Neutral: 25% (5 comments)
- Negative: 10% (2 comments)

## Recommended Actions
1. **Fix dashboard crash** (critical, affects 5% of users)
2. **Add profile comparison table** to README (closes 5 questions)
3. **Prioritize GitLab CI** (high demand, aligns with roadmap)
4. **Create troubleshooting doc** for Trivy timeouts
5. **Share success story** in next newsletter

## Roadmap Impact
Based on feedback, suggest reprioritizing:
- Move "GitLab CI integration" from Month 6 — Month 3
- Add "Profile comparison guide" to next sprint
- Defer "VS Code extension" (low demand, high effort)
```

---

## 4. Draft Social Media Posts

When user says "draft social post about [milestone]":

### For X/Twitter

```text
JMo Security just hit [milestone]!

[Context in 1 sentence]

[Stat or achievement]

[Personal note from developer]

Thanks to everyone who starred, contributed, or supported on Ko-Fi. This is just the beginning.

Try it: [link]
```

### For LinkedIn

```text
I'm excited to share that JMo Security just reached [milestone].

[Longer context, 2-3 sentences about what the project is]

What started as a capstone project for my cybersecurity bootcamp has grown into [achievement].

The community has been incredible:
- [Stat 1]
- [Stat 2]
- [Stat 3]

[Personal reflection, 1-2 sentences]

If you're working on security automation, I'd love to hear your feedback: [link]

Special thanks to [names or "everyone who contributed"].
```
