# Memory Integration & Cross-Skill Workflows

How the community-manager skill integrates with other skills and workflows.

---

## Integration with Other Skills

When generating summaries or responses:

- **Defer to content-generator** for blog posts about feedback
- **Defer to jmo-refactoring-assistant** for technical fixes to reported issues
- **Use GitHub MCP tools** for all GitHub operations
- **Suggest content ideas** to content-generator skill

---

## Example Workflow

**User:** "What should I focus on this week?"

**You:**

1. Generate weekly summary (use GitHub MCP tools)
2. Identify top 3 priorities:
   - Critical bug to fix
   - High-demand feature to consider
   - Community member to thank
3. Draft responses for pending issues
4. Suggest content idea based on discussions
5. Provide focused action plan

**Output:**

```markdown
# This Week's Focus — [Date]

## Top 3 Priorities
1. **Fix dashboard crash (Issue #52)** — Critical, affects 5% of users
2. **Respond to 3 pending issues** — #48, #51, #53
3. **Thank Ko-Fi supporters** — 2 new this week

## Time Estimate
- Priority 1: 4-6 hours (requires debugging + testing)
- Priority 2: 1 hour (draft responses, link to docs)
- Priority 3: 30 minutes (personal emails + social post)

**Total:** ~6-8 hours of community work this week

## Content Opportunity
Active discussion about "multi-target scanning workflow" (Issue #48) — Good blog post topic for next week.

## Suggested Schedule
- Monday: Respond to pending issues
- Wednesday: Fix dashboard crash, deploy patch
- Friday: Thank supporters, share update on social media
```

---

## Telemetry Analytics (Usage Data)

- **Purpose:** Track real-world usage patterns, popular profiles, tool failures, platform distribution
- **Data Source:** GitHub Gist backend (anonymous, opt-out telemetry)
- **Script:** `./scripts/dev/view_telemetry.sh`
- **Environment Variables:**
  - `JMO_TELEMETRY_GIST_ID` - Gist ID (fc897ef9a7f7ed40d001410fa369a1e1)
  - `JMO_TELEMETRY_GITHUB_TOKEN` - GitHub token for Gist API access
- **Frequency:** Weekly or when analyzing feature prioritization

### Fetching Telemetry Data

```bash
# View interactive dashboard
./scripts/dev/view_telemetry.sh

# View raw JSONL data
./scripts/dev/view_telemetry.sh --raw | jq .

# Export to CSV for analysis
./scripts/dev/view_telemetry.sh --export

# Manual Gist fetch
gh gist view fc897ef9a7f7ed40d001410fa369a1e1 --raw > /tmp/telemetry-events.jsonl

# Query specific events
jq 'select(.event == "scan.started")' /tmp/telemetry-events.jsonl

# Count events by type
jq -r '.event' /tmp/telemetry-events.jsonl | sort | uniq -c | sort -rn

# Profile popularity
jq -r 'select(.event == "scan.started") | .metadata.profile' /tmp/telemetry-events.jsonl | sort | uniq -c | sort -rn

# Version distribution
jq -r '.version' /tmp/telemetry-events.jsonl | sort | uniq -c | sort -rn

# Platform distribution
jq -r '.platform' /tmp/telemetry-events.jsonl | sort | uniq -c

# Execution mode breakdown
jq -r 'select(.event == "scan.started") | .metadata.mode' /tmp/telemetry-events.jsonl | sort | uniq -c

# Tool failures
jq -r 'select(.event == "tool.failed") | .metadata.tool' /tmp/telemetry-events.jsonl | sort | uniq -c | sort -rn

# Unique users
jq -r '.anonymous_id' /tmp/telemetry-events.jsonl | sort -u | wc -l
```

### Telemetry Insights for Community Summary

Include in weekly summaries:

```markdown
## Usage Analytics (Anonymous Telemetry)
- **Unique Users:** X (anonymous IDs)
- **Total Scans:** Y
- **Most Popular Profile:** balanced (Z% of scans)
- **Top Platform:** Linux (A% of users)
- **Version Adoption:**
  - v0.9.0: B%
  - v0.8.0: C%
  - v0.7.x: D%
- **Execution Mode:** CLI (E%), Docker (F%), Wizard (G%)
- **Tool Failures:** [trivy timeout: X%, zap crash: Y%]

### Key Insights:
- [e.g., "70% of users prefer 'balanced' profile - consider optimizing it further"]
- [e.g., "Trivy timeouts increased 15% - investigate timeout settings"]
- [e.g., "Wizard usage up 20% - invest in wizard UX improvements"]
```

**Privacy Note:** Telemetry is 100% anonymous (random UUID, no PII, no repo names/secrets). Opt-out model with auto-disable in CI/CD.

---

## Quick Monitoring Checklist

Use this checklist when user asks for "weekly community summary" or "check all platforms":

**GitHub (5 min):**

- [ ] `gh api repos/jimmy058910/jmo-security-repo | jq '{stars, forks, watchers, open_issues}'`
- [ ] Check new issues/PRs in last 7 days
- [ ] Check discussions activity

**Social Media (10 min):**

- [ ] Check Mastodon: <https://infosec.exchange/@jmosecurity> (mentions, boosts)
- [ ] Check X/Twitter: <https://x.com/JMoSecurity> (mentions, replies)
- [ ] Check LinkedIn: <https://www.linkedin.com/in/jimmy-moceri/> (post engagement)

**Content Platforms (5 min):**

- [ ] Check Hashnode: <https://blog.jmotools.com/> (comments, views)
- [ ] Check Dev.to: <https://dev.to/jmogaming> (reactions, comments)

**Container Registries (5 min):**

- [ ] `curl https://hub.docker.com/v2/repositories/jmogaming/jmo-security/ | jq '{pull_count, star_count, last_updated}'`
- [ ] Check GHCR packages tab in GitHub repo

**PyPI (3 min):**

- [ ] `curl https://pypi.org/pypi/jmo-security/json | jq '.info.version'`
- [ ] Check download stats (manual or pypistats)

**Ko-Fi (2 min):**

- [ ] Check dashboard for new supporters (manual)
- [ ] Review messages and feedback

**Web Search (5 min):**

- [ ] `WebSearch: "JMo Security" OR "jmotools" (last 7 days)`
- [ ] `WebSearch: "@JMoSecurity" OR "@jmosecurity" site:x.com`
- [ ] `WebSearch: "jmo-security" site:reddit.com`

**Total Time:** ~35 minutes for comprehensive weekly check
