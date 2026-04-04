# Reddit Post for r/opensource

**Created:** 2025-10-24
**Target Subreddit:** r/opensource (150k members)
**Post Type:** Text post
**Recommended Posting Time:** Monday, 10 AM-4 PM EST

---

## Title (Option 1 - Story-Driven)

```text
JMo Security: Open-source security scanner I built for my bootcamp capstone – now seeking contributors and feedback
```

(107 characters)

---

## Title (Option 2 - Feature-Driven)

```text
JMo Security: Scan repos, containers, IaC, web apps, GitLab, and K8s with one CLI – auto-maps to OWASP/NIST/PCI DSS
```

(120 characters)

---

## Title (Option 3 - Community-Driven) ⭐ RECOMMENDED

```text
Built an open-source security scanner as my bootcamp capstone – would love your feedback and contributions
```

(109 characters)

---

## Post Body (r/opensource Format)

```markdown
Hey r/opensource! 👋

I just finished the Michigan Tech Cybersecurity Bootcamp and built an open-source security audit platform as my capstone project. I'm sharing it here to get feedback from the community and hopefully find some contributors.

## What It Does

**JMo Security** orchestrates 11+ security scanners (Trivy, Semgrep, TruffleHog, OWASP ZAP, Falco, etc.) into one unified platform with:

- 🎯 **Multi-target scanning** – Scan repos, containers, IaC, web apps, GitLab, and Kubernetes clusters
- 📊 **Compliance automation** – Auto-maps findings to 6 frameworks (OWASP, CWE, NIST CSF, PCI DSS, CIS Controls, MITRE ATT&CK)
- 📈 **Unified reporting** – Interactive dashboard, SARIF 2.1.0, JSON, Markdown
- 🐳 **Zero installation** – Docker mode for instant scanning (no tool setup required)
- 🧙 **Beginner-friendly** – Interactive wizard for first-time users

## Why I Built It

During my capstone, I scanned 22 random GitHub repos with 4 secrets scanners and found:

- 🚨 **1,562 security findings**
- 🔴 **5 CRITICAL verified secrets** (live AWS keys, GitHub PATs, Stripe API keys)
- 🟠 **579 HIGH severity issues**

The problem? **I spent 3-4 hours manually parsing 4 different JSON formats and mapping findings to compliance frameworks.**

Most small teams and solo developers don't have $50k/year for commercial scanners. They deserve enterprise-grade security tools too.

So I built this.

## Quick Example

**Scan your entire infrastructure in one command:**

```bash
# Docker mode (zero installation)
docker pull ghcr.io/jimmy058910/jmo-security:latest

docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest \
  scan --repo /scan/myapp --profile balanced

# Or install locally
pip install jmo-security
jmo scan --repo . --profile balanced
```

**Multi-target scanning (v0.6.0+):**

```bash
# Scan repo + container + web app + K8s cluster together
jmo scan \
  --repo ./myapp \
  --image myapp:latest \
  --url https://myapp.com \
  --k8s-context prod \
  --results-dir ./audit
```

**Output:**

- Interactive HTML dashboard with filters/sorting/exports
- SARIF 2.1.0 for GitHub/GitLab Security tab
- Compliance reports auto-mapped to OWASP/NIST/PCI DSS
- JSON/YAML/Markdown formats

## Tech Stack

- **Language:** Python 3.10+ (type hints, pytest, 91% test coverage)
- **Containerization:** Docker (multi-arch: amd64/arm64)
- **CI/CD:** GitHub Actions (automated PyPI + Docker releases)
- **License:** MIT + Apache 2.0 (dual licensed) ✅
- **Tools:** 11 security scanners orchestrated

## Current Status

- ✅ **v0.7.1 released** (privacy-first telemetry, multi-target wizard)
- ✅ **272 tests passing** (91% coverage, enforced in CI)
- ✅ **PyPI package** – `pip install jmo-security`
- ✅ **Docker images** – 3 variants (full/slim/alpine)
- ✅ **Multi-platform** – Linux, macOS, Windows (via Docker)

## What I'm Looking For

**Feedback:**

- Is the compliance auto-mapping useful? What frameworks are missing? (SOC 2, ISO 27001?)
- Tool recommendations? (Snyk, Dependency-Track, etc.)
- UX improvements? (CLI flags, wizard workflow, dashboard design?)

**Contributors:**

- PRs welcome! See [CONTRIBUTING.md](https://github.com/jimmy058910/jmo-security-repo/blob/main/CONTRIBUTING.md)
- Open issues: Scheduled scans, diff reports, plugin system
- Roadmap: [ROADMAP.md](https://github.com/jimmy058910/jmo-security-repo/blob/main/ROADMAP.md)

**Job Opportunities:**

- Actively seeking Security Engineering/DevSecOps/AppSec roles
- 12+ years operational management background + fresh cybersecurity skills
- Portfolio: This project (production-ready, 91% test coverage)

## Links

- 📦 **GitHub:** https://github.com/jimmy058910/jmo-security-repo
- 📖 **Documentation:** https://docs.jmotools.com
- 🐍 **PyPI:** https://pypi.org/project/jmo-security
- 🐳 **Docker Hub:** https://hub.docker.com/r/jmogaming/jmo-security
- 📧 **Newsletter:** https://jmotools.com/subscribe.html (security tips, case studies)
- 💚 **Support:** https://ko-fi.com/jmogaming

## Why Open Source?

I'm building this in public for three reasons:

1. **Security tools should be accessible.** Not everyone has enterprise budgets. Those 5 critical secrets I found were in projects maintained by solo developers and small teams.

2. **I'm learning.** After 12+ years in operational management, I'm bringing that process mindset to cybersecurity. I want experienced engineers to critique this, suggest improvements, and help me build something truly useful.

3. **Giving back.** The bootcamp and open-source community helped me transition careers. This is my contribution.

---

If you're juggling multiple security tools or just starting in cybersecurity, I built this for you.

**Issues, PRs, and stars are all welcome.** Let's make security accessible to everyone. 🎉

— James (JMo)

---

**P.S.** If you're building security teams that value both technical depth and process excellence, I'd love to connect. Currently seeking my first security engineering role.

```text

---

## Posting Instructions

### Step 1: Create Post on r/opensource

1. Go to: https://www.reddit.com/r/opensource/submit
2. Select: **Text** post
3. **Title:** Use **Option 3** (Community-Driven)
   ```

   Built an open-source security scanner as my bootcamp capstone – would love your feedback and contributions

```text
4. **Body:** Copy the post body above
5. **Flair:** Select "Project" or "Show and Tell" (if available)

### Step 2: Monitor and Respond

**First 2 Hours (Critical):**
- ✅ Check for comments every 15 minutes
- ✅ Respond to questions thoughtfully
- ✅ Thank people for feedback
- ✅ Upvote all constructive comments
- ✅ Pin a comment with quick links (GitHub, Docker, Docs)

**Common Questions to Prepare For:**

1. **"How is this different from [commercial tool]?"**
   - Answer: "Great question! JMo focuses on compliance automation and multi-target scanning. Commercial tools like Snyk/Veracode are more comprehensive but cost $50k+/year. JMo is 100% free, self-hosted, and designed for small teams/solo devs."

2. **"Why not just use GitHub Advanced Security?"**
   - Answer: "GitHub Advanced Security is excellent but requires GitHub Enterprise ($21/user/month). JMo works with any Git host (GitLab, Bitbucket, self-hosted) and adds compliance auto-mapping that GitHub doesn't provide."

3. **"Can I use this in production?"**
   - Answer: "Yes! v0.7.1 is production-ready with 91% test coverage and 272 passing tests. I recommend starting with the 'balanced' profile for CI/CD."

4. **"How do I contribute?"**
   - Answer: "Check out [CONTRIBUTING.md](https://github.com/jimmy058910/jmo-security-repo/blob/main/CONTRIBUTING.md)! Easy first issues are tagged 'good-first-issue'. The codebase uses pytest, pre-commit hooks, and has detailed setup docs."

5. **"Is telemetry opt-in or opt-out?"**
   - Answer: "Opt-out by default (as of v0.7.1). 100% anonymous (random UUID, no PII/repo names/secrets). Auto-disabled in CI/CD. Full transparency: [docs/TELEMETRY.md](https://github.com/jimmy058910/jmo-security-repo/blob/main/docs/TELEMETRY.md). Easy opt-out: `jmo telemetry disable`"

### Step 3: Track Metrics

**Success Indicators:**
- 50+ upvotes (good engagement)
- 10+ comments (active discussion)
- 20+ GitHub visits (Analytics)
- 5+ stars (early adopters)

**Warning Signs:**
- <5 upvotes after 2 hours → Title may be weak
- Negative comments → Address concerns professionally
- Post removed → Check modmail, learn from feedback

### Step 4: Follow-Up Actions

**If successful (50+ upvotes):**
- [ ] Post thank-you comment after 24 hours
- [ ] Update CHANGELOG.md with "Featured on r/opensource"
- [ ] Share screenshot to LinkedIn/Twitter
- [ ] Schedule Week 2 posts (r/devops, r/Python)

**If moderate success (20-50 upvotes):**
- [ ] Analyze feedback (what resonated? what didn't?)
- [ ] Refine messaging for next post
- [ ] Continue with Week 2 as planned

**If low engagement (<20 upvotes):**
- [ ] Test alternative title on r/Python (Week 1 Friday)
- [ ] Revise approach before r/devops
- [ ] Ask r/opensource mods for feedback (via modmail)

---

## Alternative Versions

### Shorter Version (if original feels too long)

```markdown
Hey r/opensource! 👋

I just finished the Michigan Tech Cybersecurity Bootcamp and built an open-source security scanner as my capstone. Would love your feedback!

## What It Does

**JMo Security** unifies 11+ security tools (Trivy, Semgrep, TruffleHog, OWASP ZAP) with:

- Multi-target scanning (repos, containers, IaC, web apps, K8s)
- Automated compliance mapping (OWASP, NIST, PCI DSS, CIS, ATT&CK)
- Interactive dashboard + SARIF 2.1.0 export
- Zero-installation Docker mode

## Why I Built It

During my capstone, I found **5 critical secrets** in 22 random repos. But I spent **3-4 hours** manually parsing 4 different JSON formats and mapping to compliance frameworks.

Solo devs and small teams can't afford $50k/year commercial scanners. They deserve enterprise-grade tools too.

## Quick Start

```bash
# Docker (zero installation)
docker pull ghcr.io/jimmy058910/jmo-security:latest
docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan

# Or local install
pip install jmo-security
jmo wizard
```

## Current Status

- ✅ v0.7.1 released
- ✅ 272 tests, 91% coverage
- ✅ PyPI + Docker + Multi-platform
- ✅ MIT + Apache 2.0 license

## Looking For

- **Feedback:** What compliance frameworks are missing? UX improvements?
- **Contributors:** PRs welcome! See [CONTRIBUTING.md](https://github.com/jimmy058910/jmo-security-repo/blob/main/CONTRIBUTING.md)
- **Job opportunities:** Seeking Security Engineering/DevSecOps roles

**GitHub:** https://github.com/jimmy058910/jmo-security-repo
**Docs:** https://docs.jmotools.com

Thanks for reading! Issues, PRs, and stars welcome. 🎉

```text

---

## Next Steps After Posting

1. **Immediately after posting:**
   - [ ] Pin a comment with quick links
   - [ ] Share to Twitter/LinkedIn (optional)
   - [ ] Set phone reminder to check every 15 min for 2 hours

2. **24 hours later:**
   - [ ] Post thank-you comment
   - [ ] Compile feedback into GitHub issues
   - [ ] Update reddit-strategy.md with results

3. **Week 2 prep:**
   - [ ] Draft r/Python post (Wednesday)
   - [ ] Draft r/cscareerquestions post (Friday)
   - [ ] Refine messaging based on r/opensource feedback

---

**Ready to post? Copy the "Community-Driven" title + post body and create your r/opensource post now!** 🚀

Good luck! Let me know how it goes. 🎉
