# Custom Domain & CAPTCHA Implementation Guide

**Purpose:** Complete walkthrough for adding api.jmotools.com custom domain and researching CAPTCHA options.

**Date:** October 17, 2025

---

## 🌐 Task 1: Custom Domain Setup (api.jmotools.com)

### Overview

**Current URL:** `https://jmo-security-subscribe-7o52zyplw-jmotools.vercel.app`
**Target URL:** `https://api.jmotools.com/api/subscribe`

**Benefits:**
- Professional, branded URL
- Easier to remember and share
- Better for marketing materials
- Consistent with main site (jmotools.com)

**Time Required:** 15-20 minutes

---

### Step 1: Add Domain to Vercel (5 minutes)

#### Option A: Using Vercel CLI (Recommended)

```bash
cd /home/jimmy058910/jmo-security-repo/scripts/api

# Add custom domain to project
vercel domains add api.jmotools.com

# You'll see output like:
# > Adding Domain api.jmotools.com to Project jmo-security-subscribe-api
# > Success! Domain api.jmotools.com added to Project jmo-security-subscribe-api
```

#### Option B: Using Vercel Dashboard (Visual)

1. Visit: https://vercel.com/jmotools/jmo-security-subscribe-api/settings/domains
2. Click **"Add Domain"**
3. Enter: `api.jmotools.com`
4. Click **"Add"**

---

### Step 2: Configure DNS Records (10 minutes)

After adding the domain, Vercel will show you DNS records to configure.

#### Where is jmotools.com hosted?

First, let's identify your DNS provider:

```bash
# Check current nameservers
dig jmotools.com NS +short
# OR
nslookup -type=NS jmotools.com
```

**Common providers:**
- **Cloudflare:** ns1.cloudflare.com, ns2.cloudflare.com
- **GoDaddy:** ns01.domaincontrol.com, ns02.domaincontrol.com
- **Namecheap:** dns1.registrar-servers.com, dns2.registrar-servers.com
- **AWS Route 53:** ns-xxxx.awsdns-xx.com

#### DNS Records to Add

Vercel will provide specific records, but typically you need:

**CNAME Record:**
```
Type:  CNAME
Name:  api
Value: cname.vercel-dns.com.
TTL:   3600 (or Auto)
```

**OR A Record (if CNAME not supported):**
```
Type:  A
Name:  api
Value: 76.76.21.21
TTL:   3600
```

---

### Step 3: DNS Configuration by Provider

#### Cloudflare (Most Common)

1. Login to Cloudflare: https://dash.cloudflare.com
2. Select `jmotools.com` domain
3. Go to **DNS → Records**
4. Click **"Add record"**
5. Fill in:
   - **Type:** CNAME
   - **Name:** api
   - **Target:** cname.vercel-dns.com
   - **Proxy status:** DNS only (gray cloud, not orange)
   - **TTL:** Auto
6. Click **"Save"**

**⚠️ IMPORTANT:** Must be **DNS only** (gray cloud), not proxied (orange cloud), for SSL to work correctly.

#### GoDaddy

1. Login to GoDaddy: https://account.godaddy.com/products
2. Find `jmotools.com` → Click **"DNS"**
3. Click **"Add New Record"**
4. Fill in:
   - **Type:** CNAME
   - **Name:** api
   - **Value:** cname.vercel-dns.com
   - **TTL:** 1 Hour
5. Click **"Save"**

#### Namecheap

1. Login to Namecheap: https://ap.www.namecheap.com
2. Go to **Domain List** → `jmotools.com` → **"Manage"**
3. Select **"Advanced DNS"** tab
4. Click **"Add New Record"**
5. Fill in:
   - **Type:** CNAME Record
   - **Host:** api
   - **Value:** cname.vercel-dns.com
   - **TTL:** Automatic
6. Click **"Save All Changes"**

---

### Step 4: Verify DNS Propagation (5-10 minutes)

DNS changes can take 5 minutes to 24 hours to propagate globally.

#### Check DNS Propagation

```bash
# Test if DNS is configured (should return Vercel's IP)
dig api.jmotools.com +short

# Expected output:
# 76.76.21.21 (or similar Vercel IP)

# Check multiple global DNS servers
dig api.jmotools.com @8.8.8.8 +short  # Google DNS
dig api.jmotools.com @1.1.1.1 +short  # Cloudflare DNS
```

#### Online DNS Checker

Use: https://dnschecker.org
- Enter: `api.jmotools.com`
- Check worldwide propagation status

---

### Step 5: Test Custom Domain (2 minutes)

Once DNS propagates, test the API:

```bash
# Health check
curl https://api.jmotools.com/api/health

# Expected output:
# {"status":"ok","message":"JMo Security Email API is running","timestamp":"..."}

# Test subscription
curl -X POST https://api.jmotools.com/api/subscribe \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","source":"test"}'

# Expected output:
# {"success":true,"message":"✅ Thanks! Check your inbox for a welcome email."}
```

---

### Step 6: Update Frontend URLs (5 minutes)

Once custom domain is working, update your forms:

#### Update Subscribe Page

```bash
# Edit docs/subscribe.html
# Find line ~262 (form action)
# Change:
# FROM: https://jmo-security-subscribe-7o52zyplw-jmotools.vercel.app/api/subscribe
# TO:   https://api.jmotools.com/api/subscribe
```

#### Update Dashboard Form

```bash
# Edit scripts/core/reporters/html_reporter.py
# Find line ~713 (form action)
# Change:
# FROM: https://jmo-security-subscribe-7o52zyplw-jmotools.vercel.app/api/subscribe
# TO:   https://api.jmotools.com/api/subscribe
```

#### Commit Changes

```bash
git add docs/subscribe.html scripts/core/reporters/html_reporter.py
git commit -m "feat(api): migrate to custom domain api.jmotools.com

Updated email subscription forms to use custom domain instead of
auto-generated Vercel URL.

- docs/subscribe.html: Updated form action
- scripts/core/reporters/html_reporter.py: Updated dashboard form

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Step 7: SSL Certificate (Automatic)

Vercel automatically provisions and renews SSL certificates via Let's Encrypt.

**Verify HTTPS:**
```bash
curl -I https://api.jmotools.com/api/health | head -5

# Should show:
# HTTP/2 200
# content-type: application/json
# ...
```

---

### Troubleshooting Custom Domain

#### Issue 1: DNS Not Resolving

**Symptom:** `dig api.jmotools.com` returns nothing or NXDOMAIN

**Solutions:**
1. Verify CNAME record in DNS provider dashboard
2. Check TTL hasn't expired (wait 5-10 minutes)
3. Flush your local DNS cache:
   ```bash
   # Linux/WSL
   sudo systemd-resolve --flush-caches

   # Windows (PowerShell as Admin)
   ipconfig /flushdns
   ```

#### Issue 2: SSL Certificate Error

**Symptom:** `ERR_CERT_COMMON_NAME_INVALID` in browser

**Solutions:**
1. Wait 2-5 minutes for Vercel to provision certificate
2. Check Vercel dashboard: https://vercel.com/jmotools/jmo-security-subscribe-api/settings/domains
3. Click "Renew Certificate" if stuck

#### Issue 3: 404 Not Found

**Symptom:** Domain resolves but returns 404

**Solutions:**
1. Verify domain is added in Vercel dashboard
2. Check `vercel.json` routes configuration
3. Redeploy: `vercel --prod`

#### Issue 4: Cloudflare Proxy Issues

**Symptom:** SSL errors with Cloudflare orange cloud enabled

**Solutions:**
1. Change Cloudflare DNS record to **DNS only** (gray cloud)
2. Let Vercel handle SSL, not Cloudflare
3. Wait 5 minutes for propagation

---

### Custom Domain Checklist

- [ ] Added domain to Vercel (`vercel domains add api.jmotools.com`)
- [ ] Configured DNS CNAME record in domain provider
- [ ] Verified DNS propagation (`dig api.jmotools.com`)
- [ ] Tested health check (`curl https://api.jmotools.com/api/health`)
- [ ] Tested subscription endpoint
- [ ] Updated subscribe.html form action
- [ ] Updated dashboard form action
- [ ] Committed frontend URL changes
- [ ] Verified HTTPS certificate is active

---

## 🔒 Task 2: CAPTCHA Research & Recommendation

### Should You Implement CAPTCHA Now?

**Short Answer: NO - Honeypot should be sufficient for 95%+ of bot traffic.**

**Reasoning:**
1. Honeypot is invisible to legitimate users (better UX)
2. CAPTCHA adds friction and reduces conversion rates by 10-30%
3. Your API has rate limiting (10 requests/hour per IP)
4. You haven't experienced spam yet (no data to justify it)

**When to implement CAPTCHA:**
- If honeypot catches >50 bots/week consistently
- If you see bot submissions bypassing honeypot
- If Resend flags your domain for spam issues

---

### CAPTCHA Options Comparison

If you do need CAPTCHA in the future, here are the best options:

#### 1. Cloudflare Turnstile (⭐ RECOMMENDED)

**Pros:**
- ✅ **FREE** unlimited requests
- ✅ Privacy-focused (no cookies, no tracking)
- ✅ Invisible challenge for most users
- ✅ GDPR/CCPA compliant out-of-box
- ✅ Fastest implementation (10 minutes)
- ✅ Best user experience (95% invisible)

**Cons:**
- ❌ Requires Cloudflare account
- ❌ Newer service (launched 2022, less battle-tested)

**Implementation Complexity:** 🟢 Easy (10-15 minutes)

**Docs:** https://developers.cloudflare.com/turnstile

**Example Code:**
```html
<!-- Frontend -->
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<div class="cf-turnstile" data-sitekey="YOUR_SITE_KEY"></div>
```

```javascript
// Backend validation
const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    secret: process.env.TURNSTILE_SECRET_KEY,
    response: req.body.cfTurnstileResponse
  })
});
```

---

#### 2. hCaptcha

**Pros:**
- ✅ FREE tier (10,000 requests/month)
- ✅ Privacy-focused (GDPR compliant)
- ✅ Good UX (invisible mode available for low-risk users)
- ✅ Pays publishers (you earn for validated users)
- ✅ Battle-tested (used by Cloudflare, Discord)

**Cons:**
- ❌ 10k/month limit (paid after that)
- ❌ Slightly more visible challenges than Turnstile
- ❌ Requires account signup

**Implementation Complexity:** 🟢 Easy (15 minutes)

**Docs:** https://docs.hcaptcha.com

**Pricing:** FREE up to 10k requests/month, then $0.50 per 1,000

---

#### 3. Google reCAPTCHA v3

**Pros:**
- ✅ Completely invisible (no user interaction)
- ✅ FREE 1 million requests/month
- ✅ Battle-tested (most widely used)
- ✅ Risk score system (0.0 to 1.0)

**Cons:**
- ❌ Google tracking/cookies (privacy concerns)
- ❌ NOT GDPR compliant without consent banner
- ❌ Requires Google account
- ❌ Can flag legitimate users in VPN/privacy-focused browsers

**Implementation Complexity:** 🟡 Medium (20-30 minutes)

**Docs:** https://developers.google.com/recaptcha/docs/v3

**Privacy Issue:** Requires cookie consent in EU/California

---

#### 4. FriendlyCaptcha

**Pros:**
- ✅ Privacy-first (EU-based, GDPR compliant)
- ✅ No user interaction (proof-of-work in browser)
- ✅ No cookies or tracking
- ✅ Good for privacy-conscious users

**Cons:**
- ❌ FREE tier only 1,000 requests/month
- ❌ Paid after 1k ($10/month for 10k)
- ❌ Slower on mobile devices (CPU-intensive)

**Implementation Complexity:** 🟡 Medium (20 minutes)

**Docs:** https://docs.friendlycaptcha.com

**Pricing:** FREE up to 1k/month, then $10/month

---

### CAPTCHA Recommendation Matrix

| Use Case | Recommended Solution | Reasoning |
|----------|---------------------|-----------|
| **Privacy-first** | Cloudflare Turnstile | No tracking, GDPR compliant, free |
| **Budget-conscious** | Cloudflare Turnstile | Unlimited free tier |
| **Best UX** | Cloudflare Turnstile | 95% invisible |
| **Enterprise** | hCaptcha or reCAPTCHA v3 | Battle-tested, proven scale |
| **EU/California** | Cloudflare Turnstile or hCaptcha | GDPR compliant |
| **Already using Cloudflare** | Cloudflare Turnstile | Integrated ecosystem |

---

### Implementation Plan (If Needed)

**Scenario:** Honeypot is insufficient, spam is persistent

**Recommended Approach: Cloudflare Turnstile**

#### Step 1: Sign Up for Turnstile

1. Visit: https://dash.cloudflare.com/sign-up
2. Go to **Turnstile** in left sidebar
3. Click **"Add Site"**
4. Fill in:
   - **Site Name:** JMo Security Email
   - **Domains:** jmotools.com, api.jmotools.com, localhost (for testing)
5. Copy **Site Key** and **Secret Key**

#### Step 2: Add to Frontend

**docs/subscribe.html:**
```html
<!-- Add before closing </body> tag -->
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>

<!-- Add inside form, after email input -->
<div class="cf-turnstile"
     data-sitekey="YOUR_SITE_KEY"
     data-theme="light"
     data-size="normal"></div>
```

**scripts/core/reporters/html_reporter.py:**
Same addition to dashboard form

#### Step 3: Add Server-Side Validation

**scripts/api/subscribe_endpoint.js:**
```javascript
// Add after honeypot check, before email validation

const cfTurnstileResponse = req.body['cf-turnstile-response'];

if (!cfTurnstileResponse) {
  return res.status(400).json({
    success: false,
    error: 'captcha_required',
    message: 'Please complete the CAPTCHA.'
  });
}

// Verify Turnstile response
const turnstileVerify = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    secret: process.env.TURNSTILE_SECRET_KEY,
    response: cfTurnstileResponse
  })
});

const turnstileResult = await turnstileVerify.json();

if (!turnstileResult.success) {
  console.log('Turnstile verification failed:', turnstileResult);
  return res.status(400).json({
    success: false,
    error: 'captcha_failed',
    message: 'CAPTCHA verification failed. Please try again.'
  });
}
```

#### Step 4: Add Environment Variable

```bash
# In Vercel dashboard or CLI
vercel env add TURNSTILE_SECRET_KEY production
# Paste your secret key when prompted
```

#### Step 5: Test and Deploy

```bash
# Test locally first
vercel env pull
vercel dev

# Deploy to production
vercel --prod
```

**Estimated Time:** 20-30 minutes total

---

### CAPTCHA Decision Flowchart

```
Start: Are you receiving bot submissions?
  |
  ├─ NO → Don't implement CAPTCHA yet
  |        ↓
  |        Continue monitoring with honeypot
  |
  └─ YES → How many per week?
           |
           ├─ <10 → Honeypot sufficient
           |         ↓
           |         Monitor for trends
           |
           ├─ 10-50 → Consider implementing
           |          ↓
           |          Use Cloudflare Turnstile (best UX)
           |
           └─ >50 → Implement CAPTCHA immediately
                    ↓
                    Use Cloudflare Turnstile + review rate limits
```

---

## 📊 Monitoring CAPTCHA Effectiveness

If you implement CAPTCHA, track these metrics:

### Key Metrics

| Metric | Calculation | Target |
|--------|-------------|--------|
| **Bot Block Rate** | Bots blocked / Total attempts | >95% |
| **False Positive Rate** | Humans blocked / Total humans | <1% |
| **Conversion Impact** | Subscriptions before/after | <10% drop |
| **Solve Rate** | Successful solves / Total challenges | >90% |

### Weekly Monitoring

```bash
# Check Turnstile dashboard
# https://dash.cloudflare.com/[account]/turnstile

# Key questions:
1. How many challenges served?
2. How many passed vs failed?
3. What's the average solve time?
4. Are legitimate users being blocked?
```

---

## ✅ Summary & Recommendations

### Custom Domain: ✅ RECOMMENDED TO DO NOW

**Reasons:**
- Professional appearance
- Easier to share/remember
- Better for marketing
- Only takes 15 minutes

**Next Steps:**
1. Run `vercel domains add api.jmotools.com`
2. Configure DNS CNAME in your domain provider
3. Wait 5-10 minutes for propagation
4. Test with `curl https://api.jmotools.com/api/health`
5. Update frontend URLs

---

### CAPTCHA: ⏳ WAIT AND MONITOR

**Reasons:**
- No spam data yet to justify it
- Honeypot is working perfectly
- CAPTCHA reduces conversions by 10-30%
- Can implement in <30 minutes if needed

**When to revisit:**
- After 1 month of data collection
- If honeypot catches >50 bots/week
- If Resend bounce rate >5%
- If spam complaints >0.1%

**If needed, implement:** Cloudflare Turnstile (best UX, free, GDPR compliant)

---

## 📚 Resources

### Custom Domain
- Vercel Domains Docs: https://vercel.com/docs/projects/domains
- DNS Propagation Checker: https://dnschecker.org
- Vercel CLI Reference: https://vercel.com/docs/cli

### CAPTCHA
- Cloudflare Turnstile: https://developers.cloudflare.com/turnstile
- hCaptcha: https://docs.hcaptcha.com
- reCAPTCHA v3: https://developers.google.com/recaptcha/docs/v3
- FriendlyCaptcha: https://docs.friendlycaptcha.com

---

**Last Updated:** October 17, 2025
**Next Review:** 30 days (monitor honeypot effectiveness)
