# Monitoring Setup Guide

**Purpose:** Configure error notifications and bounce rate monitoring for the JMo Security email system.

**Date:** October 17, 2025

---

## 🚨 Vercel Error Notifications

### What Gets Monitored

Vercel automatically sends email notifications for:
- **Deployment Failures** - When builds fail
- **Error Anomalies** - When 5XX errors exceed thresholds
- **Function Failures** - When serverless functions crash

### Configuration Steps

1. **Access Notification Settings:**
   - Visit: https://vercel.com/account
   - Navigate to **Settings → My Notifications**
   - Or direct link: https://vercel.com/[your-username]/settings/notifications

2. **Enable Email Notifications:**
   - Toggle **Email** ON for these alert types:
     - ✅ Deployment Failures
     - ✅ Error Anomalies (requires Pro/Enterprise with Observability Plus)
     - ✅ Function Errors
   - Toggle **Web** ON for dashboard popover alerts

3. **Verify Email:**
   - Ensure your Vercel account email is correct: https://vercel.com/account
   - Check spam folder for initial test notifications

### Default Behavior

By default, Vercel sends **both web and email** notifications for all critical alerts. You should already be receiving:
- Email when deployments fail
- Email when function invocations fail
- Dashboard notifications for all alert types

### Additional Monitoring (Optional)

For more granular control, consider third-party services:
- **Logalert** (https://www.logalert.app/) - Email alerts for user-facing errors
- **Sentry** - Error tracking with stack traces
- **Better Uptime** - Uptime monitoring with incident alerts

---

## 📧 Resend Bounce Rate Monitoring

### What Gets Monitored

Monitor email delivery health:
- **Bounce Rate** - Emails rejected by recipient servers (target: <5%)
- **Complaint Rate** - Users marking emails as spam (target: <0.1%)
- **Delivery Rate** - Successfully delivered emails (target: >95%)

### Configuration Steps

#### 1. Access Resend Dashboard

Visit: https://resend.com/emails

#### 2. Monitor Key Metrics

Navigate to **Analytics** tab:
- **Delivered** - Successful deliveries
- **Bounced** - Hard bounces (invalid emails) + Soft bounces (temporary failures)
- **Complained** - Spam complaints
- **Opened** - Email opens (optional tracking)

#### 3. Set Up Email Alerts (Manual Check)

Resend does not have built-in alert thresholds, so **manually check weekly**:

**Weekly Checklist (Every Monday):**
```bash
# Check Resend dashboard for last 7 days:
# 1. Bounce rate: Should be <5%
# 2. Complaint rate: Should be <0.1%
# 3. Delivery rate: Should be >95%
```

#### 4. Calculate Bounce Rate

Formula:
```
Bounce Rate = (Bounced / Sent) × 100
```

Example:
- Sent: 1,000 emails
- Bounced: 30 emails
- Bounce Rate: (30 / 1,000) × 100 = 3% ✅ GOOD

**Thresholds:**
- ✅ **<5%** - Excellent (industry standard)
- ⚠️ **5-10%** - Warning (clean email list)
- ❌ **>10%** - Critical (risk of domain reputation damage)

#### 5. Handle Bounces

**Hard Bounces (Permanent Failures):**
- Invalid email addresses
- Non-existent domains
- **Action:** Remove from subscriber list immediately

**Soft Bounces (Temporary Failures):**
- Mailbox full
- Server temporarily unavailable
- **Action:** Retry up to 3 times, then remove

#### 6. Monitor Spam Complaints

If complaint rate >0.1%:
1. Review recent email content
2. Ensure unsubscribe link is prominent
3. Check that users opted in (double opt-in recommended)
4. Verify email frequency isn't too high

---

## 📊 Recommended Monitoring Schedule

### Daily (Automated)
- ✅ Vercel email alerts (automatic)
- ✅ Resend delivery status (check for anomalies)

### Weekly (Manual - Every Monday)
- [ ] Check Resend bounce rate (<5%)
- [ ] Check Resend complaint rate (<0.1%)
- [ ] Review Vercel function logs for errors
- [ ] Verify API health check: https://jmo-security-subscribe-7o52zyplw-jmotools.vercel.app/api/health

### Monthly (Manual - First Monday)
- [ ] Review total subscriber growth
- [ ] Calculate email open rate (if tracking enabled)
- [ ] Review unsubscribe rate (<5% ideal)
- [ ] Clean bounced emails from list

---

## 🔧 Troubleshooting

### High Bounce Rate (>5%)

**Possible Causes:**
1. Users entering fake emails (e.g., test@test.com)
2. Old/inactive email addresses
3. Typos in email addresses

**Solutions:**
1. Implement email verification (double opt-in)
2. Use email validation library (e.g., `email-validator`)
3. Check for common typo patterns (gmial.com → gmail.com)

### High Complaint Rate (>0.1%)

**Possible Causes:**
1. Users didn't explicitly opt in
2. Email frequency too high
3. Content doesn't match expectations

**Solutions:**
1. Add GDPR-compliant consent checkbox
2. Reduce email frequency
3. Make unsubscribe link more prominent
4. Include reminder: "You subscribed via [source]"

### Vercel Alerts Not Received

**Checklist:**
1. Check spam folder
2. Verify email address in Vercel account settings
3. Ensure notifications are enabled: https://vercel.com/account/notifications
4. Test with intentional error: `throw new Error("test alert")`

---

## 📈 Success Metrics Dashboard

Create a simple tracking spreadsheet:

| Metric | Target | Current | Status |
|--------|--------|---------|--------|
| Bounce Rate | <5% | TBD | ⏳ |
| Complaint Rate | <0.1% | TBD | ⏳ |
| Delivery Rate | >95% | TBD | ⏳ |
| Subscriber Growth | +50/week | TBD | ⏳ |
| Unsubscribe Rate | <5% | TBD | ⏳ |

---

## 🚀 Quick Links

### Vercel
- Notifications Settings: https://vercel.com/account/notifications
- Project Logs: https://vercel.com/jmotools/jmo-security-subscribe-api/logs
- Project Settings: https://vercel.com/jmotools/jmo-security-subscribe-api/settings

### Resend
- Dashboard: https://resend.com/emails
- Analytics: https://resend.com/emails?tab=analytics
- Domain Settings: https://resend.com/domains
- API Keys: https://resend.com/api-keys

### Testing
- Health Check: https://jmo-security-subscribe-7o52zyplw-jmotools.vercel.app/api/health
- Subscribe Test: `curl -X POST [API_URL]/api/subscribe -H "Content-Type: application/json" -d '{"email":"test@example.com","source":"test"}'`

---

## ✅ Checklist: Initial Setup

Complete this checklist to finish monitoring setup:

- [ ] Verified Vercel email notifications are enabled
- [ ] Bookmarked Resend analytics dashboard
- [ ] Set calendar reminder for weekly bounce rate checks (Mondays at 9 AM)
- [ ] Created metrics tracking spreadsheet
- [ ] Tested health check endpoint
- [ ] Documented baseline metrics (first week)

---

**Last Updated:** October 17, 2025
**Next Review:** October 24, 2025 (weekly check)
