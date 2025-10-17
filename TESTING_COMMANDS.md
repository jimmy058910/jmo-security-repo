# Email System Testing Commands (WSL-Friendly)

Quick reference for testing the email system in WSL Ubuntu.

---

## 🚀 Quick Start: Run All Tests

```bash
cd /home/jimmy058910/jmo-security-repo
./scripts/testing/test_email_system.sh
```

This interactive script walks you through all 4 tests with prompts.

---

## 📋 Individual Test Commands

### Test 1: API Health Check

```bash
curl -s "https://jmo-security-subscribe-d1h77tlh1-james-moceris-projects.vercel.app/api/health" | python3 -m json.tool
```

**Expected Output:**
```json
{
    "status": "ok",
    "service": "jmo-security-subscribe-api",
    "version": "1.0.0",
    "timestamp": "2025-10-17T..."
}
```

---

### Test 2: Subscribe Landing Page (Browser Test)

**Option A: Use wslview (recommended)**
```bash
wslview /home/jimmy058910/jmo-security-repo/docs/subscribe.html
```

**Option B: Use Windows explorer**
```bash
explorer.exe "$(wslpath -w /home/jimmy058910/jmo-security-repo/docs/subscribe.html)"
```

**Option C: Get Windows path and open manually**
```bash
wslpath -w /home/jimmy058910/jmo-security-repo/docs/subscribe.html
# Copy output and paste into Windows browser
```

**Manual Steps:**
1. Enter your email in the form
2. Click "Subscribe - It's Free"
3. Verify success message appears
4. Check inbox for email from `hello@jmotools.com`

---

### Test 3: Dashboard Form (Browser Test)

**Generate dashboard first (if needed):**
```bash
cd /home/jimmy058910/jmo-security-repo

# Option 1: If you have existing results
jmo report ./results

# Option 2: Run a quick scan first
jmo scan --repo . --profile fast --results-dir ./results
jmo report ./results
```

**Open dashboard:**
```bash
# Option A: wslview
wslview results/summaries/dashboard.html

# Option B: Windows explorer
explorer.exe "$(wslpath -w results/summaries/dashboard.html)"

# Option C: Get Windows path
wslpath -w results/summaries/dashboard.html
```

**Manual Steps:**
1. Scroll down to purple "Stay Ahead of Security Threats" section
2. Enter your email
3. Click "Subscribe Free"
4. Verify success message

---

### Test 4: CLI First-Run Experience

**Backup your config (if you want to keep it):**
```bash
[ -f ~/.jmo/config.yml ] && cp ~/.jmo/config.yml ~/.jmo/config.yml.bak
```

**Reset config to simulate first run:**
```bash
rm -f ~/.jmo/config.yml
```

**Run a scan (will trigger welcome prompt):**
```bash
cd /home/jimmy058910/jmo-security-repo

# If 'jmo' command is installed
jmo scan --repo . --profile fast --results-dir /tmp/test-results --human-logs

# OR if not installed, use direct Python
python3 scripts/cli/jmo.py scan --repo . --profile fast --results-dir /tmp/test-results --human-logs
```

**Expected Output:**
```
🎉 Welcome to JMo Security!

📧 Get notified about new features, updates, and security tips?
   (We'll never spam you. Unsubscribe anytime.)

   Enter email (or press Enter to skip):
```

**Verify config was saved:**
```bash
cat ~/.jmo/config.yml
```

**Expected Contents:**
```yaml
onboarding_completed: true
email: your@email.com  # If you entered one
scan_count: 1
```

**Restore backup (if you made one):**
```bash
[ -f ~/.jmo/config.yml.bak ] && mv ~/.jmo/config.yml.bak ~/.jmo/config.yml
```

---

## 🧪 Bonus: API Direct Test

Test the API subscription endpoint directly:

```bash
curl -X POST "https://jmo-security-subscribe-d1h77tlh1-james-moceris-projects.vercel.app/api/subscribe" \
  -H "Content-Type: application/json" \
  -d '{"email":"YOUR_EMAIL@example.com","source":"test"}' \
  -s | python3 -m json.tool
```

**Replace `YOUR_EMAIL@example.com` with your real email!**

**Expected Output:**
```json
{
    "success": true,
    "message": "✅ Thanks! Check your inbox for a welcome email.",
    "email_id": "re_..."
}
```

---

## 📊 Check Results

### Resend Dashboard (Email Delivery)
```bash
# Open in Windows browser
explorer.exe "https://resend.com/emails"
```

### Vercel Logs (API Activity)
```bash
explorer.exe "https://vercel.com/james-moceris-projects/jmo-security-subscribe-api/logs"
```

### Local Config File
```bash
cat ~/.jmo/config.yml
```

---

## 🔧 Troubleshooting

### "wslview: command not found"

Install wslu package:
```bash
sudo apt update
sudo apt install wslu
```

### "jmo: command not found"

Install JMo Security:
```bash
cd /home/jimmy058910/jmo-security-repo
pip install -e .
```

Or use direct Python:
```bash
python3 scripts/cli/jmo.py <command>
```

### Browser doesn't open

Manually get the Windows path:
```bash
wslpath -w /home/jimmy058910/jmo-security-repo/docs/subscribe.html
```

Copy the output (e.g., `C:\Users\...\docs\subscribe.html`) and paste into Windows browser.

### Email not received

1. **Check spam folder**
2. **Check Resend dashboard:** https://resend.com/emails
3. **Verify domain:** https://resend.com/domains
4. **Wait 2-3 minutes** - sometimes there's a delay

### Rate limit error

If you get "Too many requests":
- Wait 1 hour (limit is 10 requests/hour per IP)
- This is expected after testing multiple times

---

## ✅ Success Checklist

After testing, you should have:

- [ ] API health check returns `"status": "ok"`
- [ ] Subscribe page form submits successfully
- [ ] Dashboard form submits successfully
- [ ] CLI shows welcome prompt on first run
- [ ] Email received in inbox from `hello@jmotools.com`
- [ ] Config file created at `~/.jmo/config.yml`
- [ ] No errors in Vercel logs

---

## 🎉 All Tests Passed?

Congratulations! Your email collection system is fully functional and ready to start gathering subscribers!

**Next steps:**
- Update external platforms (Docker Hub, PyPI) with newsletter CTA
- Set up monitoring alerts
- Create welcome email sequence
- Start newsletter content calendar

