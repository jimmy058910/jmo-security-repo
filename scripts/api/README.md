# JMo Security - Email Subscription API

**Simple API endpoint for email newsletter subscriptions**

This API endpoint powers email collection for the JMo Security newsletter across multiple touch points (CLI, Dashboard, Subscribe page, etc.).

---

## Features

- ✅ **Email validation** (format + optional DNS check)
- ✅ **Rate limiting** (10 requests/hour per IP)
- ✅ **CORS configuration** for GitHub Pages
- ✅ **Resend API integration** with welcome emails
- ✅ **Source tracking** (CLI, dashboard, website, subscribe_page)
- ✅ **Health check endpoint**
- ✅ **Zero-downtime deployments** (serverless)

---

## Quick Deploy (Vercel - Recommended)

**Prerequisites:**

- Vercel account (free): https://vercel.com/signup
- Resend API key: https://resend.com/api-keys

**Steps:**

```bash
# 1. Install Vercel CLI
npm install -g vercel

# 2. Navigate to API directory
cd scripts/api

# 3. Install dependencies
npm install

# 4. Deploy to Vercel
vercel

# Follow prompts:
# - Set up and deploy? Yes
# - Which scope? (Your Vercel account)
# - Link to existing project? No
# - Project name? jmo-security-subscribe-api
# - Directory? ./
# - Want to override settings? No

# 5. Add Resend API key as environment variable
vercel env add RESEND_API_KEY
# Paste your Resend API key: re_...
# Select environment: Production
```

**Your API will be live at:**

`https://jmo-security-subscribe-api.vercel.app/api/subscribe`

---

## Alternative Deployments

### Netlify Functions

```bash
# 1. Install Netlify CLI
npm install -g netlify-cli

# 2. Create netlify.toml
cat > netlify.toml <<EOF
[build]
  functions = "."

[[redirects]]
  from = "/api/*"
  to = "/.netlify/functions/:splat"
  status = 200
EOF

# 3. Deploy
netlify deploy --prod

# 4. Set environment variable
netlify env:set RESEND_API_KEY re_your_key_here
```

### AWS Lambda (via Serverless Framework)

```bash
# 1. Install Serverless
npm install -g serverless

# 2. Create serverless.yml
cat > serverless.yml <<EOF
service: jmo-subscribe-api

provider:
  name: aws
  runtime: nodejs18.x
  environment:
    RESEND_API_KEY: \${env:RESEND_API_KEY}

functions:
  api:
    handler: subscribe_endpoint.handler
    events:
      - http:
          path: /api/{proxy+}
          method: ANY
          cors: true
EOF

# 3. Deploy
serverless deploy
```

### Docker Deployment

```bash
# 1. Create Dockerfile
cat > Dockerfile <<EOF
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY subscribe_endpoint.js ./
EXPOSE 3000
CMD ["node", "subscribe_endpoint.js"]
EOF

# 2. Build image
docker build -t jmo-subscribe-api .

# 3. Run container
docker run -d -p 3000:3000 \
  -e RESEND_API_KEY=re_your_key_here \
  --name jmo-subscribe-api \
  jmo-subscribe-api
```

---

## Local Testing

```bash
# 1. Install dependencies
npm install

# 2. Set environment variable
export RESEND_API_KEY="re_your_key_here"

# 3. Start server
npm start

# Server runs on http://localhost:3000
```

**Test subscription:**

```bash
# Using curl
curl -X POST http://localhost:3000/api/subscribe \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","source":"test"}'

# Using HTTPie
http POST localhost:3000/api/subscribe email=test@example.com source=test

# Expected response:
# {
#   "success": true,
#   "message": "✅ Thanks! Check your inbox for a welcome email.",
#   "email_id": "re_abc123xyz..."
# }
```

**Test health check:**

```bash
curl http://localhost:3000/api/health

# Expected:
# {
#   "status": "ok",
#   "service": "jmo-security-subscribe-api",
#   "version": "1.0.0",
#   "timestamp": "2025-10-16T..."
# }
```

---

## API Reference

### POST /api/subscribe

Subscribe an email to the newsletter.

**Request Body:**

```json
{
  "email": "user@example.com",
  "source": "cli|dashboard|website|subscribe_page|github_readme"
}
```

**Success Response (200):**

```json
{
  "success": true,
  "message": "✅ Thanks! Check your inbox for a welcome email.",
  "email_id": "re_abc123xyz..."
}
```

**Error Responses:**

```json
// 400 - Invalid email
{
  "success": false,
  "error": "invalid_email",
  "message": "Please provide a valid email address."
}

// 429 - Rate limit exceeded
{
  "success": false,
  "error": "rate_limit_exceeded",
  "message": "Too many subscription requests. Please try again in an hour."
}

// 500 - Server error
{
  "success": false,
  "error": "server_error",
  "message": "Failed to process subscription. Please try again later."
}
```

### GET /api/health

Health check endpoint for monitoring.

**Success Response (200):**

```json
{
  "status": "ok",
  "service": "jmo-security-subscribe-api",
  "version": "1.0.0",
  "timestamp": "2025-10-16T12:34:56.789Z"
}
```

---

## Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `RESEND_API_KEY` | Yes | Resend API key for sending emails | `re_abc123...` |
| `PORT` | No | Port for local server (default: 3000) | `8080` |

---

## Rate Limiting

- **Limit:** 10 requests per hour per IP address
- **Window:** 1 hour (60 minutes)
- **Headers:**
  - `RateLimit-Limit`: Maximum requests allowed
  - `RateLimit-Remaining`: Requests remaining
  - `RateLimit-Reset`: Unix timestamp when limit resets

**Example:**

```bash
curl -i http://localhost:3000/api/subscribe ...

# Response headers:
# RateLimit-Limit: 10
# RateLimit-Remaining: 9
# RateLimit-Reset: 1697468400
```

---

## CORS Configuration

**Allowed Origins:**

- `https://jimmy058910.github.io` (GitHub Pages)
- `https://jmotools.com` (Main website)
- `http://localhost:3000` (Local testing)
- `http://localhost:8000` (Alternative local port)

**Allowed Methods:**

- `POST` (Subscribe endpoint)
- `OPTIONS` (Preflight requests)

---

## Monitoring & Observability

### Vercel (Built-in)

- **Logs:** https://vercel.com/dashboard/logs
- **Analytics:** https://vercel.com/dashboard/analytics
- **Errors:** Automatic error tracking

### Custom Monitoring (Optional)

Add monitoring with Sentry, Datadog, or New Relic:

```javascript
// At the top of subscribe_endpoint.js
const Sentry = require('@sentry/node');
Sentry.init({ dsn: process.env.SENTRY_DSN });

// Add error handler
app.use(Sentry.Handlers.errorHandler());
```

---

## Security Considerations

1. **API Key Protection**
   - Never commit `RESEND_API_KEY` to Git
   - Use environment variables in production
   - Rotate keys quarterly

2. **Rate Limiting**
   - Prevents abuse and spam
   - Adjust limits based on legitimate traffic

3. **Email Validation**
   - Format validation prevents typos
   - Optional DNS check (not implemented) for extra verification

4. **CORS**
   - Restricts API calls to trusted origins
   - Prevents unauthorized cross-origin requests

5. **Input Sanitization**
   - All inputs validated before processing
   - Prevents injection attacks

---

## Troubleshooting

### "RESEND_API_KEY not configured"

**Fix:**

```bash
# Local
export RESEND_API_KEY="re_your_key_here"

# Vercel
vercel env add RESEND_API_KEY

# Netlify
netlify env:set RESEND_API_KEY re_your_key_here
```

### "Email sent successfully but no email received"

**Check:**

1. Spam folder
2. Resend dashboard: https://resend.com/emails
3. Domain verification: https://resend.com/domains
4. FROM email matches verified domain (`hello@jmotools.com`)

### Rate limit errors in production

**Solutions:**

1. Increase limit in `subscribe_endpoint.js`:
   ```javascript
   max: 20, // Increase from 10 to 20
   ```

2. Use Redis for distributed rate limiting (multi-instance deployments)

### CORS errors from GitHub Pages

**Verify:**

1. GitHub Pages URL in CORS origins list
2. HTTPS used (not HTTP)
3. Correct API endpoint URL in frontend code

---

## Updating the API

### Frontend Integration

Update all frontend forms to use your deployed API URL:

**Dashboard Form** (`scripts/core/reporters/html_reporter.py`):

```html
<form action="https://jmo-security-subscribe-api.vercel.app/api/subscribe" method="post">
```

**Subscribe Page** (`docs/subscribe.html`):

```javascript
const response = await fetch('https://jmo-security-subscribe-api.vercel.app/api/subscribe', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, source: 'subscribe_page' })
});
```

---

## Performance

**Expected Response Times:**

- Health check: <50ms
- Subscription (with email send): 200-500ms
- Rate limit check: <10ms

**Capacity:**

- Vercel Free: 100,000 requests/month
- Vercel Pro: 1,000,000 requests/month

**Scaling:**

- Serverless functions scale automatically
- No manual intervention needed for traffic spikes

---

## Support

- **Issues:** https://github.com/jimmy058910/jmo-security-repo/issues
- **Email:** general@jmogaming.com
- **Resend Support:** https://resend.com/support

---

**Last Updated:** October 16, 2025
**Version:** 1.0.0
