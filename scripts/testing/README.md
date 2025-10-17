# Testing Scripts

Helper scripts for testing JMo Security email collection and newsletter system.

## Scripts

### `test_email_system.sh`

Interactive testing script that walks through all email collection touchpoints.

**Usage:**
```bash
./scripts/testing/test_email_system.sh
```

**Tests:**
1. API health check
2. Subscribe landing page (browser)
3. Dashboard email form (browser)
4. CLI first-run experience

### `serve_subscribe_page.sh`

Starts a local HTTP server to test the subscribe page without CORS issues.

**Usage:**
```bash
./scripts/testing/serve_subscribe_page.sh
```

Opens `http://localhost:8000/subscribe.html` in your browser.

Press `Ctrl+C` to stop the server when done.

### `test_resend_now.sh`

Quick test script for Resend API email sending.

**Usage:**
```bash
export RESEND_API_KEY="your_key_here"
./scripts/testing/test_resend_now.sh
```

Tests direct email sending via Resend API (bypasses Vercel).

## Testing Documentation

For complete testing instructions, see:
- [TESTING_COMMANDS.md](../../TESTING_COMMANDS.md) - WSL-friendly commands
- [DEPLOYMENT_SUMMARY.md](../../DEPLOYMENT_SUMMARY.md) - Full deployment status

## Requirements

- Python 3.6+ (for HTTP server)
- curl (for API testing)
- WSL/Ubuntu environment
- Resend API key (for email tests)
