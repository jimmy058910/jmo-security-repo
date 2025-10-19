"""Email collection and welcome sequence for JMo Security.

This module handles email collection via Resend API for:
1. CLI first-run onboarding
2. Dashboard HTML form submissions
3. Website/GitHub Pages subscriptions

Privacy-first approach:
- Opt-in only (never mandatory)
- Clear unsubscribe links
- No tracking pixels
- GDPR-compliant via Resend

Environment Variables:
    RESEND_API_KEY: Your Resend API key (get from https://resend.com/api-keys)
    JMO_FROM_EMAIL: Sender email (default: onboarding@resend.dev)

Note:
    In testing mode (unverified domain), Resend only allows sending to the email
    address registered with your account. To send to any email:
    1. Verify your domain at https://resend.com/domains
    2. Set JMO_FROM_EMAIL to use your verified domain

    For production, you must verify jmotools.com or use a verified domain.

Example:
    >>> from scripts.core.email_service import send_welcome_email
    >>> send_welcome_email("user@example.com", source="cli")
    True
"""

import os
import sys
from typing import Optional, Literal

# Check if resend is available
try:
    import resend

    RESEND_AVAILABLE = True
except ImportError:
    RESEND_AVAILABLE = False

# Configuration
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
# Use verified jmotools.com domain (verified on 2025-10-16)
# Override with JMO_FROM_EMAIL env var if needed
FROM_EMAIL = os.getenv("JMO_FROM_EMAIL", "hello@jmotools.com")

# Email templates
WELCOME_EMAIL_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
            line-height: 1.6;
            color: #1a202c;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        h1 {
            color: #2d3748;
            font-size: 24px;
            margin-bottom: 20px;
        }
        h2 {
            color: #4a5568;
            font-size: 18px;
            margin-top: 24px;
            margin-bottom: 12px;
        }
        code {
            background: #f7fafc;
            border: 1px solid #e2e8f0;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 14px;
        }
        .cta {
            background: #10b981;
            color: white;
            padding: 12px 24px;
            text-decoration: none;
            border-radius: 6px;
            display: inline-block;
            margin: 20px 0;
            font-weight: 600;
        }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e2e8f0;
            font-size: 14px;
            color: #718096;
        }
        ul {
            margin: 12px 0;
        }
        li {
            margin-bottom: 8px;
        }
    </style>
</head>
<body>
    <h1>🎉 Welcome to JMo Security!</h1>

    <p>Thanks for joining! You're now part of a community securing thousands of repositories with unified security scanning.</p>

    <h2>Quick Start Guide</h2>
    <ul>
        <li>Run your first scan: <code>jmo scan --repo . --profile fast</code></li>
        <li>View interactive results: <code>open results/summaries/dashboard.html</code></li>
        <li>Get help anytime: <code>jmo --help</code></li>
    </ul>

    <h2>Three Scanning Profiles</h2>
    <ul>
        <li><strong>Fast</strong> (5-8 min): Pre-commit checks, quick validation</li>
        <li><strong>Balanced</strong> (15-20 min): CI/CD pipelines, production scans</li>
        <li><strong>Deep</strong> (30-60 min): Security audits, compliance scans</li>
    </ul>

    <h2>What's Next?</h2>
    <ul>
        <li>📖 <a href="https://github.com/jimmy058910/jmo-security-repo#readme">Read the full documentation</a></li>
        <li>🐳 <a href="https://github.com/jimmy058910/jmo-security-repo/blob/main/docs/DOCKER_README.md">Try Docker mode (zero installation)</a></li>
        <li>🧙 <a href="https://github.com/jimmy058910/jmo-security-repo/blob/main/docs/examples/wizard-examples.md">Use the interactive wizard</a></li>
        <li>💬 <a href="https://github.com/jimmy058910/jmo-security-repo/discussions">Join community discussions</a></li>
    </ul>

    <a href="https://ko-fi.com/jmogaming" class="cta">💚 Support Full-Time Development</a>

    <div class="footer">
        <p><strong>What you'll receive:</strong></p>
        <ul>
            <li>🚀 New feature announcements (monthly)</li>
            <li>🔒 Security tips and best practices (weekly)</li>
            <li>💡 Real-world security audit case studies</li>
            <li>🎁 Exclusive guides and cheat sheets</li>
        </ul>

        <p style="margin-top: 20px;">
            We'll never spam you. Unsubscribe anytime.<br>
            Questions? Reply to this email or <a href="https://github.com/jimmy058910/jmo-security-repo/issues">open an issue</a>.
        </p>
    </div>
</body>
</html>
"""

WELCOME_EMAIL_TEXT = """
🎉 Welcome to JMo Security!

Thanks for joining! You're now part of a community securing thousands of repositories with unified security scanning.

Quick Start Guide
-----------------
- Run your first scan: jmo scan --repo . --profile fast
- View interactive results: open results/summaries/dashboard.html
- Get help anytime: jmo --help

Three Scanning Profiles
-----------------------
- Fast (5-8 min): Pre-commit checks, quick validation
- Balanced (15-20 min): CI/CD pipelines, production scans
- Deep (30-60 min): Security audits, compliance scans

What's Next?
------------
📖 Read the docs: https://github.com/jimmy058910/jmo-security-repo#readme
🐳 Try Docker mode: https://github.com/jimmy058910/jmo-security-repo/blob/main/docs/DOCKER_README.md
🧙 Use the wizard: https://github.com/jimmy058910/jmo-security-repo/blob/main/docs/examples/wizard-examples.md
💬 Join discussions: https://github.com/jimmy058910/jmo-security-repo/discussions

💚 Support full-time development: https://ko-fi.com/jmogaming

---

What you'll receive:
🚀 New feature announcements (monthly)
🔒 Security tips and best practices (weekly)
💡 Real-world security audit case studies
🎁 Exclusive guides and cheat sheets

We'll never spam you. Unsubscribe anytime.
Questions? Reply to this email or open an issue on GitHub.
"""


def send_welcome_email(
    email: str, source: Literal["cli", "dashboard", "website"] = "cli"
) -> bool:
    """Send welcome email to new subscriber.

    Args:
        email: Subscriber email address
        source: Where the signup came from (for analytics)

    Returns:
        True if email sent successfully, False otherwise

    Note:
        Fails silently if RESEND_API_KEY not configured or resend not installed.
        This ensures email collection never blocks the CLI workflow.
    """
    # Fail silently if not configured
    if not RESEND_AVAILABLE:
        return False

    if not RESEND_API_KEY:
        return False

    # Configure Resend
    resend.api_key = RESEND_API_KEY

    try:
        # Send email via Resend API
        # NOTE: Resend's Python SDK expects a dictionary, not keyword arguments
        params = {
            "from": f"JMo Security <{FROM_EMAIL}>",
            "to": [email],
            "subject": "Welcome to JMo Security! 🎉",
            "html": WELCOME_EMAIL_HTML,
            "text": WELCOME_EMAIL_TEXT,
            "tags": [
                {"name": "source", "value": source},
                {"name": "type", "value": "welcome"},
            ],
        }

        response = resend.Emails.send(params)

        # Resend returns a dict with 'id' on success
        return bool(
            response
            and (
                isinstance(response, dict)
                and "id" in response
                or hasattr(response, "id")
            )
        )

    except Exception as e:
        # Fail silently - don't block CLI workflow
        # In production, you might want to log this to a file
        # Always print error in test mode for debugging
        print(f"[ERROR] Email send failed: {e}", file=sys.stderr)
        import traceback

        traceback.print_exc()
        return False


def validate_email(email: str) -> bool:
    """Basic email validation.

    Args:
        email: Email address to validate

    Returns:
        True if email looks valid, False otherwise
    """
    if not email or "@" not in email:
        return False

    parts = email.split("@")
    if len(parts) != 2:
        return False

    username, domain = parts
    if not username or not domain:
        return False

    if "." not in domain:
        return False

    return True


def get_subscriber_count() -> Optional[int]:
    """Get current subscriber count from Resend.

    Returns:
        Number of subscribers, or None if unavailable

    Note:
        This is a placeholder. Resend doesn't have a direct API for this yet.
        You may need to track this separately or use Resend's dashboard.
    """
    # TODO: Implement when Resend adds audiences API
    # For now, return None and track manually
    return None


if __name__ == "__main__":
    # Test the email service
    import sys

    if len(sys.argv) < 2:
        print("Usage: python scripts/core/email_service.py <test_email>")
        print("\nMake sure to set RESEND_API_KEY environment variable first:")
        print("  export RESEND_API_KEY='re_...'")
        sys.exit(1)

    test_email = sys.argv[1]

    if not RESEND_API_KEY:
        print("❌ Error: RESEND_API_KEY environment variable not set")
        print("\nGet your API key from: https://resend.com/api-keys")
        print("Then run: export RESEND_API_KEY='re_...'")
        sys.exit(1)

    if not RESEND_AVAILABLE:
        print("❌ Error: resend package not installed")
        print("\nInstall with: pip install resend")
        sys.exit(1)

    print(f"Sending test welcome email to: {test_email}")
    success = send_welcome_email(test_email, source="cli")

    if success:
        print("✅ Email sent successfully!")
        print("\nCheck your inbox (and spam folder)")
    else:
        print("❌ Failed to send email")
        print("\nCheck:")
        print("  1. RESEND_API_KEY is valid")
        print("  2. FROM_EMAIL domain is verified in Resend")
        print("  3. Email address is valid")
