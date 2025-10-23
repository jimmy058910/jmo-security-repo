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
    resend = None  # type: ignore  # Set to None for test mocking
    RESEND_AVAILABLE = False

# Configuration
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
# Use verified jmotools.com domain (verified on 2025-10-16)
# Override with JMO_FROM_EMAIL env var if needed
FROM_EMAIL = os.getenv("JMO_FROM_EMAIL", "marketing@jmotools.com")

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
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 12px;
            text-align: center;
            margin-bottom: 30px;
        }
        h1 {
            margin: 0;
            font-size: 32px;
        }
        .tagline {
            margin: 15px 0 0 0;
            font-size: 18px;
            opacity: 0.95;
        }
        h2 {
            color: #667eea;
            font-size: 20px;
            margin-top: 30px;
            margin-bottom: 12px;
        }
        .value-prop {
            background: #f7fafc;
            border-left: 4px solid #667eea;
            padding: 20px;
            margin: 20px 0;
            border-radius: 6px;
        }
        .value-prop p {
            margin: 0 0 15px 0;
            font-size: 16px;
            line-height: 1.7;
        }
        .benefits {
            list-style: none;
            padding: 0;
            margin: 15px 0;
        }
        .benefits li {
            padding-left: 1.5em;
            margin-bottom: 10px;
            position: relative;
        }
        .benefits li::before {
            content: '✅';
            position: absolute;
            left: 0;
        }
        .quick-start {
            background: #f7fafc;
            border-left: 4px solid #10b981;
            padding: 15px;
            margin: 15px 0;
            border-radius: 6px;
        }
        .quick-start strong {
            color: #10b981;
        }
        code {
            background: #2d3748;
            color: #e2e8f0;
            padding: 3px 8px;
            border-radius: 4px;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 13px;
        }
        .cta {
            background: #10b981;
            color: white;
            padding: 14px 28px;
            text-decoration: none;
            border-radius: 8px;
            display: inline-block;
            margin: 20px 0;
            font-weight: 600;
            font-size: 16px;
        }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e2e8f0;
            font-size: 14px;
            color: #718096;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🎉 Welcome to JMo Security!</h1>
        <p class="tagline">Unified security scanning for code, containers, cloud, and web</p>
    </div>

    <p>Thanks for joining!</p>

    <div class="value-prop">
        <p><strong>JMo Security finds vulnerabilities in code, containers, cloud configs, and live websites—all in one command. No security expertise required.</strong></p>
        <ul class="benefits">
            <li><strong>Zero installation:</strong> Scan in 60 seconds with Docker (or install locally)</li>
            <li><strong>For everyone:</strong> Interactive wizard guides beginners; CLI power for pros</li>
            <li><strong>Always current:</strong> Auto-updated security tools (11+ scanners, weekly checks)</li>
            <li><strong>Compliance ready:</strong> Auto-tags findings with OWASP, CWE, NIST, PCI DSS, CIS, MITRE ATT&CK</li>
            <li><strong>Actionable results:</strong> Interactive HTML dashboard with copy-paste fixes, not 100-page PDFs</li>
        </ul>
        <p style="margin-bottom: 0;">Replace 11 separate security tools with one unified scanner that catches hardcoded secrets, vulnerable dependencies, cloud misconfigurations, and web security flaws—then exports compliance-ready reports for audits.</p>
    </div>

    <h2>🚀 Quick Start (Choose Your Path)</h2>

    <div class="quick-start">
        <strong>Complete beginner?</strong><br>
        Run <code>jmotools wizard</code> for 5-minute guided setup<br>
        <a href="https://github.com/jimmy058910/jmo-security-repo/blob/main/docs/examples/wizard-examples.md">📖 Wizard Documentation</a>
    </div>

    <div class="quick-start">
        <strong>Docker user?</strong><br>
        Pull image, scan in 60 seconds (Windows-friendly)<br>
        <a href="https://github.com/jimmy058910/jmo-security-repo/blob/main/docs/DOCKER_README.md">📖 Docker Guide</a>
    </div>

    <div class="quick-start">
        <strong>Security pro?</strong><br>
        Install CLI, customize profiles, automate in CI/CD<br>
        <a href="https://github.com/jimmy058910/jmo-security-repo#readme">📖 Full Documentation</a>
    </div>

    <h2>📚 Additional Resources</h2>
    <ul>
        <li>💬 <a href="https://github.com/jimmy058910/jmo-security-repo/discussions">Join community discussions</a></li>
        <li>🐛 <a href="https://github.com/jimmy058910/jmo-security-repo/issues">Report issues or request features</a></li>
        <li>⭐ <a href="https://github.com/jimmy058910/jmo-security-repo">Star on GitHub</a> to help others discover JMo Security</li>
    </ul>

    <div style="text-align: center;">
        <a href="https://ko-fi.com/jmogaming" class="cta">💚 Support Full-Time Development</a>
    </div>

    <div class="footer">
        <p><strong>What you'll receive:</strong></p>
        <ul>
            <li>🚀 New feature announcements</li>
            <li>🔒 Security tips and best practices</li>
            <li>💡 Case studies & exclusive guides - Learn from actual security audits with deep-dives not available elsewhere</li>
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
Unified security scanning for code, containers, cloud, and web

Thanks for joining!

What is JMo Security?
---------------------
JMo Security finds vulnerabilities in code, containers, cloud configs, and live websites—all in one command. No security expertise required.

✅ Zero installation: Scan in 60 seconds with Docker (or install locally)
✅ For everyone: Interactive wizard guides beginners; CLI power for pros
✅ Always current: Auto-updated security tools (11+ scanners, weekly checks)
✅ Compliance ready: Auto-tags findings with OWASP, CWE, NIST, PCI DSS, CIS, MITRE ATT&CK
✅ Actionable results: Interactive HTML dashboard with copy-paste fixes, not 100-page PDFs

Replace 11 separate security tools with one unified scanner that catches hardcoded secrets, vulnerable dependencies, cloud misconfigurations, and web security flaws—then exports compliance-ready reports for audits.

Quick Start (Choose Your Path)
-------------------------------
Complete beginner?
  → Run: jmotools wizard (5-minute guided setup)
  → Docs: https://github.com/jimmy058910/jmo-security-repo/blob/main/docs/examples/wizard-examples.md

Docker user?
  → Pull image, scan in 60 seconds (Windows-friendly)
  → Docs: https://github.com/jimmy058910/jmo-security-repo/blob/main/docs/DOCKER_README.md

Security pro?
  → Install CLI, customize profiles, automate in CI/CD
  → Docs: https://github.com/jimmy058910/jmo-security-repo#readme

Additional Resources
--------------------
💬 Join community discussions: https://github.com/jimmy058910/jmo-security-repo/discussions
🐛 Report issues or request features: https://github.com/jimmy058910/jmo-security-repo/issues
⭐ Star on GitHub: https://github.com/jimmy058910/jmo-security-repo

💚 Support full-time development: https://ko-fi.com/jmogaming

---

What you'll receive:
🚀 New feature announcements
🔒 Security tips and best practices
💡 Case studies & exclusive guides - Learn from actual security audits with deep-dives not available elsewhere

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

        response = resend.Emails.send(params)  # type: ignore[arg-type]

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
