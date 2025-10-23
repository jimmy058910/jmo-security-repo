/**
 * JMo Security - Email Subscription API Endpoint
 *
 * Simple Express endpoint for jmotools.com/api/subscribe
 *
 * Features:
 * - Email validation (format + DNS check optional)
 * - Rate limiting (10 requests/hour per IP)
 * - CORS configuration for GitHub Pages
 * - Resend API integration
 * - Source tracking (CLI, dashboard, website, subscribe_page)
 *
 * Deploy to: Vercel, Netlify Functions, AWS Lambda, or any Node.js host
 */

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { Resend } = require('resend');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy - required for Vercel/serverless deployments to get real client IP
app.set('trust proxy', 1);

// Initialize Resend client
const resend = new Resend(process.env.RESEND_API_KEY);

// CORS configuration - allow GitHub Pages origin
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps, curl, or file://)
    const allowedOrigins = [
      'https://jimmy058910.github.io',
      'https://jmotools.com',
      'http://localhost:3000',
      'http://localhost:8000'
    ];

    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['POST', 'OPTIONS', 'GET'],
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting: 10 requests per hour per IP
const limiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  message: {
    success: false,
    error: 'rate_limit_exceeded',
    message: 'Too many subscription requests. Please try again in an hour.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/subscribe', limiter);

// Email validation helper
function isValidEmail(email) {
  // RFC 5322 simplified regex
  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  return emailRegex.test(email);
}

// Main subscription endpoint
app.post('/api/subscribe', async (req, res) => {
  try {
    const { email, source = 'website', website } = req.body;
    const cfTurnstileResponse = req.body['cf-turnstile-response'];

    // Honeypot check - reject if filled (bots typically auto-fill all fields)
    if (website) {
      console.log('Bot detected via honeypot field');
      return res.status(400).json({
        success: false,
        error: 'invalid_request',
        message: 'Invalid submission detected.'
      });
    }

    // CAPTCHA check - verify Turnstile response (CSRF protection)
    if (!cfTurnstileResponse) {
      console.log('CAPTCHA verification failed: missing token');
      return res.status(403).json({
        success: false,
        error: 'captcha_required',
        message: 'Please complete the CAPTCHA verification.'
      });
    }

    // Verify Turnstile response with Cloudflare
    try {
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
        console.log('Turnstile verification failed:', turnstileResult['error-codes']);
        return res.status(403).json({
          success: false,
          error: 'captcha_failed',
          message: 'CAPTCHA verification failed. Please try again.'
        });
      }

      console.log('Turnstile verification passed');
    } catch (error) {
      console.error('Turnstile API error:', error);
      // Fail closed - reject if CAPTCHA verification fails
      return res.status(503).json({
        success: false,
        error: 'captcha_unavailable',
        message: 'CAPTCHA verification service temporarily unavailable. Please try again later.'
      });
    }

    // Validate email format
    if (!email || !isValidEmail(email)) {
      return res.status(400).json({
        success: false,
        error: 'invalid_email',
        message: 'Please provide a valid email address.'
      });
    }

    // Validate source
    const validSources = ['cli', 'cli_onboarding', 'dashboard', 'website', 'subscribe_page', 'github_readme'];
    const safeSource = validSources.includes(source) ? source : 'website';

    // Check if Resend API key is configured
    if (!process.env.RESEND_API_KEY) {
      console.error('RESEND_API_KEY not configured');
      return res.status(500).json({
        success: false,
        error: 'server_error',
        message: 'Email service temporarily unavailable. Please try again later.'
      });
    }

    // Send welcome email via Resend (unified template matching Python CLI)
    const welcomeEmailHTML = `
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

        <p style="font-size: 12px; color: #a0aec0; text-align: center; margin-top: 20px;">
            You're receiving this email because you subscribed via ${safeSource.replace('_', ' ')}. <br>
            <a href="{{unsubscribe_url}}" style="color: #667eea; text-decoration: none;">Unsubscribe</a> |
            <a href="https://jimmy058910.github.io/jmo-security-repo/PRIVACY.html" style="color: #667eea; text-decoration: none;">Privacy Policy</a>
        </p>
    </div>
</body>
</html>`;

    const welcomeEmailText = `
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

---
You're receiving this email because you subscribed via ${safeSource.replace('_', ' ')}.
Unsubscribe: {{unsubscribe_url}}
Privacy Policy: https://jimmy058910.github.io/jmo-security-repo/PRIVACY.html
`;

    // Send email via Resend
    const response = await resend.emails.send({
      from: 'JMo Security <marketing@jmotools.com>',
      to: [email],
      subject: 'Welcome to JMo Security! 🎉',
      html: welcomeEmailHTML,
      text: welcomeEmailText,
      tags: [
        { name: 'source', value: safeSource },
        { name: 'type', value: 'welcome' }
      ]
    });

    // Success response
    return res.status(200).json({
      success: true,
      message: '✅ Thanks! Check your inbox for a welcome email.',
      email_id: response.id
    });

  } catch (error) {
    console.error('Subscription error:', error);

    // Handle Resend-specific errors
    if (error.message && error.message.includes('Invalid API key')) {
      return res.status(500).json({
        success: false,
        error: 'configuration_error',
        message: 'Email service misconfigured. Please contact support.'
      });
    }

    // Generic error response
    return res.status(500).json({
      success: false,
      error: 'server_error',
      message: 'Failed to process subscription. Please try again later.'
    });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'jmo-security-subscribe-api',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'not_found',
    message: 'Endpoint not found. Use POST /api/subscribe'
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    error: 'internal_server_error',
    message: 'An unexpected error occurred.'
  });
});

// Start server (for local testing)
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`✅ JMo Security Subscribe API running on port ${PORT}`);
    console.log(`📧 Resend API Key: ${process.env.RESEND_API_KEY ? 'Configured' : 'NOT CONFIGURED'}`);
    console.log(`\nEndpoints:`);
    console.log(`  POST http://localhost:${PORT}/api/subscribe`);
    console.log(`  GET  http://localhost:${PORT}/api/health`);
  });
}

// Export for serverless deployment (Vercel, Netlify, etc.)
module.exports = app;
