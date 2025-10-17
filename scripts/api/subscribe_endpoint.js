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

    // Honeypot check - reject if filled (bots typically auto-fill all fields)
    if (website) {
      console.log('Bot detected via honeypot field');
      return res.status(400).json({
        success: false,
        error: 'invalid_request',
        message: 'Invalid submission detected.'
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

    // Send welcome email via Resend
    const welcomeEmailHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Welcome to JMo Security</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
  <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 12px; text-align: center; margin-bottom: 30px;">
    <h1 style="margin: 0; font-size: 32px;">🎉 Welcome to JMo Security!</h1>
    <p style="margin: 15px 0 0 0; font-size: 18px; opacity: 0.95;">Terminal-first security scanning for developers</p>
  </div>

  <div style="padding: 20px;">
    <p style="font-size: 16px; margin-bottom: 20px;">Hi there!</p>

    <p style="font-size: 16px; margin-bottom: 20px;">Thanks for subscribing to the JMo Security newsletter. Welcome to the community!</p>

    <h2 style="color: #667eea; font-size: 22px; margin-top: 30px; margin-bottom: 15px;">🚀 What You'll Receive</h2>
    <ul style="font-size: 16px; line-height: 1.8;">
      <li><strong>Weekly Security Tips</strong> - Practical advice for securing your code</li>
      <li><strong>New Feature Announcements</strong> - Be first to try new scanners and tools</li>
      <li><strong>Real-World Case Studies</strong> - Learn from actual security audits</li>
      <li><strong>Exclusive Guides</strong> - Deep-dives not available elsewhere</li>
      <li><strong>Early Access</strong> - Test premium features before public release</li>
    </ul>

    <h2 style="color: #667eea; font-size: 22px; margin-top: 30px; margin-bottom: 15px;">⚡ Quick Start Guide</h2>
    <p style="font-size: 16px; margin-bottom: 15px;">Get started with JMo Security in 3 ways:</p>

    <div style="background: #f7fafc; border-left: 4px solid #667eea; padding: 15px; margin: 15px 0; border-radius: 6px;">
      <strong style="color: #667eea;">1️⃣ Interactive Wizard (Recommended)</strong>
      <pre style="background: #2d3748; color: #e2e8f0; padding: 12px; border-radius: 6px; margin: 10px 0; overflow-x: auto;"><code>jmotools wizard</code></pre>
    </div>

    <div style="background: #f7fafc; border-left: 4px solid #667eea; padding: 15px; margin: 15px 0; border-radius: 6px;">
      <strong style="color: #667eea;">2️⃣ Docker (Zero Installation)</strong>
      <pre style="background: #2d3748; color: #e2e8f0; padding: 12px; border-radius: 6px; margin: 10px 0; overflow-x: auto;"><code>docker pull ghcr.io/jimmy058910/jmo-security:latest
docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest \\
  scan --repo /scan --results /scan/results --profile balanced</code></pre>
    </div>

    <div style="background: #f7fafc; border-left: 4px solid #667eea; padding: 15px; margin: 15px 0; border-radius: 6px;">
      <strong style="color: #667eea;">3️⃣ CLI Wrapper Commands</strong>
      <pre style="background: #2d3748; color: #e2e8f0; padding: 12px; border-radius: 6px; margin: 10px 0; overflow-x: auto;"><code>jmotools fast --repos-dir ~/repos</code></pre>
    </div>

    <div style="text-align: center; margin: 40px 0 30px 0;">
      <a href="https://github.com/jimmy058910/jmo-security-repo" style="display: inline-block; background: #667eea; color: white; padding: 14px 28px; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 16px;">View on GitHub</a>
      <a href="https://jmotools.com" style="display: inline-block; background: #10b981; color: white; padding: 14px 28px; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 16px; margin-left: 10px;">Documentation</a>
    </div>

    <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 30px 0;">

    <p style="font-size: 14px; color: #718096; text-align: center;">
      💚 <a href="https://ko-fi.com/jmogaming" style="color: #667eea; text-decoration: none;">Support full-time development on Ko-Fi</a>
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
Welcome to JMo Security!

Thanks for subscribing to the JMo Security newsletter. Welcome to the community!

What You'll Receive:
- Weekly Security Tips - Practical advice for securing your code
- New Feature Announcements - Be first to try new scanners and tools
- Real-World Case Studies - Learn from actual security audits
- Exclusive Guides - Deep-dives not available elsewhere
- Early Access - Test premium features before public release

Quick Start Guide:

1. Interactive Wizard (Recommended):
   jmotools wizard

2. Docker (Zero Installation):
   docker pull ghcr.io/jimmy058910/jmo-security:latest
   docker run --rm -v $(pwd):/scan ghcr.io/jimmy058910/jmo-security:latest scan --repo /scan --results /scan/results --profile balanced

3. CLI Wrapper Commands:
   jmotools fast --repos-dir ~/repos

GitHub: https://github.com/jimmy058910/jmo-security-repo
Documentation: https://jmotools.com

Support full-time development: https://ko-fi.com/jmogaming

---
You're receiving this email because you subscribed via ${safeSource.replace('_', ' ')}.
Unsubscribe: {{unsubscribe_url}}
Privacy Policy: https://jimmy058910.github.io/jmo-security-repo/PRIVACY.html
`;

    // Send email via Resend
    const response = await resend.emails.send({
      from: 'JMo Security <hello@jmotools.com>',
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
