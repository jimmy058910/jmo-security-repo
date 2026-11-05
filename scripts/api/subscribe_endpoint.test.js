/**
 * Run with `npm test` (after `npm ci`), on Node's own test runner.
 *
 * resend 6 throws "Missing API key" in its constructor, and the endpoint built
 * its client when the module loaded, so without RESEND_API_KEY the server could
 * not start, and the handler's own "not configured" answer could never run
 * (#1437).
 */
const { test } = require('node:test');
const assert = require('node:assert');

test('without RESEND_API_KEY the module loads and a subscribe answers 500', async (t) => {
  delete process.env.RESEND_API_KEY;
  const realFetch = globalThis.fetch;
  // The handler checks the CAPTCHA with Cloudflare before it looks for the key.
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    if (String(url).startsWith('https://challenges.cloudflare.com/')) {
      return new Response(JSON.stringify({ success: true }));
    }
    return realFetch(url, options);
  });

  const app = require('./subscribe_endpoint.js');
  const server = app.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  try {
    const { port } = server.address();
    const response = await fetch(`http://127.0.0.1:${port}/api/subscribe`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'someone@example.com',
        source: 'website',
        'cf-turnstile-response': 'token',
      }),
    });

    assert.strictEqual(response.status, 500);
    const body = await response.json();
    assert.strictEqual(body.error, 'server_error');
    assert.match(body.message, /temporarily unavailable/);
  } finally {
    server.close();
  }
});
