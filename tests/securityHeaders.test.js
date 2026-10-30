import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { applySecurityHeaders } from '../src/middleware/securityHeaders.js';

test('Security Headers Middleware: enforces defense-in-depth security policies', () => {
  const mockReq = { headers: {} };
  const mockRes = new http.ServerResponse({ method: 'GET' });

  // Add dummy header to test stripping
  mockRes.setHeader('X-Powered-By', 'Express/Next.js');

  const nonce = applySecurityHeaders(mockReq, mockRes);

  assert.ok(nonce, 'Cryptographic nonce should be generated');
  assert.equal(typeof nonce, 'string');
  assert.ok(nonce.length >= 16);

  const csp = mockRes.getHeader('content-security-policy');
  assert.ok(csp, 'CSP must be present');
  assert.match(csp, /frame-ancestors 'none'/i, 'Must deny unauthorized iframing');
  assert.ok(csp.includes(`nonce-${nonce}`), 'CSP must include dynamic nonce');

  assert.equal(mockRes.getHeader('strict-transport-security'), 'max-age=63072000; includeSubDomains; preload');
  assert.equal(mockRes.getHeader('x-frame-options'), 'DENY');
  assert.equal(mockRes.getHeader('x-content-type-options'), 'nosniff');
  assert.equal(mockRes.getHeader('referrer-policy'), 'strict-origin-when-cross-origin');
  assert.ok(!mockRes.getHeader('x-powered-by'), 'X-Powered-By must be stripped');
});
