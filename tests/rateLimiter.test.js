import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { SlidingWindowRateLimiter } from '../src/middleware/rateLimiter.js';

test('SlidingWindowRateLimiter: strictly controls burst traffic and injects RFC headers', () => {
  const limiter = new SlidingWindowRateLimiter(3, 5000); // 3 requests per 5 seconds
  const clientKey = 'candidate_ip_192_0_2_1';

  // Requests 1, 2, 3 must be allowed
  const req1 = limiter.check(clientKey);
  assert.equal(req1.allowed, true);
  assert.equal(req1.remaining, 2);

  const req2 = limiter.check(clientKey);
  assert.equal(req2.allowed, true);
  assert.equal(req2.remaining, 1);

  const req3 = limiter.check(clientKey);
  assert.equal(req3.allowed, true);
  assert.equal(req3.remaining, 0);

  // Request 4 must be BLOCKED
  const req4 = limiter.check(clientKey);
  assert.equal(req4.allowed, false);
  assert.equal(req4.remaining, 0);
  assert.ok(req4.resetSeconds > 0, 'Reset seconds must be positive');

  // Verify header injection
  const mockRes = new http.ServerResponse({ method: 'POST' });
  limiter.setHeaders(mockRes, req4);

  assert.equal(mockRes.getHeader('x-ratelimit-limit'), '3');
  assert.equal(mockRes.getHeader('x-ratelimit-remaining'), '0');
  assert.ok(mockRes.getHeader('retry-after'), 'Retry-After header must be set on blocked request');
});
