import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { sendProblemDetails, ValidationError, RateLimitError } from '../src/middleware/errorHandler.js';

test('ErrorHandler: outputs RFC 7807 compliant problem details envelopes', () => {
  // Test Validation Error
  const mockRes = new http.ServerResponse({ method: 'POST' });
  let responseBody = '';
  mockRes.end = (chunk) => {
    if (chunk) responseBody += chunk;
  };

  const validationErr = new ValidationError('Invalid submission', [
    { field: 'repositoryUrl', message: 'Invalid URL scheme' }
  ]);

  sendProblemDetails(mockRes, validationErr, '/api/candidate/submit', true);

  assert.equal(mockRes.statusCode, 422);
  assert.equal(mockRes.getHeader('content-type'), 'application/problem+json; charset=utf-8');

  const parsed = JSON.parse(responseBody);
  assert.equal(parsed.status, 422);
  assert.equal(parsed.title, 'Unprocessable Content');
  assert.equal(parsed.type, 'https://cynbit.in/errors/validation-error');
  assert.equal(parsed.instance, '/api/candidate/submit');
  assert.ok(Array.isArray(parsed.invalidParams));
  assert.equal(parsed.invalidParams[0].field, 'repositoryUrl');
});

test('ErrorHandler: sanitizes unhandled exceptions in production mode', () => {
  const mockRes = new http.ServerResponse({ method: 'GET' });
  let responseBody = '';
  mockRes.end = (chunk) => {
    if (chunk) responseBody += chunk;
  };

  const internalErr = new Error('Database password failed: /var/secrets/db_pass.key');
  sendProblemDetails(mockRes, internalErr, '/api/candidate/db', true);

  assert.equal(mockRes.statusCode, 500);
  const parsed = JSON.parse(responseBody);
  assert.equal(parsed.title, 'Internal Server Error');
  // Stack and path must NOT be leaked in production
  assert.ok(!parsed.detail.includes('/var/secrets'));
  assert.match(parsed.detail, /unexpected error occurred/i);
});
