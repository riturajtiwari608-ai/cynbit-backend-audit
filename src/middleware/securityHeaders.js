import crypto from 'node:crypto';

/**
 * Applies defense-in-depth security headers (RFC compliance & OWASP Top 10 A05).
 * 
 * @param {import('node:http').IncomingMessage} req 
 * @param {import('node:http').ServerResponse} res 
 * @returns {string} Generated cryptographic nonce for the request
 */
export function applySecurityHeaders(req, res) {
  const nonce = crypto.randomBytes(16).toString('base64');

  // Strict Content Security Policy with dynamic cryptographic nonce
  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' https://cdn.jsdelivr.net`,
    `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com`,
    "font-src 'self' https://fonts.gstatic.com data:",
    "img-src 'self' data: https:",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "upgrade-insecure-requests"
  ].join('; ');

  // Enforce headers
  res.setHeader('Content-Security-Policy', csp);
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), browsing-topics=()');
  res.setHeader('X-DNS-Prefetch-Control', 'on');
  
  // Prevent server fingerprinting
  res.removeHeader('X-Powered-By');

  return nonce;
}
