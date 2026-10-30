import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { config } from './config.js';
import { applySecurityHeaders } from './middleware/securityHeaders.js';
import { candidateRateLimiter } from './middleware/rateLimiter.js';
import { sendProblemDetails, ValidationError, RateLimitError, NotFoundError } from './middleware/errorHandler.js';
import { CandidateSecurityService } from './security/tokenSigner.js';
import { validateCandidateSubmission } from './validation/candidateValidator.js';
import { databaseCircuitBreaker } from './resilience/circuitBreaker.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PUBLIC_DIR = path.join(__dirname, '../public');

/**
 * Parses JSON request body with memory safety limit (1MB max).
 * 
 * @param {http.IncomingMessage} req 
 * @returns {Promise<Record<string, unknown>>}
 */
function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    const maxBytes = 1024 * 1024; // 1 MB limit
    let bytesReceived = 0;

    req.on('data', chunk => {
      bytesReceived += chunk.length;
      if (bytesReceived > maxBytes) {
        req.destroy();
        reject(new ValidationError('Payload exceeds maximum permissible size of 1MB'));
        return;
      }
      body += chunk;
    });

    req.on('end', () => {
      if (!body) {
        resolve({});
        return;
      }
      try {
        const parsed = JSON.parse(body);
        resolve(parsed);
      } catch {
        reject(new ValidationError('Malformed JSON payload'));
      }
    });

    req.on('error', err => reject(err));
  });
}

/**
 * Creates and configures the hardened Cynbit Reference HTTP Server.
 */
export function createServer() {
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const pathname = url.pathname;
    const method = req.method || 'GET';

    // 1. Enforce Zero-Trust Defense-in-Depth Security Headers
    const nonce = applySecurityHeaders(req, res);

    try {
      // Favicon handler (suppress 404 in browser console)
      if (pathname === '/favicon.ico') {
        res.statusCode = 204;
        res.end();
        return;
      }

      // 2. Health & Telemetry Endpoint
      if (method === 'GET' && pathname === '/api/health') {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({
          status: 'HEALTHY',
          service: 'cynbit-backend-reference',
          timestamp: new Date().toISOString(),
          circuitBreaker: databaseCircuitBreaker.getStatus(),
          nodeVersion: process.version
        }, null, 2));
        return;
      }

      // 3. Serve Interactive Web Dashboard with Dynamic Nonce Injection (GET /)
      if (method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
        const indexPath = path.join(PUBLIC_DIR, 'index.html');
        if (fs.existsSync(indexPath)) {
          const rawHtml = fs.readFileSync(indexPath, 'utf-8');
          const noncedHtml = rawHtml.replace('<script>', `<script nonce="${nonce}">`);
          res.setHeader('Content-Type', 'text/html; charset=utf-8');
          res.end(noncedHtml);
          return;
        }
      }

      // 4. Candidate Assessment Submission Endpoint (POST /api/candidate/submit)
      if (method === 'POST' && pathname === '/api/candidate/submit') {
        const clientIp = req.socket.remoteAddress || '127.0.0.1';

        // Check sliding-window rate limit
        const rateStatus = candidateRateLimiter.check(clientIp);
        candidateRateLimiter.setHeaders(res, rateStatus);

        if (!rateStatus.allowed) {
          throw new RateLimitError(rateStatus.resetSeconds);
        }

        // Parse and validate incoming payload
        const rawBody = await parseJsonBody(req);
        const validation = validateCandidateSubmission(rawBody);

        if (!validation.valid) {
          throw new ValidationError(
            'Candidate submission failed boundary validation',
            validation.errors
          );
        }

        // Simulate resilient database ingestion via Circuit Breaker
        const persistedRecord = await databaseCircuitBreaker.execute(async () => {
          return {
            id: `sub_${Date.now()}`,
            ...validation.data,
            ingestionStatus: 'ACCEPTED_FOR_EVALUATION',
            evaluatedBy: 'Aria AI Talent Engine'
          };
        });

        res.setHeader('Content-Type', 'application/json');
        res.statusCode = 200;
        res.end(JSON.stringify({
          success: true,
          message: 'Assessment submission successfully validated and ingested',
          data: persistedRecord
        }, null, 2));
        return;
      }

      // 5. Cryptographic HMAC Token Signing (POST /api/security/sign-candidate)
      if (method === 'POST' && pathname === '/api/security/sign-candidate') {
        const body = await parseJsonBody(req);
        const candidateId = String(body.candidateId || 'cmtykw6c0000004igfwa7a18q');
        const ttlHours = parseInt(String(body.ttlHours || '72'), 10);

        const signed = CandidateSecurityService.signCandidateAccess(candidateId, ttlHours);
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(signed, null, 2));
        return;
      }

      // 6. Candidate Access Verification (GET /api/candidate/:id)
      if (method === 'GET' && pathname.startsWith('/api/candidate/')) {
        const parts = pathname.split('/');
        const candidateId = parts[3];
        const exp = url.searchParams.get('exp');
        const sig = url.searchParams.get('sig');

        if (!candidateId) {
          throw new NotFoundError('Candidate identifier missing');
        }

        let authStatus = { valid: false, note: 'Unsigned access attempt' };
        if (exp && sig) {
          authStatus = CandidateSecurityService.verifyCandidateAccess(candidateId, exp, sig);
        }

        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({
          candidateId,
          role: 'Backend Developer Intern',
          assessment: 'Analyze Cynbit From a Backend Perspective',
          hmacVerification: authStatus,
          applicantName: 'Rituraj Tiwari'
        }, null, 2));
        return;
      }

      // 7. 404 Not Found fallback
      throw new NotFoundError(`Endpoint '${pathname}' does not exist on this server`);

    } catch (err) {
      // Route all errors to centralized RFC 7807 Problem Details handler
      sendProblemDetails(res, err, pathname, config.nodeEnv === 'production');
    }
  });

  return server;
}
