import crypto from 'node:crypto';
import { config } from '../config.js';

/**
 * Candidate Security Service
 * Provides cryptographic HMAC-SHA256 signature generation and constant-time verification
 * for candidate capability URLs, preventing IDOR and unauthorized assessment tampering.
 */
export class CandidateSecurityService {
  /**
   * Generates a signed capability URL with expiration.
   * 
   * @param {string} candidateId - Prisma CUID format (e.g. cmtykw6c0000004igfwa7a18q)
   * @param {number} [ttlHours=72] - Validity window in hours
   * @param {string} [secret] - Signing key
   * @returns {{ url: string, expiresAt: number, signature: string }}
   */
  static signCandidateAccess(candidateId, ttlHours = 72, secret = config.portalSigningSecret) {
    if (!candidateId || typeof candidateId !== 'string') {
      throw new Error('Candidate identifier must be a non-empty string');
    }

    const expiresAt = Math.floor(Date.now() / 1000) + (ttlHours * 3600);
    const payload = `${candidateId}:${expiresAt}`;

    const signature = crypto
      .createHmac('sha256', secret)
      .update(payload)
      .digest('hex');

    const url = `https://cynbit.in/candidate/${candidateId}?exp=${expiresAt}&sig=${signature}`;

    return {
      url,
      expiresAt,
      signature
    };
  }

  /**
   * Verifies an incoming candidate request signature against current timestamp.
   * 
   * @param {string} candidateId 
   * @param {number|string} exp - Expiration unix timestamp
   * @param {string} sig - HMAC hex signature
   * @param {string} [secret]
   * @returns {{ valid: boolean, reason?: string }}
   */
  static verifyCandidateAccess(candidateId, exp, sig, secret = config.portalSigningSecret) {
    if (!candidateId || !exp || !sig) {
      return { valid: false, reason: 'Missing cryptographic authorization parameters (exp, sig)' };
    }

    const expirationTimestamp = parseInt(String(exp), 10);
    if (isNaN(expirationTimestamp)) {
      return { valid: false, reason: 'Malformed expiration timestamp' };
    }

    const now = Math.floor(Date.now() / 1000);
    if (now > expirationTimestamp) {
      return { valid: false, reason: 'Assessment capability link has expired' };
    }

    const payload = `${candidateId}:${expirationTimestamp}`;
    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(payload)
      .digest('hex');

    // Constant-time comparison to prevent timing side-channel attacks
    try {
      const sigBuffer = Buffer.from(String(sig), 'hex');
      const expectedBuffer = Buffer.from(expectedSignature, 'hex');

      if (sigBuffer.length !== expectedBuffer.length) {
        return { valid: false, reason: 'Invalid signature byte length' };
      }

      const isValid = crypto.timingSafeEqual(sigBuffer, expectedBuffer);
      return isValid 
        ? { valid: true } 
        : { valid: false, reason: 'Signature mismatch / unauthorized link alteration' };
    } catch {
      return { valid: false, reason: 'Cryptographic comparison failure' };
    }
  }
}
