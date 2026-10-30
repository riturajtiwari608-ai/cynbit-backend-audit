/**
 * Candidate Boundary Validation & Anti-SSRF Defense
 * Enforces strict input validation and blocks prototype pollution & SSRF attempts.
 */

const ALLOWED_VCS_HOSTS = ['github.com', 'gitlab.com', 'bitbucket.org'];

// Disallowed private & internal IP patterns (SSRF Defense)
const PRIVATE_IP_PATTERNS = [
  /^localhost$/i,
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
  /^192\.168\./,
  /^169\.254\./,        // Cloud metadata service (AWS/GCP/Azure)
  /^0\.0\.0\.0$/,
  /^::1$/,
  /^fe80::/i
];

/**
 * Validates and sanitizes candidate submission payload.
 * 
 * @param {Record<string, unknown>} payload 
 * @returns {{ valid: boolean, data?: Record<string, unknown>, errors?: Array<{ field: string, message: string }> }}
 */
export function validateCandidateSubmission(payload) {
  const errors = [];

  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return {
      valid: false,
      errors: [{ field: 'body', message: 'Request body must be a valid JSON object' }]
    };
  }

  // Check prototype pollution attempts
  if (Object.prototype.hasOwnProperty.call(payload, '__proto__') ||
      Object.prototype.hasOwnProperty.call(payload, 'constructor') ||
      Object.prototype.hasOwnProperty.call(payload, 'prototype')) {
    return {
      valid: false,
      errors: [{ field: 'security', message: 'Prototype pollution vector rejected' }]
    };
  }

  const { candidateId, repositoryUrl, technicalNotes, submittedAt } = payload;

  // 1. Candidate ID validation (Prisma CUID format)
  if (!candidateId || typeof candidateId !== 'string') {
    errors.push({ field: 'candidateId', message: 'candidateId is required and must be a string' });
  } else if (!/^c[a-z0-9]{24}$/.test(candidateId)) {
    errors.push({
      field: 'candidateId',
      message: 'Invalid candidate identifier format. Must match 25-character CUID pattern (e.g. cmtykw6c0000004igfwa7a18q)'
    });
  }

  // 2. Repository URL Validation & SSRF Guard
  if (!repositoryUrl || typeof repositoryUrl !== 'string') {
    errors.push({ field: 'repositoryUrl', message: 'repositoryUrl is required and must be a string' });
  } else {
    try {
      const parsed = new URL(repositoryUrl);

      // Must be HTTPS protocol
      if (parsed.protocol !== 'https:') {
        errors.push({ field: 'repositoryUrl', message: 'Repository URL must use secure HTTPS protocol' });
      }

      // Check for private / internal hostnames
      const hostname = parsed.hostname.toLowerCase();
      const isPrivate = PRIVATE_IP_PATTERNS.some(pattern => pattern.test(hostname));
      if (isPrivate) {
        errors.push({ field: 'repositoryUrl', message: 'SSRF Violation: Internal or loopback hosts are forbidden' });
      }

      // Verify domain whitelist
      const isWhitelisted = ALLOWED_VCS_HOSTS.some(
        host => hostname === host || hostname.endsWith(`.${host}`)
      );
      if (!isWhitelisted) {
        errors.push({
          field: 'repositoryUrl',
          message: `Repository must be hosted on an authorized VCS platform (${ALLOWED_VCS_HOSTS.join(', ')})`
        });
      }
    } catch {
      errors.push({ field: 'repositoryUrl', message: 'Malformed repository URL' });
    }
  }

  // 3. Technical Notes Validation
  if (!technicalNotes || typeof technicalNotes !== 'string') {
    errors.push({ field: 'technicalNotes', message: 'technicalNotes is required and must be a string' });
  } else {
    const trimmedNotes = technicalNotes.trim();
    if (trimmedNotes.length < 20) {
      errors.push({
        field: 'technicalNotes',
        message: 'technicalNotes must be at least 20 characters explaining your setup and approach'
      });
    } else if (trimmedNotes.length > 20000) {
      errors.push({
        field: 'technicalNotes',
        message: 'technicalNotes exceeds maximum permissible boundary of 20,000 characters'
      });
    }
  }

  if (errors.length > 0) {
    return { valid: false, errors };
  }

  return {
    valid: true,
    data: {
      candidateId,
      repositoryUrl: String(repositoryUrl).trim(),
      technicalNotes: String(technicalNotes).trim(),
      submittedAt: submittedAt ? String(submittedAt) : new Date().toISOString()
    }
  };
}
