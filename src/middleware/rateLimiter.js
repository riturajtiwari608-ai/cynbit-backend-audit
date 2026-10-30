/**
 * Sliding Window Log Rate Limiter
 * Provides microsecond precision rate limiting across request bursts,
 * preventing connection starvation and brute force abuse.
 */
export class SlidingWindowRateLimiter {
  constructor(limit = 5, windowMs = 60000) {
    this.limit = limit;
    this.windowMs = windowMs;
    /** @type {Map<string, number[]>} */
    this.requests = new Map();
  }

  /**
   * Evaluates if a request from the given identifier is permitted.
   * 
   * @param {string} identifier - Client IP or authenticated candidate ID
   * @returns {{ allowed: boolean, limit: number, remaining: number, resetSeconds: number }}
   */
  check(identifier) {
    const now = Date.now();
    const windowStart = now - this.windowMs;

    const timestamps = this.requests.get(identifier) || [];
    
    // Purge timestamps outside the active sliding window
    const validTimestamps = timestamps.filter(t => t > windowStart);

    if (validTimestamps.length >= this.limit) {
      const oldest = validTimestamps[0];
      const resetSeconds = Math.max(1, Math.ceil((oldest + this.windowMs - now) / 1000));
      this.requests.set(identifier, validTimestamps);
      
      return {
        allowed: false,
        limit: this.limit,
        remaining: 0,
        resetSeconds
      };
    }

    // Record request timestamp
    validTimestamps.push(now);
    this.requests.set(identifier, validTimestamps);

    return {
      allowed: true,
      limit: this.limit,
      remaining: this.limit - validTimestamps.length,
      resetSeconds: Math.ceil(this.windowMs / 1000)
    };
  }

  /**
   * Injects standardized RFC rate limiting headers into the HTTP response.
   * 
   * @param {import('node:http').ServerResponse} res 
   * @param {{ allowed: boolean, limit: number, remaining: number, resetSeconds: number }} status 
   */
  setHeaders(res, status) {
    res.setHeader('X-RateLimit-Limit', status.limit.toString());
    res.setHeader('X-RateLimit-Remaining', status.remaining.toString());
    res.setHeader('X-RateLimit-Reset', status.resetSeconds.toString());
    
    if (!status.allowed) {
      res.setHeader('Retry-After', status.resetSeconds.toString());
    }
  }

  /**
   * Clears in-memory storage (useful for testing)
   */
  reset() {
    this.requests.clear();
  }
}

// Global default singleton
export const candidateRateLimiter = new SlidingWindowRateLimiter(5, 60000);
