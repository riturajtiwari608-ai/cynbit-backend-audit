import { CircuitBreakerError } from '../middleware/errorHandler.js';

export const CircuitState = {
  CLOSED: 'CLOSED',
  OPEN: 'OPEN',
  HALF_OPEN: 'HALF_OPEN'
};

/**
 * Enterprise Circuit Breaker
 * Protects downstream databases and microservices against cascade failure
 * and thread/connection exhaustion during partial network outages.
 */
export class CircuitBreaker {
  /**
   * @param {number} [failureThreshold=3] - Consecutive failures before opening
   * @param {number} [cooldownMs=10000] - Duration in OPEN state before trying HALF_OPEN
   */
  constructor(failureThreshold = 3, cooldownMs = 10000) {
    this.failureThreshold = failureThreshold;
    this.cooldownMs = cooldownMs;
    this.state = CircuitState.CLOSED;
    this.failureCount = 0;
    this.nextAttempt = Date.now();
  }

  /**
   * Executes a protected asynchronous action.
   * 
   * @template T
   * @param {() => Promise<T>} action 
   * @returns {Promise<T>}
   */
  async execute(action) {
    const now = Date.now();

    if (this.state === CircuitState.OPEN) {
      if (now > this.nextAttempt) {
        this.state = CircuitState.HALF_OPEN;
      } else {
        const retryAfter = Math.ceil((this.nextAttempt - now) / 1000);
        throw new CircuitBreakerError(
          `Circuit breaker is OPEN. Upstream database/service is resting. Retry after ${retryAfter}s.`
        );
      }
    }

    try {
      const result = await action();
      if (this.state === CircuitState.HALF_OPEN) {
        this.reset();
      }
      return result;
    } catch (err) {
      this.failureCount++;
      if (this.failureCount >= this.failureThreshold) {
        this.state = CircuitState.OPEN;
        this.nextAttempt = now + this.cooldownMs;
      }
      throw err;
    }
  }

  reset() {
    this.state = CircuitState.CLOSED;
    this.failureCount = 0;
  }

  getStatus() {
    return {
      state: this.state,
      failureCount: this.failureCount,
      failureThreshold: this.failureThreshold,
      nextAttemptInSeconds: this.state === CircuitState.OPEN 
        ? Math.max(0, Math.ceil((this.nextAttempt - Date.now()) / 1000)) 
        : 0
    };
  }
}

export const databaseCircuitBreaker = new CircuitBreaker(3, 10000);
