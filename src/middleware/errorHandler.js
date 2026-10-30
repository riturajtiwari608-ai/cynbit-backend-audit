/**
 * Standard Application Error Hierarchy
 * Maps domain exceptions to HTTP status codes and RFC 7807 Problem Details.
 */
export class AppError extends Error {
  /**
   * @param {number} status 
   * @param {string} title 
   * @param {string} detail 
   * @param {string} type 
   * @param {Array<{ field: string, message: string }>} [invalidParams]
   */
  constructor(status, title, detail, type = 'about:blank', invalidParams = undefined) {
    super(detail);
    this.name = this.constructor.name;
    this.status = status;
    this.title = title;
    this.detail = detail;
    this.type = type;
    this.invalidParams = invalidParams;
    Error.captureStackTrace(this, this.constructor);
  }
}

export class ValidationError extends AppError {
  /**
   * @param {string} detail 
   * @param {Array<{ field: string, message: string }>} [invalidParams]
   */
  constructor(detail, invalidParams) {
    super(
      422,
      'Unprocessable Content',
      detail,
      'https://cynbit.in/errors/validation-error',
      invalidParams
    );
  }
}

export class AuthenticationError extends AppError {
  /**
   * @param {string} detail 
   */
  constructor(detail = 'Invalid or expired authentication credentials') {
    super(
      401,
      'Unauthorized',
      detail,
      'https://cynbit.in/errors/unauthorized'
    );
  }
}

export class NotFoundError extends AppError {
  /**
   * @param {string} detail 
   */
  constructor(detail = 'The requested resource was not found') {
    super(
      404,
      'Not Found',
      detail,
      'https://cynbit.in/errors/not-found'
    );
  }
}

export class RateLimitError extends AppError {
  /**
   * @param {number} retryAfterSeconds 
   */
  constructor(retryAfterSeconds) {
    super(
      429,
      'Too Many Requests',
      `Rate limit quota exceeded. Please retry after ${retryAfterSeconds} seconds.`,
      'https://cynbit.in/errors/rate-limit-exceeded'
    );
    this.retryAfter = retryAfterSeconds;
  }
}

export class CircuitBreakerError extends AppError {
  constructor(detail = 'Upstream database service is currently in recovery. Circuit breaker is OPEN.') {
    super(
      503,
      'Service Unavailable',
      detail,
      'https://cynbit.in/errors/circuit-breaker-open'
    );
  }
}

/**
 * Formats and writes an RFC 7807 Problem Details response to the client.
 * 
 * @param {import('node:http').ServerResponse} res 
 * @param {unknown} err 
 * @param {string} instancePath 
 * @param {boolean} [isProduction] 
 */
export function sendProblemDetails(res, err, instancePath, isProduction = process.env.NODE_ENV === 'production') {
  res.setHeader('Content-Type', 'application/problem+json; charset=utf-8');

  if (err instanceof AppError) {
    res.statusCode = err.status;
    const body = {
      type: err.type,
      title: err.title,
      status: err.status,
      detail: err.detail,
      instance: instancePath,
      timestamp: new Date().toISOString()
    };

    if (err.invalidParams) {
      body.invalidParams = err.invalidParams;
    }
    if (err instanceof RateLimitError) {
      body.retryAfter = err.retryAfter;
    }

    res.end(JSON.stringify(body, null, 2));
    return;
  }

  // Fallback for uncaught 500 exceptions (Defense-in-depth: stack traces suppressed)
  res.statusCode = 500;
  const genericBody = {
    type: 'https://cynbit.in/errors/internal-server-error',
    title: 'Internal Server Error',
    status: 500,
    detail: isProduction
      ? 'An unexpected error occurred while executing the server request. Please contact opportunities@cynbit.in.'
      : String(err instanceof Error ? err.message : err),
    instance: instancePath,
    timestamp: new Date().toISOString()
  };

  res.end(JSON.stringify(genericBody, null, 2));
}
