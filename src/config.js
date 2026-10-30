/**
 * System Configuration
 */
export const config = {
  port: parseInt(process.env.PORT || '3000', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  portalSigningSecret: process.env.PORTAL_SIGNING_SECRET || 'cynbit-enterprise-audit-secret-key-32b',
  rateLimit: {
    limit: 5,           // 5 requests
    windowMs: 60 * 1000 // per 60 seconds
  },
  cors: {
    allowedOrigins: ['https://cynbit.in', 'https://www.cynbit.in', 'http://localhost:3000']
  }
};
