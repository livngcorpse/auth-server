const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const { getClient } = require('../config/redis');

const createRateLimiter = (options = {}) => {
  const windowMs = options.windowMs || parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000;
  
  return rateLimit({
    windowMs,
    max: options.max || 5,
    message: options.message || 'Too many requests, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    store: new RedisStore({
      client: getClient(),
      prefix: `rl:${options.prefix || 'default'}:`
    }),
    keyGenerator: (req) => {
      return req.ip || req.connection.remoteAddress;
    },
    skip: (req) => {
      // Skip rate limiting in test environment
      return process.env.NODE_ENV === 'test';
    }
  });
};

const loginLimiter = createRateLimiter({
  windowMs: 900000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_LOGIN) || 5,
  message: 'Too many login attempts, please try again after 15 minutes',
  prefix: 'login'
});

const signupLimiter = createRateLimiter({
  windowMs: 3600000, // 1 hour
  max: parseInt(process.env.RATE_LIMIT_MAX_SIGNUP) || 3,
  message: 'Too many signup attempts, please try again after 1 hour',
  prefix: 'signup'
});

const otpLimiter = createRateLimiter({
  windowMs: 900000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_OTP) || 3,
  message: 'Too many OTP requests, please try again after 15 minutes',
  prefix: 'otp'
});

const resetPasswordLimiter = createRateLimiter({
  windowMs: 3600000, // 1 hour
  max: parseInt(process.env.RATE_LIMIT_MAX_RESET) || 3,
  message: 'Too many password reset requests, please try again after 1 hour',
  prefix: 'reset'
});

const generalLimiter = createRateLimiter({
  windowMs: 60000, // 1 minute
  max: 60,
  message: 'Too many requests',
  prefix: 'general'
});

module.exports = {
  loginLimiter,
  signupLimiter,
  otpLimiter,
  resetPasswordLimiter,
  generalLimiter
};