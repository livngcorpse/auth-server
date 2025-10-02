// Security configuration and constants

const SECURITY_CONSTANTS = {
  // Password requirements
  PASSWORD: {
    MIN_LENGTH: parseInt(process.env.PASSWORD_MIN_LENGTH) || 8,
    REQUIRE_UPPERCASE: true,
    REQUIRE_LOWERCASE: true,
    REQUIRE_NUMBER: true,
    REQUIRE_SPECIAL: true
  },
  
  // Argon2 configuration
  ARGON2: {
    MEMORY_COST: parseInt(process.env.ARGON2_MEMORY_COST) || 65536, // 64 MB
    TIME_COST: parseInt(process.env.ARGON2_TIME_COST) || 3,
    PARALLELISM: parseInt(process.env.ARGON2_PARALLELISM) || 4
  },
  
  // JWT configuration
  JWT: {
    ACCESS_EXPIRY: process.env.JWT_ACCESS_EXPIRY || '15m',
    REFRESH_EXPIRY: process.env.JWT_REFRESH_EXPIRY || '7d',
    ALGORITHM: 'HS256'
  },
  
  // OTP configuration
  OTP: {
    LENGTH: parseInt(process.env.OTP_LENGTH) || 6,
    EXPIRY_MINUTES: parseInt(process.env.OTP_EXPIRY_MINUTES) || 5,
    MAX_ATTEMPTS: parseInt(process.env.OTP_MAX_ATTEMPTS) || 3
  },
  
  // Rate limiting
  RATE_LIMIT: {
    WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000,
    MAX_LOGIN: parseInt(process.env.RATE_LIMIT_MAX_LOGIN) || 5,
    MAX_SIGNUP: parseInt(process.env.RATE_LIMIT_MAX_SIGNUP) || 3,
    MAX_OTP: parseInt(process.env.RATE_LIMIT_MAX_OTP) || 3,
    MAX_RESET: parseInt(process.env.RATE_LIMIT_MAX_RESET) || 3
  },
  
  // Token expiry
  RESET_TOKEN_EXPIRY_MS: 3600000, // 1 hour
  
  // Allowed origins
  ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS?.split(',') || ['*']
};

// Helper function to validate environment variables
const validateSecurityConfig = () => {
  const errors = [];
  
  if (!process.env.JWT_ACCESS_SECRET || process.env.JWT_ACCESS_SECRET.length < 32) {
    errors.push('JWT_ACCESS_SECRET must be at least 32 characters');
  }
  
  if (!process.env.JWT_REFRESH_SECRET || process.env.JWT_REFRESH_SECRET.length < 32) {
    errors.push('JWT_REFRESH_SECRET must be at least 32 characters');
  }
  
  if (process.env.JWT_ACCESS_SECRET === process.env.JWT_REFRESH_SECRET) {
    errors.push('JWT_ACCESS_SECRET and JWT_REFRESH_SECRET must be different');
  }
  
  if (!process.env.DB_PASSWORD) {
    errors.push('DB_PASSWORD is required');
  }
  
  if (process.env.NODE_ENV === 'production') {
    if (!process.env.DB_SSL || process.env.DB_SSL !== 'true') {
      errors.push('DB_SSL must be enabled in production');
    }
    
    if (!process.env.REDIS_PASSWORD) {
      errors.push('REDIS_PASSWORD is required in production');
    }
    
    if (!process.env.BASE_URL || !process.env.BASE_URL.startsWith('https://')) {
      errors.push('BASE_URL must use HTTPS in production');
    }
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
};

// Helmet security headers configuration
const helmetConfig = {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  noSniff: true,
  xssFilter: true,
  referrerPolicy: {
    policy: 'strict-origin-when-cross-origin'
  },
  frameguard: {
    action: 'deny'
  }
};

// CORS configuration
const corsConfig = {
  origin: (origin, callback) => {
    const allowedOrigins = SECURITY_CONSTANTS.ALLOWED_ORIGINS;
    
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    
    // Allow all origins in development
    if (process.env.NODE_ENV === 'development') {
      return callback(null, true);
    }
    
    // Check if origin is allowed
    if (allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200,
  maxAge: 86400 // 24 hours
};

module.exports = {
  SECURITY_CONSTANTS,
  validateSecurityConfig,
  helmetConfig,
  corsConfig
};