const Joi = require('joi');
const User = require('../models/User');
const { generateTokenPair, verifyRefreshToken, isRefreshTokenRevoked, revokeRefreshToken } = require('../utils/jwt');
const { validatePasswordStrength } = require('../utils/password');
const logger = require('../utils/logger');
const crypto = require('crypto');
const sgMail = require('@sendgrid/mail');
const { pool } = require('../config/database');

// Initialize SendGrid
if (process.env.SENDGRID_API_KEY) {
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
}

// Validation schemas
const signupSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).required()
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

const forgotPasswordSchema = Joi.object({
  email: Joi.string().email().required()
});

const resetPasswordSchema = Joi.object({
  token: Joi.string().required(),
  newPassword: Joi.string().min(8).required()
});

const refreshTokenSchema = Joi.object({
  refreshToken: Joi.string().required()
});

// Signup controller
const signup = async (req, res) => {
  const { error, value } = signupSchema.validate(req.body);
  
  if (error) {
    return res.status(400).json({
      success: false,
      error: error.details[0].message
    });
  }
  
  const { email, password } = value;
  
  // Validate password strength
  const passwordValidation = validatePasswordStrength(password);
  if (!passwordValidation.valid) {
    return res.status(400).json({
      success: false,
      error: 'Password does not meet requirements',
      details: passwordValidation.errors
    });
  }
  
  // Check if user already exists
  const existingUser = await User.findByEmail(email);
  if (existingUser) {
    return res.status(409).json({
      success: false,
      error: 'Email already registered'
    });
  }
  
  // Create user
  const user = await User.create({
    email: email.toLowerCase(),
    password,
    provider_type: 'local',
    email_verified: false
  });
  
  // Generate tokens
  const tokens = await generateTokenPair(user, req.ip, req.get('user-agent'));
  
  // Log audit
  await pool.query(
    `INSERT INTO audit_logs (user_id, action, ip_address, user_agent, metadata, success)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [user.id, 'signup', req.ip, req.get('user-agent'), JSON.stringify({ method: 'local' }), true]
  );
  
  logger.info(`New user signup: ${user.id}`);
  
  res.status(201).json({
    success: true,
    data: {
      userId: user.id,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresIn: tokens.expiresIn
    }
  });
};

// Login controller
const login = async (req, res) => {
  const { error, value } = loginSchema.validate(req.body);
  
  if (error) {
    return res.status(400).json({
      success: false,
      error: error.details[0].message
    });
  }
  
  const { email, password } = value;
  
  // Verify credentials
  const user = await User.verifyPassword(email, password);
  
  if (!user) {
    // Log failed attempt
    await pool.query(
      `INSERT INTO audit_logs (action, ip_address, user_agent, metadata, success)
       VALUES ($1, $2, $3, $4, $5)`,
      ['login', req.ip, req.get('user-agent'), JSON.stringify({ email, reason: 'invalid_credentials' }), false]
    );
    
    return res.status(401).json({
      success: false,
      error: 'Invalid email or password'
    });
  }
  
  // Update last login
  await User.updateLastLogin(user.id);
  
  // Generate tokens
  const tokens = await generateTokenPair(user, req.ip, req.get('user-agent'));
  
  // Log successful login
  await pool.query(
    `INSERT INTO audit_logs (user_id, action, ip_address, user_agent, metadata, success)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [user.id, 'login', req.ip, req.get('user-agent'), JSON.stringify({ method: 'local' }), true]
  );
  
  logger.info(`User login: ${user.id}`);
  
  res.json({
    success: true,
    data: {
      userId: user.id,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresIn: tokens.expiresIn
    }
  });
};

// Forgot password controller
const forgotPassword = async (req, res) => {
  const { error, value } = forgotPasswordSchema.validate(req.body);
  
  if (error) {
    return res.status(400).json({
      success: false,
      error: error.details[0].message
    });
  }
  
  const { email } = value;
  
  const user = await User.findByEmail(email);
  
  // Always return success to prevent email enumeration
  if (!user) {
    logger.warn(`Password reset requested for non-existent email: ${email}`);
    return res.json({
      success: true,
      message: 'If the email exists, a password reset link has been sent'
    });
  }
  
  // Generate reset token
  const resetToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
  const expiresAt = new Date(Date.now() + 3600000); // 1 hour
  
  // Save token to database
  await pool.query(
    `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
     VALUES ($1, $2, $3)`,
    [user.id, tokenHash, expiresAt]
  );
  
  // Send email
  const resetUrl = `${process.env.FRONTEND_SUCCESS_URL}/reset-password?token=${resetToken}`;
  
  if (process.env.SENDGRID_API_KEY) {
    try {
      await sgMail.send({
        to: email,
        from: {
          email: process.env.FROM_EMAIL,
          name: process.env.FROM_NAME || 'Auth Server'
        },
        subject: 'Password Reset Request',
        html: `
          <h2>Password Reset</h2>
          <p>You requested a password reset. Click the link below to reset your password:</p>
          <p><a href="${resetUrl}">Reset Password</a></p>
          <p>This link expires in 1 hour.</p>
          <p>If you didn't request this, please ignore this email.</p>
        `
      });
      
      logger.info(`Password reset email sent to ${email}`);
    } catch (error) {
      logger.error('Failed to send reset email:', error);
    }
  } else {
    logger.warn(`Email service not configured. Reset token: ${resetToken}`);
  }
  
  // Log audit
  await pool.query(
    `INSERT INTO audit_logs (user_id, action, ip_address, user_agent, success)
     VALUES ($1, $2, $3, $4, $5)`,
    [user.id, 'password_reset_request', req.ip, req.get('user-agent'), true]
  );
  
  res.json({
    success: true,
    message: 'If the email exists, a password reset link has been sent'
  });
};

// Reset password controller
const resetPassword = async (req, res) => {
  const { error, value } = resetPasswordSchema.validate(req.body);
  
  if (error) {
    return res.status(400).json({
      success: false,
      error: error.details[0].message
    });
  }
  
  const { token, newPassword } = value;
  
  // Validate password strength
  const passwordValidation = validatePasswordStrength(newPassword);
  if (!passwordValidation.valid) {
    return res.status(400).json({
      success: false,
      error: 'Password does not meet requirements',
      details: passwordValidation.errors
    });
  }
  
  // Hash token and find it
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  
  const result = await pool.query(
    `SELECT user_id FROM password_reset_tokens
     WHERE token_hash = $1 AND expires_at > NOW() AND used = false`,
    [tokenHash]
  );
  
  if (result.rows.length === 0) {
    return res.status(400).json({
      success: false,
      error: 'Invalid or expired reset token'
    });
  }
  
  const userId = result.rows[0].user_id;
  
  // Update password
  await User.updatePassword(userId, newPassword);
  
  // Mark token as used
  await pool.query(
    `UPDATE password_reset_tokens
     SET used = true
     WHERE token_hash = $1`,
    [tokenHash]
  );
  
  // Log audit
  await pool.query(
    `INSERT INTO audit_logs (user_id, action, ip_address, user_agent, success)
     VALUES ($1, $2, $3, $4, $5)`,
    [userId, 'password_reset_complete', req.ip, req.get('user-agent'), true]
  );
  
  logger.info(`Password reset completed for user: ${userId}`);
  
  res.json({
    success: true,
    message: 'Password reset successful'
  });
};

// Refresh token controller
const refreshToken = async (req, res) => {
  const { error, value } = refreshTokenSchema.validate(req.body);
  
  if (error) {
    return res.status(400).json({
      success: false,
      error: error.details[0].message
    });
  }
  
  const { refreshToken: token } = value;
  
  // Verify token
  let decoded;
  try {
    decoded = verifyRefreshToken(token);
  } catch (err) {
    return res.status(401).json({
      success: false,
      error: 'Invalid refresh token'
    });
  }
  
  // Check if token is revoked
  const revoked = await isRefreshTokenRevoked(token);
  if (revoked) {
    return res.status(401).json({
      success: false,
      error: 'Refresh token has been revoked'
    });
  }
  
  // Get user
  const user = await User.findById(decoded.userId);
  if (!user) {
    return res.status(401).json({
      success: false,
      error: 'User not found'
    });
  }
  
  // Revoke old token
  await revokeRefreshToken(token);
  
  // Generate new token pair
  const tokens = await generateTokenPair(user, req.ip, req.get('user-agent'));
  
  logger.info(`Token refreshed for user: ${user.id}`);
  
  res.json({
    success: true,
    data: {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresIn: tokens.expiresIn
    }
  });
};

// Logout controller
const logout = async (req, res) => {
  const { refreshToken: token } = req.body;
  
  if (token) {
    await revokeRefreshToken(token);
  }
  
  // Log audit
  await pool.query(
    `INSERT INTO audit_logs (user_id, action, ip_address, user_agent, success)
     VALUES ($1, $2, $3, $4, $5)`,
    [req.user.userId, 'logout', req.ip, req.get('user-agent'), true]
  );
  
  logger.info(`User logout: ${req.user.userId}`);
  
  res.json({
    success: true,
    message: 'Logged out successfully'
  });
};

// Validate token controller
const validate = async (req, res) => {
  res.json({
    success: true,
    data: {
      userId: req.user.userId,
      email: req.user.email,
      phone: req.user.phone,
      provider: req.user.provider,
      iat: req.user.iat,
      exp: req.user.exp
    }
  });
};

module.exports = {
  signup,
  login,
  forgotPassword,
  resetPassword,
  refreshToken,
  logout,
  validate
};