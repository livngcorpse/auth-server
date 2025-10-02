const Joi = require('joi');
const User = require('../models/User');
const { validatePasswordStrength } = require('../utils/password');
const { pool } = require('../config/database');
const { revokeAllUserTokens } = require('../utils/jwt');
const logger = require('../utils/logger');

// Validation schemas
const updateProfileSchema = Joi.object({
  email: Joi.string().email().optional(),
  phone: Joi.string().pattern(/^\+[1-9]\d{1,14}$/).optional()
}).min(1);

const changePasswordSchema = Joi.object({
  currentPassword: Joi.string().required(),
  newPassword: Joi.string().min(8).required()
});

// Get current user profile
const getProfile = async (req, res) => {
  const user = await User.findById(req.user.userId);
  
  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }
  
  res.json({
    success: true,
    data: {
      id: user.id,
      email: user.email,
      phone: user.phone,
      provider: user.provider_type,
      emailVerified: user.email_verified,
      phoneVerified: user.phone_verified,
      isActive: user.is_active,
      lastLogin: user.last_login,
      createdAt: user.created_at
    }
  });
};

// Update user profile
const updateProfile = async (req, res) => {
  const { error, value } = updateProfileSchema.validate(req.body);
  
  if (error) {
    return res.status(400).json({
      success: false,
      error: error.details[0].message
    });
  }
  
  const userId = req.user.userId;
  const updates = [];
  const values = [];
  let paramIndex = 1;
  
  if (value.email) {
    // Check if email is already taken
    const existingUser = await User.findByEmail(value.email);
    if (existingUser && existingUser.id !== userId) {
      return res.status(409).json({
        success: false,
        error: 'Email already in use'
      });
    }
    
    updates.push(`email = $${paramIndex++}`);
    updates.push(`email_verified = false`); // Reset verification on email change
    values.push(value.email.toLowerCase());
  }
  
  if (value.phone) {
    // Check if phone is already taken
    const existingUser = await User.findByPhone(value.phone);
    if (existingUser && existingUser.id !== userId) {
      return res.status(409).json({
        success: false,
        error: 'Phone number already in use'
      });
    }
    
    updates.push(`phone = $${paramIndex++}`);
    updates.push(`phone_verified = false`); // Reset verification on phone change
    values.push(value.phone);
  }
  
  if (updates.length === 0) {
    return res.status(400).json({
      success: false,
      error: 'No valid updates provided'
    });
  }
  
  updates.push('updated_at = NOW()');
  values.push(userId);
  
  await pool.query(
    `UPDATE users SET ${updates.join(', ')} WHERE id = $${paramIndex}`,
    values
  );
  
  // Log audit
  await pool.query(
    `INSERT INTO audit_logs (user_id, action, ip_address, user_agent, metadata, success)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [userId, 'profile_update', req.ip, req.get('user-agent'), JSON.stringify(value), true]
  );
  
  logger.info(`Profile updated for user: ${userId}`);
  
  // Fetch updated user
  const updatedUser = await User.findById(userId);
  
  res.json({
    success: true,
    message: 'Profile updated successfully',
    data: {
      id: updatedUser.id,
      email: updatedUser.email,
      phone: updatedUser.phone,
      emailVerified: updatedUser.email_verified,
      phoneVerified: updatedUser.phone_verified
    }
  });
};

// Change password
const changePassword = async (req, res) => {
  const { error, value } = changePasswordSchema.validate(req.body);
  
  if (error) {
    return res.status(400).json({
      success: false,
      error: error.details[0].message
    });
  }
  
  const { currentPassword, newPassword } = value;
  const userId = req.user.userId;
  
  // Get user
  const user = await User.findById(userId);
  
  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }
  
  // Check if user has password (not OAuth-only)
  if (!user.password_hash) {
    return res.status(400).json({
      success: false,
      error: 'Password change not available for OAuth accounts'
    });
  }
  
  // Verify current password
  const { verifyPassword } = require('../utils/password');
  const isValid = await verifyPassword(currentPassword, user.password_hash);
  
  if (!isValid) {
    // Log failed attempt
    await pool.query(
      `INSERT INTO audit_logs (user_id, action, ip_address, user_agent, success)
       VALUES ($1, $2, $3, $4, $5)`,
      [userId, 'password_change', req.ip, req.get('user-agent'), false]
    );
    
    return res.status(401).json({
      success: false,
      error: 'Current password is incorrect'
    });
  }
  
  // Validate new password strength
  const passwordValidation = validatePasswordStrength(newPassword);
  if (!passwordValidation.valid) {
    return res.status(400).json({
      success: false,
      error: 'New password does not meet requirements',
      details: passwordValidation.errors
    });
  }
  
  // Update password
  await User.updatePassword(userId, newPassword);
  
  // Revoke all refresh tokens (force re-login on all devices)
  await revokeAllUserTokens(userId);
  
  // Log successful change
  await pool.query(
    `INSERT INTO audit_logs (user_id, action, ip_address, user_agent, success)
     VALUES ($1, $2, $3, $4, $5)`,
    [userId, 'password_change', req.ip, req.get('user-agent'), true]
  );
  
  logger.info(`Password changed for user: ${userId}`);
  
  res.json({
    success: true,
    message: 'Password changed successfully. Please login again.'
  });
};

// Delete account
const deleteAccount = async (req, res) => {
  const userId = req.user.userId;
  
  // Deactivate user instead of hard delete
  await User.deactivate(userId);
  
  // Revoke all tokens
  await revokeAllUserTokens(userId);
  
  // Log audit
  await pool.query(
    `INSERT INTO audit_logs (user_id, action, ip_address, user_agent, success)
     VALUES ($1, $2, $3, $4, $5)`,
    [userId, 'account_delete', req.ip, req.get('user-agent'), true]
  );
  
  logger.info(`Account deleted for user: ${userId}`);
  
  res.json({
    success: true,
    message: 'Account deleted successfully'
  });
};

// Get user sessions (active refresh tokens)
const getSessions = async (req, res) => {
  const userId = req.user.userId;
  
  const result = await pool.query(
    `SELECT id, ip_address, user_agent, created_at, expires_at, revoked
     FROM refresh_tokens
     WHERE user_id = $1 AND expires_at > NOW()
     ORDER BY created_at DESC`,
    [userId]
  );
  
  res.json({
    success: true,
    data: {
      sessions: result.rows.map(row => ({
        id: row.id,
        ipAddress: row.ip_address,
        userAgent: row.user_agent,
        createdAt: row.created_at,
        expiresAt: row.expires_at,
        isActive: !row.revoked
      }))
    }
  });
};

// Revoke specific session
const revokeSession = async (req, res) => {
  const userId = req.user.userId;
  const { sessionId } = req.params;
  
  const result = await pool.query(
    `UPDATE refresh_tokens
     SET revoked = true
     WHERE id = $1 AND user_id = $2 AND revoked = false
     RETURNING id`,
    [sessionId, userId]
  );
  
  if (result.rows.length === 0) {
    return res.status(404).json({
      success: false,
      error: 'Session not found'
    });
  }
  
  logger.info(`Session ${sessionId} revoked for user: ${userId}`);
  
  res.json({
    success: true,
    message: 'Session revoked successfully'
  });
};

// Revoke all sessions except current
const revokeAllSessions = async (req, res) => {
  const userId = req.user.userId;
  
  // Get current token from header
  const token = req.headers.authorization?.split(' ')[1];
  const crypto = require('crypto');
  const currentTokenHash = crypto.createHash('sha256').update(token || '').digest('hex');
  
  await pool.query(
    `UPDATE refresh_tokens
     SET revoked = true
     WHERE user_id = $1 AND token_hash != $2 AND revoked = false`,
    [userId, currentTokenHash]
  );
  
  logger.info(`All sessions revoked (except current) for user: ${userId}`);
  
  res.json({
    success: true,
    message: 'All other sessions revoked successfully'
  });
};

module.exports = {
  getProfile,
  updateProfile,
  changePassword,
  deleteAccount,
  getSessions,
  revokeSession,
  revokeAllSessions
};