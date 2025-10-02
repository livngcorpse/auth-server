const Joi = require('joi');
const crypto = require('crypto');
const sgMail = require('@sendgrid/mail');
const { pool } = require('../config/database');
const User = require('../models/User');
const logger = require('../utils/logger');

// Initialize SendGrid
if (process.env.SENDGRID_API_KEY) {
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
}

// Validation schemas
const sendVerificationSchema = Joi.object({
  email: Joi.string().email().required()
});

const verifyEmailSchema = Joi.object({
  token: Joi.string().required()
});

// Send verification email
const sendVerificationEmail = async (req, res) => {
  const { error, value } = sendVerificationSchema.validate(req.body);
  
  if (error) {
    return res.status(400).json({
      success: false,
      error: error.details[0].message
    });
  }
  
  const { email } = value;
  
  const user = await User.findByEmail(email);
  
  if (!user) {
    // Don't reveal if email exists
    return res.json({
      success: true,
      message: 'If the email exists and is not verified, a verification link has been sent'
    });
  }
  
  if (user.email_verified) {
    return res.status(400).json({
      success: false,
      error: 'Email already verified'
    });
  }
  
  // Generate verification token
  const verificationToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(verificationToken).digest('hex');
  const expiresAt = new Date(Date.now() + 86400000); // 24 hours
  
  // Save token to database
  await pool.query(
    `INSERT INTO email_verification_tokens (user_id, token_hash, expires_at)
     VALUES ($1, $2, $3)
     ON CONFLICT (user_id) 
     DO UPDATE SET token_hash = $2, expires_at = $3, used = false, created_at = NOW()`,
    [user.id, tokenHash, expiresAt]
  );
  
  // Send email
  const verificationUrl = `${process.env.BASE_URL}/auth/verify-email?token=${verificationToken}`;
  
  if (process.env.SENDGRID_API_KEY) {
    try {
      await sgMail.send({
        to: email,
        from: {
          email: process.env.FROM_EMAIL,
          name: process.env.FROM_NAME || 'Auth Server'
        },
        subject: 'Verify Your Email Address',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #333;">Verify Your Email</h2>
            <p>Thank you for signing up! Please verify your email address by clicking the button below:</p>
            <div style="text-align: center; margin: 30px 0;">
              <a href="${verificationUrl}" 
                 style="background-color: #4CAF50; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
                Verify Email
              </a>
            </div>
            <p style="color: #666;">Or copy and paste this link in your browser:</p>
            <p style="color: #0066cc; word-break: break-all;">${verificationUrl}</p>
            <p style="color: #666; font-size: 14px;">This link expires in 24 hours.</p>
            <p style="color: #666; font-size: 14px;">If you didn't create an account, please ignore this email.</p>
          </div>
        `
      });
      
      logger.info(`Verification email sent to ${email}`);
    } catch (error) {
      logger.error('Failed to send verification email:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to send verification email'
      });
    }
  } else {
    logger.warn(`Email service not configured. Verification token: ${verificationToken}`);
  }
  
  // Log audit
  await pool.query(
    `INSERT INTO audit_logs (user_id, action, ip_address, user_agent, success)
     VALUES ($1, $2, $3, $4, $5)`,
    [user.id, 'email_verification_sent', req.ip, req.get('user-agent'), true]
  );
  
  res.json({
    success: true,
    message: 'Verification email sent'
  });
};

// Verify email with token
const verifyEmail = async (req, res) => {
  const { error, value } = verifyEmailSchema.validate(req.query);
  
  if (error) {
    return res.status(400).json({
      success: false,
      error: error.details[0].message
    });
  }
  
  const { token } = value;
  
  // Hash token and find it
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  
  const result = await pool.query(
    `SELECT user_id FROM email_verification_tokens
     WHERE token_hash = $1 AND expires_at > NOW() AND used = false`,
    [tokenHash]
  );
  
  if (result.rows.length === 0) {
    return res.status(400).json({
      success: false,
      error: 'Invalid or expired verification token'
    });
  }
  
  const userId = result.rows[0].user_id;
  
  // Verify email
  await User.verifyEmail(userId);
  
  // Mark token as used
  await pool.query(
    `UPDATE email_verification_tokens
     SET used = true
     WHERE token_hash = $1`,
    [tokenHash]
  );
  
  // Log audit
  await pool.query(
    `INSERT INTO audit_logs (user_id, action, ip_address, user_agent, success)
     VALUES ($1, $2, $3, $4, $5)`,
    [userId, 'email_verified', req.ip, req.get('user-agent'), true]
  );
  
  logger.info(`Email verified for user: ${userId}`);
  
  // Redirect to frontend success page
  if (process.env.FRONTEND_SUCCESS_URL) {
    return res.redirect(`${process.env.FRONTEND_SUCCESS_URL}?verified=true`);
  }
  
  res.json({
    success: true,
    message: 'Email verified successfully'
  });
};

// Resend verification email
const resendVerificationEmail = async (req, res) => {
  // Check if user is authenticated
  if (!req.user || !req.user.userId) {
    return res.status(401).json({
      success: false,
      error: 'Authentication required'
    });
  }
  
  const user = await User.findById(req.user.userId);
  
  if (!user) {
    return res.status(404).json({
      success: false,
      error: 'User not found'
    });
  }
  
  if (user.email_verified) {
    return res.status(400).json({
      success: false,
      error: 'Email already verified'
    });
  }
  
  if (!user.email) {
    return res.status(400).json({
      success: false,
      error: 'No email associated with this account'
    });
  }
  
  // Generate new verification token
  const verificationToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(verificationToken).digest('hex');
  const expiresAt = new Date(Date.now() + 86400000); // 24 hours
  
  // Save token to database
  await pool.query(
    `INSERT INTO email_verification_tokens (user_id, token_hash, expires_at)
     VALUES ($1, $2, $3)
     ON CONFLICT (user_id) 
     DO UPDATE SET token_hash = $2, expires_at = $3, used = false, created_at = NOW()`,
    [user.id, tokenHash, expiresAt]
  );
  
  // Send email
  const verificationUrl = `${process.env.BASE_URL}/auth/verify-email?token=${verificationToken}`;
  
  if (process.env.SENDGRID_API_KEY) {
    try {
      await sgMail.send({
        to: user.email,
        from: {
          email: process.env.FROM_EMAIL,
          name: process.env.FROM_NAME || 'Auth Server'
        },
        subject: 'Verify Your Email Address',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #333;">Verify Your Email</h2>
            <p>Please verify your email address by clicking the button below:</p>
            <div style="text-align: center; margin: 30px 0;">
              <a href="${verificationUrl}" 
                 style="background-color: #4CAF50; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">
                Verify Email
              </a>
            </div>
            <p style="color: #666;">Or copy and paste this link in your browser:</p>
            <p style="color: #0066cc; word-break: break-all;">${verificationUrl}</p>
            <p style="color: #666; font-size: 14px;">This link expires in 24 hours.</p>
          </div>
        `
      });
      
      logger.info(`Verification email resent to ${user.email}`);
    } catch (error) {
      logger.error('Failed to resend verification email:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to send verification email'
      });
    }
  }
  
  res.json({
    success: true,
    message: 'Verification email sent'
  });
};

module.exports = {
  sendVerificationEmail,
  verifyEmail,
  resendVerificationEmail
};