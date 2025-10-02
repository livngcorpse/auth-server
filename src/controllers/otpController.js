const Joi = require('joi');
const OTP = require('../models/OTP');
const User = require('../models/User');
const { sendOTP, validatePhoneNumber } = require('../utils/otp');
const { generateTokenPair } = require('../utils/jwt');
const { pool } = require('../config/database');
const logger = require('../utils/logger');

// Validation schemas
const requestOtpSchema = Joi.object({
  phone: Joi.string().pattern(/^\+[1-9]\d{1,14}$/).required()
    .messages({
      'string.pattern.base': 'Phone number must be in E.164 format (e.g., +1234567890)'
    })
});

const verifyOtpSchema = Joi.object({
  phone: Joi.string().pattern(/^\+[1-9]\d{1,14}$/).required(),
  code: Joi.string().pattern(/^\d{4,8}$/).required()
});

// Request OTP controller
const requestOtp = async (req, res) => {
  const { error, value } = requestOtpSchema.validate(req.body);
  
  if (error) {
    return res.status(400).json({
      success: false,
      error: error.details[0].message
    });
  }
  
  const { phone } = value;
  
  // Validate phone number format
  if (!validatePhoneNumber(phone)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid phone number format'
    });
  }
  
  // Invalidate any existing OTPs for this phone
  await OTP.invalidateAllForPhone(phone);
  
  // Generate new OTP
  const otp = await OTP.create(phone);
  
  // Send OTP via SMS
  const sendResult = await sendOTP(phone, otp.code);
  
  if (!sendResult.success) {
    logger.error(`Failed to send OTP to ${phone}: ${sendResult.message}`);
    return res.status(500).json({
      success: false,
      error: 'Failed to send OTP. Please try again.'
    });
  }
  
  // Log audit
  await pool.query(
    `INSERT INTO audit_logs (action, ip_address, user_agent, metadata, success)
     VALUES ($1, $2, $3, $4, $5)`,
    ['otp_request', req.ip, req.get('user-agent'), JSON.stringify({ phone }), true]
  );
  
  logger.info(`OTP sent to ${phone}`);
  
  res.json({
    success: true,
    message: 'OTP sent to phone',
    expiresIn: parseInt(process.env.OTP_EXPIRY_MINUTES || 5) * 60
  });
};

// Verify OTP controller
const verifyOtp = async (req, res) => {
  const { error, value } = verifyOtpSchema.validate(req.body);
  
  if (error) {
    return res.status(400).json({
      success: false,
      error: error.details[0].message
    });
  }
  
  const { phone, code } = value;
  
  // Find valid OTP
  const otp = await OTP.findValid(phone, code);
  
  if (!otp) {
    // Increment attempts for any existing OTP
    const anyOtp = await pool.query(
      `SELECT id FROM otp_codes
       WHERE phone = $1 AND used = false AND expires_at > NOW()
       ORDER BY created_at DESC LIMIT 1`,
      [phone]
    );
    
    if (anyOtp.rows.length > 0) {
      await OTP.incrementAttempts(anyOtp.rows[0].id);
    }
    
    // Log failed attempt
    await pool.query(
      `INSERT INTO audit_logs (action, ip_address, user_agent, metadata, success)
       VALUES ($1, $2, $3, $4, $5)`,
      ['otp_verify', req.ip, req.get('user-agent'), JSON.stringify({ phone, reason: 'invalid_code' }), false]
    );
    
    return res.status(401).json({
      success: false,
      error: 'Invalid or expired OTP'
    });
  }
  
  // Mark OTP as used
  await OTP.markAsUsed(otp.id);
  
  // Find or create user
  let user = await User.findByPhone(phone);
  
  if (!user) {
    user = await User.create({
      phone,
      provider_type: 'otp',
      phone_verified: true
    });
    
    logger.info(`New OTP user created: ${user.id}`);
  } else {
    // Update last login and verify phone
    await User.updateLastLogin(user.id);
    if (!user.phone_verified) {
      await User.verifyPhone(user.id);
    }
  }
  
  // Generate tokens
  const tokens = await generateTokenPair(user, req.ip, req.get('user-agent'));
  
  // Log successful verification
  await pool.query(
    `INSERT INTO audit_logs (user_id, action, ip_address, user_agent, metadata, success)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [user.id, 'otp_verify', req.ip, req.get('user-agent'), JSON.stringify({ phone }), true]
  );
  
  logger.info(`OTP verified for user: ${user.id}`);
  
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

module.exports = {
  requestOtp,
  verifyOtp
};