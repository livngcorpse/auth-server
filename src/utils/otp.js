const crypto = require('crypto');
const twilio = require('twilio');
const logger = require('./logger');

const twilioClient = process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN
  ? twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN)
  : null;

const generateOTP = () => {
  const length = parseInt(process.env.OTP_LENGTH) || 6;
  const max = Math.pow(10, length) - 1;
  const min = Math.pow(10, length - 1);
  
  return crypto.randomInt(min, max + 1).toString();
};

const sendOTP = async (phone, code) => {
  if (!twilioClient) {
    logger.warn('Twilio not configured, OTP not sent. Code:', code);
    return { success: false, message: 'SMS service not configured' };
  }
  
  try {
    const message = await twilioClient.messages.create({
      body: `Your verification code is: ${code}. Valid for ${process.env.OTP_EXPIRY_MINUTES || 5} minutes.`,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: phone
    });
    
    logger.info(`OTP sent to ${phone}, SID: ${message.sid}`);
    return { success: true, messageSid: message.sid };
  } catch (error) {
    logger.error('Failed to send OTP:', error);
    return { success: false, message: error.message };
  }
};

const validatePhoneNumber = (phone) => {
  // Basic E.164 format validation
  const phoneRegex = /^\+[1-9]\d{1,14}$/;
  return phoneRegex.test(phone);
};

module.exports = {
  generateOTP,
  sendOTP,
  validatePhoneNumber
};