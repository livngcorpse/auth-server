const { pool } = require('../config/database');
const { generateOTP } = require('../utils/otp');

class OTP {
  static async create(phone) {
    const code = generateOTP();
    const expiryMinutes = parseInt(process.env.OTP_EXPIRY_MINUTES) || 5;
    const expiresAt = new Date(Date.now() + expiryMinutes * 60 * 1000);
    
    const result = await pool.query(
      `INSERT INTO otp_codes (phone, code, expires_at)
       VALUES ($1, $2, $3)
       RETURNING id, phone, code, expires_at, created_at`,
      [phone, code, expiresAt]
    );
    
    return result.rows[0];
  }
  
  static async findValid(phone, code) {
    const result = await pool.query(
      `SELECT id, phone, code, expires_at, attempts, used
       FROM otp_codes
       WHERE phone = $1 
         AND code = $2 
         AND used = false 
         AND expires_at > NOW()
         AND attempts < $3
       ORDER BY created_at DESC
       LIMIT 1`,
      [phone, code, parseInt(process.env.OTP_MAX_ATTEMPTS) || 3]
    );
    
    return result.rows[0] || null;
  }
  
  static async incrementAttempts(otpId) {
    await pool.query(
      `UPDATE otp_codes 
       SET attempts = attempts + 1
       WHERE id = $1`,
      [otpId]
    );
  }
  
  static async markAsUsed(otpId) {
    await pool.query(
      `UPDATE otp_codes 
       SET used = true
       WHERE id = $1`,
      [otpId]
    );
  }
  
  static async invalidateAllForPhone(phone) {
    await pool.query(
      `UPDATE otp_codes 
       SET used = true
       WHERE phone = $1 AND used = false`,
      [phone]
    );
  }
  
  static async cleanupExpired() {
    const result = await pool.query(
      `DELETE FROM otp_codes 
       WHERE expires_at < NOW() - INTERVAL '1 day'
       RETURNING id`
    );
    
    return result.rowCount;
  }
}

module.exports = OTP;