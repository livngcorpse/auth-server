const { pool } = require('../config/database');
const { hashPassword, verifyPassword } = require('../utils/password');
const logger = require('../utils/logger');

class User {
  static async create({ email, password, phone, provider_type, provider_id, email_verified = false, phone_verified = false }) {
    const client = await pool.connect();
    
    try {
      let passwordHash = null;
      
      if (password) {
        passwordHash = await hashPassword(password);
      }
      
      const result = await client.query(
        `INSERT INTO users (email, phone, password_hash, provider_type, provider_id, email_verified, phone_verified)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id, email, phone, provider_type, email_verified, phone_verified, created_at`,
        [email, phone, passwordHash, provider_type, provider_id, email_verified, phone_verified]
      );
      
      return result.rows[0];
    } finally {
      client.release();
    }
  }
  
  static async findByEmail(email) {
    if (!email) return null;
    
    const result = await pool.query(
      `SELECT id, email, phone, password_hash, provider_type, provider_id, 
              email_verified, phone_verified, is_active, last_login, created_at
       FROM users 
       WHERE email = $1 AND is_active = true`,
      [email.toLowerCase()]
    );
    
    return result.rows[0] || null;
  }
  
  static async findByPhone(phone) {
    if (!phone) return null;
    
    const result = await pool.query(
      `SELECT id, email, phone, password_hash, provider_type, provider_id, 
              email_verified, phone_verified, is_active, last_login, created_at
       FROM users 
       WHERE phone = $1 AND is_active = true`,
      [phone]
    );
    
    return result.rows[0] || null;
  }
  
  static async findById(id) {
    const result = await pool.query(
      `SELECT id, email, phone, provider_type, email_verified, phone_verified, 
              is_active, last_login, created_at
       FROM users 
       WHERE id = $1 AND is_active = true`,
      [id]
    );
    
    return result.rows[0] || null;
  }
  
  static async findByProvider(providerType, providerId) {
    const result = await pool.query(
      `SELECT id, email, phone, provider_type, provider_id, 
              email_verified, phone_verified, is_active, last_login, created_at
       FROM users 
       WHERE provider_type = $1 AND provider_id = $2 AND is_active = true`,
      [providerType, providerId]
    );
    
    return result.rows[0] || null;
  }
  
  static async verifyPassword(email, password) {
    const user = await this.findByEmail(email);
    
    if (!user || !user.password_hash) {
      return null;
    }
    
    const isValid = await verifyPassword(password, user.password_hash);
    
    if (!isValid) {
      return null;
    }
    
    return user;
  }
  
  static async updatePassword(userId, newPassword) {
    const passwordHash = await hashPassword(newPassword);
    
    await pool.query(
      `UPDATE users 
       SET password_hash = $1, updated_at = NOW()
       WHERE id = $2`,
      [passwordHash, userId]
    );
  }
  
  static async updateLastLogin(userId) {
    await pool.query(
      `UPDATE users 
       SET last_login = NOW(), updated_at = NOW()
       WHERE id = $1`,
      [userId]
    );
  }
  
  static async verifyEmail(userId) {
    await pool.query(
      `UPDATE users 
       SET email_verified = true, updated_at = NOW()
       WHERE id = $1`,
      [userId]
    );
  }
  
  static async verifyPhone(userId) {
    await pool.query(
      `UPDATE users 
       SET phone_verified = true, updated_at = NOW()
       WHERE id = $1`,
      [userId]
    );
  }
  
  static async deactivate(userId) {
    await pool.query(
      `UPDATE users 
       SET is_active = false, updated_at = NOW()
       WHERE id = $1`,
      [userId]
    );
  }
}

module.exports = User;