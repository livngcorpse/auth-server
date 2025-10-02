const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { pool } = require('../config/database');

const generateAccessToken = (payload) => {
  return jwt.sign(
    payload,
    process.env.JWT_ACCESS_SECRET,
    { 
      expiresIn: process.env.JWT_ACCESS_EXPIRY || '15m',
      algorithm: 'HS256'
    }
  );
};

const generateRefreshToken = (payload) => {
  return jwt.sign(
    payload,
    process.env.JWT_REFRESH_SECRET,
    { 
      expiresIn: process.env.JWT_REFRESH_EXPIRY || '7d',
      algorithm: 'HS256'
    }
  );
};

const verifyAccessToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_ACCESS_SECRET);
  } catch (error) {
    throw new Error('Invalid or expired access token');
  }
};

const verifyRefreshToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_REFRESH_SECRET);
  } catch (error) {
    throw new Error('Invalid or expired refresh token');
  }
};

const hashToken = (token) => {
  return crypto.createHash('sha256').update(token).digest('hex');
};

const saveRefreshToken = async (userId, token, ipAddress, userAgent) => {
  const tokenHash = hashToken(token);
  const decoded = jwt.decode(token);
  const expiresAt = new Date(decoded.exp * 1000);
  
  await pool.query(
    `INSERT INTO refresh_tokens (user_id, token_hash, expires_at, ip_address, user_agent)
     VALUES ($1, $2, $3, $4, $5)`,
    [userId, tokenHash, expiresAt, ipAddress, userAgent]
  );
};

const isRefreshTokenRevoked = async (token) => {
  const tokenHash = hashToken(token);
  
  const result = await pool.query(
    `SELECT revoked FROM refresh_tokens
     WHERE token_hash = $1 AND expires_at > NOW()`,
    [tokenHash]
  );
  
  if (result.rows.length === 0) {
    return true; // Token not found, consider it revoked
  }
  
  return result.rows[0].revoked;
};

const revokeRefreshToken = async (token) => {
  const tokenHash = hashToken(token);
  
  await pool.query(
    `UPDATE refresh_tokens
     SET revoked = true
     WHERE token_hash = $1`,
    [tokenHash]
  );
};

const revokeAllUserTokens = async (userId) => {
  await pool.query(
    `UPDATE refresh_tokens
     SET revoked = true
     WHERE user_id = $1 AND revoked = false`,
    [userId]
  );
};

const cleanupExpiredTokens = async () => {
  const result = await pool.query(
    `DELETE FROM refresh_tokens
     WHERE expires_at < NOW() - INTERVAL '30 days'
     RETURNING id`
  );
  
  return result.rowCount;
};

const generateTokenPair = async (user, ipAddress, userAgent) => {
  const payload = {
    userId: user.id,
    email: user.email,
    phone: user.phone,
    provider: user.provider_type
  };
  
  const accessToken = generateAccessToken(payload);
  const refreshToken = generateRefreshToken({ userId: user.id });
  
  await saveRefreshToken(user.id, refreshToken, ipAddress, userAgent);
  
  return {
    accessToken,
    refreshToken,
    expiresIn: 900 // 15 minutes in seconds
  };
};

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  saveRefreshToken,
  isRefreshTokenRevoked,
  revokeRefreshToken,
  revokeAllUserTokens,
  cleanupExpiredTokens,
  generateTokenPair
};