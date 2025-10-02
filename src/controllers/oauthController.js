const passport = require('passport');
const { generateTokenPair } = require('../utils/jwt');
const { pool } = require('../config/database');
const logger = require('../utils/logger');

// Google OAuth callback
const googleCallback = async (req, res) => {
  try {
    if (!req.user) {
      const errorUrl = `${process.env.FRONTEND_ERROR_URL}?error=oauth_failed`;
      return res.redirect(errorUrl);
    }
    
    const user = req.user;
    
    // Generate tokens
    const tokens = await generateTokenPair(user, req.ip, req.get('user-agent'));
    
    // Log audit
    await pool.query(
      `INSERT INTO audit_logs (user_id, action, ip_address, user_agent, metadata, success)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [user.id, 'login', req.ip, req.get('user-agent'), JSON.stringify({ method: 'google' }), true]
    );
    
    logger.info(`User logged in via Google: ${user.id}`);
    
    // Redirect to frontend with tokens
    const successUrl = `${process.env.FRONTEND_SUCCESS_URL}?accessToken=${tokens.accessToken}&refreshToken=${tokens.refreshToken}&expiresIn=${tokens.expiresIn}`;
    res.redirect(successUrl);
  } catch (error) {
    logger.error('Google OAuth callback error:', error);
    const errorUrl = `${process.env.FRONTEND_ERROR_URL}?error=server_error`;
    res.redirect(errorUrl);
  }
};

// GitHub OAuth callback
const githubCallback = async (req, res) => {
  try {
    if (!req.user) {
      const errorUrl = `${process.env.FRONTEND_ERROR_URL}?error=oauth_failed`;
      return res.redirect(errorUrl);
    }
    
    const user = req.user;
    
    // Generate tokens
    const tokens = await generateTokenPair(user, req.ip, req.get('user-agent'));
    
    // Log audit
    await pool.query(
      `INSERT INTO audit_logs (user_id, action, ip_address, user_agent, metadata, success)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [user.id, 'login', req.ip, req.get('user-agent'), JSON.stringify({ method: 'github' }), true]
    );
    
    logger.info(`User logged in via GitHub: ${user.id}`);
    
    // Redirect to frontend with tokens
    const successUrl = `${process.env.FRONTEND_SUCCESS_URL}?accessToken=${tokens.accessToken}&refreshToken=${tokens.refreshToken}&expiresIn=${tokens.expiresIn}`;
    res.redirect(successUrl);
  } catch (error) {
    logger.error('GitHub OAuth callback error:', error);
    const errorUrl = `${process.env.FRONTEND_ERROR_URL}?error=server_error`;
    res.redirect(errorUrl);
  }
};

// OAuth error handler
const oauthError = (err, req, res, next) => {
  logger.error('OAuth error:', err);
  const errorUrl = `${process.env.FRONTEND_ERROR_URL}?error=${encodeURIComponent(err.message)}`;
  res.redirect(errorUrl);
};

module.exports = {
  googleCallback,
  githubCallback,
  oauthError
};