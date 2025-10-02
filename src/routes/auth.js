const express = require('express');
const passport = require('passport');
const authController = require('../controllers/authController');
const oauthController = require('../controllers/oauthController');
const otpController = require('../controllers/otpController');
const emailController = require('../controllers/emailController');
const userController = require('../controllers/userController');
const validateToken = require('../middleware/validateToken');
const {
  loginLimiter,
  signupLimiter,
  otpLimiter,
  resetPasswordLimiter,
  generalLimiter
} = require('../middleware/rateLimiter');

const router = express.Router();

// Apply general rate limiter to all routes
router.use(generalLimiter);

// ==================== Authentication ====================

// Email/Password Authentication
router.post('/signup', signupLimiter, authController.signup);
router.post('/login', loginLimiter, authController.login);
router.post('/forgot-password', resetPasswordLimiter, authController.forgotPassword);
router.post('/reset-password', authController.resetPassword);
router.post('/refresh', authController.refreshToken);
router.post('/logout', validateToken, authController.logout);
router.post('/validate', validateToken, authController.validate);

// ==================== Email Verification ====================

router.post('/send-verification', emailController.sendVerificationEmail);
router.get('/verify-email', emailController.verifyEmail);
router.post('/resend-verification', validateToken, emailController.resendVerificationEmail);

// ==================== User Profile ====================

// Get current user
router.get('/me', validateToken, userController.getProfile);

// Update profile
router.patch('/me', validateToken, userController.updateProfile);

// Change password
router.post('/change-password', validateToken, userController.changePassword);

// Delete account
router.delete('/me', validateToken, userController.deleteAccount);

// ==================== Session Management ====================

// Get all sessions
router.get('/sessions', validateToken, userController.getSessions);

// Revoke specific session
router.delete('/sessions/:sessionId', validateToken, userController.revokeSession);

// Revoke all sessions except current
router.post('/sessions/revoke-all', validateToken, userController.revokeAllSessions);

// ==================== OAuth ====================

// Google OAuth
router.get('/google',
  passport.authenticate('google', { 
    scope: ['profile', 'email'],
    session: false
  })
);

router.get('/google/callback',
  passport.authenticate('google', { 
    session: false,
    failureRedirect: process.env.FRONTEND_ERROR_URL + '?error=google_auth_failed'
  }),
  oauthController.googleCallback
);

// GitHub OAuth
router.get('/github',
  passport.authenticate('github', { 
    scope: ['user:email'],
    session: false
  })
);

router.get('/github/callback',
  passport.authenticate('github', { 
    session: false,
    failureRedirect: process.env.FRONTEND_ERROR_URL + '?error=github_auth_failed'
  }),
  oauthController.githubCallback
);

// ==================== OTP Authentication ====================

router.post('/otp/request', otpLimiter, otpController.requestOtp);
router.post('/otp/verify', otpController.verifyOtp);

module.exports = router;