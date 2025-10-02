const express = require('express');
const passport = require('passport');
const authController = require('../controllers/authController');
const oauthController = require('../controllers/oauthController');
const otpController = require('../controllers/otpController');
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

// Email/Password Authentication
router.post('/signup', signupLimiter, authController.signup);
router.post('/login', loginLimiter, authController.login);
router.post('/forgot-password', resetPasswordLimiter, authController.forgotPassword);
router.post('/reset-password', authController.resetPassword);
router.post('/refresh', authController.refreshToken);
router.post('/logout', validateToken, authController.logout);
router.post('/validate', validateToken, authController.validate);

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

// OTP Authentication
router.post('/otp/request', otpLimiter, otpController.requestOtp);
router.post('/otp/verify', otpController.verifyOtp);

module.exports = router;