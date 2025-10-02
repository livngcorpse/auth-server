const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const User = require('../models/User');
const logger = require('../utils/logger');

// Google OAuth Strategy
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL,
    scope: ['profile', 'email']
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.emails[0].value;
      const providerId = profile.id;
      
      let user = await User.findByProvider('google', providerId);
      
      if (!user) {
        // Check if email already exists with different provider
        const existingUser = await User.findByEmail(email);
        if (existingUser) {
          return done(null, false, { 
            message: 'Email already registered with different provider' 
          });
        }
        
        // Create new user
        user = await User.create({
          email,
          provider_type: 'google',
          provider_id: providerId,
          email_verified: true
        });
        
        logger.info(`New Google user created: ${user.id}`);
      } else {
        await User.updateLastLogin(user.id);
      }
      
      return done(null, user);
    } catch (error) {
      logger.error('Google OAuth error:', error);
      return done(error, null);
    }
  }));
}

// GitHub OAuth Strategy
if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: process.env.GITHUB_CALLBACK_URL,
    scope: ['user:email']
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.emails?.[0]?.value;
      const providerId = profile.id;
      
      if (!email) {
        return done(null, false, { 
          message: 'GitHub account must have a public email' 
        });
      }
      
      let user = await User.findByProvider('github', providerId);
      
      if (!user) {
        const existingUser = await User.findByEmail(email);
        if (existingUser) {
          return done(null, false, { 
            message: 'Email already registered with different provider' 
          });
        }
        
        user = await User.create({
          email,
          provider_type: 'github',
          provider_id: providerId,
          email_verified: true
        });
        
        logger.info(`New GitHub user created: ${user.id}`);
      } else {
        await User.updateLastLogin(user.id);
      }
      
      return done(null, user);
    } catch (error) {
      logger.error('GitHub OAuth error:', error);
      return done(error, null);
    }
  }));
}

module.exports = passport;