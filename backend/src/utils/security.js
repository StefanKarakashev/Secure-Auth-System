import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { promisify } from 'util';

/**
 * PRODUCTION-GRADE SECURITY UTILITIES
 * 
 * This module contains all the security-related functions for our authentication system.
 * Each function is designed with production security best practices in mind.
 */

/**
 * PASSWORD SECURITY
 * 
 * Why we use bcrypt:
 * - Built-in salt generation (prevents rainbow table attacks)
 * - Adaptive hashing (can increase rounds as hardware improves)
 * - Time-constant comparison (prevents timing attacks)
 * - Widely audited and trusted
 */

export const hashPassword = async (password) => {
  try {
    const saltRounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
    
    // Higher rounds = more security but slower performance
    // 12 rounds is currently recommended for production (as of 2024)
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    return hashedPassword;
  } catch (error) {
    throw new Error('Password hashing failed');
  }
};

export const verifyPassword = async (password, hashedPassword) => {
  try {
    // bcrypt.compare is timing-attack resistant
    const isValid = await bcrypt.compare(password, hashedPassword);
    return isValid;
  } catch (error) {
    throw new Error('Password verification failed');
  }
};

/**
 * JWT TOKEN MANAGEMENT
 * 
 * We use separate secrets for different token types to limit damage if one is compromised.
 * Short-lived access tokens + long-lived refresh tokens = secure and user-friendly.
 */

export const generateAccessToken = (payload) => {
  try {
    return jwt.sign(
      payload,
      process.env.JWT_ACCESS_SECRET,
      { 
        expiresIn: process.env.JWT_ACCESS_EXPIRE || '15m',
        issuer: 'auth-system',
        audience: 'auth-system-users'
      }
    );
  } catch (error) {
    throw new Error('Access token generation failed');
  }
};

export const generateRefreshToken = (payload) => {
  try {
    return jwt.sign(
      payload,
      process.env.JWT_REFRESH_SECRET,
      { 
        expiresIn: process.env.JWT_REFRESH_EXPIRE || '7d',
        issuer: 'auth-system',
        audience: 'auth-system-users'
      }
    );
  } catch (error) {
    throw new Error('Refresh token generation failed');
  }
};

export const generatePasswordResetToken = (payload) => {
  try {
    return jwt.sign(
      payload,
      process.env.JWT_RESET_SECRET,
      { 
        expiresIn: process.env.JWT_RESET_EXPIRE || '1h',
        issuer: 'auth-system',
        audience: 'auth-system-users'
      }
    );
  } catch (error) {
    throw new Error('Password reset token generation failed');
  }
};

export const generateEmailVerificationToken = (payload) => {
  try {
    return jwt.sign(
      payload,
      process.env.JWT_EMAIL_SECRET,
      { 
        expiresIn: process.env.JWT_EMAIL_EXPIRE || '24h',
        issuer: 'auth-system',
        audience: 'auth-system-users'
      }
    );
  } catch (error) {
    throw new Error('Email verification token generation failed');
  }
};

/**
 * TOKEN VERIFICATION FUNCTIONS
 * 
 * These functions verify tokens and return the decoded payload.
 * They throw errors for invalid/expired tokens.
 */

export const verifyAccessToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_ACCESS_SECRET, {
      issuer: 'auth-system',
      audience: 'auth-system-users'
    });
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw new Error('Access token expired');
    } else if (error.name === 'JsonWebTokenError') {
      throw new Error('Invalid access token');
    }
    throw new Error('Token verification failed');
  }
};

export const verifyRefreshToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_REFRESH_SECRET, {
      issuer: 'auth-system',
      audience: 'auth-system-users'
    });
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw new Error('Refresh token expired');
    } else if (error.name === 'JsonWebTokenError') {
      throw new Error('Invalid refresh token');
    }
    throw new Error('Token verification failed');
  }
};

export const verifyPasswordResetToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_RESET_SECRET, {
      issuer: 'auth-system',
      audience: 'auth-system-users'
    });
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw new Error('Password reset token expired');
    } else if (error.name === 'JsonWebTokenError') {
      throw new Error('Invalid password reset token');
    }
    throw new Error('Token verification failed');
  }
};

export const verifyEmailVerificationToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_EMAIL_SECRET, {
      issuer: 'auth-system',
      audience: 'auth-system-users'
    });
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw new Error('Email verification token expired');
    } else if (error.name === 'JsonWebTokenError') {
      throw new Error('Invalid email verification token');
    }
    throw new Error('Token verification failed');
  }
};

/**
 * SECURE RANDOM TOKEN GENERATION
 * 
 * For tokens that don't need to be JWTs (like session IDs),
 * we use cryptographically secure random generation.
 */

export const generateSecureToken = (length = 32) => {
  return crypto.randomBytes(length).toString('hex');
};

export const generateSessionToken = () => {
  // Generate a longer token for session IDs
  return crypto.randomBytes(48).toString('hex');
};

/**
 * TIMING ATTACK PROTECTION
 * 
 * These functions help prevent timing attacks by ensuring operations
 * take consistent time regardless of whether they succeed or fail.
 */

export const safeCompare = async (a, b) => {
  // Use crypto.timingSafeEqual for timing-attack resistant comparison
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }
  
  if (a.length !== b.length) {
    return false;
  }
  
  const bufferA = Buffer.from(a);
  const bufferB = Buffer.from(b);
  
  return crypto.timingSafeEqual(bufferA, bufferB);
};

/**
 * HASH FUNCTIONS FOR STORING TOKENS
 * 
 * We hash tokens before storing them in the database.
 * This way, even if the database is compromised, tokens can't be used directly.
 */

export const hashToken = (token) => {
  return crypto.createHash('sha256').update(token).digest('hex');
};

/**
 * DEVICE FINGERPRINTING
 * 
 * Create a semi-unique identifier for user devices to help with session management.
 * This isn't perfect but helps identify suspicious activity.
 */

export const generateDeviceFingerprint = (userAgent, ip, additionalData = {}) => {
  const fingerprintData = {
    userAgent: userAgent || 'unknown',
    ip: ip || 'unknown',
    ...additionalData
  };
  
  const fingerprintString = JSON.stringify(fingerprintData);
  return crypto.createHash('sha256').update(fingerprintString).digest('hex');
};

/**
 * RATE LIMITING HELPERS
 * 
 * Functions to help with rate limiting and brute force protection.
 */

export const generateRateLimitKey = (identifier, action) => {
  return `ratelimit:${action}:${identifier}`;
};

/**
 * SECURE COOKIE OPTIONS
 * 
 * Cookie configuration for maximum security in production.
 */

export const getSecureCookieOptions = () => {
  return {
    httpOnly: true, // Prevent XSS attacks
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    sameSite: 'strict', // CSRF protection
    maxAge: process.env.SESSION_MAX_AGE || 24 * 60 * 60 * 1000, // 24 hours
    domain: process.env.COOKIE_DOMAIN, // Set domain if needed
    path: '/' // Available to entire application
  };
};

/**
 * INPUT SANITIZATION
 * 
 * Basic sanitization functions to prevent common attacks.
 */

export const sanitizeEmail = (email) => {
  if (typeof email !== 'string') return '';
  
  return email
    .toLowerCase()
    .trim()
    .replace(/\s+/g, '') // Remove all whitespace
    .slice(0, 320); // RFC 5321 email length limit
};

export const sanitizeString = (str, maxLength = 1000) => {
  if (typeof str !== 'string') return '';
  
  return str
    .trim()
    .slice(0, maxLength)
    .replace(/[\x00-\x1F\x7F]/g, ''); // Remove control characters
};

/**
 * PASSWORD STRENGTH VALIDATION
 * 
 * Check if password meets security requirements.
 */

export const validatePasswordStrength = (password) => {
  const minLength = 8;
  const maxLength = 128;
  
  const checks = {
    length: password.length >= minLength && password.length <= maxLength,
    lowercase: /[a-z]/.test(password),
    uppercase: /[A-Z]/.test(password),
    number: /\d/.test(password),
    symbol: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
  };
  
  const score = Object.values(checks).filter(Boolean).length;
  
  return {
    isValid: checks.length && score >= 3, // Must have length + 2 other criteria
    score,
    checks,
    feedback: {
      length: !checks.length ? `Password must be ${minLength}-${maxLength} characters` : null,
      complexity: score < 3 ? 'Password must contain at least 3 of: lowercase, uppercase, number, symbol' : null
    }
  };
}; 