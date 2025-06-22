import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import slowDown from 'express-slow-down';
import User from '../models/User.js';
import SessionService from '../services/SessionService.js';
import { verifyAccessToken, generateAccessToken } from '../utils/security.js';
import { query } from '../config/database.js';

/**
 * AUTHENTICATION MIDDLEWARE
 * 
 * This file contains all authentication and authorization middleware.
 * Each middleware has a specific purpose and can be combined as needed.
 * 
 * Production considerations:
 * - Proper error handling and logging
 * - Rate limiting to prevent abuse
 * - Token validation and refresh
 * - Role-based access control
 * - IP and device tracking for security
 */

/**
 * EXTRACT TOKEN FROM REQUEST
 * 
 * Supports multiple token formats:
 * - Authorization header: "Bearer <token>"
 * - Cookie: "accessToken"
 * - Query parameter: "?token=<token>" (use sparingly, less secure)
 */
const extractToken = (req) => {
  // Check Authorization header first (most common)
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    return req.headers.authorization.substring(7);
  }
  
  // Check cookies (useful for browser-based apps)
  if (req.cookies && req.cookies.accessToken) {
    return req.cookies.accessToken;
  }
  
  // Check query parameter (least secure, use only when necessary)
  if (req.query && req.query.token) {
    return req.query.token;
  }
  
  return null;
};

/**
 * AUTHENTICATE USER MIDDLEWARE
 * 
 * Validates JWT token AND session status, adds user information to request.
 * This ensures immediate session revocation across all authenticated routes.
 * This is the core authentication middleware.
 */
export const authenticate = async (req, res, next) => {
  try {
    const token = extractToken(req);
    
    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access denied. No token provided.',
        code: 'NO_TOKEN'
      });
    }

    // Verify JWT token
    let decoded;
    try {
      decoded = verifyAccessToken(token);
    } catch (error) {
      // Handle different token errors
      if (error.message === 'Access token expired') {
        return res.status(401).json({
          success: false,
          message: 'Token expired. Please refresh your token.',
          code: 'TOKEN_EXPIRED'
        });
      } else if (error.message === 'Invalid access token') {
        return res.status(401).json({
          success: false,
          message: 'Invalid token.',
          code: 'INVALID_TOKEN'
        });
      }
      
      return res.status(401).json({
        success: false,
        message: 'Token verification failed.',
        code: 'TOKEN_VERIFICATION_FAILED'
      });
    }

    // Get user from database to ensure they still exist and are active
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User account not found or inactive.',
        code: 'USER_NOT_FOUND'
      });
    }

    // ALWAYS validate session status for immediate revocation capability
    if (decoded.sessionId) {
      try {
        // Check if session is still active
        const sessionResult = await query(
          'SELECT is_active FROM user_sessions WHERE id = $1 AND user_id = $2',
          [decoded.sessionId, decoded.userId]
        );

        if (sessionResult.rows.length === 0 || !sessionResult.rows[0].is_active) {
          console.log('🚫 Session revoked or not found:', { 
            sessionId: decoded.sessionId, 
            userId: decoded.userId 
          });
          
          return res.status(401).json({
            success: false,
            message: 'Session has been revoked. Please log in again.',
            code: 'SESSION_REVOKED'
          });
        }

        // Update session last_accessed time for activity tracking
        await query(
          'UPDATE user_sessions SET last_accessed = NOW() WHERE id = $1',
          [decoded.sessionId]
        );
        
      } catch (sessionError) {
        console.error('❌ Session validation error:', sessionError.message);
        return res.status(401).json({
          success: false,
          message: 'Session validation failed. Please log in again.',
          code: 'SESSION_VALIDATION_ERROR'
        });
      }
    }

    // Add user information to request object
    req.user = user;
    req.userId = user.id;
    req.userRole = user.role;
    req.sessionId = decoded.sessionId;
    
    // Track request for security monitoring
    req.authInfo = {
      tokenType: 'access',
      userId: user.id,
      role: user.role,
      sessionId: decoded.sessionId,
      issuedAt: new Date(decoded.iat * 1000),
      expiresAt: new Date(decoded.exp * 1000)
    };

    next();
    
  } catch (error) {
    console.error('❌ Authentication middleware error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Authentication error occurred.',
      code: 'AUTH_ERROR'
    });
  }
};

/**
 * AUTHENTICATE WITH SESSION VALIDATION
 * 
 * Validates JWT token AND checks if the associated session is still active.
 * This ensures revoked sessions are immediately invalidated.
 * Use this for routes that need immediate session revocation capability.
 */
export const authenticateWithSession = async (req, res, next) => {
  try {
    // First, run the standard JWT authentication
    await new Promise((resolve, reject) => {
      authenticate(req, res, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    // Now validate the session status if sessionId exists
    if (req.sessionId) {
      try {
        // Check if session is still active
        const sessionResult = await query(
          'SELECT is_active FROM user_sessions WHERE id = $1 AND user_id = $2',
          [req.sessionId, req.userId]
        );

        if (sessionResult.rows.length === 0 || !sessionResult.rows[0].is_active) {
          console.log('🚫 Session revoked or not found:', { 
            sessionId: req.sessionId, 
            userId: req.userId 
          });
          
          return res.status(401).json({
            success: false,
            message: 'Session has been revoked. Please log in again.',
            code: 'SESSION_REVOKED'
          });
        }

        // Update session last_accessed time
        await query(
          'UPDATE user_sessions SET last_accessed = NOW() WHERE id = $1',
          [req.sessionId]
        );
        
      } catch (sessionError) {
        console.error('❌ Session validation error:', sessionError.message);
        return res.status(401).json({
          success: false,
          message: 'Session validation failed. Please log in again.',
          code: 'SESSION_VALIDATION_ERROR'
        });
      }
    }

    next();
    
  } catch (error) {
    // Error from JWT authentication, pass it through
    return;
  }
};

/**
 * OPTIONAL AUTHENTICATION MIDDLEWARE
 * 
 * Like authenticate() but doesn't return error if no token is provided.
 * Useful for routes that work for both authenticated and unauthenticated users.
 */
export const optionalAuth = async (req, res, next) => {
  const token = extractToken(req);
  
  if (!token) {
    // No token provided, continue without authentication
    req.user = null;
    req.userId = null;
    req.userRole = null;
    return next();
  }
  
  // Token provided, try to authenticate
  try {
    const decoded = verifyAccessToken(token);
    const user = await User.findById(decoded.userId);
    
    if (user) {
      req.user = user;
      req.userId = user.id;
      req.userRole = user.role;
      req.sessionId = decoded.sessionId;
      req.authInfo = {
        tokenType: 'access',
        userId: user.id,
        role: user.role,
        sessionId: decoded.sessionId,
        issuedAt: new Date(decoded.iat * 1000),
        expiresAt: new Date(decoded.exp * 1000)
      };
    }
  } catch (error) {
    // Invalid token, but we don't return an error
    console.warn('⚠️ Optional auth failed:', error.message);
  }
  
  next();
};

/**
 * ROLE-BASED ACCESS CONTROL
 * 
 * Middleware factory that creates role-checking middleware.
 * Usage: requireRole('admin') or requireRole(['admin', 'moderator'])
 */
export const requireRole = (allowedRoles) => {
  // Ensure allowedRoles is an array
  const roles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];
  
  return (req, res, next) => {
    // Must be authenticated first
    if (!req.user || !req.userRole) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required.',
        code: 'AUTH_REQUIRED'
      });
    }
    
    // Check if user has required role
    if (!roles.includes(req.userRole)) {
      return res.status(403).json({
        success: false,
        message: `Access denied. Required role: ${roles.join(' or ')}.`,
        code: 'INSUFFICIENT_ROLE',
        required: roles,
        current: req.userRole
      });
    }
    
    next();
  };
};

/**
 * REQUIRE EMAIL VERIFICATION
 * 
 * Ensures user has verified their email address.
 */
export const requireEmailVerification = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      success: false,
      message: 'Authentication required.',
      code: 'AUTH_REQUIRED'
    });
  }
  
  if (!req.user.is_email_verified) {
    return res.status(403).json({
      success: false,
      message: 'Email verification required.',
      code: 'EMAIL_NOT_VERIFIED'
    });
  }
  
  next();
};

/**
 * RATE LIMITING MIDDLEWARE
 * 
 * Different rate limits for different types of operations.
 */

// General API rate limiting
export const generalRateLimit = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX) || (process.env.NODE_ENV === 'development' ? 1000 : 100), // Higher limit for development
  message: {
    success: false,
    message: 'Too many requests. Please try again later.',
    code: 'RATE_LIMIT_EXCEEDED'
  },
  standardHeaders: true,
  legacyHeaders: false,
  // Custom key generator (can include user ID for authenticated requests)
  keyGenerator: (req) => {
    return req.userId || req.ip;
  }
});

// Strict rate limiting for authentication endpoints
export const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'development' ? 100 : 10, // Higher limit for development
  message: {
    success: false,
    message: 'Too many authentication attempts. Please try again later.',
    code: 'AUTH_RATE_LIMIT_EXCEEDED'
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Don't count successful requests
  keyGenerator: (req) => {
    // Rate limit by IP and email (if provided)
    const email = req.body?.email || '';
    return `auth:${req.ip}:${email}`;
  }
});

// Slow down middleware for repeated requests
export const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000, // 15 minutes
  delayAfter: 5, // Start slowing down after 5 requests
  delayMs: 500, // Add 500ms delay per request after delayAfter
  maxDelayMs: 5000, // Maximum delay of 5 seconds
  keyGenerator: (req) => {
    return req.userId || req.ip;
  }
});

/**
 * SESSION-BASED AUTHENTICATION
 * 
 * Alternative to JWT - validates session tokens stored in database.
 * Useful for scenarios requiring immediate session revocation.
 */
export const authenticateSession = async (req, res, next) => {
  try {
    // Get session token from cookies or headers
    const sessionToken = req.cookies?.sessionToken || 
                        req.headers['x-session-token'] ||
                        req.query?.sessionToken;
    
    if (!sessionToken) {
      return res.status(401).json({
        success: false,
        message: 'Session token required.',
        code: 'NO_SESSION_TOKEN'
      });
    }

    // Validate session
    const session = await SessionService.validateSession(sessionToken);
    if (!session) {
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired session.',
        code: 'INVALID_SESSION'
      });
    }

    // Add session and user info to request
    req.session = session;
    req.user = session.user;
    req.userId = session.userId;
    req.userRole = session.user.role;
    req.sessionId = session.sessionId;

    next();

  } catch (error) {
    console.error('❌ Session authentication error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Session authentication failed.',
      code: 'SESSION_AUTH_ERROR'
    });
  }
};

/**
 * REFRESH TOKEN MIDDLEWARE
 * 
 * Handles automatic token refresh when access token is expired.
 */
export const handleTokenRefresh = async (req, res, next) => {
  try {
    const accessToken = extractToken(req);
    const refreshToken = req.cookies?.refreshToken || req.headers['x-refresh-token'];

    // If no access token, continue to next middleware (will likely fail auth)
    if (!accessToken) {
      return next();
    }

    // Try to verify access token
    try {
      const decoded = verifyAccessToken(accessToken);
      // Token is valid, continue
      return next();
    } catch (error) {
      // Access token is invalid or expired, try to refresh
      if (error.message !== 'Access token expired' || !refreshToken) {
        return next(); // Let the auth middleware handle the error
      }
    }

    // Try to refresh the token
    try {
      const refreshResult = await SessionService.refreshAccessToken(
        refreshToken,
        req.ip,
        req.get('User-Agent')
      );

      // Generate new access token
      const newAccessToken = generateAccessToken({
        userId: refreshResult.user.id,
        email: refreshResult.user.email,
        role: refreshResult.user.role,
        sessionId: refreshResult.sessionId
      });

      // Set new tokens in response headers/cookies
      res.cookie('accessToken', newAccessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 15 * 60 * 1000 // 15 minutes
      });

      res.cookie('refreshToken', refreshResult.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      });

      // Update request with new token
      req.headers.authorization = `Bearer ${newAccessToken}`;

      next();

    } catch (refreshError) {
      // Refresh failed, let auth middleware handle it
      console.warn('⚠️ Token refresh failed:', refreshError.message);
      next();
    }

  } catch (error) {
    console.error('❌ Token refresh middleware error:', error.message);
    next();
  }
};

/**
 * AUDIT LOGGING MIDDLEWARE
 * 
 * Logs important security events for monitoring and compliance.
 */
export const auditLog = (action, resource = null) => {
  return async (req, res, next) => {
    // Store audit info in request for later use
    req.auditInfo = {
      action,
      resource,
      userId: req.userId || null,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date()
    };

    // Continue to next middleware
    next();

    // Log after response (in background)
    setImmediate(async () => {
      try {
        // In a production app, you might send this to a logging service
        console.log('📋 Audit log:', {
          ...req.auditInfo,
          success: res.statusCode < 400,
          statusCode: res.statusCode
        });

        // Optionally store in database
        // await AuditService.log(req.auditInfo);
      } catch (error) {
        console.error('❌ Audit logging failed:', error.message);
      }
    });
  };
};

/**
 * IP WHITELIST MIDDLEWARE
 * 
 * Restrict access to specific IP addresses (useful for admin routes).
 */
export const requireIPWhitelist = (allowedIPs = []) => {
  return (req, res, next) => {
    const clientIP = req.ip;
    
    if (!allowedIPs.includes(clientIP)) {
      console.warn('⚠️ Unauthorized IP access attempt:', {
        ip: clientIP,
        userAgent: req.get('User-Agent'),
        path: req.path
      });
      
      return res.status(403).json({
        success: false,
        message: 'Access denied from this IP address.',
        code: 'IP_NOT_ALLOWED'
      });
    }
    
    next();
  };
};

/**
 * DEVICE LIMIT MIDDLEWARE
 * 
 * Limit the number of concurrent sessions per user.
 */
export const enforceDeviceLimit = (maxDevices = 5) => {
  return async (req, res, next) => {
    if (!req.userId) {
      return next(); // Not authenticated, skip check
    }

    try {
      const userSessions = await SessionService.getUserSessions(req.userId);
      
      if (userSessions.length >= maxDevices) {
        return res.status(429).json({
          success: false,
          message: `Maximum ${maxDevices} devices allowed. Please logout from other devices.`,
          code: 'DEVICE_LIMIT_EXCEEDED',
          activeSessions: userSessions.length,
          maxDevices
        });
      }
      
      next();
    } catch (error) {
      console.error('❌ Device limit check failed:', error.message);
      next(); // Continue on error
    }
  };
};

/**
 * COMBINE MIDDLEWARE HELPER
 * 
 * Utility to combine multiple middleware functions.
 */
export const combineMiddleware = (...middlewares) => {
  return (req, res, next) => {
    const runMiddleware = (index) => {
      if (index >= middlewares.length) {
        return next();
      }
      
      middlewares[index](req, res, (err) => {
        if (err) {
          return next(err);
        }
        runMiddleware(index + 1);
      });
    };
    
    runMiddleware(0);
  };
}; 