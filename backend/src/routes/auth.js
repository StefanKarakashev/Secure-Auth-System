import express from 'express';
import Joi from 'joi';
import AuthController from '../controllers/AuthController.js';
import emailService from '../services/EmailService.js';
import User from '../models/User.js';
import SessionService from '../services/SessionService.js';
import { generateEmailVerificationToken, hashToken } from '../utils/security.js';
import { query } from '../config/database.js';
import { 
  authenticate, 
  authRateLimit, 
  generalRateLimit,
  requireRole,
  requireEmailVerification,
  auditLog,
  handleTokenRefresh,
  optionalAuth
} from '../middleware/auth.js';
import { validate, schemas, sanitize, checkHoneypot } from '../middleware/validation.js';

/**
 * AUTHENTICATION ROUTES
 * 
 * This module defines all authentication-related routes with proper:
 * - Input validation and sanitization
 * - Rate limiting for security
 * - Middleware for authentication and authorization
 * - Audit logging for security monitoring
 * - Error handling and consistent responses
 * 
 * Route patterns:
 * - POST /auth/register - Create new user account
 * - POST /auth/login - Authenticate user
 * - POST /auth/logout - Logout current session
 * - POST /auth/logout-all - Logout all user sessions
 * - POST /auth/refresh - Refresh access token
 * - POST /auth/forgot-password - Request password reset
 * - POST /auth/reset-password - Reset password with token
 * - POST /auth/verify-email - Verify email address
 * - GET /auth/me - Get current user info
 * - GET /auth/sessions - Get user's active sessions
 * - DELETE /auth/sessions/:sessionId - Revoke specific session
 */

const router = express.Router();

/**
 * PUBLIC ROUTES (No authentication required)
 */

/**
 * @route   POST /auth/register
 * @desc    Register a new user account
 * @access  Public
 * @rateLimit authRateLimit (10 requests per 15 minutes)
 */
router.post('/register',
  authRateLimit, // Rate limiting for registration
  sanitize, // Input sanitization
  validate(schemas.register), // Input validation
  checkHoneypot(), // Spam protection
  auditLog('USER_REGISTRATION_ATTEMPT', 'user'), // Audit logging
  AuthController.register
);

/**
 * @route   POST /auth/login
 * @desc    Authenticate user and create session
 * @access  Public
 * @rateLimit authRateLimit (10 requests per 15 minutes)
 */
router.post('/login',
  authRateLimit, // Strict rate limiting for login attempts
  sanitize, // Input sanitization
  validate(schemas.login), // Input validation
  auditLog('USER_LOGIN_ATTEMPT', 'session'), // Audit logging
  AuthController.login
);

/**
 * @route   POST /auth/forgot-password
 * @desc    Request password reset email
 * @access  Public
 * @rateLimit authRateLimit (10 requests per 15 minutes)
 */
router.post('/forgot-password',
  authRateLimit, // Rate limiting to prevent abuse
  sanitize,
  validate(schemas.passwordResetRequest),
  auditLog('PASSWORD_RESET_REQUEST_ATTEMPT', 'user'),
  AuthController.requestPasswordReset
);

/**
 * @route   POST /auth/reset-password
 * @desc    Reset password using reset token
 * @access  Public
 * @rateLimit authRateLimit (10 requests per 15 minutes)
 */
router.post('/reset-password',
  authRateLimit, // Rate limiting for security
  sanitize,
  validate(schemas.passwordReset),
  auditLog('PASSWORD_RESET_ATTEMPT', 'user'),
  AuthController.resetPassword
);

/**
 * @route   POST /auth/verify-email
 * @desc    Verify email address using verification token
 * @access  Public
 * @rateLimit generalRateLimit (100 requests per 15 minutes)
 */
router.post('/verify-email',
  generalRateLimit, // Re-enabled now that we fixed the root cause
  sanitize,
  validate(schemas.verifyEmail),
  auditLog('EMAIL_VERIFICATION_ATTEMPT', 'user'),
  AuthController.verifyEmail
);

/**
 * @route   POST /auth/refresh
 * @desc    Refresh access token using refresh token
 * @access  Public (but requires valid refresh token)
 * @rateLimit generalRateLimit (100 requests per 15 minutes)
 */
router.post('/refresh',
  generalRateLimit,
  sanitize,
  validate(schemas.refreshToken),
  auditLog('TOKEN_REFRESH_ATTEMPT', 'session'),
  AuthController.refreshToken
);

/**
 * AUTHENTICATED ROUTES (Require valid access token)
 */

/**
 * @route   GET /auth/me
 * @desc    Get current authenticated user information
 * @access  Private
 * @middleware authenticate, generalRateLimit
 */
router.get('/me',
  generalRateLimit,
  handleTokenRefresh, // Automatic token refresh if needed
  authenticate, // Require authentication
  AuthController.getCurrentUser
);

/**
 * @route   POST /auth/logout
 * @desc    Logout current session
 * @access  Private
 * @middleware authenticate, generalRateLimit
 */
router.post('/logout',
  generalRateLimit,
  optionalAuth, // Optional auth - logout should work even with expired tokens
  auditLog('USER_LOGOUT_ATTEMPT', 'session'),
  AuthController.logout
);

/**
 * @route   POST /auth/logout-all
 * @desc    Logout all user sessions (all devices)
 * @access  Private
 * @middleware authenticate, generalRateLimit
 */
router.post('/logout-all',
  generalRateLimit,
  authenticate, // Must be authenticated
  auditLog('USER_LOGOUT_ALL_ATTEMPT', 'session'),
  AuthController.logoutAll
);

/**
 * @route   GET /auth/sessions
 * @desc    Get all active sessions for current user
 * @access  Private
 * @middleware authenticate, generalRateLimit
 */
router.get('/sessions',
  generalRateLimit,
  authenticate,
  AuthController.getUserSessions
);

/**
 * @route   DELETE /auth/sessions/:sessionId
 * @desc    Revoke/logout a specific session
 * @access  Private
 * @middleware authenticate, generalRateLimit
 */
router.delete('/sessions/:sessionId',
  generalRateLimit,
  authenticate,
  auditLog('SESSION_REVOCATION_ATTEMPT', 'session'),
  AuthController.revokeSession
);

/**
 * EMAIL VERIFIED ROUTES (Require email verification)
 */

/**
 * @route   POST /auth/change-password
 * @desc    Change user password (requires current password)
 * @access  Private + Email Verified
 * @middleware authenticate, requireEmailVerification, authRateLimit
 */
router.post('/change-password',
  authRateLimit, // Strict rate limiting for password changes
  authenticate,
  requireEmailVerification, // Must have verified email
  sanitize,
  validate(schemas.changePassword),
  auditLog('PASSWORD_CHANGE_ATTEMPT', 'user'),
  async (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body;
      const userId = req.userId;

      // Use the User model to change password
      await User.updatePassword(userId, currentPassword, newPassword);

      // Logout all other sessions (security measure)
      await SessionService.logoutAllSessions(userId);

      res.status(200).json({
        success: true,
        message: 'Password changed successfully. You have been logged out from all other devices.'
      });

    } catch (error) {
      console.error('❌ Password change failed:', error.message);

      if (error.message.includes('Current password is incorrect')) {
        return res.status(400).json({
          success: false,
          message: 'Current password is incorrect',
          code: 'INVALID_CURRENT_PASSWORD'
        });
      }

      res.status(500).json({
        success: false,
        message: 'Password change failed. Please try again.',
        code: 'PASSWORD_CHANGE_ERROR'
      });
    }
  }
);

/**
 * @route   POST /auth/resend-verification
 * @desc    Resend email verification link
 * @access  Private
 * @middleware authenticate, authRateLimit
 */
router.post('/resend-verification',
  authRateLimit,
  authenticate,
  auditLog('EMAIL_VERIFICATION_RESEND_ATTEMPT', 'user'),
  async (req, res) => {
    try {
      const user = await User.findById(req.userId);

      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
          code: 'USER_NOT_FOUND'
        });
      }

      if (user.is_email_verified) {
        return res.status(400).json({
          success: false,
          message: 'Email is already verified',
          code: 'EMAIL_ALREADY_VERIFIED'
        });
      }

      // Generate new verification token
      const emailToken = generateEmailVerificationToken({
        userId: user.id,
        email: user.email,
        type: 'email_verification'
      });

      // Store in database
      const tokenHash = hashToken(emailToken);
      const expiresAt = new Date(Date.now() + (24 * 60 * 60 * 1000)); // 24 hours

      await query(
        `INSERT INTO email_verifications (user_id, token_hash, expires_at)
         VALUES ($1, $2, $3)`,
        [user.id, tokenHash, expiresAt]
      );

      // Send verification email
      await emailService.sendWelcomeEmail(user.email, user.first_name, emailToken);

      console.log('✅ Verification email resent:', { userId: user.id });

      res.status(200).json({
        success: true,
        message: 'Verification email sent successfully'
      });

    } catch (error) {
      console.error('❌ Resend verification failed:', error.message);

      res.status(500).json({
        success: false,
        message: 'Failed to resend verification email',
        code: 'RESEND_VERIFICATION_ERROR'
      });
    }
  }
);

/**
 * ADMIN ROUTES (Require admin role)
 */

/**
 * @route   GET /auth/admin/sessions
 * @desc    Get session statistics (admin only)
 * @access  Private + Admin
 * @middleware authenticate, requireRole('admin'), generalRateLimit
 */
router.get('/admin/sessions',
  generalRateLimit,
  authenticate,
  requireRole('admin'),
  auditLog('ADMIN_SESSION_STATS_VIEW', 'admin'),
  async (req, res) => {
    try {
      const stats = await SessionService.getSessionStats();

      res.status(200).json({
        success: true,
        data: {
          sessionStats: stats
        }
      });

    } catch (error) {
      console.error('❌ Get session stats failed:', error.message);

      res.status(500).json({
        success: false,
        message: 'Failed to retrieve session statistics',
        code: 'GET_SESSION_STATS_ERROR'
      });
    }
  }
);

/**
 * @route   POST /auth/admin/revoke-session
 * @desc    Revoke any user's session (admin only)
 * @access  Private + Admin
 * @middleware authenticate, requireRole('admin'), authRateLimit
 */
router.post('/admin/revoke-session',
  authRateLimit,
  authenticate,
  requireRole('admin'),
  sanitize,
  validate(Joi.object({
    sessionId: Joi.string().required().messages({
      'any.required': 'Session ID is required'
    })
  })),
  auditLog('ADMIN_SESSION_REVOCATION', 'admin'),
  async (req, res) => {
    try {
      const { sessionId } = req.body;

      const result = await SessionService.revokeSession(sessionId);

      console.log('✅ Admin revoked session:', { 
        adminId: req.userId, 
        revokedSessionId: sessionId,
        affectedUserId: result.user_id
      });

      res.status(200).json({
        success: true,
        message: 'Session revoked successfully',
        data: {
          revokedSession: result
        }
      });

    } catch (error) {
      console.error('❌ Admin session revocation failed:', error.message);

      res.status(500).json({
        success: false,
        message: 'Failed to revoke session',
        code: 'ADMIN_REVOKE_SESSION_ERROR'
      });
    }
  }
);

/**
 * UTILITY ROUTES
 */

/**
 * @route   GET /auth/check
 * @desc    Check if user is authenticated (useful for frontend)
 * @access  Public
 * @middleware optionalAuth, generalRateLimit
 */
router.get('/check',
  generalRateLimit,
  optionalAuth, // Optional authentication
  (req, res) => {
    res.status(200).json({
      success: true,
      data: {
        isAuthenticated: !!req.user,
        user: req.user ? {
          id: req.user.id,
          email: req.user.email,
          firstName: req.user.first_name,
          lastName: req.user.last_name,
          role: req.user.role,
          isEmailVerified: req.user.is_email_verified
        } : null
      }
    });
  }
);

/**
 * ERROR HANDLING MIDDLEWARE
 * 
 * Catches any errors that weren't handled by route handlers.
 */
router.use((error, req, res, next) => {
  console.error('❌ Auth route error:', error);

  // Don't expose internal errors in production
  const message = process.env.NODE_ENV === 'production' 
    ? 'An authentication error occurred' 
    : error.message;

  res.status(500).json({
    success: false,
    message,
    code: 'AUTH_ROUTE_ERROR'
  });
});

export default router; 