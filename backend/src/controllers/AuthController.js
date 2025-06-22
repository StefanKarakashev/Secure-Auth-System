import User from '../models/User.js';
import SessionService from '../services/SessionService.js';
import emailService from '../services/EmailService.js';
import { 
  generateAccessToken, 
  generateRefreshToken,
  generatePasswordResetToken,
  generateEmailVerificationToken,
  verifyPasswordResetToken,
  verifyEmailVerificationToken,
  hashToken,
  getSecureCookieOptions
} from '../utils/security.js';
import { query, getClient } from '../config/database.js';

/**
 * AUTHENTICATION CONTROLLER
 * 
 * This controller handles all authentication-related operations.
 * It implements industry-standard security practices and provides
 * comprehensive error handling and logging.
 * 
 * Key features:
 * - Secure user registration with email verification
 * - Multi-device session management
 * - JWT access tokens with refresh token rotation
 * - Password reset flow with secure tokens
 * - Comprehensive audit logging
 * - Rate limiting and brute force protection
 */

class AuthController {

  /**
   * USER REGISTRATION
   * 
   * Creates a new user account with email verification requirement.
   */
  static async register(req, res) {
    try {
      const { email, password, firstName, lastName, acceptTerms } = req.body;

      // Check if email already exists
      const existingUser = await User.findByEmail(email);
      if (existingUser) {
        return res.status(409).json({
          success: false,
          message: 'An account with this email already exists',
          code: 'EMAIL_EXISTS'
        });
      }

      // Create user account
      const user = await User.create({
        email,
        password,
        firstName,
        lastName,
        role: 'user'
      });

      // Generate email verification token
      const emailToken = generateEmailVerificationToken({
        userId: user.id,
        email: user.email,
        type: 'email_verification'
      });

      // Store email verification token in database
      const tokenHash = hashToken(emailToken);
      const expiresAt = new Date(Date.now() + (24 * 60 * 60 * 1000)); // 24 hours

      await query(
        `INSERT INTO email_verifications (user_id, token_hash, expires_at)
         VALUES ($1, $2, $3)`,
        [user.id, tokenHash, expiresAt]
      );

      // Send welcome email with verification link
      await emailService.sendWelcomeEmail(user.email, user.first_name, emailToken);

      console.log('✅ User registered successfully:', { 
        userId: user.id, 
        email: user.email 
      });

      // Log registration event
      await AuthController.logAuditEvent(req, 'USER_REGISTERED', 'user', {
        userId: user.id,
        email: user.email
      });

      res.status(201).json({
        success: true,
        message: 'Account created successfully. Please check your email to verify your account.',
        data: {
          user: {
            id: user.id,
            email: user.email,
            firstName: user.first_name,
            lastName: user.last_name,
            isEmailVerified: user.is_email_verified,
            createdAt: user.created_at
          }
        }
      });

    } catch (error) {
      console.error('❌ Registration failed:', error.message);
      
      res.status(500).json({
        success: false,
        message: 'Registration failed. Please try again.',
        code: 'REGISTRATION_ERROR'
      });
    }
  }

  /**
   * USER LOGIN
   * 
   * Authenticates user and creates session with JWT tokens.
   */
  static async login(req, res) {
    try {
      const { email, password, rememberMe = false, deviceInfo = {} } = req.body;
      const ipAddress = req.ip;
      const userAgent = req.get('User-Agent');

      // Authenticate user
      const user = await User.authenticate(email, password, ipAddress, userAgent);

      // Create session and generate tokens
      const session = await SessionService.createSession(
        user.id,
        ipAddress,
        userAgent,
        deviceInfo
      );

      // Generate access token
      const accessToken = generateAccessToken({
        userId: user.id,
        email: user.email,
        role: user.role,
        sessionId: session.sessionId
      });

      // Set secure cookies
      const cookieOptions = getSecureCookieOptions();
      
      // Access token (short-lived)
      res.cookie('accessToken', accessToken, {
        ...cookieOptions,
        maxAge: 15 * 60 * 1000 // 15 minutes
      });

      // Refresh token (longer-lived)
      res.cookie('refreshToken', session.refreshToken, {
        ...cookieOptions,
        maxAge: rememberMe ? 30 * 24 * 60 * 60 * 1000 : 7 * 24 * 60 * 60 * 1000 // 30 days if "remember me", 7 days otherwise
      });

      // Session token (for immediate revocation if needed)
      res.cookie('sessionToken', session.sessionToken, {
        ...cookieOptions,
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      });

      console.log('✅ User logged in successfully:', { 
        userId: user.id, 
        sessionId: session.sessionId 
      });

      // Log login event
      await AuthController.logAuditEvent(req, 'USER_LOGIN', 'session', {
        userId: user.id,
        sessionId: session.sessionId
      });

      res.status(200).json({
        success: true,
        message: 'Login successful',
        data: {
          user: {
            id: user.id,
            email: user.email,
            firstName: user.first_name,
            lastName: user.last_name,
            role: user.role,
            isEmailVerified: user.is_email_verified,
            lastLogin: user.last_login
          },
          session: {
            id: session.sessionId,
            expiresAt: session.expiresAt
          },
          tokens: {
            accessToken,
            refreshToken: session.refreshToken, // Only return if not using httpOnly cookies
            expiresIn: 900 // 15 minutes in seconds
          }
        }
      });

    } catch (error) {
      console.error('❌ Login failed:', error.message);

      // Determine appropriate response based on error
      if (error.message.includes('Invalid email or password')) {
        return res.status(401).json({
          success: false,
          message: 'Invalid email or password',
          code: 'INVALID_CREDENTIALS'
        });
      } else if (error.message.includes('Account locked')) {
        return res.status(423).json({
          success: false,
          message: error.message,
          code: 'ACCOUNT_LOCKED'
        });
      } else if (error.message.includes('Account is deactivated')) {
        return res.status(403).json({
          success: false,
          message: 'Account is deactivated. Please contact support.',
          code: 'ACCOUNT_DEACTIVATED'
        });
      }

      res.status(500).json({
        success: false,
        message: 'Login failed. Please try again.',
        code: 'LOGIN_ERROR'
      });
    }
  }

  /**
   * REFRESH ACCESS TOKEN
   * 
   * Validates refresh token and issues new access token.
   */
  static async refreshToken(req, res) {
    try {
      const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;

      if (!refreshToken) {
        return res.status(401).json({
          success: false,
          message: 'Refresh token required',
          code: 'NO_REFRESH_TOKEN'
        });
      }

      // Refresh the access token
      const result = await SessionService.refreshAccessToken(
        refreshToken,
        req.ip,
        req.get('User-Agent')
      );

      // Generate new access token
      const newAccessToken = generateAccessToken({
        userId: result.user.id,
        email: result.user.email,
        role: result.user.role
      });

      // Set new tokens in cookies
      const cookieOptions = getSecureCookieOptions();
      
      res.cookie('accessToken', newAccessToken, {
        ...cookieOptions,
        maxAge: 15 * 60 * 1000 // 15 minutes
      });

      res.cookie('refreshToken', result.refreshToken, {
        ...cookieOptions,
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
      });

      console.log('✅ Token refreshed successfully:', { 
        userId: result.user.id 
      });

      res.status(200).json({
        success: true,
        message: 'Token refreshed successfully',
        data: {
          accessToken: newAccessToken,
          refreshToken: result.refreshToken,
          expiresIn: 900, // 15 minutes
          user: result.user
        }
      });

    } catch (error) {
      console.error('❌ Token refresh failed:', error.message);

      // Clear invalid refresh token cookie
      res.clearCookie('refreshToken');
      res.clearCookie('accessToken');

      res.status(401).json({
        success: false,
        message: 'Token refresh failed. Please login again.',
        code: 'TOKEN_REFRESH_FAILED'
      });
    }
  }

  /**
   * LOGOUT
   * 
   * Invalidates current session and clears cookies.
   */
  static async logout(req, res) {
    try {
      const userId = req.userId;
      const sessionId = req.sessionId;

      if (sessionId) {
        // Logout specific session
        await SessionService.logoutSession(sessionId, userId);
      }

      // Clear all auth cookies
      res.clearCookie('accessToken');
      res.clearCookie('refreshToken');
      res.clearCookie('sessionToken');

      console.log('✅ User logged out successfully:', { 
        userId, 
        sessionId 
      });

      // Log logout event
      await AuthController.logAuditEvent(req, 'USER_LOGOUT', 'session', {
        userId,
        sessionId
      });

      res.status(200).json({
        success: true,
        message: 'Logged out successfully'
      });

    } catch (error) {
      console.error('❌ Logout failed:', error.message);
      
      // Clear cookies even if logout fails
      res.clearCookie('accessToken');
      res.clearCookie('refreshToken');
      res.clearCookie('sessionToken');

      res.status(200).json({
        success: true,
        message: 'Logged out successfully'
      });
    }
  }

  /**
   * LOGOUT ALL SESSIONS
   * 
   * Invalidates all user sessions across all devices.
   */
  static async logoutAll(req, res) {
    try {
      const userId = req.userId;

      // Logout all sessions for the user
      const result = await SessionService.logoutAllSessions(userId);

      // Clear cookies for current session
      res.clearCookie('accessToken');
      res.clearCookie('refreshToken');
      res.clearCookie('sessionToken');

      console.log('✅ All sessions logged out:', { 
        userId, 
        sessionsCount: result.loggedOutSessions 
      });

      // Log logout all event
      await AuthController.logAuditEvent(req, 'USER_LOGOUT_ALL', 'session', {
        userId,
        loggedOutSessions: result.loggedOutSessions
      });

      res.status(200).json({
        success: true,
        message: `Logged out from ${result.loggedOutSessions} devices successfully`,
        data: {
          loggedOutSessions: result.loggedOutSessions
        }
      });

    } catch (error) {
      console.error('❌ Logout all failed:', error.message);

      res.status(500).json({
        success: false,
        message: 'Failed to logout from all devices',
        code: 'LOGOUT_ALL_ERROR'
      });
    }
  }

  /**
   * REQUEST PASSWORD RESET
   * 
   * Generates password reset token and sends email.
   */
  static async requestPasswordReset(req, res) {
    try {
      const { email } = req.body;

      // Find user by email (always return success to prevent email enumeration)
      const user = await User.findByEmail(email);

      if (user) {
        // Generate password reset token
        const resetToken = generatePasswordResetToken({
          userId: user.id,
          email: user.email,
          type: 'password_reset'
        });

        // Store reset token in database
        const tokenHash = hashToken(resetToken);
        const expiresAt = new Date(Date.now() + (60 * 60 * 1000)); // 1 hour

        await query(
          `INSERT INTO password_resets (user_id, token_hash, expires_at, ip_address)
           VALUES ($1, $2, $3, $4)`,
          [user.id, tokenHash, expiresAt, req.ip]
        );

        // Send password reset email
        await emailService.sendPasswordResetEmail(user.email, user.first_name, resetToken);

        console.log('✅ Password reset requested:', { 
          userId: user.id, 
          email: user.email 
        });

        // Log password reset request
        await AuthController.logAuditEvent(req, 'PASSWORD_RESET_REQUESTED', 'user', {
          userId: user.id,
          email: user.email
        });
      }

      // Always return success to prevent email enumeration
      res.status(200).json({
        success: true,
        message: 'If an account with that email exists, a password reset link has been sent.'
      });

    } catch (error) {
      console.error('❌ Password reset request failed:', error.message);

      res.status(500).json({
        success: false,
        message: 'Failed to process password reset request',
        code: 'PASSWORD_RESET_REQUEST_ERROR'
      });
    }
  }

  /**
   * RESET PASSWORD
   * 
   * Validates reset token and updates password.
   */
  static async resetPassword(req, res) {
    try {
      const { token, password } = req.body;

      // Verify reset token
      let decoded;
      try {
        decoded = verifyPasswordResetToken(token);
      } catch (error) {
        return res.status(400).json({
          success: false,
          message: 'Invalid or expired reset token',
          code: 'INVALID_RESET_TOKEN'
        });
      }

      // Check if token exists in database and is not used
      const tokenHash = hashToken(token);
      const tokenResult = await query(
        `SELECT pr.id, pr.user_id, pr.is_used, u.email
         FROM password_resets pr
         JOIN users u ON pr.user_id = u.id
         WHERE pr.token_hash = $1 AND pr.expires_at > NOW() AND pr.is_used = false`,
        [tokenHash]
      );

      if (tokenResult.rows.length === 0) {
        return res.status(400).json({
          success: false,
          message: 'Invalid or expired reset token',
          code: 'INVALID_RESET_TOKEN'
        });
      }

      const resetRecord = tokenResult.rows[0];

      // Verify user matches token
      if (resetRecord.user_id !== decoded.userId) {
        return res.status(400).json({
          success: false,
          message: 'Invalid reset token',
          code: 'INVALID_RESET_TOKEN'
        });
      }

      const client = await getClient();

      try {
        await client.query('BEGIN');

        // Update user password
        await User.updatePassword(resetRecord.user_id, password, password);

        // Mark reset token as used
        await client.query(
          'UPDATE password_resets SET is_used = true WHERE id = $1',
          [resetRecord.id]
        );

        // Invalidate all user sessions (force re-login)
        await SessionService.logoutAllSessions(resetRecord.user_id);

        await client.query('COMMIT');

        console.log('✅ Password reset successful:', { 
          userId: resetRecord.user_id 
        });

        // Log password reset success
        await AuthController.logAuditEvent(req, 'PASSWORD_RESET_COMPLETED', 'user', {
          userId: resetRecord.user_id,
          email: resetRecord.email
        });

        res.status(200).json({
          success: true,
          message: 'Password reset successful. Please login with your new password.'
        });

      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }

    } catch (error) {
      console.error('❌ Password reset failed:', error.message);

      res.status(500).json({
        success: false,
        message: 'Password reset failed. Please try again.',
        code: 'PASSWORD_RESET_ERROR'
      });
    }
  }

  /**
   * VERIFY EMAIL
   * 
   * Validates email verification token and activates account.
   */
  static async verifyEmail(req, res) {
    try {
      const { token } = req.body;

      // Verify email token
      let decoded;
      try {
        decoded = verifyEmailVerificationToken(token);
      } catch (error) {
        return res.status(400).json({
          success: false,
          message: 'Invalid or expired verification token',
          code: 'INVALID_VERIFICATION_TOKEN'
        });
      }

      // Check if token exists in database and is not used
      const tokenHash = hashToken(token);
      const tokenResult = await query(
        `SELECT ev.id, ev.user_id, ev.is_used, u.email, u.is_email_verified
         FROM email_verifications ev
         JOIN users u ON ev.user_id = u.id
         WHERE ev.token_hash = $1 AND ev.expires_at > NOW() AND ev.is_used = false`,
        [tokenHash]
      );

      if (tokenResult.rows.length === 0) {
        return res.status(400).json({
          success: false,
          message: 'Invalid or expired verification token',
          code: 'INVALID_VERIFICATION_TOKEN'
        });
      }

      const verificationRecord = tokenResult.rows[0];

      // Check if email is already verified
      if (verificationRecord.is_email_verified) {
        return res.status(200).json({
          success: true,
          message: 'Email is already verified'
        });
      }

      // Verify user matches token
      if (verificationRecord.user_id !== decoded.userId) {
        return res.status(400).json({
          success: false,
          message: 'Invalid verification token',
          code: 'INVALID_VERIFICATION_TOKEN'
        });
      }

      const client = await getClient();

      try {
        await client.query('BEGIN');

        // Mark email as verified
        await User.verifyEmail(verificationRecord.user_id);

        // Mark verification token as used
        await client.query(
          'UPDATE email_verifications SET is_used = true WHERE id = $1',
          [verificationRecord.id]
        );

        await client.query('COMMIT');

        console.log('✅ Email verified successfully:', { 
          userId: verificationRecord.user_id 
        });

        // Log email verification
        await AuthController.logAuditEvent(req, 'EMAIL_VERIFIED', 'user', {
          userId: verificationRecord.user_id,
          email: verificationRecord.email
        });

        res.status(200).json({
          success: true,
          message: 'Email verified successfully'
        });

      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }

    } catch (error) {
      console.error('❌ Email verification failed:', error.message);

      res.status(500).json({
        success: false,
        message: 'Email verification failed. Please try again.',
        code: 'EMAIL_VERIFICATION_ERROR'
      });
    }
  }

  /**
   * GET CURRENT USER
   * 
   * Returns current authenticated user information.
   */
  static async getCurrentUser(req, res) {
    try {
      const user = await User.findById(req.userId);

      if (!user) {
        return res.status(404).json({
          success: false,
          message: 'User not found',
          code: 'USER_NOT_FOUND'
        });
      }

      res.status(200).json({
        success: true,
        data: {
          user: {
            id: user.id,
            email: user.email,
            firstName: user.first_name,
            lastName: user.last_name,
            role: user.role,
            isEmailVerified: user.is_email_verified,
            isActive: user.is_active,
            lastLogin: user.last_login,
            createdAt: user.created_at,
            updatedAt: user.updated_at
          }
        }
      });

    } catch (error) {
      console.error('❌ Get current user failed:', error.message);

      res.status(500).json({
        success: false,
        message: 'Failed to retrieve user information',
        code: 'GET_USER_ERROR'
      });
    }
  }

  /**
   * GET USER SESSIONS
   * 
   * Returns all active sessions for the current user.
   */
  static async getUserSessions(req, res) {
    try {
      const sessions = await SessionService.getUserSessions(req.userId);

      // Mark current session
      const currentSessionId = req.sessionId;
      const sessionsWithCurrent = sessions.map(session => ({
        ...session,
        isCurrent: session.id === currentSessionId
      }));

      res.status(200).json({
        success: true,
        data: {
          sessions: sessionsWithCurrent,
          total: sessions.length
        }
      });

    } catch (error) {
      console.error('❌ Get user sessions failed:', error.message);

      res.status(500).json({
        success: false,
        message: 'Failed to retrieve user sessions',
        code: 'GET_SESSIONS_ERROR'
      });
    }
  }

  /**
   * REVOKE SESSION
   * 
   * Revokes a specific session.
   */
  static async revokeSession(req, res) {
    try {
      const { sessionId } = req.params;
      const userId = req.userId;

      await SessionService.logoutSession(sessionId, userId);

      // Log session revocation
      await AuthController.logAuditEvent(req, 'SESSION_REVOKED', 'session', {
        userId,
        revokedSessionId: sessionId
      });

      res.status(200).json({
        success: true,
        message: 'Session revoked successfully'
      });

    } catch (error) {
      console.error('❌ Revoke session failed:', error.message);

      res.status(500).json({
        success: false,
        message: 'Failed to revoke session',
        code: 'REVOKE_SESSION_ERROR'
      });
    }
  }

  /**
   * AUDIT LOGGING HELPER
   * 
   * Logs security-related events for monitoring and compliance.
   */
  static async logAuditEvent(req, action, resource, details = {}) {
    try {
      await query(
        `INSERT INTO audit_logs (user_id, action, resource, details, ip_address, user_agent)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          req.userId || null,
          action,
          resource,
          JSON.stringify(details),
          req.ip,
          req.get('User-Agent')
        ]
      );
    } catch (error) {
      console.error('❌ Audit logging failed:', error.message);
      // Don't throw error - audit logging is not critical
    }
  }
}

export default AuthController; 