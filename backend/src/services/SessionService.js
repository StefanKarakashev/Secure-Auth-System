import { query, getClient } from '../config/database.js';
import { 
  generateSessionToken, 
  generateRefreshToken, 
  verifyRefreshToken,
  hashToken,
  generateDeviceFingerprint,
  safeCompare
} from '../utils/security.js';

/**
 * SESSION SERVICE
 * 
 * This service handles all session-related operations including:
 * - Creating and managing user sessions across multiple devices
 * - JWT refresh token rotation
 * - Session invalidation and cleanup
 * - Device tracking for security
 * 
 * Key concepts:
 * - Each user can have multiple active sessions (different devices)
 * - Refresh tokens are stored hashed in the database
 * - Sessions have expiration times and can be revoked
 * - Device fingerprinting helps identify suspicious activity
 */

class SessionService {

  /**
   * CREATE NEW SESSION
   * 
   * Creates a new session for a user with refresh token.
   * This is called after successful login.
   */
  static async createSession(userId, ipAddress, userAgent, additionalDeviceInfo = {}) {
    const client = await getClient();

    try {
      await client.query('BEGIN');

      // Generate tokens
      const sessionToken = generateSessionToken();
      const refreshToken = generateRefreshToken({ userId, type: 'refresh' });
      const refreshTokenHash = hashToken(refreshToken);

      // Create device fingerprint
      const deviceInfo = {
        ...additionalDeviceInfo,
        fingerprint: generateDeviceFingerprint(userAgent, ipAddress, additionalDeviceInfo)
      };

      // Calculate expiration times
      const sessionExpiry = new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)); // 7 days
      const refreshExpiry = new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)); // 7 days

      // Create session record
      const sessionResult = await client.query(
        `INSERT INTO user_sessions (user_id, session_token, device_info, ip_address, user_agent, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, session_token, expires_at, created_at`,
        [userId, sessionToken, JSON.stringify(deviceInfo), ipAddress, userAgent, sessionExpiry]
      );

      const session = sessionResult.rows[0];

      // Create refresh token record
      await client.query(
        `INSERT INTO refresh_tokens (user_id, token_hash, session_id, device_info, expires_at)
         VALUES ($1, $2, $3, $4, $5)`,
        [userId, refreshTokenHash, session.id, JSON.stringify(deviceInfo), refreshExpiry]
      );

      await client.query('COMMIT');

      console.log('✅ New session created:', { 
        userId, 
        sessionId: session.id, 
        deviceFingerprint: deviceInfo.fingerprint 
      });

      return {
        sessionId: session.id,
        sessionToken: session.session_token,
        refreshToken,
        expiresAt: session.expires_at,
        createdAt: session.created_at
      };

    } catch (error) {
      await client.query('ROLLBACK');
      console.error('❌ Session creation failed:', error.message);
      throw new Error('Failed to create session');
    } finally {
      client.release();
    }
  }

  /**
   * REFRESH ACCESS TOKEN
   * 
   * Validates refresh token and issues new access token.
   * Implements token rotation for enhanced security.
   */
  static async refreshAccessToken(refreshToken, ipAddress, userAgent) {
    const client = await getClient();

    try {
      await client.query('BEGIN');

      // Verify refresh token structure
      let decoded;
      try {
        decoded = verifyRefreshToken(refreshToken);
      } catch (error) {
        throw new Error('Invalid refresh token');
      }

      // Hash the refresh token to look up in database
      const refreshTokenHash = hashToken(refreshToken);

      // Find refresh token in database
      const tokenResult = await client.query(
        `SELECT rt.id, rt.user_id, rt.session_id, rt.device_info, rt.expires_at,
                us.is_active as session_active, us.ip_address, us.user_agent
         FROM refresh_tokens rt
         JOIN user_sessions us ON rt.session_id = us.id
         WHERE rt.token_hash = $1 AND rt.is_revoked = false`,
        [refreshTokenHash]
      );

      if (tokenResult.rows.length === 0) {
        throw new Error('Refresh token not found or revoked');
      }

      const tokenData = tokenResult.rows[0];

      // Check if token is expired
      if (new Date() > new Date(tokenData.expires_at)) {
        // Clean up expired token
        await client.query(
          'UPDATE refresh_tokens SET is_revoked = true WHERE id = $1',
          [tokenData.id]
        );
        throw new Error('Refresh token expired');
      }

      // Check if session is still active
      if (!tokenData.session_active) {
        throw new Error('Session is no longer active');
      }

      // Verify user still exists and is active
      const userResult = await client.query(
        'SELECT id, email, role, is_active FROM users WHERE id = $1',
        [tokenData.user_id]
      );

      if (userResult.rows.length === 0 || !userResult.rows[0].is_active) {
        throw new Error('User account is not active');
      }

      const user = userResult.rows[0];

      // Optional: Check device consistency (for enhanced security)
      const currentDeviceFingerprint = generateDeviceFingerprint(userAgent, ipAddress);
      const storedDeviceInfo = JSON.parse(tokenData.device_info);
      
      // Log if device fingerprint changed (potential security concern)
      if (storedDeviceInfo.fingerprint !== currentDeviceFingerprint) {
        console.warn('⚠️ Device fingerprint mismatch:', {
          userId: user.id,
          sessionId: tokenData.session_id,
          stored: storedDeviceInfo.fingerprint,
          current: currentDeviceFingerprint
        });
      }

      // REFRESH TOKEN ROTATION (Security Best Practice)
      // Generate new refresh token and revoke the old one
      const newRefreshToken = generateRefreshToken({ userId: user.id, type: 'refresh' });
      const newRefreshTokenHash = hashToken(newRefreshToken);
      const newExpiry = new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)); // 7 days

      // Revoke old refresh token
      await client.query(
        'UPDATE refresh_tokens SET is_revoked = true WHERE id = $1',
        [tokenData.id]
      );

      // Create new refresh token
      await client.query(
        `INSERT INTO refresh_tokens (user_id, token_hash, session_id, device_info, expires_at)
         VALUES ($1, $2, $3, $4, $5)`,
        [user.id, newRefreshTokenHash, tokenData.session_id, tokenData.device_info, newExpiry]
      );

      // Update session last accessed time
      await client.query(
        'UPDATE user_sessions SET last_accessed = NOW() WHERE id = $1',
        [tokenData.session_id]
      );

      await client.query('COMMIT');

      console.log('✅ Access token refreshed:', { 
        userId: user.id, 
        sessionId: tokenData.session_id 
      });

      return {
        user: {
          id: user.id,
          email: user.email,
          role: user.role
        },
        refreshToken: newRefreshToken,
        sessionId: tokenData.session_id
      };

    } catch (error) {
      await client.query('ROLLBACK');
      console.error('❌ Token refresh failed:', error.message);
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * VALIDATE SESSION
   * 
   * Check if a session is valid and active.
   */
  static async validateSession(sessionToken) {
    try {
      const result = await query(
        `SELECT us.id, us.user_id, us.expires_at, us.is_active,
                u.id as user_id, u.email, u.role, u.is_active as user_active
         FROM user_sessions us
         JOIN users u ON us.user_id = u.id
         WHERE us.session_token = $1 AND us.is_active = true`,
        [sessionToken]
      );

      if (result.rows.length === 0) {
        return null;
      }

      const session = result.rows[0];

      // Check if session is expired
      if (new Date() > new Date(session.expires_at)) {
        // Deactivate expired session
        await query(
          'UPDATE user_sessions SET is_active = false WHERE id = $1',
          [session.id]
        );
        return null;
      }

      // Check if user is still active
      if (!session.user_active) {
        return null;
      }

      // Update last accessed time
      await query(
        'UPDATE user_sessions SET last_accessed = NOW() WHERE id = $1',
        [session.id]
      );

      return {
        sessionId: session.id,
        userId: session.user_id,
        user: {
          id: session.user_id,
          email: session.email,
          role: session.role
        }
      };

    } catch (error) {
      console.error('❌ Session validation failed:', error.message);
      return null;
    }
  }

  /**
   * LOGOUT SESSION
   * 
   * Invalidate a specific session and its refresh tokens.
   */
  static async logoutSession(sessionId, userId) {
    const client = await getClient();

    try {
      await client.query('BEGIN');

      // Deactivate session
      const sessionResult = await client.query(
        `UPDATE user_sessions 
         SET is_active = false
         WHERE id = $1 AND user_id = $2
         RETURNING id`,
        [sessionId, userId]
      );

      if (sessionResult.rows.length === 0) {
        throw new Error('Session not found');
      }

      // Revoke all refresh tokens for this session
      await client.query(
        'UPDATE refresh_tokens SET is_revoked = true WHERE session_id = $1',
        [sessionId]
      );

      await client.query('COMMIT');

      console.log('✅ Session logged out:', { sessionId, userId });
      return true;

    } catch (error) {
      await client.query('ROLLBACK');
      console.error('❌ Session logout failed:', error.message);
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * LOGOUT ALL SESSIONS
   * 
   * Invalidate all sessions for a user (useful for "logout everywhere").
   */
  static async logoutAllSessions(userId) {
    const client = await getClient();

    try {
      await client.query('BEGIN');

      // Get all active sessions for the user
      const sessionsResult = await client.query(
        'SELECT id FROM user_sessions WHERE user_id = $1 AND is_active = true',
        [userId]
      );

      if (sessionsResult.rows.length === 0) {
        await client.query('COMMIT');
        return { loggedOutSessions: 0 };
      }

      // Deactivate all sessions
      await client.query(
        'UPDATE user_sessions SET is_active = false WHERE user_id = $1',
        [userId]
      );

      // Revoke all refresh tokens for the user
      await client.query(
        'UPDATE refresh_tokens SET is_revoked = true WHERE user_id = $1',
        [userId]
      );

      await client.query('COMMIT');

      const loggedOutCount = sessionsResult.rows.length;
      console.log('✅ All sessions logged out:', { userId, count: loggedOutCount });

      return { loggedOutSessions: loggedOutCount };

    } catch (error) {
      await client.query('ROLLBACK');
      console.error('❌ Logout all sessions failed:', error.message);
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * GET USER SESSIONS
   * 
   * Get all active sessions for a user (for security dashboard).
   */
  static async getUserSessions(userId) {
    try {
      const result = await query(
        `SELECT id, device_info, ip_address, user_agent, created_at, 
                last_accessed, expires_at
         FROM user_sessions 
         WHERE user_id = $1 AND is_active = true
         ORDER BY last_accessed DESC`,
        [userId]
      );

      const sessions = result.rows.map(session => {
        let deviceInfo = {};
        
        // Safely parse device_info JSON
        try {
          if (session.device_info) {
            if (typeof session.device_info === 'string') {
              deviceInfo = JSON.parse(session.device_info);
            } else if (typeof session.device_info === 'object') {
              deviceInfo = session.device_info;
            }
          }
        } catch (parseError) {
          console.warn('⚠️ Failed to parse device_info for session:', session.id, parseError.message);
          deviceInfo = {};
        }

        return {
          id: session.id,
          deviceInfo,
          ipAddress: session.ip_address,
          userAgent: session.user_agent,
          createdAt: session.created_at,
          lastAccessed: session.last_accessed,
          expiresAt: session.expires_at,
          isCurrent: false // This would be set by the calling code
        };
      });

      return sessions;

    } catch (error) {
      console.error('❌ Get user sessions failed:', error.message);
      throw new Error('Failed to retrieve user sessions');
    }
  }

  /**
   * REVOKE SESSION
   * 
   * Admin function to revoke a specific session.
   */
  static async revokeSession(sessionId) {
    try {
      const result = await query(
        `UPDATE user_sessions 
         SET is_active = false
         WHERE id = $1
         RETURNING id, user_id`,
        [sessionId]
      );

      if (result.rows.length === 0) {
        throw new Error('Session not found');
      }

      // Also revoke refresh tokens
      await query(
        'UPDATE refresh_tokens SET is_revoked = true WHERE session_id = $1',
        [sessionId]
      );

      console.log('✅ Session revoked:', { sessionId });
      return result.rows[0];

    } catch (error) {
      console.error('❌ Session revocation failed:', error.message);
      throw error;
    }
  }

  /**
   * CLEANUP EXPIRED SESSIONS
   * 
   * Remove expired sessions and tokens (run periodically).
   */
  static async cleanupExpiredSessions() {
    const client = await getClient();

    try {
      await client.query('BEGIN');

      // Deactivate expired sessions
      const expiredSessionsResult = await client.query(
        `UPDATE user_sessions 
         SET is_active = false 
         WHERE expires_at < NOW() AND is_active = true
         RETURNING id`
      );

      // Revoke expired refresh tokens
      const expiredTokensResult = await client.query(
        `UPDATE refresh_tokens 
         SET is_revoked = true 
         WHERE expires_at < NOW() AND is_revoked = false
         RETURNING id`
      );

      await client.query('COMMIT');

      const expiredSessions = expiredSessionsResult.rows.length;
      const expiredTokens = expiredTokensResult.rows.length;

      console.log('✅ Expired sessions cleaned up:', { 
        expiredSessions, 
        expiredTokens 
      });

      return { expiredSessions, expiredTokens };

    } catch (error) {
      await client.query('ROLLBACK');
      console.error('❌ Session cleanup failed:', error.message);
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * GET SESSION STATISTICS
   * 
   * Get session statistics for monitoring.
   */
  static async getSessionStats() {
    try {
      const result = await query(`
        SELECT 
          COUNT(*) as total_sessions,
          COUNT(*) FILTER (WHERE is_active = true) as active_sessions,
          COUNT(DISTINCT user_id) FILTER (WHERE is_active = true) as active_users,
          COUNT(*) FILTER (WHERE expires_at < NOW()) as expired_sessions
        FROM user_sessions
      `);

      return result.rows[0];

    } catch (error) {
      console.error('❌ Get session stats failed:', error.message);
      throw new Error('Failed to retrieve session statistics');
    }
  }
}

export default SessionService; 