import { query, getClient } from '../config/database.js';
import { hashPassword, verifyPassword, sanitizeEmail, sanitizeString } from '../utils/security.js';

/**
 * USER MODEL
 * 
 * This model handles all database operations related to users.
 * It follows the Repository pattern - separating data access logic from business logic.
 * 
 * In production applications, models should:
 * - Handle only data access (no business logic)
 * - Use parameterized queries (prevent SQL injection)
 * - Provide consistent error handling
 * - Include proper logging for debugging
 */

class User {
  
  /**
   * CREATE A NEW USER
   * 
   * This method creates a new user with properly hashed password.
   * It uses a database transaction to ensure data consistency.
   */
  static async create({ email, password, firstName, lastName, role = 'user' }) {
    const client = await getClient();
    
    try {
      await client.query('BEGIN');
      
      // Sanitize inputs
      const sanitizedEmail = sanitizeEmail(email);
      const sanitizedFirstName = sanitizeString(firstName, 100);
      const sanitizedLastName = sanitizeString(lastName, 100);
      
      // Hash password
      const passwordHash = await hashPassword(password);
      
      // Insert user
      const userResult = await client.query(
        `INSERT INTO users (email, password_hash, first_name, last_name, role)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, email, first_name, last_name, role, is_email_verified, 
                   is_active, created_at, updated_at`,
        [sanitizedEmail, passwordHash, sanitizedFirstName, sanitizedLastName, role]
      );
      
      await client.query('COMMIT');
      
      console.log('✅ New user created:', { email: sanitizedEmail, role });
      return userResult.rows[0];
      
    } catch (error) {
      await client.query('ROLLBACK');
      
      // Handle unique constraint violation (duplicate email)
      if (error.code === '23505' && error.constraint === 'users_email_key') {
        throw new Error('Email address already exists');
      }
      
      console.error('❌ User creation failed:', error.message);
      throw new Error('Failed to create user');
    } finally {
      client.release();
    }
  }
  
  /**
   * FIND USER BY EMAIL
   * 
   * Used for login and email verification.
   * Returns user with password hash for authentication.
   */
  static async findByEmail(email, includePassword = false) {
    try {
      const sanitizedEmail = sanitizeEmail(email);
      
      const selectFields = includePassword 
        ? 'id, email, password_hash, first_name, last_name, role, is_email_verified, is_active, failed_login_attempts, locked_until, last_login, created_at, updated_at'
        : 'id, email, first_name, last_name, role, is_email_verified, is_active, failed_login_attempts, locked_until, last_login, created_at, updated_at';
      
      const result = await query(
        `SELECT ${selectFields} FROM users WHERE email = $1`,
        [sanitizedEmail]
      );
      
      return result.rows[0] || null;
      
    } catch (error) {
      console.error('❌ Find user by email failed:', error.message);
      throw new Error('Failed to find user');
    }
  }
  
  /**
   * FIND USER BY ID
   * 
   * Used for retrieving user information during authenticated requests.
   */
  static async findById(userId) {
    try {
      const result = await query(
        `SELECT id, email, first_name, last_name, role, is_email_verified, 
                is_active, last_login, created_at, updated_at
         FROM users WHERE id = $1 AND is_active = true`,
        [userId]
      );
      
      return result.rows[0] || null;
      
    } catch (error) {
      console.error('❌ Find user by ID failed:', error.message);
      throw new Error('Failed to find user');
    }
  }
  
  /**
   * AUTHENTICATE USER
   * 
   * Verifies email and password combination.
   * Includes account lockout protection against brute force attacks.
   */
  static async authenticate(email, password, ipAddress, userAgent) {
    const client = await getClient();
    
    try {
      await client.query('BEGIN');
      
      const sanitizedEmail = sanitizeEmail(email);
      
      // Find user with password hash
      const user = await this.findByEmail(sanitizedEmail, true);
      
      // Always record the login attempt (for security analysis)
      await this.recordLoginAttempt(sanitizedEmail, ipAddress, userAgent, false, 'User not found');
      
      if (!user) {
        await client.query('COMMIT');
        // Return generic error to prevent email enumeration
        throw new Error('Invalid email or password');
      }
      
      // Check if account is locked
      if (user.locked_until && new Date() < new Date(user.locked_until)) {
        await client.query('COMMIT');
        const lockTimeRemaining = Math.ceil((new Date(user.locked_until) - new Date()) / 1000 / 60);
        throw new Error(`Account locked. Try again in ${lockTimeRemaining} minutes.`);
      }
      
      // Check if account is active
      if (!user.is_active) {
        await client.query('COMMIT');
        throw new Error('Account is deactivated');
      }
      
      // Verify password
      const isPasswordValid = await verifyPassword(password, user.password_hash);
      
      if (!isPasswordValid) {
        // Increment failed attempts
        await this.incrementFailedAttempts(user.id);
        await this.recordLoginAttempt(sanitizedEmail, ipAddress, userAgent, false, 'Invalid password');
        await client.query('COMMIT');
        throw new Error('Invalid email or password');
      }
      
      // Successful login - reset failed attempts and update last login
      await client.query(
        `UPDATE users 
         SET failed_login_attempts = 0, locked_until = NULL, last_login = NOW()
         WHERE id = $1`,
        [user.id]
      );
      
      // Record successful login
      await this.recordLoginAttempt(sanitizedEmail, ipAddress, userAgent, true);
      
      await client.query('COMMIT');
      
      // Remove password hash from returned user object
      const { password_hash, ...userWithoutPassword } = user;
      
      console.log('✅ User authenticated successfully:', { email: sanitizedEmail });
      return userWithoutPassword;
      
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
  
  /**
   * INCREMENT FAILED LOGIN ATTEMPTS
   * 
   * Track failed login attempts and lock account after threshold.
   */
  static async incrementFailedAttempts(userId) {
    try {
      const maxAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5;
      const lockoutTime = parseInt(process.env.LOCKOUT_TIME) || 15 * 60 * 1000; // 15 minutes
      
      const result = await query(
        `UPDATE users 
         SET failed_login_attempts = failed_login_attempts + 1,
             locked_until = CASE 
               WHEN failed_login_attempts + 1 >= $1 
               THEN NOW() + INTERVAL '${lockoutTime} milliseconds'
               ELSE locked_until
             END
         WHERE id = $2
         RETURNING failed_login_attempts, locked_until`,
        [maxAttempts, userId]
      );
      
      const updatedUser = result.rows[0];
      
      if (updatedUser.failed_login_attempts >= maxAttempts) {
        console.warn('⚠️ Account locked due to failed attempts:', { userId });
      }
      
    } catch (error) {
      console.error('❌ Failed to increment failed attempts:', error.message);
      throw new Error('Failed to update login attempts');
    }
  }
  
  /**
   * RECORD LOGIN ATTEMPT
   * 
   * Log all login attempts for security analysis and monitoring.
   */
  static async recordLoginAttempt(email, ipAddress, userAgent, success, failureReason = null) {
    try {
      await query(
        `INSERT INTO login_attempts (email, ip_address, user_agent, success, failure_reason)
         VALUES ($1, $2, $3, $4, $5)`,
        [email, ipAddress, userAgent, success, failureReason]
      );
      
    } catch (error) {
      // Don't throw error here - login attempt logging is not critical
      console.error('❌ Failed to record login attempt:', error.message);
    }
  }
  
  /**
   * UPDATE USER PROFILE
   * 
   * Update user's profile information.
   */
  static async updateProfile(userId, { firstName, lastName }) {
    try {
      const sanitizedFirstName = sanitizeString(firstName, 100);
      const sanitizedLastName = sanitizeString(lastName, 100);
      
      const result = await query(
        `UPDATE users 
         SET first_name = $1, last_name = $2, updated_at = NOW()
         WHERE id = $3 AND is_active = true
         RETURNING id, email, first_name, last_name, role, is_email_verified, 
                   is_active, created_at, updated_at`,
        [sanitizedFirstName, sanitizedLastName, userId]
      );
      
      if (result.rows.length === 0) {
        throw new Error('User not found or inactive');
      }
      
      console.log('✅ User profile updated:', { userId });
      return result.rows[0];
      
    } catch (error) {
      console.error('❌ Profile update failed:', error.message);
      throw new Error('Failed to update profile');
    }
  }
  
  /**
   * UPDATE PASSWORD
   * 
   * Change user's password with proper validation.
   */
  static async updatePassword(userId, currentPassword, newPassword) {
    const client = await getClient();
    
    try {
      await client.query('BEGIN');
      
      // Get current password hash
      const result = await client.query(
        'SELECT password_hash FROM users WHERE id = $1 AND is_active = true',
        [userId]
      );
      
      if (result.rows.length === 0) {
        throw new Error('User not found');
      }
      
      // Verify current password
      const isCurrentPasswordValid = await verifyPassword(currentPassword, result.rows[0].password_hash);
      if (!isCurrentPasswordValid) {
        throw new Error('Current password is incorrect');
      }
      
      // Hash new password
      const newPasswordHash = await hashPassword(newPassword);
      
      // Update password
      await client.query(
        'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
        [newPasswordHash, userId]
      );
      
      await client.query('COMMIT');
      
      console.log('✅ Password updated successfully:', { userId });
      return true;
      
    } catch (error) {
      await client.query('ROLLBACK');
      console.error('❌ Password update failed:', error.message);
      throw error;
    } finally {
      client.release();
    }
  }
  
  /**
   * VERIFY EMAIL
   * 
   * Mark user's email as verified.
   */
  static async verifyEmail(userId) {
    try {
      const result = await query(
        `UPDATE users 
         SET is_email_verified = true, updated_at = NOW()
         WHERE id = $1
         RETURNING id, email, is_email_verified`,
        [userId]
      );
      
      if (result.rows.length === 0) {
        throw new Error('User not found');
      }
      
      console.log('✅ Email verified:', { userId });
      return result.rows[0];
      
    } catch (error) {
      console.error('❌ Email verification failed:', error.message);
      throw new Error('Failed to verify email');
    }
  }
  
  /**
   * DEACTIVATE USER
   * 
   * Soft delete - mark user as inactive instead of deleting.
   */
  static async deactivate(userId) {
    try {
      const result = await query(
        `UPDATE users 
         SET is_active = false, updated_at = NOW()
         WHERE id = $1
         RETURNING id, email, is_active`,
        [userId]
      );
      
      if (result.rows.length === 0) {
        throw new Error('User not found');
      }
      
      console.log('✅ User deactivated:', { userId });
      return result.rows[0];
      
    } catch (error) {
      console.error('❌ User deactivation failed:', error.message);
      throw new Error('Failed to deactivate user');
    }
  }
  
  /**
   * GET USERS WITH PAGINATION
   * 
   * Admin function to get list of users with pagination.
   */
  static async getUsers({ page = 1, limit = 10, role = null, active = null }) {
    try {
      const offset = (page - 1) * limit;
      let whereClause = '';
      const params = [limit, offset];
      let paramIndex = 3;
      
      // Build WHERE clause dynamically
      const conditions = [];
      if (role) {
        conditions.push(`role = $${paramIndex++}`);
        params.push(role);
      }
      if (active !== null) {
        conditions.push(`is_active = $${paramIndex++}`);
        params.push(active);
      }
      
      if (conditions.length > 0) {
        whereClause = `WHERE ${conditions.join(' AND ')}`;
      }
      
      // Get users
      const usersResult = await query(
        `SELECT id, email, first_name, last_name, role, is_email_verified, 
                is_active, last_login, created_at, updated_at
         FROM users
         ${whereClause}
         ORDER BY created_at DESC
         LIMIT $1 OFFSET $2`,
        params
      );
      
      // Get total count
      const countResult = await query(
        `SELECT COUNT(*) as total FROM users ${whereClause}`,
        params.slice(2) // Remove limit and offset from params
      );
      
      const totalUsers = parseInt(countResult.rows[0].total);
      const totalPages = Math.ceil(totalUsers / limit);
      
      return {
        users: usersResult.rows,
        pagination: {
          currentPage: page,
          totalPages,
          totalUsers,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1
        }
      };
      
    } catch (error) {
      console.error('❌ Get users failed:', error.message);
      throw new Error('Failed to retrieve users');
    }
  }
}

export default User; 