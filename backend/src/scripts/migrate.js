import { query, testConnection } from '../config/database.js';
import dotenv from 'dotenv';

dotenv.config();

/**
 * DATABASE MIGRATION SCRIPT
 * 
 * This script creates all the tables needed for our authentication system.
 * In production, you'd typically use a proper migration tool like Knex.js or Sequelize,
 * but this shows you exactly what tables and indexes are needed.
 * 
 * Tables we'll create:
 * 1. users - Core user information with authentication data
 * 2. user_sessions - Track active sessions across multiple devices
 * 3. refresh_tokens - Store refresh tokens for JWT token rotation
 * 4. password_resets - Temporary tokens for password reset flow
 * 5. email_verifications - Tokens for email verification
 * 6. login_attempts - Track failed login attempts for brute force protection
 */

const migrations = [
  {
    name: 'Create users table',
    sql: `
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        first_name VARCHAR(100) NOT NULL,
        last_name VARCHAR(100) NOT NULL,
        role VARCHAR(50) NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin', 'moderator')),
        is_email_verified BOOLEAN DEFAULT FALSE,
        is_active BOOLEAN DEFAULT TRUE,
        failed_login_attempts INTEGER DEFAULT 0,
        locked_until TIMESTAMP WITH TIME ZONE,
        last_login TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      );

      -- Indexes for performance (crucial for production)
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
      CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);
      CREATE INDEX IF NOT EXISTS idx_users_email_verified ON users(is_email_verified);
      CREATE INDEX IF NOT EXISTS idx_users_locked_until ON users(locked_until);
    `
  },

  {
    name: 'Create user_sessions table',
    sql: `
      CREATE TABLE IF NOT EXISTS user_sessions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        session_token VARCHAR(500) NOT NULL UNIQUE,
        device_info JSONB, -- Store device fingerprinting data
        ip_address INET,
        user_agent TEXT,
        is_active BOOLEAN DEFAULT TRUE,
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        last_accessed TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      );

      -- Indexes for session management
      CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(session_token);
      CREATE INDEX IF NOT EXISTS idx_sessions_active ON user_sessions(is_active);
      CREATE INDEX IF NOT EXISTS idx_sessions_expires ON user_sessions(expires_at);
    `
  },

  {
    name: 'Create refresh_tokens table',
    sql: `
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash VARCHAR(255) NOT NULL UNIQUE, -- We hash refresh tokens for security
        session_id UUID REFERENCES user_sessions(id) ON DELETE CASCADE,
        device_info JSONB,
        is_revoked BOOLEAN DEFAULT FALSE,
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      );

      -- Indexes for token validation
      CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
      CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash);
      CREATE INDEX IF NOT EXISTS idx_refresh_tokens_session ON refresh_tokens(session_id);
      CREATE INDEX IF NOT EXISTS idx_refresh_tokens_revoked ON refresh_tokens(is_revoked);
      CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);
    `
  },

  {
    name: 'Create password_resets table',
    sql: `
      CREATE TABLE IF NOT EXISTS password_resets (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash VARCHAR(255) NOT NULL UNIQUE,
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        is_used BOOLEAN DEFAULT FALSE,
        ip_address INET,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      );

      -- Indexes for password reset flow
      CREATE INDEX IF NOT EXISTS idx_password_resets_user_id ON password_resets(user_id);
      CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token_hash);
      CREATE INDEX IF NOT EXISTS idx_password_resets_expires ON password_resets(expires_at);
      CREATE INDEX IF NOT EXISTS idx_password_resets_used ON password_resets(is_used);
    `
  },

  {
    name: 'Create email_verifications table',
    sql: `
      CREATE TABLE IF NOT EXISTS email_verifications (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash VARCHAR(255) NOT NULL UNIQUE,
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        is_used BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      );

      -- Indexes for email verification
      CREATE INDEX IF NOT EXISTS idx_email_verifications_user_id ON email_verifications(user_id);
      CREATE INDEX IF NOT EXISTS idx_email_verifications_token ON email_verifications(token_hash);
      CREATE INDEX IF NOT EXISTS idx_email_verifications_expires ON email_verifications(expires_at);
    `
  },

  {
    name: 'Create login_attempts table',
    sql: `
      CREATE TABLE IF NOT EXISTS login_attempts (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) NOT NULL,
        ip_address INET NOT NULL,
        user_agent TEXT,
        success BOOLEAN DEFAULT FALSE,
        failure_reason VARCHAR(100),
        attempted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      );

      -- Indexes for brute force protection analysis
      CREATE INDEX IF NOT EXISTS idx_login_attempts_email ON login_attempts(email);
      CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address);
      CREATE INDEX IF NOT EXISTS idx_login_attempts_success ON login_attempts(success);
      CREATE INDEX IF NOT EXISTS idx_login_attempts_time ON login_attempts(attempted_at);
      CREATE INDEX IF NOT EXISTS idx_login_attempts_email_ip ON login_attempts(email, ip_address);
    `
  },

  {
    name: 'Create audit_logs table',
    sql: `
      CREATE TABLE IF NOT EXISTS audit_logs (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES users(id) ON DELETE SET NULL,
        action VARCHAR(100) NOT NULL,
        resource VARCHAR(100),
        details JSONB,
        ip_address INET,
        user_agent TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      );

      -- Indexes for audit trail analysis
      CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource);
      CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
    `
  },

  {
    name: 'Create cleanup functions',
    sql: `
      -- Function to clean up expired tokens automatically
      CREATE OR REPLACE FUNCTION cleanup_expired_tokens()
      RETURNS void AS $$
      BEGIN
        -- Clean up expired refresh tokens
        DELETE FROM refresh_tokens WHERE expires_at < NOW();
        
        -- Clean up expired password reset tokens
        DELETE FROM password_resets WHERE expires_at < NOW();
        
        -- Clean up expired email verification tokens  
        DELETE FROM email_verifications WHERE expires_at < NOW();
        
        -- Clean up expired sessions
        DELETE FROM user_sessions WHERE expires_at < NOW();
        
        -- Clean up old login attempts (keep last 30 days)
        DELETE FROM login_attempts WHERE attempted_at < NOW() - INTERVAL '30 days';
        
        -- Clean up old audit logs (keep last 90 days)
        DELETE FROM audit_logs WHERE created_at < NOW() - INTERVAL '90 days';
      END;
      $$ LANGUAGE plpgsql;

      -- Function to update user's updated_at timestamp
      CREATE OR REPLACE FUNCTION update_updated_at_column()
      RETURNS TRIGGER AS $$
      BEGIN
        NEW.updated_at = NOW();
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;

      -- Trigger to automatically update updated_at on users table
      DROP TRIGGER IF EXISTS update_users_updated_at ON users;
      CREATE TRIGGER update_users_updated_at
        BEFORE UPDATE ON users
        FOR EACH ROW
        EXECUTE FUNCTION update_updated_at_column();
    `
  }
];

/**
 * Run all migrations
 */
async function runMigrations() {
  console.log('🚀 Starting database migrations...\n');

  // Test connection first
  const isConnected = await testConnection();
  if (!isConnected) {
    console.error('❌ Cannot connect to database. Migration aborted.');
    process.exit(1);
  }

  try {
    for (const migration of migrations) {
      console.log(`⏳ Running: ${migration.name}`);
      await query(migration.sql);
      console.log(`✅ Completed: ${migration.name}\n`);
    }

    console.log('🎉 All migrations completed successfully!');
    console.log('\n📊 Database schema summary:');
    console.log('   • users - Core user data with authentication');
    console.log('   • user_sessions - Multi-device session management');
    console.log('   • refresh_tokens - JWT token rotation');
    console.log('   • password_resets - Password reset flow');
    console.log('   • email_verifications - Email verification');
    console.log('   • login_attempts - Brute force protection');
    console.log('   • audit_logs - Security audit trail');
    console.log('\n🛠️  Utility functions created:');
    console.log('   • cleanup_expired_tokens() - Run periodically to clean up');
    console.log('   • update_updated_at_column() - Auto-update timestamps');

  } catch (error) {
    console.error('❌ Migration failed:', error.message);
    process.exit(1);
  }
}

// Run migrations if this file is executed directly
if (process.argv[1].endsWith('migrate.js')) {
  runMigrations().then(() => process.exit(0));
}

export { runMigrations }; 