import pg from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const { Pool } = pg;

/**
 * PRODUCTION-READY DATABASE CONFIGURATION
 * 
 * Why we use connection pooling:
 * - Connection pools reuse database connections instead of creating new ones for each request
 * - This dramatically improves performance and prevents connection exhaustion
 * - Essential for production applications that handle multiple concurrent requests
 * 
 * Configuration explanations:
 * - max: Maximum number of connections in the pool (adjust based on your database plan)
 * - idleTimeoutMillis: How long connections stay alive when not in use
 * - connectionTimeoutMillis: How long to wait when trying to get a connection from pool
 * - statement_timeout: PostgreSQL setting to prevent runaway queries
 */

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'auth_system_db',
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  
  // Connection pool configuration for production
  max: 20, // Maximum number of connections in pool
  idleTimeoutMillis: 30000, // Close idle connections after 30 seconds
  connectionTimeoutMillis: 2000, // Return error after 2 seconds if unable to connect
  
  // Security and performance settings
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  statement_timeout: 30000, // 30 second query timeout
  query_timeout: 30000,
});

/**
 * Connection event handlers for monitoring and debugging
 * These help you understand what's happening with your database connections
 */
pool.on('connect', (_client) => {
  console.log('🔗 New database connection established');
});

pool.on('error', (err, _client) => {
  console.error('💥 Unexpected error on idle database client:', err);
  process.exit(-1);
});

pool.on('acquire', (_client) => {
  console.log('📨 Connection acquired from pool');
});

pool.on('release', (_client) => {
  console.log('📤 Connection released back to pool');
});

/**
 * Helper function to execute queries with proper error handling
 * This wrapper provides consistent error handling and logging across your app
 */
export const query = async (text, params = []) => {
  const start = Date.now();
  try {
    const result = await pool.query(text, params);
    const duration = Date.now() - start;
    
    // Log slow queries (anything over 1 second)
    if (duration > 1000) {
      console.warn(`🐌 Slow query detected (${duration}ms):`, text);
    }
    
    return result;
  } catch (error) {
    console.error('❌ Database query error:', {
      query: text,
      params: params,
      error: error.message,
      duration: Date.now() - start
    });
    throw error;
  }
};

/**
 * Helper to get a client for transactions
 * Transactions ensure data consistency - either all operations succeed or all fail
 */
export const getClient = async () => {
  const client = await pool.connect();
  return client;
};

/**
 * Test database connection
 * Call this during application startup to ensure database is accessible
 */
export const testConnection = async () => {
  try {
    const result = await query('SELECT NOW() as current_time, version() as pg_version');
    console.log('✅ Database connection successful:', {
      time: result.rows[0].current_time,
      version: result.rows[0].pg_version.split(' ')[0]
    });
    return true;
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    return false;
  }
};

/**
 * Graceful shutdown
 * Call this when your application is shutting down to properly close connections
 */
export const closePool = async () => {
  try {
    await pool.end();
    console.log('🔒 Database connection pool closed');
  } catch (error) {
    console.error('❌ Error closing database pool:', error.message);
  }
};

export default pool; 