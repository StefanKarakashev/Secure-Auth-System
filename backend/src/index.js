import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import compression from 'compression';
import hpp from 'hpp';
import dotenv from 'dotenv';
import { testConnection, closePool } from './config/database.js';
import { generalRateLimit } from './middleware/auth.js';
import authRoutes from './routes/auth.js';

// Load environment variables
dotenv.config();

/**
 * PRODUCTION-READY EXPRESS SERVER
 * 
 * This file sets up a secure Express.js server with comprehensive security middleware
 * and proper error handling. It's designed for production use with all the necessary
 * security measures that real-world applications require.
 * 
 * Security features implemented:
 * - Helmet for security headers
 * - CORS with proper configuration
 * - Rate limiting and brute force protection
 * - Request parsing with size limits
 * - HPP (HTTP Parameter Pollution) protection
 * - Compression for performance
 * - Trust proxy settings for deployment
 * - Comprehensive error handling
 * - Graceful shutdown handling
 */

const app = express();
const PORT = process.env.PORT || 5000;

/**
 * TRUST PROXY CONFIGURATION
 * 
 * Essential for applications deployed behind reverse proxies (Nginx, load balancers, etc.)
 * This ensures req.ip returns the real client IP, not the proxy IP.
 */
app.set('trust proxy', 1);

/**
 * SECURITY MIDDLEWARE
 * 
 * Applied in order of importance for security and performance.
 */

// Helmet - Sets various HTTP headers for security
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false, // Adjust based on your needs
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  }
}));

// CORS Configuration
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    // In development, allow ALL origins for debugging
    if (process.env.NODE_ENV !== 'production') {
      console.log('🌐 CORS allowing origin:', origin);
      return callback(null, true);
    }
    
    // Production allowed origins
    const allowedOrigins = process.env.CORS_ORIGIN?.split(',') || [
      'http://localhost:3000',  // Backend API
      'http://localhost:3001',  // React dev server
      'http://127.0.0.1:3000',
      'http://127.0.0.1:3001',
    ];
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log('🚫 CORS blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: false, // Temporarily disabled for mobile testing
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Origin',
    'X-Requested-With',
    'Content-Type',
    'Accept',
    'Authorization',
    'X-Refresh-Token',
    'X-Session-Token'
  ],
  exposedHeaders: ['X-Total-Count'], // Headers that frontend can access
  maxAge: 86400 // Cache preflight response for 24 hours
};

app.use(cors(corsOptions));

// Compression for better performance
app.use(compression({
  level: 6, // Compression level (1-9)
  threshold: 1024, // Only compress if response > 1KB
  filter: (req, res) => {
    // Don't compress if explicitly not wanted
    if (req.headers['x-no-compression']) {
      return false;
    }
    // Use compression for all other responses
    return compression.filter(req, res);
  }
}));

// HTTP Parameter Pollution protection
app.use(hpp({
  whitelist: ['sort'] // Allow arrays for these parameters
}));

// Request parsing middleware with security limits
app.use(express.json({ 
  limit: '10mb', // Prevent large JSON payloads
  verify: (req, res, buf) => {
    // Store raw body for webhook verification if needed
    req.rawBody = buf;
  }
}));

app.use(express.urlencoded({ 
  extended: true, 
  limit: '10mb',
  parameterLimit: 50 // Limit number of parameters
}));

// Cookie parser for session management
app.use(cookieParser(process.env.SESSION_SECRET));

// Global rate limiting (before routes)
app.use(generalRateLimit);

/**
 * REQUEST LOGGING MIDDLEWARE
 * 
 * Log all requests for monitoring and debugging.
 * In production, you might want to use a proper logging library like Winston.
 */
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  const method = req.method;
  const url = req.url;
  const ip = req.ip;
  const userAgent = req.get('User-Agent') || 'Unknown';
  
  console.log(`📨 ${timestamp} - ${method} ${url} - IP: ${ip} - UA: ${userAgent}`);
  
  // Track response time
  req.startTime = Date.now();
  
  // Log response when finished
  res.on('finish', () => {
    const duration = Date.now() - req.startTime;
    const statusCode = res.statusCode;
    const statusEmoji = statusCode >= 400 ? '❌' : statusCode >= 300 ? '⚠️' : '✅';
    
    console.log(`${statusEmoji} ${method} ${url} - ${statusCode} - ${duration}ms`);
  });
  
  next();
});

/**
 * HEALTH CHECK ENDPOINT
 * 
 * Essential for load balancers and monitoring systems.
 */
app.get('/health', async (req, res) => {
  try {
    // Test database connection
    const dbHealthy = await testConnection();
    
    const health = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: process.env.NODE_ENV,
      version: process.env.npm_package_version || '1.0.0',
      database: dbHealthy ? 'connected' : 'disconnected',
      memory: {
        used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
        total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024),
        unit: 'MB'
      }
    };
    
    // Return 503 if database is not healthy
    const statusCode = dbHealthy ? 200 : 503;
    
    res.status(statusCode).json(health);
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: 'Health check failed'
    });
  }
});

/**
 * API ROUTES
 */

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: 'Authentication API Server',
    version: '1.0.0',
    documentation: '/api/docs', // Future API documentation endpoint
    endpoints: {
      auth: '/api/v1/auth',
      health: '/health'
    }
  });
});

// Authentication routes
app.use('/api/v1/auth', authRoutes);

// API documentation placeholder
app.get('/api/docs', (req, res) => {
  res.json({
    message: 'API Documentation',
    note: 'In a production app, you would serve Swagger/OpenAPI docs here',
    authEndpoints: {
      'POST /api/v1/auth/register': 'Register new user',
      'POST /api/v1/auth/login': 'Login user',
      'POST /api/v1/auth/logout': 'Logout current session',
      'POST /api/v1/auth/logout-all': 'Logout all sessions',
      'POST /api/v1/auth/refresh': 'Refresh access token',
      'POST /api/v1/auth/forgot-password': 'Request password reset',
      'POST /api/v1/auth/reset-password': 'Reset password',
      'POST /api/v1/auth/verify-email': 'Verify email address',
      'GET /api/v1/auth/me': 'Get current user',
      'GET /api/v1/auth/sessions': 'Get user sessions',
      'DELETE /api/v1/auth/sessions/:id': 'Revoke session'
    }
  });
});

/**
 * 404 HANDLER
 * 
 * Handle requests to non-existent endpoints.
 */
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint not found',
    code: 'NOT_FOUND',
    path: req.originalUrl,
    method: req.method,
    timestamp: new Date().toISOString()
  });
});

/**
 * GLOBAL ERROR HANDLER
 * 
 * Catches all unhandled errors and returns appropriate responses.
 * This is the last middleware and catches everything that wasn't handled above.
 */
app.use((error, req, res, next) => {
  console.error('💥 Unhandled error:', {
    message: error.message,
    stack: error.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  // Handle specific error types
  if (error.name === 'ValidationError') {
    return res.status(400).json({
      success: false,
      message: 'Validation error',
      code: 'VALIDATION_ERROR',
      details: error.message
    });
  }

  if (error.name === 'CastError') {
    return res.status(400).json({
      success: false,
      message: 'Invalid ID format',
      code: 'INVALID_ID'
    });
  }

  if (error.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({
      success: false,
      message: 'File too large',
      code: 'FILE_TOO_LARGE'
    });
  }

  if (error.type === 'entity.parse.failed') {
    return res.status(400).json({
      success: false,
      message: 'Invalid JSON format',
      code: 'INVALID_JSON'
    });
  }

  // CORS errors
  if (error.message.includes('CORS')) {
    return res.status(403).json({
      success: false,
      message: 'CORS error: Origin not allowed',
      code: 'CORS_ERROR'
    });
  }

  // Rate limiting errors
  if (error.status === 429) {
    return res.status(429).json({
      success: false,
      message: 'Too many requests',
      code: 'RATE_LIMIT_EXCEEDED'
    });
  }

  // Database connection errors
  if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
    return res.status(503).json({
      success: false,
      message: 'Service temporarily unavailable',
      code: 'SERVICE_UNAVAILABLE'
    });
  }

  // Default error response
  const statusCode = error.statusCode || error.status || 500;
  const message = process.env.NODE_ENV === 'production' 
    ? 'An unexpected error occurred' 
    : error.message;

  res.status(statusCode).json({
    success: false,
    message,
    code: 'INTERNAL_SERVER_ERROR',
    ...(process.env.NODE_ENV !== 'production' && { stack: error.stack })
  });
});

/**
 * GRACEFUL SHUTDOWN HANDLING
 * 
 * Properly close database connections and other resources when the server shuts down.
 */
const gracefulShutdown = async (signal) => {
  console.log(`\n🛑 Received ${signal}. Starting graceful shutdown...`);
  
  // Stop accepting new requests
  server.close(async (error) => {
    if (error) {
      console.error('❌ Error during server close:', error);
      process.exit(1);
    }
    
    console.log('✅ HTTP server closed');
    
    try {
      // Close database connections
      await closePool();
      console.log('✅ Database connections closed');
      
      console.log('✅ Graceful shutdown completed');
      process.exit(0);
    } catch (error) {
      console.error('❌ Error during shutdown:', error);
      process.exit(1);
    }
  });
  
  // Force close after timeout
  setTimeout(() => {
    console.error('⏰ Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000); // 10 seconds timeout
};

// Handle shutdown signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('💥 Uncaught Exception:', error);
  gracefulShutdown('uncaughtException');
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
  gracefulShutdown('unhandledRejection');
});

/**
 * START SERVER
 * 
 * Initialize the server and test database connection.
 */
const startServer = async () => {
  try {
    console.log('🚀 Starting authentication server...\n');
    
    // Test database connection
    console.log('📡 Testing database connection...');
    const dbConnected = await testConnection();
    
    if (!dbConnected) {
      console.error('❌ Could not connect to database. Exiting...');
      process.exit(1);
    }
    
    // Start HTTP server
    const HOST = process.env.HOST || '0.0.0.0';
    const server = app.listen(PORT, HOST, () => {
      console.log('\n🎉 Server started successfully!');
      console.log(`📡 Server running on ${HOST}:${PORT}`);
      console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`🔗 Local URL: http://localhost:${PORT}`);
      console.log(`🌐 Network URL: http://${HOST}:${PORT}`);
      console.log(`�� Health check: http://localhost:${PORT}/health`);
      console.log(`📚 API docs: http://localhost:${PORT}/api/docs`);
      console.log('\n🔐 Authentication endpoints available at /api/v1/auth');
      console.log('\n⚡ Ready to handle requests!\n');
    });
    
    // Store server reference for graceful shutdown
    global.server = server;
    
    return server;
    
  } catch (error) {
    console.error('💥 Failed to start server:', error);
    process.exit(1);
  }
};

// Start the server
const server = await startServer();

export default app;


