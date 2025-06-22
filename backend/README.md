# 🔐 Production-Ready Authentication System

A comprehensive, production-grade authentication and authorization system built with **Express.js** and **PostgreSQL**. This system implements industry-standard security practices and is designed to scale for real-world applications.

## 🎯 **What You'll Learn**

This project demonstrates how to build a complete authentication system that you'd find in production applications. As a beginner, you'll understand:

- **JWT-based authentication** with access and refresh tokens
- **Multi-device session management** (login on phone, computer, tablet simultaneously)
- **Password security** with proper hashing and strength validation
- **Rate limiting** and brute force attack protection
- **Email verification** and password reset flows
- **Role-based access control** (user, admin, moderator)
- **Security middleware** and input validation
- **Database design** for authentication systems
- **Production deployment** considerations

## 🚀 **Key Features**

### 🔒 **Core Authentication**
- ✅ User registration with email verification
- ✅ Secure login with JWT tokens
- ✅ Automatic token refresh
- ✅ Multi-device session management
- ✅ Logout single device or all devices
- ✅ Password reset via email

### 🛡️ **Security Features**
- ✅ Bcrypt password hashing (12 rounds)
- ✅ JWT with separate secrets for different token types
- ✅ Rate limiting (10 login attempts per 15 minutes)
- ✅ Account lockout after failed attempts
- ✅ Input validation and sanitization
- ✅ CORS protection
- ✅ Helmet security headers
- ✅ HTTP Parameter Pollution protection
- ✅ Timing attack resistance

### 🎭 **Advanced Features**
- ✅ Role-based access control (user/admin/moderator)
- ✅ Device fingerprinting for session tracking
- ✅ Comprehensive audit logging
- ✅ Session statistics for admins
- ✅ Graceful shutdown handling
- ✅ Health check endpoint
- ✅ Error handling with proper HTTP status codes

## 🏗️ **Architecture Overview**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │────│   Express.js    │────│   PostgreSQL    │
│   (React/Vue)   │    │   REST API      │    │   Database      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                    ┌─────────┼─────────┐
                    │         │         │
            ┌───────▼───┐ ┌───▼───┐ ┌───▼────┐
            │Middleware │ │Models │ │Services│
            │& Security │ │& Auth │ │& Utils │
            └───────────┘ └───────┘ └────────┘
```

### **File Structure**
```
backend/
├── src/
│   ├── config/
│   │   └── database.js         # PostgreSQL connection & pooling
│   ├── controllers/
│   │   └── AuthController.js   # Authentication logic
│   ├── middleware/
│   │   ├── auth.js            # Authentication & authorization
│   │   └── validation.js      # Input validation with Joi
│   ├── models/
│   │   └── User.js            # User database operations
│   ├── routes/
│   │   └── auth.js            # API route definitions
│   ├── services/
│   │   └── SessionService.js  # Session management
│   ├── scripts/
│   │   └── migrate.js         # Database schema setup
│   ├── utils/
│   │   └── security.js        # Security utilities (JWT, hashing)
│   └── index.js               # Main application file
├── env.example                # Environment variables template
├── package.json               # Dependencies
└── README.md                  # This file
```

## 🔧 **Setup Instructions**

### **Prerequisites**
- Node.js 18+ 
- PostgreSQL 13+
- npm or yarn

### **1. Install Dependencies**
```bash
cd backend
npm install
```

### **2. Database Setup**

**Option A: Local PostgreSQL**
```bash
# Install PostgreSQL (Ubuntu/Debian)
sudo apt update
sudo apt install postgresql postgresql-contrib

# Start PostgreSQL service
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database and user
sudo -u postgres psql
CREATE DATABASE auth_system_db;
CREATE USER auth_user WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE auth_system_db TO auth_user;
\q
```

**Option B: Docker PostgreSQL**
```bash
docker run --name postgres-auth \
  -e POSTGRES_DB=auth_system_db \
  -e POSTGRES_USER=auth_user \
  -e POSTGRES_PASSWORD=your_secure_password \
  -p 5432:5432 \
  -d postgres:15
```

### **3. Environment Configuration**
```bash
# Copy environment template
cp env.example .env

# Edit .env file with your settings
nano .env
```

**Required Environment Variables:**
```env
# Database
DATABASE_URL=postgresql://auth_user:your_secure_password@localhost:5432/auth_system_db

# JWT Secrets (generate with: node -e "console.log(require('crypto').randomBytes(64).toString('hex'))")
JWT_ACCESS_SECRET=your_64_char_access_secret
JWT_REFRESH_SECRET=your_64_char_refresh_secret
JWT_RESET_SECRET=your_64_char_reset_secret
JWT_EMAIL_SECRET=your_64_char_email_secret

# Session
SESSION_SECRET=your_64_char_session_secret

# Security
BCRYPT_ROUNDS=12
MAX_LOGIN_ATTEMPTS=5
```

### **4. Database Migration**
```bash
# Create database tables
npm run db:migrate
```

### **5. Start the Server**
```bash
# Development mode (with auto-restart)
npm run dev

# Production mode
npm start
```

The server will start on `http://localhost:3000`

## 📡 **API Endpoints**

### **Authentication Endpoints**

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/auth/register` | Register new user | No |
| `POST` | `/api/v1/auth/login` | Login user | No |
| `POST` | `/api/v1/auth/logout` | Logout current session | Optional |
| `POST` | `/api/v1/auth/logout-all` | Logout all sessions | Yes |
| `POST` | `/api/v1/auth/refresh` | Refresh access token | No* |
| `GET` | `/api/v1/auth/me` | Get current user | Yes |

### **Password Management**

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/auth/forgot-password` | Request reset email | No |
| `POST` | `/api/v1/auth/reset-password` | Reset with token | No |
| `POST` | `/api/v1/auth/change-password` | Change password | Yes + Email Verified |

### **Email Verification**

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/auth/verify-email` | Verify email with token | No |
| `POST` | `/api/v1/auth/resend-verification` | Resend verification email | Yes |

### **Session Management**

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/v1/auth/sessions` | Get user's active sessions | Yes |
| `DELETE` | `/api/v1/auth/sessions/:id` | Revoke specific session | Yes |

### **Admin Endpoints**

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/v1/auth/admin/sessions` | Get session statistics | Admin |
| `POST` | `/api/v1/auth/admin/revoke-session` | Revoke any session | Admin |

*Requires valid refresh token

## 🔐 **How Authentication Works**

### **1. Registration Flow**
```mermaid
sequenceDiagram
    User->>API: POST /register {email, password, name}
    API->>Database: Check if email exists
    API->>API: Hash password (bcrypt)
    API->>Database: Create user account
    API->>Database: Create email verification token
    API->>Email: Send verification email
    API->>User: Registration successful
```

### **2. Login Flow**
```mermaid
sequenceDiagram
    User->>API: POST /login {email, password}
    API->>Database: Find user by email
    API->>API: Verify password (bcrypt)
    API->>Database: Create session record
    API->>API: Generate JWT access token (15min)
    API->>API: Generate refresh token (7 days)
    API->>User: Return tokens + user data
```

### **3. Token Refresh Flow**
```mermaid
sequenceDiagram
    User->>API: POST /refresh {refreshToken}
    API->>Database: Validate refresh token
    API->>Database: Revoke old refresh token
    API->>Database: Create new refresh token
    API->>API: Generate new access token
    API->>User: Return new tokens
```

### **4. Multi-Device Sessions**
Each login creates a separate session with its own refresh token. Users can:
- View all active sessions
- Logout from specific devices
- Logout from all devices at once
- See device information (browser, OS, location)

## 🛡️ **Security Features Explained**

### **Password Security**
- **Bcrypt hashing** with 12 rounds (computationally expensive)
- **Password strength validation** (length, complexity requirements)
- **Timing attack resistance** using constant-time comparisons

### **JWT Token Security**
- **Separate secrets** for different token types
- **Short-lived access tokens** (15 minutes) 
- **Refresh token rotation** (new token on each refresh)
- **Token storage** in httpOnly cookies (XSS protection)

### **Rate Limiting**
- **Login attempts**: 10 per 15 minutes per IP/email
- **General API**: 100 requests per 15 minutes
- **Account lockout**: 5 failed attempts = 15 minute lockout

### **Session Security**
- **Device fingerprinting** to detect session hijacking
- **Session expiration** and cleanup
- **Immediate revocation** capability
- **Audit logging** of all authentication events

### **Input Validation**
- **Joi schemas** for all endpoints
- **Sanitization** to prevent XSS
- **Parameter pollution** protection
- **File upload** validation (if implemented)

## 🚀 **Production Deployment**

### **Environment Setup**
```bash
# Production environment variables
NODE_ENV=production
PORT=3000

# Use strong secrets in production
JWT_ACCESS_SECRET=<64-char-random-string>
JWT_REFRESH_SECRET=<different-64-char-random-string>

# Database connection pooling
DB_MAX_CONNECTIONS=20
DB_IDLE_TIMEOUT=30000

# Security settings
CORS_ORIGIN=https://yourdomain.com
COOKIE_DOMAIN=.yourdomain.com
```

### **Database Optimization**
```sql
-- Create indexes for performance
CREATE INDEX CONCURRENTLY idx_users_email_active ON users(email) WHERE is_active = true;
CREATE INDEX CONCURRENTLY idx_sessions_user_active ON user_sessions(user_id) WHERE is_active = true;
CREATE INDEX CONCURRENTLY idx_refresh_tokens_hash ON refresh_tokens(token_hash) WHERE is_revoked = false;

-- Set up automatic cleanup (run daily)
CREATE OR REPLACE FUNCTION cleanup_expired_data()
RETURNS void AS $$
BEGIN
    -- Clean expired sessions and tokens
    SELECT cleanup_expired_tokens();
    
    -- Clean old audit logs (keep 90 days)
    DELETE FROM audit_logs WHERE created_at < NOW() - INTERVAL '90 days';
END;
$$ LANGUAGE plpgsql;

-- Schedule cleanup (requires pg_cron extension)
SELECT cron.schedule('cleanup-auth-data', '0 2 * * *', 'SELECT cleanup_expired_data();');
```

### **Docker Deployment**
```dockerfile
# Dockerfile
FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci --only=production

# Copy source code
COPY src/ ./src/

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nextjs -u 1001
USER nextjs

EXPOSE 3000

CMD ["npm", "start"]
```

### **Nginx Configuration**
```nginx
# /etc/nginx/sites-available/auth-api
server {
    listen 443 ssl;
    server_name api.yourdomain.com;

    # SSL configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

## 🧪 **Testing the API**

### **Register a New User**
```bash
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePass123!",
    "firstName": "John",
    "lastName": "Doe",
    "acceptTerms": true
  }'
```

### **Login**
```bash
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'
```

### **Access Protected Route**
```bash
curl -X GET http://localhost:3000/api/v1/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## 🔍 **Monitoring & Logging**

### **Health Check**
```bash
curl http://localhost:3000/health
```

Response:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "uptime": 3600,
  "database": "connected",
  "memory": {
    "used": 45,
    "total": 128,
    "unit": "MB"
  }
}
```

### **Audit Logs**
All security events are logged to the `audit_logs` table:
- User registrations
- Login attempts (successful and failed)
- Password changes
- Session management
- Admin actions

### **Performance Monitoring**
The application logs response times and slow queries:
```
📨 2024-01-15T10:30:00Z - POST /api/v1/auth/login - IP: 192.168.1.100
✅ POST /api/v1/auth/login - 200 - 150ms
⚠️  Slow query detected (1200ms): SELECT * FROM users WHERE email = $1
```

## 🐛 **Common Issues & Solutions**

### **Database Connection Issues**
```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Test connection
psql -h localhost -U auth_user -d auth_system_db -c "SELECT version();"

# Check environment variables
node -e "console.log(process.env.DATABASE_URL)"
```

### **JWT Token Issues**
```bash
# Generate new secrets
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# Verify token format
node -e "console.log(require('jsonwebtoken').decode('YOUR_TOKEN'))"
```

### **CORS Issues**
Make sure your frontend URL is in the `CORS_ORIGIN` environment variable:
```env
CORS_ORIGIN=http://localhost:3000,https://yourdomain.com
```

## 📚 **Learn More**

### **Recommended Reading**
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [JWT Best Practices](https://auth0.com/blog/a-look-at-the-latest-draft-for-jwt-bcp/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)

### **Security Resources**
- [bcrypt vs alternatives](https://security.stackexchange.com/questions/4781/do-any-security-experts-recommend-bcrypt-for-password-storage)
- [Session Management Security](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [Rate Limiting Strategies](https://blog.cloudflare.com/rate-limiting-nginx-plus/)

## 🤝 **Contributing**

This is a learning project, but improvements are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Follow the existing code style
5. Submit a pull request

## 📄 **License**

This project is for educational purposes. Use it as a starting point for your own authentication systems.

---

## 🎓 **What You've Built**

Congratulations! You now have a production-ready authentication system with:

✅ **Secure user management** with proper password hashing  
✅ **JWT-based authentication** with token refresh  
✅ **Multi-device session support** like Netflix or Google  
✅ **Rate limiting** to prevent abuse  
✅ **Email verification** and password reset flows  
✅ **Role-based access control** for different user types  
✅ **Comprehensive audit logging** for security monitoring  
✅ **Production-ready security** with all the best practices  

This system can handle thousands of users and serves as a solid foundation for any web application. You've learned the same patterns used by companies like GitHub, Stripe, and Shopify in their authentication systems.

**Next Steps:**
- Add email service integration (SendGrid, AWS SES)
- Implement OAuth (Google, Facebook login)
- Add two-factor authentication (2FA)
- Create a React/Vue frontend
- Deploy to AWS/Digital Ocean/Vercel

Keep building! 🚀 