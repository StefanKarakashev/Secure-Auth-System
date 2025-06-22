# Authentication System

A secure authentication system built with Express.js and PostgreSQL.

## Features

- User registration and login
- JWT-based authentication with refresh tokens
- Password reset functionality
- Email verification
- Session management
- Role-based access control
- Rate limiting and security middleware

## Getting Started

### Prerequisites
- Node.js 18+
- PostgreSQL 13+

### Installation

1. Install dependencies:
```bash
cd backend
npm install
```

2. Set up your database:
```bash
# Create database
createdb auth_system_db

# Run migrations
npm run db:migrate
```

3. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your database credentials and JWT secrets
```

4. Start the server:
```bash
npm run dev
```

## API Endpoints

### Authentication
- `POST /api/v1/auth/register` - Register new user
- `POST /api/v1/auth/login` - Login user
- `POST /api/v1/auth/logout` - Logout current session
- `POST /api/v1/auth/refresh` - Refresh access token
- `GET /api/v1/auth/me` - Get current user info

### Password Management
- `POST /api/v1/auth/forgot-password` - Request password reset
- `POST /api/v1/auth/reset-password` - Reset password with token

### Session Management
- `GET /api/v1/auth/sessions` - Get active sessions
- `DELETE /api/v1/auth/sessions/:id` - Revoke specific session

## Security Features

- Bcrypt password hashing
- JWT tokens with secure secrets
- Rate limiting on login attempts
- Input validation and sanitization
- CORS protection
- Security headers (Helmet)

## Environment Variables

```env
DATABASE_URL=postgresql://user:password@localhost:5432/auth_system_db
JWT_ACCESS_SECRET=your-secret-here
JWT_REFRESH_SECRET=your-refresh-secret-here
JWT_RESET_SECRET=your-reset-secret-here
JWT_EMAIL_SECRET=your-email-secret-here
SESSION_SECRET=your-session-secret-here
```

## Testing

Use curl or Postman to test the API:

```bash
# Register a user
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123","firstName":"Test","lastName":"User","acceptTerms":true}'

# Login
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'
```

## Production Deployment

1. Set `NODE_ENV=production`
2. Use strong, unique secrets for all JWT tokens
3. Configure proper CORS origins
4. Set up SSL/TLS
5. Use a process manager like PM2

## License

This project is for educational purposes. 