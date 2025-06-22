# Authentication System

Full-stack authentication application with Express.js backend and React frontend.

## Quick Start

1. **Backend Setup:**
   ```bash
   cd backend
   npm install
   cp .env.example .env
   # Edit .env with your database credentials
   npm run db:migrate
   npm run dev
   ```

2. **Frontend Setup:**
   ```bash
   cd frontend
   npm install
   npm start
   ```

## Project Structure

- `backend/` - Express.js API server
- `frontend/` - React application

## Features

- User registration and login
- JWT authentication
- Password reset
- Session management
- PostgreSQL database
- Email verification

## Tech Stack

- **Backend:** Node.js, Express.js, PostgreSQL
- **Frontend:** React, Tailwind CSS
- **Authentication:** JWT tokens
- **Database:** PostgreSQL

## Environment Setup

Both frontend and backend require environment configuration. See the README files in each directory for specific setup instructions.

## License

Educational use only. 