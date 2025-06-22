import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import VerifyEmailPage from './pages/VerifyEmailPage';
import ForgotPasswordPage from './pages/ForgotPasswordPage';
import ResetPasswordPage from './pages/ResetPasswordPage';
import DashboardPage from './pages/DashboardPage';
import SessionsPage from './pages/SessionsPage';
import ChangePasswordPage from './pages/ChangePasswordPage';
import LoadingSpinner from './components/ui/LoadingSpinner';
import DebugPanel from './components/debug/DebugPanel';
import './index.css';

/**
 * PROTECTED ROUTE COMPONENT
 * 
 * This component protects routes that require authentication.
 * If user is not logged in, redirect to login page.
 */
const ProtectedRoute = ({ children }) => {
  const { isAuthenticated, isInitialized } = useAuth();

  if (!isInitialized) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <LoadingSpinner size="large" text="Loading..." />
      </div>
    );
  }

  return isAuthenticated ? children : <Navigate to="/login" replace />;
};

/**
 * PUBLIC ROUTE COMPONENT
 * 
 * This component redirects authenticated users away from public pages
 * like login and register to the dashboard.
 */
const PublicRoute = ({ children }) => {
  const { isAuthenticated, isInitialized } = useAuth();

  if (!isInitialized) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <LoadingSpinner size="large" text="Loading..." />
      </div>
    );
  }

  return !isAuthenticated ? children : <Navigate to="/dashboard" replace />;
};

/**
 * EMAIL VERIFIED ROUTE COMPONENT
 * 
 * This component protects routes that require email verification.
 */
const EmailVerifiedRoute = ({ children }) => {
  const { user, isAuthenticated, isInitialized } = useAuth();

  if (!isInitialized) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <LoadingSpinner size="large" text="Loading..." />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (!user?.isEmailVerified) {
    return <Navigate to="/dashboard" replace />;
  }

  return children;
};

/**
 * APP ROUTES COMPONENT
 * 
 * This handles all the routing logic inside the AuthProvider context.
 */
const AppRoutes = () => {
  return (
    <>
      <Routes>
        {/* Public Routes - only accessible when NOT logged in */}
        <Route 
          path="/login" 
          element={
            <PublicRoute>
              <LoginPage />
            </PublicRoute>
          } 
        />
        <Route 
          path="/register" 
          element={
            <PublicRoute>
              <RegisterPage />
            </PublicRoute>
          } 
        />
        <Route 
          path="/forgot-password" 
          element={
            <PublicRoute>
              <ForgotPasswordPage />
            </PublicRoute>
          } 
        />
        <Route 
          path="/reset-password" 
          element={
            <PublicRoute>
              <ResetPasswordPage />
            </PublicRoute>
          } 
        />

        {/* Email Verification Route - accessible to everyone */}
        <Route 
          path="/verify-email" 
          element={<VerifyEmailPage />} 
        />

        {/* Protected Routes - only accessible when logged in */}
        <Route 
          path="/dashboard" 
          element={
            <ProtectedRoute>
              <DashboardPage />
            </ProtectedRoute>
          } 
        />
        <Route 
          path="/sessions" 
          element={
            <ProtectedRoute>
              <SessionsPage />
            </ProtectedRoute>
          } 
        />

        {/* Email Verified Routes - require authentication AND email verification */}
        <Route 
          path="/change-password" 
          element={
            <EmailVerifiedRoute>
              <ChangePasswordPage />
            </EmailVerifiedRoute>
          } 
        />

        {/* Default route - redirect based on authentication status */}
        <Route 
          path="/" 
          element={<Navigate to="/dashboard" replace />} 
        />

        {/* Catch all route - redirect to home */}
        <Route 
          path="*" 
          element={<Navigate to="/" replace />} 
        />
      </Routes>
      
      {/* Debug Panel - only shows in development */}
      <DebugPanel />
    </>
  );
};

/**
 * MAIN APP COMPONENT
 * 
 * This is the root component that sets up:
 * - Authentication context for the entire app
 * - React Router for navigation
 * - Route protection based on authentication status
 * - Email verification requirements for sensitive routes
 */
function App() {
  return (
    <AuthProvider>
      <Router>
        <div className="App">
          <AppRoutes />
        </div>
      </Router>
    </AuthProvider>
  );
}

export default App;
