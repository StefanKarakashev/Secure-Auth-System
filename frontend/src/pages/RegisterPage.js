import React from 'react';
import RegisterForm from '../components/auth/RegisterForm';
import { useAuth } from '../contexts/AuthContext';
import LoadingSpinner from '../components/ui/LoadingSpinner';

/**
 * REGISTER PAGE
 * 
 * This page displays the registration form for new users.
 * If user is already logged in, they'll be redirected automatically.
 */

const RegisterPage = () => {
  const { isLoading, isInitialized } = useAuth();

  // Show loading spinner while checking authentication status
  if (!isInitialized || isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <LoadingSpinner 
          size="large" 
          text="Loading..." 
        />
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-lg w-full">
        {/* App Logo/Title */}
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900">
            🔐 SecureAuth
          </h1>
          <p className="mt-2 text-gray-600">
            Professional Authentication System
          </p>
        </div>

        {/* Register Form Component */}
        <RegisterForm />
      </div>
    </div>
  );
};

export default RegisterPage; 