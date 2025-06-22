import React, { useEffect, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import LoginForm from '../components/auth/LoginForm';
import Alert from '../components/ui/Alert';

/**
 * LOGIN PAGE
 * 
 * Production-ready login page with:
 * - Responsive design
 * - Link to forgot password
 * - Link to registration
 * - URL parameter message handling
 * - Clean, accessible UI
 */

const LoginPage = () => {
  const location = useLocation();
  const [message, setMessage] = useState(null);

  useEffect(() => {
    // Check for URL parameters to show messages
    const urlParams = new URLSearchParams(location.search);
    const messageParam = urlParams.get('message');
    
    if (messageParam === 'session_revoked') {
      setMessage({
        type: 'warning',
        text: 'Your session has been revoked from another device. Please log in again.'
      });
    } else if (messageParam === 'email_verified') {
      setMessage({
        type: 'success',
        text: 'Email verified successfully! You can now log in.'
      });
    }
    
    // Clear the URL parameter after showing the message
    if (messageParam) {
      const newUrl = window.location.pathname;
      window.history.replaceState({}, '', newUrl);
    }
  }, [location]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <div className="mx-auto h-12 w-12 flex items-center justify-center rounded-full bg-indigo-100">
            <span className="text-2xl">🔐</span>
          </div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            Sign in to your account
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            Welcome back! Please enter your details.
          </p>
        </div>
        
        {/* Show message if present */}
        {message && (
          <Alert 
            type={message.type}
            message={message.text}
            onClose={() => setMessage(null)}
          />
        )}
        
        {/* Login Form */}
        <LoginForm />
        
        {/* Additional Links */}
        <div className="mt-6">
          <div className="relative">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-gray-300" />
            </div>
            <div className="relative flex justify-center text-sm">
              <span className="px-2 bg-gray-50 text-gray-500">Need help?</span>
            </div>
          </div>

          <div className="mt-4 flex flex-col space-y-3">
            <Link
              to="/forgot-password"
              className="text-center text-sm text-indigo-600 hover:text-indigo-500 transition-colors duration-200"
            >
              🔑 Forgot your password?
            </Link>
            
            <div className="text-center text-sm text-gray-600">
              Don't have an account?{' '}
              <Link
                to="/register"
                className="font-medium text-indigo-600 hover:text-indigo-500 transition-colors duration-200"
              >
                Sign up here
              </Link>
            </div>
          </div>
        </div>

        {/* Security Notice */}
        <div className="mt-6 p-4 bg-blue-50 rounded-lg border border-blue-200">
          <div className="flex items-center">
            <span className="text-blue-600 mr-2">🛡️</span>
            <div className="text-sm text-blue-800">
              <p className="font-medium">Secure Login</p>
              <p>Your connection is encrypted and protected.</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginPage; 