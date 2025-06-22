import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import authService from '../services/authService';
import LoadingSpinner from '../components/ui/LoadingSpinner';
import Alert from '../components/ui/Alert';

/**
 * FORGOT PASSWORD PAGE
 * 
 * Production-ready password reset request page with:
 * - Form validation and sanitization
 * - Loading states and error handling
 * - Rate limiting awareness
 * - Security best practices
 * - Accessibility features
 */

const ForgotPasswordPage = () => {
  const [formData, setFormData] = useState({
    email: ''
  });
  const [isLoading, setIsLoading] = useState(false);
  const [alert, setAlert] = useState(null);
  const [emailSent, setEmailSent] = useState(false);
  const [errors, setErrors] = useState({});

  // Form validation
  const validateForm = () => {
    const newErrors = {};

    // Email validation
    if (!formData.email) {
      newErrors.email = 'Email address is required';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email)) {
      newErrors.email = 'Please enter a valid email address';
    } else if (formData.email.length > 255) {
      newErrors.email = 'Email address is too long';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  // Handle input changes
  const handleChange = (e) => {
    const { name, value } = e.target;
    
    // Clear specific field error when user starts typing
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: '' }));
    }
    
    // Clear general alert when user starts typing
    if (alert && alert.type === 'error') {
      setAlert(null);
    }

    setFormData(prev => ({
      ...prev,
      [name]: value.trim()
    }));
  };

  // Handle form submission
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    setIsLoading(true);
    setAlert(null);

    try {
      await authService.requestPasswordReset(formData.email);
      
      setEmailSent(true);
      setAlert({
        type: 'success',
        message: 'Password reset instructions have been sent to your email address.'
      });

    } catch (error) {
      console.error('Password reset request failed:', error);
      
      // Handle specific error cases
      if (error.response?.status === 429) {
        setAlert({
          type: 'error',
          message: 'Too many requests. Please wait a few minutes before trying again.'
        });
      } else if (error.response?.status === 404) {
        // For security, don't reveal if email exists or not
        setEmailSent(true);
        setAlert({
          type: 'success',
          message: 'If an account with that email exists, password reset instructions have been sent.'
        });
      } else {
        setAlert({
          type: 'error',
          message: error.response?.data?.message || 'Failed to send password reset email. Please try again.'
        });
      }
    } finally {
      setIsLoading(false);
    }
  };

  // Handle resend email
  const handleResendEmail = async () => {
    setIsLoading(true);
    setAlert(null);

    try {
      await authService.requestPasswordReset(formData.email);
      setAlert({
        type: 'success',
        message: 'Password reset email has been resent.'
      });
    } catch (error) {
      setAlert({
        type: 'error',
        message: 'Failed to resend email. Please try again.'
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <div className="mx-auto h-12 w-12 flex items-center justify-center rounded-full bg-indigo-100">
            <span className="text-2xl">🔑</span>
          </div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            Reset your password
          </h2>
          <p className="mt-2 text-center text-sm text-gray-600">
            Enter your email address and we'll send you instructions to reset your password.
          </p>
        </div>

        {!emailSent ? (
          <form className="mt-8 space-y-6" onSubmit={handleSubmit} noValidate>
            <div className="space-y-4">
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                  Email address
                </label>
                <input
                  id="email"
                  name="email"
                  type="email"
                  autoComplete="email"
                  required
                  value={formData.email}
                  onChange={handleChange}
                  className={`mt-1 appearance-none relative block w-full px-3 py-2 border ${
                    errors.email ? 'border-red-300' : 'border-gray-300'
                  } placeholder-gray-500 text-gray-900 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm`}
                  placeholder="Enter your email address"
                  disabled={isLoading}
                />
                {errors.email && (
                  <p className="mt-1 text-sm text-red-600" role="alert">
                    {errors.email}
                  </p>
                )}
              </div>
            </div>

            {alert && (
              <Alert 
                type={alert.type} 
                message={alert.message}
                onClose={() => setAlert(null)}
              />
            )}

            <div>
              <button
                type="submit"
                disabled={isLoading}
                className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
              >
                {isLoading ? (
                  <LoadingSpinner size="small" text="Sending..." />
                ) : (
                  'Send reset instructions'
                )}
              </button>
            </div>

            <div className="text-center">
              <Link
                to="/login"
                className="font-medium text-indigo-600 hover:text-indigo-500 transition-colors duration-200"
              >
                ← Back to login
              </Link>
            </div>
          </form>
        ) : (
          <div className="mt-8 space-y-6">
            {alert && (
              <Alert 
                type={alert.type} 
                message={alert.message}
                onClose={() => setAlert(null)}
              />
            )}

            <div className="text-center space-y-4">
              <div className="p-4 bg-green-50 rounded-lg border border-green-200">
                <div className="text-green-600 text-lg mb-2">✅</div>
                <h3 className="text-lg font-medium text-green-800">Check your email</h3>
                <p className="text-sm text-green-600 mt-1">
                  We've sent password reset instructions to <strong>{formData.email}</strong>
                </p>
              </div>

              <div className="text-sm text-gray-600 space-y-2">
                <p>Didn't receive the email?</p>
                <ul className="list-disc list-inside text-left">
                  <li>Check your spam/junk folder</li>
                  <li>Make sure the email address is correct</li>
                  <li>Wait a few minutes for delivery</li>
                </ul>
              </div>

              <button
                onClick={handleResendEmail}
                disabled={isLoading}
                className="text-indigo-600 hover:text-indigo-500 font-medium transition-colors duration-200 disabled:opacity-50"
              >
                {isLoading ? 'Resending...' : 'Resend email'}
              </button>

              <div className="border-t pt-4">
                <Link
                  to="/login"
                  className="font-medium text-indigo-600 hover:text-indigo-500 transition-colors duration-200"
                >
                  ← Back to login
                </Link>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ForgotPasswordPage; 