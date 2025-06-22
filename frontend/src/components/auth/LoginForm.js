import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import LoadingSpinner from '../ui/LoadingSpinner';

/**
 * LOGIN FORM COMPONENT
 * 
 * A beautiful and functional login form with:
 * - Email and password fields
 * - Client-side validation
 * - Error handling
 * - Loading states
 * - "Remember me" checkbox
 * - Link to registration
 */

const LoginForm = () => {
  // Get authentication functions from context
  const { login, isLoading, error, clearError } = useAuth();

  // Form state using useState hooks
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    rememberMe: false
  });

  // Form validation errors
  const [validationErrors, setValidationErrors] = useState({});

  /**
   * HANDLE INPUT CHANGES
   * 
   * Updates form data when user types in inputs
   */
  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));

    // Clear validation error for this field when user starts typing
    if (validationErrors[name]) {
      setValidationErrors(prev => ({
        ...prev,
        [name]: ''
      }));
    }

    // Clear global error when user makes changes
    if (error) {
      clearError();
    }
  };

  /**
   * VALIDATE FORM
   * 
   * Check if all fields are valid before submitting
   */
  const validateForm = () => {
    const errors = {};

    // Email validation
    if (!formData.email) {
      errors.email = 'Email is required';
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      errors.email = 'Please enter a valid email address';
    }

    // Password validation
    if (!formData.password) {
      errors.password = 'Password is required';
    } else if (formData.password.length < 6) {
      errors.password = 'Password must be at least 6 characters';
    }

    setValidationErrors(errors);
    return Object.keys(errors).length === 0;
  };

  /**
   * HANDLE FORM SUBMISSION
   * 
   * Validates form and attempts login
   */
  const handleSubmit = async (e) => {
    e.preventDefault(); // Prevent page refresh

    // Validate form first
    if (!validateForm()) {
      return;
    }

    try {
      console.log('Starting login attempt...');
      
      // Attempt login
      const result = await login(
        formData.email, 
        formData.password, 
        formData.rememberMe
      );

      console.log('Login result:', result);
      
      if (result.success) {
        console.log('Login successful!');
        // Navigation will be handled automatically by the app
      } else {
        console.log('Login failed:', result.error);
      }
    } catch (error) {
      console.error('Login error:', error);
    }
  };

  return (
    <div className="card w-full">
      <div className="card-body">
        {/* Header */}
        <div className="text-center mb-6">
          <h2 className="text-2xl font-bold text-gray-900">
            Welcome Back
          </h2>
          <p className="text-gray-600 mt-2">
            Sign in to your account
          </p>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg">
            <p className="text-red-700 text-sm">
              <strong>Login Failed:</strong> {error.message || error || 'An error occurred during login'}
            </p>
            {clearError && (
              <button
                onClick={clearError}
                className="mt-2 text-red-600 hover:text-red-800 text-sm underline"
              >
                Dismiss
              </button>
            )}
          </div>
        )}

        {/* Login Form */}
        <form onSubmit={handleSubmit} className="space-y-5">
          {/* Email Field */}
          <div>
            <label 
              htmlFor="email" 
              className="block text-sm font-medium text-gray-700 mb-1"
            >
              Email Address
            </label>
            <input
              type="email"
              id="email"
              name="email"
              value={formData.email}
              onChange={handleInputChange}
              className={`
                input-field
                ${validationErrors.email ? 'error' : ''}
              `}
              placeholder="Enter your email"
              disabled={isLoading}
            />
            {/* Show validation error */}
            {validationErrors.email && (
              <p className="text-red-600 text-sm mt-1">
                {validationErrors.email}
              </p>
            )}
          </div>

          {/* Password Field */}
          <div>
            <label 
              htmlFor="password" 
              className="block text-sm font-medium text-gray-700 mb-1"
            >
              Password
            </label>
            <input
              type="password"
              id="password"
              name="password"
              value={formData.password}
              onChange={handleInputChange}
              className={`
                input-field
                ${validationErrors.password ? 'error' : ''}
              `}
              placeholder="Enter your password"
              disabled={isLoading}
            />
            {/* Show validation error */}
            {validationErrors.password && (
              <p className="text-red-600 text-sm mt-1">
                {validationErrors.password}
              </p>
            )}
          </div>

          {/* Remember Me Checkbox */}
          <div className="flex items-center justify-between">
            <label className="flex items-center">
              <input
                type="checkbox"
                name="rememberMe"
                checked={formData.rememberMe}
                onChange={handleInputChange}
                disabled={isLoading}
                className="w-4 h-4 text-primary-600 border-gray-300 rounded focus:ring-primary-500"
              />
              <span className="ml-2 text-sm text-gray-600">
                Remember me
              </span>
            </label>

            {/* Forgot Password Link */}
            <Link 
              to="/forgot-password" 
              className="text-sm text-primary-600 hover:text-primary-500"
            >
              Forgot password?
            </Link>
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            disabled={isLoading}
            className="btn-primary w-full flex items-center justify-center"
          >
            {isLoading ? (
              <>
                <LoadingSpinner size="small" color="white" />
                <span className="ml-2">Signing in...</span>
              </>
            ) : (
              'Sign In'
            )}
          </button>
        </form>

        {/* Register Link */}
        <div className="text-center mt-6">
          <p className="text-sm text-gray-600">
            Don't have an account?{' '}
            <Link 
              to="/register" 
              className="text-primary-600 hover:text-primary-500 font-medium"
            >
              Sign up here
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default LoginForm;