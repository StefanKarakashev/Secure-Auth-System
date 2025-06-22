import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import LoadingSpinner from '../ui/LoadingSpinner';
import Alert from '../ui/Alert';

/**
 * REGISTRATION FORM COMPONENT
 * 
 * A beautiful and functional registration form with:
 * - All required fields (first name, last name, email, password)
 * - Client-side validation
 * - Password strength indicator
 * - Terms acceptance checkbox
 * - Error handling
 * - Loading states
 */

const RegisterForm = () => {
  // Get authentication functions from context
  const { register, isLoading, error, clearError } = useAuth();

  // Form state
  const [formData, setFormData] = useState({
    firstName: '',
    lastName: '',
    email: '',
    password: '',
    confirmPassword: '',
    acceptTerms: false
  });

  // Form validation errors
  const [validationErrors, setValidationErrors] = useState({});

  // Success message after registration
  const [successMessage, setSuccessMessage] = useState('');

  /**
   * PASSWORD STRENGTH CHECKER
   * 
   * Checks password strength and returns score and feedback
   */
  const getPasswordStrength = (password) => {
    if (!password) return { score: 0, text: '', color: '' };

    let score = 0;
    const feedback = [];

    // Length check
    if (password.length >= 8) {
      score++;
    } else {
      feedback.push('at least 8 characters');
    }

    // Lowercase check
    if (/[a-z]/.test(password)) {
      score++;
    } else {
      feedback.push('lowercase letter');
    }

    // Uppercase check
    if (/[A-Z]/.test(password)) {
      score++;
    } else {
      feedback.push('uppercase letter');
    }

    // Number check
    if (/\d/.test(password)) {
      score++;
    } else {
      feedback.push('number');
    }

    // Special character check
    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      score++;
    } else {
      feedback.push('special character');
    }

    // Determine strength level and color
    let text, color;
    if (score <= 2) {
      text = 'Weak';
      color = 'text-red-600';
    } else if (score <= 3) {
      text = 'Fair';
      color = 'text-yellow-600';
    } else if (score <= 4) {
      text = 'Good';
      color = 'text-blue-600';
    } else {
      text = 'Strong';
      color = 'text-green-600';
    }

    return { score, text, color, feedback };
  };

  /**
   * HANDLE INPUT CHANGES
   */
  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));

    // Clear validation error for this field
    if (validationErrors[name]) {
      setValidationErrors(prev => ({
        ...prev,
        [name]: ''
      }));
    }

    // Clear global error and success messages
    if (error) clearError();
    if (successMessage) setSuccessMessage('');
  };

  /**
   * VALIDATE FORM
   */
  const validateForm = () => {
    const errors = {};

    // First name validation
    if (!formData.firstName.trim()) {
      errors.firstName = 'First name is required';
    }

    // Last name validation
    if (!formData.lastName.trim()) {
      errors.lastName = 'Last name is required';
    }

    // Email validation
    if (!formData.email) {
      errors.email = 'Email is required';
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      errors.email = 'Please enter a valid email address';
    }

    // Password validation
    const passwordStrength = getPasswordStrength(formData.password);
    if (!formData.password) {
      errors.password = 'Password is required';
    } else if (passwordStrength.score < 3) {
      errors.password = `Password is too weak. Include: ${passwordStrength.feedback.join(', ')}`;
    }

    // Confirm password validation
    if (!formData.confirmPassword) {
      errors.confirmPassword = 'Please confirm your password';
    } else if (formData.password !== formData.confirmPassword) {
      errors.confirmPassword = 'Passwords do not match';
    }

    // Terms acceptance validation
    if (!formData.acceptTerms) {
      errors.acceptTerms = 'You must accept the terms and conditions';
    }

    setValidationErrors(errors);
    return Object.keys(errors).length === 0;
  };

  /**
   * HANDLE FORM SUBMISSION
   */
  const handleSubmit = async (e) => {
    e.preventDefault();

    // Validate form first
    if (!validateForm()) {
      return;
    }

    try {
      // Attempt registration
      const result = await register({
        firstName: formData.firstName.trim(),
        lastName: formData.lastName.trim(),
        email: formData.email.trim(),
        password: formData.password,
        acceptTerms: formData.acceptTerms
      });

      if (result.success) {
        setSuccessMessage(
          result.message || 
          'Registration successful! Please check your email to verify your account.'
        );
        
        // Clear form
        setFormData({
          firstName: '',
          lastName: '',
          email: '',
          password: '',
          confirmPassword: '',
          acceptTerms: false
        });
      }
    } catch (error) {
      console.error('❌ Registration error:', error);
    }
  };

  const passwordStrength = getPasswordStrength(formData.password);

  return (
    <div className="card max-w-md mx-auto">
      <div className="card-body">
        {/* Header */}
        <div className="text-center mb-6">
          <h2 className="text-2xl font-bold text-gray-900">
            Create Account
          </h2>
          <p className="text-gray-600 mt-2">
            Sign up for a new account
          </p>
        </div>

        {/* Success Message */}
        {successMessage && (
          <Alert 
            type="success" 
            message={successMessage} 
            className="mb-4"
          />
        )}

        {/* Error Alert */}
        {error && (
          <Alert 
            type="error" 
            message={error} 
            onClose={clearError}
            className="mb-4"
          />
        )}

        {/* Registration Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Name Fields Row */}
          <div className="grid grid-cols-2 gap-4">
            {/* First Name */}
            <div>
              <label htmlFor="firstName" className="block text-sm font-medium text-gray-700 mb-1">
                First Name
              </label>
              <input
                type="text"
                id="firstName"
                name="firstName"
                value={formData.firstName}
                onChange={handleInputChange}
                className={`input-field ${validationErrors.firstName ? 'error' : ''}`}
                placeholder="John"
                disabled={isLoading}
              />
              {validationErrors.firstName && (
                <p className="text-red-600 text-sm mt-1">{validationErrors.firstName}</p>
              )}
            </div>

            {/* Last Name */}
            <div>
              <label htmlFor="lastName" className="block text-sm font-medium text-gray-700 mb-1">
                Last Name
              </label>
              <input
                type="text"
                id="lastName"
                name="lastName"
                value={formData.lastName}
                onChange={handleInputChange}
                className={`input-field ${validationErrors.lastName ? 'error' : ''}`}
                placeholder="Doe"
                disabled={isLoading}
              />
              {validationErrors.lastName && (
                <p className="text-red-600 text-sm mt-1">{validationErrors.lastName}</p>
              )}
            </div>
          </div>

          {/* Email Field */}
          <div>
            <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">
              Email Address
            </label>
            <input
              type="email"
              id="email"
              name="email"
              value={formData.email}
              onChange={handleInputChange}
              className={`input-field ${validationErrors.email ? 'error' : ''}`}
              placeholder="john@example.com"
              disabled={isLoading}
            />
            {validationErrors.email && (
              <p className="text-red-600 text-sm mt-1">{validationErrors.email}</p>
            )}
          </div>

          {/* Password Field */}
          <div>
            <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">
              Password
            </label>
            <input
              type="password"
              id="password"
              name="password"
              value={formData.password}
              onChange={handleInputChange}
              className={`input-field ${validationErrors.password ? 'error' : ''}`}
              placeholder="Create a strong password"
              disabled={isLoading}
            />
            
            {/* Password Strength Indicator */}
            {formData.password && (
              <div className="mt-2">
                <div className="flex items-center justify-between text-sm">
                  <span className={`font-medium ${passwordStrength.color}`}>
                    Password strength: {passwordStrength.text}
                  </span>
                  <span className="text-gray-500">
                    {passwordStrength.score}/5
                  </span>
                </div>
                {/* Progress bar */}
                <div className="w-full bg-gray-200 rounded-full h-2 mt-1">
                  <div 
                    className={`h-2 rounded-full transition-all duration-300 ${
                      passwordStrength.score <= 2 ? 'bg-red-500' :
                      passwordStrength.score <= 3 ? 'bg-yellow-500' :
                      passwordStrength.score <= 4 ? 'bg-blue-500' :
                      'bg-green-500'
                    }`}
                    style={{ width: `${(passwordStrength.score / 5) * 100}%` }}
                  />
                </div>
              </div>
            )}
            
            {validationErrors.password && (
              <p className="text-red-600 text-sm mt-1">{validationErrors.password}</p>
            )}
          </div>

          {/* Confirm Password Field */}
          <div>
            <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700 mb-1">
              Confirm Password
            </label>
            <input
              type="password"
              id="confirmPassword"
              name="confirmPassword"
              value={formData.confirmPassword}
              onChange={handleInputChange}
              className={`input-field ${validationErrors.confirmPassword ? 'error' : ''}`}
              placeholder="Confirm your password"
              disabled={isLoading}
            />
            {validationErrors.confirmPassword && (
              <p className="text-red-600 text-sm mt-1">{validationErrors.confirmPassword}</p>
            )}
          </div>

          {/* Terms Acceptance */}
          <div>
            <label className="flex items-start">
              <input
                type="checkbox"
                name="acceptTerms"
                checked={formData.acceptTerms}
                onChange={handleInputChange}
                disabled={isLoading}
                className="w-4 h-4 text-primary-600 border-gray-300 rounded focus:ring-primary-500 mt-0.5"
              />
              <span className="ml-2 text-sm text-gray-600">
                I agree to the{' '}
                <a href="/terms" className="text-primary-600 hover:text-primary-500">
                  Terms of Service
                </a>{' '}
                and{' '}
                <a href="/privacy" className="text-primary-600 hover:text-primary-500">
                  Privacy Policy
                </a>
              </span>
            </label>
            {validationErrors.acceptTerms && (
              <p className="text-red-600 text-sm mt-1">{validationErrors.acceptTerms}</p>
            )}
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
                <span className="ml-2">Creating account...</span>
              </>
            ) : (
              'Create Account'
            )}
          </button>
        </form>

        {/* Login Link */}
        <div className="text-center mt-6">
          <p className="text-sm text-gray-600">
            Already have an account?{' '}
            <Link 
              to="/login" 
              className="text-primary-600 hover:text-primary-500 font-medium"
            >
              Sign in here
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default RegisterForm; 