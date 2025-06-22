import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import authService from '../services/authService';
import Navigation from '../components/ui/Navigation';
import LoadingSpinner from '../components/ui/LoadingSpinner';
import Alert from '../components/ui/Alert';

/**
 * CHANGE PASSWORD PAGE
 * 
 * Production-ready password change page with:
 * - Current password verification
 * - Password strength requirements
 * - Form validation and sanitization
 * - Loading states and error handling
 * - Security measures (logout all other sessions)
 * - Accessibility features
 */

const ChangePasswordPage = () => {
  const { user, logout } = useAuth();
  const [formData, setFormData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });
  const [isLoading, setIsLoading] = useState(false);
  const [alert, setAlert] = useState(null);
  const [errors, setErrors] = useState({});
  const [passwordStrength, setPasswordStrength] = useState({
    score: 0,
    feedback: []
  });
  const [showPasswords, setShowPasswords] = useState({
    current: false,
    new: false,
    confirm: false
  });
  const [isSuccess, setIsSuccess] = useState(false);

  // Password strength checker
  const checkPasswordStrength = (password) => {
    const feedback = [];
    let score = 0;

    if (password.length >= 8) {
      score += 1;
    } else {
      feedback.push('At least 8 characters');
    }

    if (/[a-z]/.test(password)) {
      score += 1;
    } else {
      feedback.push('At least one lowercase letter');
    }

    if (/[A-Z]/.test(password)) {
      score += 1;
    } else {
      feedback.push('At least one uppercase letter');
    }

    if (/\d/.test(password)) {
      score += 1;
    } else {
      feedback.push('At least one number');
    }

    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      score += 1;
    } else {
      feedback.push('At least one special character');
    }

    return { score, feedback };
  };

  // Form validation
  const validateForm = () => {
    const newErrors = {};

    // Current password validation
    if (!formData.currentPassword) {
      newErrors.currentPassword = 'Current password is required';
    }

    // New password validation
    if (!formData.newPassword) {
      newErrors.newPassword = 'New password is required';
    } else {
      const strength = checkPasswordStrength(formData.newPassword);
      if (strength.score < 4) {
        newErrors.newPassword = 'Password does not meet security requirements';
      }
      
      // Check if new password is same as current
      if (formData.newPassword === formData.currentPassword) {
        newErrors.newPassword = 'New password must be different from current password';
      }
    }

    // Confirm password validation
    if (!formData.confirmPassword) {
      newErrors.confirmPassword = 'Please confirm your new password';
    } else if (formData.newPassword !== formData.confirmPassword) {
      newErrors.confirmPassword = 'Passwords do not match';
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
      [name]: value
    }));

    // Update password strength for new password field
    if (name === 'newPassword') {
      setPasswordStrength(checkPasswordStrength(value));
    }
  };

  // Toggle password visibility
  const togglePasswordVisibility = (field) => {
    setShowPasswords(prev => ({
      ...prev,
      [field]: !prev[field]
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
      await authService.changePassword(
        formData.currentPassword,
        formData.newPassword,
        formData.confirmPassword);
      
      setIsSuccess(true);
      setAlert({
        type: 'success',
        message: 'Password changed successfully! You have been logged out from all other devices for security.'
      });

      // Clear form
      setFormData({
        currentPassword: '',
        newPassword: '',
        confirmPassword: ''
      });

    } catch (error) {
      console.error('Password change failed:', error);
      
      // Handle specific error cases
      if (error.response?.status === 400) {
        const errorCode = error.response.data?.code;
        if (errorCode === 'INVALID_CURRENT_PASSWORD') {
          setErrors({ currentPassword: 'Current password is incorrect' });
        } else {
          setAlert({
            type: 'error',
            message: error.response.data?.message || 'Invalid request. Please check your inputs.'
          });
        }
      } else if (error.response?.status === 429) {
        setAlert({
          type: 'error',
          message: 'Too many attempts. Please wait a few minutes before trying again.'
        });
      } else {
        setAlert({
          type: 'error',
          message: 'Failed to change password. Please try again.'
        });
      }
    } finally {
      setIsLoading(false);
    }
  };

  // Get password strength color and text
  const getPasswordStrengthInfo = () => {
    if (passwordStrength.score === 0) return { color: 'gray', text: 'Enter password' };
    if (passwordStrength.score <= 2) return { color: 'red', text: 'Weak' };
    if (passwordStrength.score === 3) return { color: 'yellow', text: 'Fair' };
    if (passwordStrength.score === 4) return { color: 'green', text: 'Good' };
    return { color: 'green', text: 'Strong' };
  };

  const strengthInfo = getPasswordStrengthInfo();

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Navigation */}
      <Navigation />

      {/* Main Content */}
      <div className="max-w-2xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          <div className="card">
            <div className="card-body">
              <div className="mb-6">
                <div className="flex items-center mb-4">
                  <span className="text-2xl mr-3">🔑</span>
                  <div>
                    <h2 className="text-xl font-semibold text-gray-900">
                      Update Your Password
                    </h2>
                    <p className="text-sm text-gray-600">
                      Choose a strong password to keep your account secure
                    </p>
                  </div>
                </div>
              </div>

              {alert && (
                <div className="mb-6">
                  <Alert 
                    type={alert.type} 
                    message={alert.message}
                    onClose={() => setAlert(null)}
                  />
                </div>
              )}

              <form onSubmit={handleSubmit} noValidate className="space-y-6">
                {/* Current Password Field */}
                <div>
                  <label htmlFor="currentPassword" className="block text-sm font-medium text-gray-700">
                    Current Password
                  </label>
                  <div className="mt-1 relative">
                    <input
                      id="currentPassword"
                      name="currentPassword"
                      type={showPasswords.current ? 'text' : 'password'}
                      autoComplete="current-password"
                      required
                      value={formData.currentPassword}
                      onChange={handleChange}
                      className={`appearance-none relative block w-full px-3 py-2 pr-10 border ${
                        errors.currentPassword ? 'border-red-300' : 'border-gray-300'
                      } placeholder-gray-500 text-gray-900 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm`}
                      placeholder="Enter your current password"
                      disabled={isLoading}
                    />
                    <button
                      type="button"
                      className="absolute inset-y-0 right-0 pr-3 flex items-center"
                      onClick={() => togglePasswordVisibility('current')}
                    >
                      <span className="text-gray-400 hover:text-gray-600">
                        {showPasswords.current ? '👁️' : '🙈'}
                      </span>
                    </button>
                  </div>
                  {errors.currentPassword && (
                    <p className="mt-1 text-sm text-red-600" role="alert">
                      {errors.currentPassword}
                    </p>
                  )}
                </div>

                {/* New Password Field */}
                <div>
                  <label htmlFor="newPassword" className="block text-sm font-medium text-gray-700">
                    New Password
                  </label>
                  <div className="mt-1 relative">
                    <input
                      id="newPassword"
                      name="newPassword"
                      type={showPasswords.new ? 'text' : 'password'}
                      autoComplete="new-password"
                      required
                      value={formData.newPassword}
                      onChange={handleChange}
                      className={`appearance-none relative block w-full px-3 py-2 pr-10 border ${
                        errors.newPassword ? 'border-red-300' : 'border-gray-300'
                      } placeholder-gray-500 text-gray-900 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm`}
                      placeholder="Enter your new password"
                      disabled={isLoading}
                    />
                    <button
                      type="button"
                      className="absolute inset-y-0 right-0 pr-3 flex items-center"
                      onClick={() => togglePasswordVisibility('new')}
                    >
                      <span className="text-gray-400 hover:text-gray-600">
                        {showPasswords.new ? '👁️' : '🙈'}
                      </span>
                    </button>
                  </div>
                  
                  {/* Password Strength Indicator */}
                  {formData.newPassword && (
                    <div className="mt-2">
                      <div className="flex items-center space-x-2">
                        <div className="flex-1 bg-gray-200 rounded-full h-2">
                          <div
                            className={`h-2 rounded-full transition-all duration-300 bg-${strengthInfo.color}-500`}
                            style={{ width: `${(passwordStrength.score / 5) * 100}%` }}
                          ></div>
                        </div>
                        <span className={`text-sm font-medium text-${strengthInfo.color}-600`}>
                          {strengthInfo.text}
                        </span>
                      </div>
                      {passwordStrength.feedback.length > 0 && (
                        <ul className="mt-1 text-xs text-gray-600 list-disc list-inside">
                          {passwordStrength.feedback.map((item, index) => (
                            <li key={index}>{item}</li>
                          ))}
                        </ul>
                      )}
                    </div>
                  )}
                  
                  {errors.newPassword && (
                    <p className="mt-1 text-sm text-red-600" role="alert">
                      {errors.newPassword}
                    </p>
                  )}
                </div>

                {/* Confirm Password Field */}
                <div>
                  <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700">
                    Confirm New Password
                  </label>
                  <div className="mt-1 relative">
                    <input
                      id="confirmPassword"
                      name="confirmPassword"
                      type={showPasswords.confirm ? 'text' : 'password'}
                      autoComplete="new-password"
                      required
                      value={formData.confirmPassword}
                      onChange={handleChange}
                      className={`appearance-none relative block w-full px-3 py-2 pr-10 border ${
                        errors.confirmPassword ? 'border-red-300' : 'border-gray-300'
                      } placeholder-gray-500 text-gray-900 rounded-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm`}
                      placeholder="Confirm your new password"
                      disabled={isLoading}
                    />
                    <button
                      type="button"
                      className="absolute inset-y-0 right-0 pr-3 flex items-center"
                      onClick={() => togglePasswordVisibility('confirm')}
                    >
                      <span className="text-gray-400 hover:text-gray-600">
                        {showPasswords.confirm ? '👁️' : '🙈'}
                      </span>
                    </button>
                  </div>
                  {errors.confirmPassword && (
                    <p className="mt-1 text-sm text-red-600" role="alert">
                      {errors.confirmPassword}
                    </p>
                  )}
                </div>

                {/* Submit Button */}
                <div className="flex items-center justify-between">
                  <button
                    type="submit"
                    disabled={isLoading}
                    className="flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors duration-200"
                  >
                    {isLoading ? (
                      <LoadingSpinner size="small" text="Changing..." />
                    ) : (
                      'Change Password'
                    )}
                  </button>
                </div>
              </form>

              {/* Security Notice */}
              <div className="mt-6 p-4 bg-blue-50 rounded-lg border border-blue-200">
                <div className="flex items-start">
                  <span className="text-blue-600 mr-2 mt-0.5">ℹ️</span>
                  <div className="text-sm text-blue-800">
                    <h4 className="font-medium mb-1">Security Notice</h4>
                    <p>
                      When you change your password, you will be automatically logged out from all other devices 
                      for security reasons. You will need to log in again on those devices with your new password.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ChangePasswordPage; 