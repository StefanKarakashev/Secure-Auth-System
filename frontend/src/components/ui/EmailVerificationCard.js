import React, { useState } from 'react';
import authService from '../../services/authService';
import LoadingSpinner from './LoadingSpinner';
import Alert from './Alert';

/**
 * EMAIL VERIFICATION CARD COMPONENT
 * 
 * Reusable component for handling email verification status and actions:
 * - Shows verification status
 * - Allows resending verification email
 * - Handles loading and error states
 * - Production-ready with proper error handling
 */

const EmailVerificationCard = ({ user, onVerificationSent, className = '' }) => {
  const [isLoading, setIsLoading] = useState(false);
  const [alert, setAlert] = useState(null);
  const [lastSentTime, setLastSentTime] = useState(null);

  // Calculate time since last email sent
  const canResend = () => {
    if (!lastSentTime) return true;
    const timeDiff = Date.now() - lastSentTime;
    return timeDiff > 60000; // 1 minute cooldown
  };

  const getResendCooldown = () => {
    if (!lastSentTime) return 0;
    const timeDiff = Date.now() - lastSentTime;
    const remaining = 60 - Math.floor(timeDiff / 1000);
    return Math.max(0, remaining);
  };

  // Handle resending verification email
  const handleResendVerification = async () => {
    if (!canResend()) {
      setAlert({
        type: 'warning',
        message: `Please wait ${getResendCooldown()} seconds before requesting another email.`
      });
      return;
    }

    setIsLoading(true);
    setAlert(null);

    try {
      await authService.resendVerification();
      setLastSentTime(Date.now());
      setAlert({
        type: 'success',
        message: 'Verification email sent successfully! Please check your inbox.'
      });

      // Notify parent component
      if (onVerificationSent) {
        onVerificationSent();
      }

    } catch (error) {
      console.error('Failed to resend verification:', error);
      
      // Handle specific error cases
      if (error.response?.status === 429) {
        setAlert({
          type: 'error',
          message: 'Too many requests. Please wait a few minutes before trying again.'
        });
      } else if (error.response?.status === 400 && error.response.data?.code === 'EMAIL_ALREADY_VERIFIED') {
        setAlert({
          type: 'info',
          message: 'Your email is already verified! Please refresh the page.'
        });
      } else {
        setAlert({
          type: 'error',
          message: error.response?.data?.message || 'Failed to send verification email. Please try again.'
        });
      }
    } finally {
      setIsLoading(false);
    }
  };

  // Don't render if user is already verified
  if (user?.isEmailVerified) {
    return null;
  }

  return (
    <div className={`card border-yellow-200 bg-yellow-50 ${className}`}>
      <div className="card-body">
        <div className="flex items-start">
          <span className="text-yellow-500 mr-3 mt-1 text-xl">⚠️</span>
          <div className="flex-1">
            <h3 className="text-lg font-semibold text-yellow-800 mb-2">
              Please Verify Your Email Address
            </h3>
            <p className="text-yellow-700 mb-4">
              To access all features and ensure account security, please verify your email address.
              We've sent a verification link to <strong>{user?.email}</strong>.
            </p>

            {alert && (
              <div className="mb-4">
                <Alert 
                  type={alert.type} 
                  message={alert.message}
                  onClose={() => setAlert(null)}
                />
              </div>
            )}

            <div className="flex flex-col sm:flex-row gap-3">
              <button
                onClick={handleResendVerification}
                disabled={isLoading || !canResend()}
                className="btn-secondary flex items-center"
              >
                {isLoading ? (
                  <LoadingSpinner size="small" text="Sending..." />
                ) : (
                  <>
                    <span className="mr-2">📧</span>
                    {canResend() ? 'Resend Verification Email' : `Resend in ${getResendCooldown()}s`}
                  </>
                )}
              </button>

              <button
                onClick={() => window.location.reload()}
                className="btn-secondary flex items-center"
              >
                <span className="mr-2">🔄</span>
                Refresh Page
              </button>
            </div>

            <div className="mt-4 text-sm text-yellow-700">
              <p className="font-medium mb-2">Didn't receive the email?</p>
              <ul className="list-disc list-inside space-y-1">
                <li>Check your spam/junk folder</li>
                <li>Make sure the email address is correct</li>
                <li>Wait a few minutes for delivery</li>
                <li>Add our email to your safe senders list</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default EmailVerificationCard; 