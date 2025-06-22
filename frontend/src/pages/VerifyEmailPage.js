import React, { useState, useEffect, useRef } from 'react';
import { useSearchParams, useNavigate, Link } from 'react-router-dom';
import authService from '../services/authService';
import LoadingSpinner from '../components/ui/LoadingSpinner';

/**
 * EMAIL VERIFICATION PAGE
 * 
 * This page handles email verification when users click the link in their email.
 * It extracts the token from URL parameters and calls the verification API.
 */
const VerifyEmailPage = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [status, setStatus] = useState('verifying'); // 'verifying', 'success', 'error'
  const [message, setMessage] = useState('');
  const [errorDetails, setErrorDetails] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [redirectTimer, setRedirectTimer] = useState(null);
  const [countdown, setCountdown] = useState(8);
  const verificationAttempted = useRef(false);

  useEffect(() => {
    const verifyEmail = async () => {
      console.log('🚀 Starting email verification process...');
      
      // Prevent duplicate verification attempts (React StrictMode issue)
      if (verificationAttempted.current) {
        console.log('🔄 Skipping duplicate email verification attempt');
        return;
      }
      verificationAttempted.current = true;
      
      try {
        // Get token from URL parameters
        const token = searchParams.get('token');
        
        console.log('🔍 Full URL:', window.location.href);
        console.log('🔍 Token from URL:', token);
        console.log('🔍 Token length:', token?.length);
        
        if (!token) {
          console.log('❌ No token found in URL');
          setStatus('error');
          setMessage('Invalid verification link. No token provided.');
          setErrorDetails('The verification link is missing the required token parameter.');
          setIsLoading(false);
          return;
        }

        console.log('🔍 Verifying email with token...');
        console.log('🔍 API Base URL:', process.env.REACT_APP_API_BASE_URL || 'http://localhost:5000/api/v1');
        
        // Add a small delay to see the loading state
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        console.log('📡 About to call authService.verifyEmail...');
        
        // Call the verification API
        const response = await authService.verifyEmail(token);
        
        console.log('✅ Email verification response:', response);
        console.log('✅ Setting status to success...');
        
        setStatus('success');
        setMessage(response.message || 'Email verified successfully!');
        
        // Start countdown
        setCountdown(8);
        const countdownInterval = setInterval(() => {
          setCountdown(prev => {
            if (prev <= 1) {
              clearInterval(countdownInterval);
              return 0;
            }
            return prev - 1;
          });
        }, 1000);
        
        // Redirect to login after 8 seconds (increased from 3)
        const timer = setTimeout(() => {
          clearInterval(countdownInterval);
          navigate('/login', { 
            state: { 
              message: 'Email verified successfully! You can now log in.',
              type: 'success'
            }
          });
        }, 8000); // Increased to 8 seconds
        setRedirectTimer(timer);
        
      } catch (error) {
        console.error('❌ Email verification failed:', error);
        console.error('❌ Error details:', {
          message: error.message,
          response: error.response?.data,
          status: error.response?.status,
          code: error.code
        });
        
        setStatus('error');
        
        // Handle specific error messages with more details
        let errorMessage = 'Email verification failed. Please try again.';
        let details = '';
        
        if (error.response?.data?.message) {
          errorMessage = error.response.data.message;
          details = `Status: ${error.response.status}, Code: ${error.response.data.code || 'N/A'}`;
        } else if (error.message) {
          errorMessage = error.message;
          details = 'Network or connection error';
        }
        
        // Add more specific error details
        if (error.response?.status === 400) {
          details += '\nThis usually means the token is invalid, expired, or already used.';
        } else if (error.response?.status === 500) {
          details += '\nThis is a server error. Please try again later.';
        } else if (error.code === 'NETWORK_ERROR' || !error.response) {
          details += '\nCannot connect to the server. Please check if the backend is running.';
        }
        
        setMessage(errorMessage);
        setErrorDetails(details);
        
        // Don't redirect on error - let user see the error
        console.log('🛑 Stopping here to show error details');
        
      } finally {
        setIsLoading(false);
      }
    };

    verifyEmail();
    
    // Cleanup timer on unmount
    return () => {
      if (redirectTimer) {
        clearTimeout(redirectTimer);
      }
    };
  }, [searchParams, navigate, redirectTimer]);

  const handleResendVerification = async () => {
    try {
      setIsLoading(true);
      await authService.resendVerification();
      setMessage('Verification email sent! Please check your inbox.');
      setErrorDetails('');
    } catch (error) {
      console.error('❌ Resend verification failed:', error);
      setMessage('Failed to resend verification email. Please try logging in first.');
      setErrorDetails('You need to be logged in to resend verification emails.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <div className="mx-auto h-12 w-12 flex items-center justify-center">
          {status === 'verifying' && (
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
          )}
          {status === 'success' && (
            <div className="rounded-full bg-green-100 p-2">
              <svg className="h-6 w-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
              </svg>
            </div>
          )}
          {status === 'error' && (
            <div className="rounded-full bg-red-100 p-2">
              <svg className="h-6 w-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path>
              </svg>
            </div>
          )}
        </div>
        
        <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
          {status === 'verifying' && 'Verifying Email'}
          {status === 'success' && 'Email Verified!'}
          {status === 'error' && 'Verification Failed'}
        </h2>
      </div>

      <div className="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="bg-white py-8 px-4 shadow sm:rounded-lg sm:px-10">
          
          {/* Loading State */}
          {isLoading && status === 'verifying' && (
            <div className="text-center">
              <LoadingSpinner size="large" text="Verifying your email address..." />
              <p className="mt-4 text-xs text-gray-500">
                This may take a few seconds...
              </p>
            </div>
          )}

          {/* Success State */}
          {status === 'success' && !isLoading && (
            <div className="text-center">
              <div className="mb-4">
                <div className="mx-auto flex items-center justify-center h-16 w-16 rounded-full bg-green-100">
                  <svg className="h-8 w-8 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
                  </svg>
                </div>
              </div>
              
              <h3 className="text-lg font-medium text-gray-900 mb-2">
                Success!
              </h3>
              
              <p className="text-sm text-gray-600 mb-6">
                {message}
              </p>
              
              <p className="text-xs text-gray-500 mb-4">
                Redirecting you to login in {countdown} seconds...
              </p>
              
              <Link
                to="/login"
                className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                Go to Login Now
              </Link>
            </div>
          )}

          {/* Error State */}
          {status === 'error' && !isLoading && (
            <div className="text-center">
              <div className="mb-4">
                <div className="mx-auto flex items-center justify-center h-16 w-16 rounded-full bg-red-100">
                  <svg className="h-8 w-8 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path>
                  </svg>
                </div>
              </div>
              
              <h3 className="text-lg font-medium text-gray-900 mb-2">
                Verification Failed
              </h3>
              
              <p className="text-sm text-gray-600 mb-4">
                {message}
              </p>
              
              {/* Show detailed error information */}
              {errorDetails && (
                <div className="mb-6 p-3 bg-gray-50 rounded-md text-left">
                  <p className="text-xs text-gray-600 font-medium mb-1">Error Details:</p>
                  <p className="text-xs text-gray-500 whitespace-pre-line">{errorDetails}</p>
                </div>
              )}
              
              <div className="space-y-3">
                {/* Show resend button for expired/invalid tokens */}
                {message.includes('expired') || message.includes('invalid') ? (
                  <button
                    onClick={handleResendVerification}
                    disabled={isLoading}
                    className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {isLoading ? 'Sending...' : 'Resend Verification Email'}
                  </button>
                ) : null}
                
                <Link
                  to="/login"
                  className="w-full flex justify-center py-2 px-4 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                >
                  Back to Login
                </Link>
                
                <Link
                  to="/register"
                  className="w-full flex justify-center py-2 px-4 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
                >
                  Create New Account
                </Link>
              </div>
            </div>
          )}
        </div>
      </div>
      
      {/* Debug Information (only in development) */}
      {process.env.NODE_ENV === 'development' && (
        <div className="mt-4 sm:mx-auto sm:w-full sm:max-w-md">
          <div className="bg-gray-100 p-3 rounded-md">
            <p className="text-xs text-gray-600 font-medium mb-1">Debug Info:</p>
            <p className="text-xs text-gray-500">URL: {window.location.href}</p>
            <p className="text-xs text-gray-500">Token: {searchParams.get('token')?.substring(0, 20)}...</p>
            <p className="text-xs text-gray-500">API URL: {process.env.REACT_APP_API_BASE_URL || 'http://localhost:5000/api/v1'}</p>
          </div>
        </div>
      )}
    </div>
  );
};

export default VerifyEmailPage; 