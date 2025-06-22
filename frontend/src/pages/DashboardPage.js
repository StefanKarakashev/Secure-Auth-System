import React, { useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import Navigation from '../components/ui/Navigation';
import EmailVerificationCard from '../components/ui/EmailVerificationCard';
import LoadingSpinner from '../components/ui/LoadingSpinner';
import Alert from '../components/ui/Alert';

/**
 * DASHBOARD PAGE
 * 
 * This is the main page users see after logging in.
 * It shows user information, provides quick access to features, and includes navigation.
 */

const DashboardPage = () => {
  const { user, logout, isLoading, refreshUser } = useAuth();

  const handleLogout = async () => {
    await logout();
  };

  // Note: No need to call refreshUser() here since AuthContext already loads user data
  // on app initialization. This was causing duplicate /me API calls.

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <LoadingSpinner 
          size="large" 
          text="Loading dashboard..." 
        />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Navigation */}
      <Navigation />

      {/* Main Content */}
      <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          {/* Welcome Card */}
          <div className="card mb-6">
            <div className="card-body">
              <h2 className="text-xl font-semibold text-gray-900 mb-4">
                🎉 Welcome to your Dashboard, {user?.firstName}!
              </h2>
              <p className="text-gray-600 mb-4">
                You have successfully logged in to the SecureAuth system. This is a production-ready 
                authentication system built with React and Express.js.
              </p>
              
              <Alert 
                type="success" 
                message="Authentication successful! Your session is secure and protected."
              />
            </div>
          </div>

          {/* Email Verification Card */}
          <EmailVerificationCard 
            user={user} 
            onVerificationSent={() => {
              // Optionally refresh user data after sending verification
              setTimeout(() => {
                refreshUser();
              }, 1000);
            }}
            className="mb-6"
          />

          {/* Quick Actions */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-6">
            {/* Sessions Management */}
            <Link to="/sessions" className="card hover:shadow-lg transition-shadow duration-200">
              <div className="card-body text-center">
                <div className="text-4xl mb-3">📱</div>
                <h3 className="text-lg font-semibold text-gray-900 mb-2">
                  Manage Sessions
                </h3>
                <p className="text-gray-600 mb-4">
                  View and manage your active sessions across all devices
                </p>
                <div className="btn-primary">
                  View Sessions
                </div>
              </div>
            </Link>

            {/* Change Password */}
            <Link 
              to="/change-password" 
              className={`card transition-shadow duration-200 ${
                user?.isEmailVerified 
                  ? 'hover:shadow-lg' 
                  : 'opacity-50 cursor-not-allowed'
              }`}
              onClick={(e) => {
                if (!user?.isEmailVerified) {
                  e.preventDefault();
                  alert('Please verify your email first to change your password.');
                }
              }}
            >
              <div className="card-body text-center">
                <div className="text-4xl mb-3">🔑</div>
                <h3 className="text-lg font-semibold text-gray-900 mb-2">
                  Change Password
                </h3>
                <p className="text-gray-600 mb-4">
                  Update your account password for better security
                </p>
                <div className={`btn-primary ${!user?.isEmailVerified ? 'opacity-50' : ''}`}>
                  {user?.isEmailVerified ? 'Change Password' : 'Email Verification Required'}
                </div>
              </div>
            </Link>

            {/* Account Security */}
            <div className="card">
              <div className="card-body text-center">
                <div className="text-4xl mb-3">🛡️</div>
                <h3 className="text-lg font-semibold text-gray-900 mb-2">
                  Account Security
                </h3>
                <p className="text-gray-600 mb-4">
                  Your account is protected with advanced security features
                </p>
                <div className="flex items-center justify-center space-x-2">
                  <span className="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-green-100 text-green-800">
                    JWT Auth
                  </span>
                  <span className="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-blue-100 text-blue-800">
                    Session Management
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* User Information Card */}
          <div className="card mb-6">
            <div className="card-body">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                👤 Your Profile Information
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    First Name
                  </label>
                  <p className="mt-1 text-sm text-gray-900">{user?.firstName}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Last Name
                  </label>
                  <p className="mt-1 text-sm text-gray-900">{user?.lastName}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Email Address
                  </label>
                  <p className="mt-1 text-sm text-gray-900">{user?.email}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Account Status
                  </label>
                  <p className="mt-1 text-sm">
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                      user?.isEmailVerified 
                        ? 'bg-green-100 text-green-800' 
                        : 'bg-yellow-100 text-yellow-800'
                    }`}>
                      {user?.isEmailVerified ? 'Verified' : 'Pending Verification'}
                    </span>
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Features Card */}
          <div className="card">
            <div className="card-body">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                🚀 Authentication Features
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                <div className="text-center p-4 border rounded-lg">
                  <div className="text-2xl mb-2">🔐</div>
                  <h4 className="font-medium">JWT Authentication</h4>
                  <p className="text-sm text-gray-600">Secure token-based auth</p>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <div className="text-2xl mb-2">🔄</div>
                  <h4 className="font-medium">Token Refresh</h4>
                  <p className="text-sm text-gray-600">Automatic token rotation</p>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <div className="text-2xl mb-2">📱</div>
                  <h4 className="font-medium">Multi-Device</h4>
                  <p className="text-sm text-gray-600">Session management</p>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <div className="text-2xl mb-2">🛡️</div>
                  <h4 className="font-medium">Security</h4>
                  <p className="text-sm text-gray-600">Rate limiting & protection</p>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <div className="text-2xl mb-2">📧</div>
                  <h4 className="font-medium">Email Verification</h4>
                  <p className="text-sm text-gray-600">Account verification</p>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <div className="text-2xl mb-2">🔑</div>
                  <h4 className="font-medium">Password Reset</h4>
                  <p className="text-sm text-gray-600">Secure password recovery</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DashboardPage; 