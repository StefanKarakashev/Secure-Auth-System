import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import authService from '../services/authService';
import Navigation from '../components/ui/Navigation';
import LoadingSpinner from '../components/ui/LoadingSpinner';
import Alert from '../components/ui/Alert';

/**
 * SESSIONS MANAGEMENT PAGE
 * 
 * Production-ready session management page with:
 * - List all active sessions from different devices
 * - Session details (device, location, last activity)
 * - Revoke individual sessions
 * - Logout from all devices
 * - Real-time session updates
 * - Security indicators
 */

const SessionsPage = () => {
  const { user, logout } = useAuth();
  const [sessions, setSessions] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [alert, setAlert] = useState(null);
  const [revokingSessionId, setRevokingSessionId] = useState(null);
  const [loggingOutAll, setLoggingOutAll] = useState(false);

  // Fetch user sessions
  const fetchSessions = async () => {
    try {
      setIsLoading(true);
      const response = await authService.getUserSessions();
      setSessions(response.data.sessions || []);
    } catch (error) {
      console.error('Failed to fetch sessions:', error);
      setAlert({
        type: 'error',
        message: 'Failed to load sessions. Please try again.'
      });
    } finally {
      setIsLoading(false);
    }
  };

  // Load sessions on component mount
  useEffect(() => {
    fetchSessions();
  }, []);

  // Auto-refresh sessions every 30 seconds
  useEffect(() => {
    const interval = setInterval(fetchSessions, 30000);
    return () => clearInterval(interval);
  }, []);

  // Revoke a specific session
  const handleRevokeSession = async (sessionId) => {
    if (!window.confirm('Are you sure you want to revoke this session?')) {
      return;
    }

    setRevokingSessionId(sessionId);
    setAlert(null);

    try {
      await authService.revokeSession(sessionId);
      
      // Remove the revoked session from the list
      setSessions(prev => prev.filter(session => session.id !== sessionId));
      
      setAlert({
        type: 'success',
        message: 'Session has been revoked successfully.'
      });
    } catch (error) {
      console.error('Failed to revoke session:', error);
      setAlert({
        type: 'error',
        message: error.response?.data?.message || 'Failed to revoke session. Please try again.'
      });
    } finally {
      setRevokingSessionId(null);
    }
  };

  // Logout from all devices
  const handleLogoutAll = async () => {
    if (!window.confirm('This will log you out from all devices. Are you sure?')) {
      return;
    }

    setLoggingOutAll(true);
    setAlert(null);

    try {
      await authService.logoutAll();
      // This will redirect to login page
      await logout();
    } catch (error) {
      console.error('Failed to logout from all devices:', error);
      setAlert({
        type: 'error',
        message: 'Failed to logout from all devices. Please try again.'
      });
    } finally {
      setLoggingOutAll(false);
    }
  };

  // Get device icon based on device type
  const getDeviceIcon = (deviceInfo) => {
    const userAgent = deviceInfo?.userAgent?.toLowerCase() || '';
    
    if (userAgent.includes('mobile') || userAgent.includes('android') || userAgent.includes('iphone')) {
      return '📱';
    } else if (userAgent.includes('tablet') || userAgent.includes('ipad')) {
      return '📱';
    } else if (userAgent.includes('mac')) {
      return '💻';
    } else if (userAgent.includes('windows')) {
      return '🖥️';
    } else if (userAgent.includes('linux')) {
      return '🐧';
    }
    return '💻';
  };

  // Get browser name from user agent
  const getBrowserName = (userAgent) => {
    if (!userAgent) return 'Unknown Browser';
    
    const ua = userAgent.toLowerCase();
    if (ua.includes('chrome')) return 'Chrome';
    if (ua.includes('firefox')) return 'Firefox';
    if (ua.includes('safari')) return 'Safari';
    if (ua.includes('edge')) return 'Edge';
    if (ua.includes('opera')) return 'Opera';
    return 'Unknown Browser';
  };

  // Format last activity timestamp
  const formatLastActivity = (timestamp) => {
    if (!timestamp) return 'Unknown';
    const date = new Date(timestamp);
    const now = new Date();
    const diffMinutes = Math.floor((now - date) / (1000 * 60));
    
    if (diffMinutes < 1) return 'Just now';
    if (diffMinutes < 60) return `${diffMinutes} minute${diffMinutes > 1 ? 's' : ''} ago`;
    
    const diffHours = Math.floor(diffMinutes / 60);
    if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
    
    const diffDays = Math.floor(diffHours / 24);
    if (diffDays < 7) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
    
    return date.toLocaleDateString();
  };

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <LoadingSpinner size="large" text="Loading sessions..." />
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
          {alert && (
            <div className="mb-6">
              <Alert 
                type={alert.type} 
                message={alert.message}
                onClose={() => setAlert(null)}
              />
            </div>
          )}

          {/* Sessions List */}
          <div className="card">
            <div className="card-body">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Your Active Sessions ({sessions.length})
              </h3>

              {sessions.length === 0 ? (
                <div className="text-center py-8">
                  <span className="text-4xl mb-4 block">🔒</span>
                  <h4 className="text-lg font-medium text-gray-900 mb-2">No Active Sessions</h4>
                  <p className="text-gray-600">
                    There are no active sessions. This might indicate you need to log in again.
                  </p>
                </div>
              ) : (
                <div className="space-y-4">
                  {sessions.map((session) => (
                    <div
                      key={session.id}
                      className={`border rounded-lg p-4 ${
                        session.isCurrent ? 'border-indigo-200 bg-indigo-50' : 'border-gray-200'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-4">
                          <div className="text-3xl">
                            {getDeviceIcon(session.deviceInfo)}
                          </div>
                          <div>
                            <div className="flex items-center space-x-2">
                              <h4 className="font-medium text-gray-900">
                                {getBrowserName(session.userAgent)}
                              </h4>
                              {session.isCurrent && (
                                <span className="inline-flex px-2 py-1 text-xs font-semibold rounded-full bg-green-100 text-green-800">
                                  Current Session
                                </span>
                              )}
                            </div>
                            <div className="text-sm text-gray-600 space-y-1">
                              <div>
                                <strong>Platform:</strong> {session.deviceInfo?.platform || 'Unknown'}
                              </div>
                              <div>
                                <strong>IP Address:</strong> {session.ipAddress || 'Unknown'}
                              </div>
                              <div>
                                <strong>Location:</strong> {session.location || 'Unknown'}
                              </div>
                              <div>
                                <strong>Last Activity:</strong> {formatLastActivity(session.lastAccessed)}
                              </div>
                              <div>
                                <strong>Created:</strong> {new Date(session.createdAt).toLocaleDateString()}
                              </div>
                            </div>
                          </div>
                        </div>

                        <div className="flex items-center space-x-2">
                          {!session.isCurrent && (
                            <button
                              onClick={() => handleRevokeSession(session.id)}
                              disabled={revokingSessionId === session.id}
                              className="btn-secondary-sm"
                            >
                              {revokingSessionId === session.id ? (
                                <LoadingSpinner size="small" text="Revoking..." />
                              ) : (
                                'Revoke'
                              )}
                            </button>
                          )}
                        </div>
                      </div>

                      {session.isCurrent && (
                        <div className="mt-3 p-3 bg-blue-50 rounded-md border border-blue-200">
                          <div className="flex items-center">
                            <span className="text-blue-600 mr-2">ℹ️</span>
                            <p className="text-sm text-blue-800">
                              This is your current session. You cannot revoke it from here.
                            </p>
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Logout from All Devices */}
          <div className="card mt-6">
            <div className="card-body">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                🚪 Session Management
              </h3>
              <p className="text-gray-600 mb-4">
                You can logout from all devices at once. This will invalidate all active sessions 
                including your current one and you'll need to log in again.
              </p>
              <button
                onClick={handleLogoutAll}
                disabled={loggingOutAll}
                className="btn-danger"
              >
                {loggingOutAll ? (
                  <LoadingSpinner size="small" text="Logging out..." />
                ) : (
                  'Logout from All Devices'
                )}
              </button>
            </div>
          </div>

          {/* Security Tips */}
          <div className="card mt-6">
            <div className="card-body">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                🛡️ Security Tips
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 bg-yellow-50 rounded-lg border border-yellow-200">
                  <h4 className="font-medium text-yellow-800 mb-2">
                    Review Sessions Regularly
                  </h4>
                  <p className="text-sm text-yellow-700">
                    Check your active sessions regularly and revoke any that you don't recognize.
                  </p>
                </div>
                <div className="p-4 bg-blue-50 rounded-lg border border-blue-200">
                  <h4 className="font-medium text-blue-800 mb-2">
                    Logout When Done
                  </h4>
                  <p className="text-sm text-blue-700">
                    Always logout from shared or public computers to keep your account secure.
                  </p>
                </div>
                <div className="p-4 bg-green-50 rounded-lg border border-green-200">
                  <h4 className="font-medium text-green-800 mb-2">
                    Use Strong Passwords
                  </h4>
                  <p className="text-sm text-green-700">
                    Use unique, strong passwords and enable two-factor authentication when available.
                  </p>
                </div>
                <div className="p-4 bg-red-50 rounded-lg border border-red-200">
                  <h4 className="font-medium text-red-800 mb-2">
                    Suspicious Activity
                  </h4>
                  <p className="text-sm text-red-700">
                    If you see unfamiliar sessions or locations, change your password immediately.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SessionsPage; 