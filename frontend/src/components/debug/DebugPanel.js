import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import authService from '../../services/authService';

/**
 * DEBUG PANEL COMPONENT
 * 
 * This component helps debug authentication and API issues.
 * Only shows in development mode.
 */

const DebugPanel = () => {
  const { user, isAuthenticated, isLoading, error, isInitialized } = useAuth();
  const [apiStatus, setApiStatus] = useState('unknown');
  const [tokenInfo, setTokenInfo] = useState({});
  const [isVisible, setIsVisible] = useState(true);
  const [detailedError, setDetailedError] = useState('');

  // Test API connection
  const testAPI = async () => {
    try {
      setApiStatus('testing...');
      const response = await fetch('http://192.168.100.3:3000/health');
      if (response.ok) {
        const data = await response.json();
        setApiStatus(`✅ Connected (DB: ${data.database})`);
      } else {
        setApiStatus(`❌ Error: ${response.status}`);
      }
    } catch (error) {
      setApiStatus(`❌ Failed: ${error.message}`);
    }
  };

  // Test login with detailed error reporting
  const testLogin = async () => {
    try {
      setDetailedError('Testing login...');
      
      const loginData = {
        email: 'test@example.com',
        password: 'TestPassword123!',
        rememberMe: false,
        deviceInfo: {
          userAgent: navigator.userAgent,
          platform: navigator.platform,
          language: navigator.language
        }
      };

      console.log('🔐 Attempting login with:', loginData);
      
      const response = await fetch('http://192.168.100.3:3000/api/v1/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify(loginData)
      });

      const responseText = await response.text();
      console.log('📡 Login response:', response.status, responseText);

      if (response.ok) {
        const data = JSON.parse(responseText);
        setDetailedError(`✅ Login successful! User: ${data.data?.user?.email}`);
      } else {
        let errorData;
        try {
          errorData = JSON.parse(responseText);
        } catch (e) {
          errorData = { message: responseText };
        }
        setDetailedError(`❌ Login failed (${response.status}): ${errorData.message || 'Unknown error'}`);
      }
    } catch (error) {
      console.error('❌ Login test error:', error);
      setDetailedError(`❌ Login test failed: ${error.message} | ${error.name} | ${error.stack?.slice(0, 100)}`);
    }
  };

  // Test registration endpoint
  const testRegistration = async () => {
    try {
      const testUser = {
        firstName: 'Test',
        lastName: 'User',
        email: 'test@example.com',
        password: 'TestPassword123!',
        acceptTerms: true
      };

      const response = await fetch('http://192.168.100.3:3000/api/v1/auth/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(testUser)
      });

      const data = await response.json();
      
      if (response.ok) {
        alert('✅ Test user created! Email: test@example.com, Password: TestPassword123!');
      } else {
        alert(`❌ Registration failed: ${data.message}`);
      }
    } catch (error) {
      alert(`❌ Registration error: ${error.message}`);
    }
  };

  // Get token information
  useEffect(() => {
    const accessToken = authService.getAccessToken();
    const refreshToken = authService.getRefreshToken();
    
    setTokenInfo({
      hasAccessToken: !!accessToken,
      hasRefreshToken: !!refreshToken,
      accessTokenLength: accessToken?.length || 0,
      refreshTokenLength: refreshToken?.length || 0
    });
  }, [user]);

  // Clear all data
  const clearAllData = () => {
    localStorage.clear();
    sessionStorage.clear();
    window.location.reload();
  };

  // Only show in development
  if (process.env.NODE_ENV !== 'development' || !isVisible) {
    return null;
  }

  return (
    <div className="fixed bottom-4 right-4 bg-gray-900 text-white p-4 rounded-lg shadow-lg max-w-sm text-xs font-mono z-50">
      <div className="flex justify-between items-center mb-2">
        <h3 className="font-bold">🔧 Debug Panel</h3>
        <button 
          onClick={() => setIsVisible(false)}
          className="text-gray-400 hover:text-white"
        >
          ✕
        </button>
      </div>
      
      <div className="space-y-2">
        {/* Authentication Status */}
        <div>
          <strong>Auth Status:</strong>
          <div className="ml-2">
            <div>Initialized: {isInitialized ? '✅' : '❌'}</div>
            <div>Loading: {isLoading ? '🔄' : '✅'}</div>
            <div>Authenticated: {isAuthenticated ? '✅' : '❌'}</div>
            <div>User: {user ? user.email : 'None'}</div>
            <div>Error: {error || 'None'}</div>
          </div>
        </div>

        {/* Token Information */}
        <div>
          <strong>Tokens:</strong>
          <div className="ml-2">
            <div>Access: {tokenInfo.hasAccessToken ? '✅' : '❌'} ({tokenInfo.accessTokenLength})</div>
            <div>Refresh: {tokenInfo.hasRefreshToken ? '✅' : '❌'} ({tokenInfo.refreshTokenLength})</div>
          </div>
        </div>

        {/* API Status */}
        <div>
          <strong>Backend API:</strong>
          <div className="ml-2">
            <div>{apiStatus}</div>
            <button 
              onClick={testAPI}
              className="text-blue-400 hover:text-blue-300 underline mr-2"
            >
              Test Connection
            </button>
            <button 
              onClick={testRegistration}
              className="text-green-400 hover:text-green-300 underline mr-2"
            >
              Create Test User
            </button>
            <button 
              onClick={testLogin}
              className="text-yellow-400 hover:text-yellow-300 underline"
            >
              Test Login
            </button>
          </div>
        </div>

        {/* Detailed Error */}
        {detailedError && (
          <div>
            <strong>Debug Info:</strong>
            <div className="ml-2 text-xs bg-gray-800 p-2 rounded mt-1 break-words">
              {detailedError}
            </div>
          </div>
        )}

        {/* Actions */}
        <div className="pt-2 border-t border-gray-700">
          <button 
            onClick={clearAllData}
            className="text-red-400 hover:text-red-300 underline mr-2"
          >
            Clear All Data & Reload
          </button>
          <button 
            onClick={() => setIsVisible(false)}
            className="text-gray-400 hover:text-gray-300 underline"
          >
            Hide Panel
          </button>
        </div>
      </div>
    </div>
  );
};

export default DebugPanel; 