import React, { createContext, useContext, useState, useEffect, useRef } from 'react';
import authService from '../services/authService';

/**
 * AUTHENTICATION CONTEXT (Simplified Version)
 * 
 * This context manages all authentication state in our React app using simple useState hooks.
 * It's much easier to understand than useReducer for beginners!
 * 
 * It provides:
 * - User login/logout state
 * - Loading states during authentication
 * - Error handling
 * - Token management
 * 
 * Using React Context prevents "prop drilling" - passing auth data
 * through multiple component levels.
 */

// Create the context
const AuthContext = createContext();

/**
 * AUTH PROVIDER COMPONENT
 * 
 * This component wraps our entire app and provides authentication
 * state and functions to all child components.
 */
export const AuthProvider = ({ children }) => {
  // Simple state variables using useState - much easier to understand!
  const [user, setUser] = useState(null);                    // Current user data
  const [isAuthenticated, setIsAuthenticated] = useState(false); // Is user logged in?
  const [isLoading, setIsLoading] = useState(true);          // Loading state
  const [error, setError] = useState(null);                  // Any errors
  const [isInitialized, setIsInitialized] = useState(false); // Has app checked for existing session?
  
  // Add a ref to prevent duplicate initialization (React StrictMode issue)
  const initializationAttempted = useRef(false);

  /**
   * Initialize authentication when app starts
   * This checks if the user is already logged in from a previous session
   */
  useEffect(() => {
    const initializeAuth = async () => {
      // Prevent duplicate initialization in React StrictMode
      if (initializationAttempted.current) {
        console.log('🔄 Skipping duplicate auth initialization');
        return;
      }
      initializationAttempted.current = true;
      
      setIsLoading(true);
      setError(null);
      
      try {
        // Check if user has valid tokens first
        if (!authService.hasValidToken()) {
          console.log('ℹ️ No valid tokens found, skipping auth check');
          setUser(null);
          setIsAuthenticated(false);
          return;
        }
        
        // Check if user is already authenticated
        const userData = await authService.getCurrentUser();
        
        // User is logged in!
        setUser(userData);
        setIsAuthenticated(true);
        console.log('✅ User already authenticated:', userData.email);
      } catch (error) {
        // User is not authenticated or tokens are invalid
        console.log('ℹ️ User not authenticated on app start:', error.response?.status);
        
        // Don't show error to user for authentication check failures
        setUser(null);
        setIsAuthenticated(false);
        
        // Clear any invalid tokens to prevent further failed requests
        if (error.response?.status === 401 || error.response?.status === 403) {
          console.log('🧹 Clearing invalid tokens');
          authService.clearTokens();
        }
      } finally {
        setIsLoading(false);
        setIsInitialized(true);
      }
    };

    initializeAuth();
  }, []); // Empty dependency array means this runs once when component mounts

  /**
   * LOGIN FUNCTION
   * 
   * Handles user login with email and password
   */
  const login = async (email, password, rememberMe = false) => {
    setIsLoading(true);
    setError(null);
    
    try {
      console.log('🔐 Attempting login for:', email);
      const response = await authService.login(email, password, rememberMe);
      
      // Login successful!
      setUser(response.user);
      setIsAuthenticated(true);
      console.log('✅ Login successful for:', response.user.email);
      
      return { success: true, user: response.user };
    } catch (error) {
      console.error('❌ Full login error object:', error);
      console.error('❌ Error response:', error.response);
      console.error('❌ Error response data:', error.response?.data);
      
      const errorMessage = error.response?.data?.message || error.message || 'Login failed';
      const fullError = {
        message: errorMessage,
        status: error.response?.status,
        statusText: error.response?.statusText,
        data: error.response?.data,
        url: error.config?.url,
        method: error.config?.method,
        timestamp: new Date().toISOString(),
        fullErrorMessage: error.message,
        networkError: !error.response ? 'Network request failed' : null
      };
      
      console.error('❌ Login failed with full error:', fullError);
      
      // Update error state with full error object
      setError(fullError);
      setUser(null);
      setIsAuthenticated(false);
      
      return { success: false, error: fullError };
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * REGISTER FUNCTION
   * 
   * Handles user registration
   */
  const register = async (userData) => {
    setIsLoading(true);
    setError(null);
    
    try {
      console.log('📝 Attempting registration for:', userData.email);
      const response = await authService.register(userData);
      
      console.log('✅ Registration successful! User needs to verify email.');
      
      // After registration, user is not automatically logged in
      // They need to verify their email first
      setUser(null);
      setIsAuthenticated(false);
      
      return { 
        success: true, 
        message: response.message,
        user: response.user 
      };
    } catch (error) {
      const errorMessage = error.response?.data?.message || 'Registration failed';
      console.error('❌ Registration failed:', errorMessage);
      
      setError(errorMessage);
      setUser(null);
      setIsAuthenticated(false);
      
      return { success: false, error: errorMessage };
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * LOGOUT FUNCTION
   * 
   * Handles user logout
   */
  const logout = async () => {
    try {
      console.log('👋 Logging out...');
      await authService.logout();
      console.log('✅ Logout successful');
    } catch (error) {
      console.error('❌ Logout error:', error);
      // We still want to clear local state even if API call fails
    } finally {
      // Clear all authentication state
      setUser(null);
      setIsAuthenticated(false);
      setError(null);
      setIsLoading(false);
    }
  };

  /**
   * LOGOUT FROM ALL DEVICES
   * 
   * Logs out from all devices
   */
  const logoutAll = async () => {
    try {
      console.log('🚪 Logging out from all devices...');
      await authService.logoutAll();
      
      // Clear local state
      setUser(null);
      setIsAuthenticated(false);
      setError(null);
      
      console.log('✅ Logged out from all devices');
      return { success: true };
    } catch (error) {
      console.error('❌ Logout all failed:', error);
      
      // Still clear local state
      setUser(null);
      setIsAuthenticated(false);
      setError(null);
      
      return { success: false, error: error.response?.data?.message };
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * CLEAR ERROR
   * 
   * Clears any authentication errors
   */
  const clearError = () => {
    setError(null);
  };

  /**
   * UPDATE USER
   * 
   * Updates user information in state (useful after profile updates)
   */
  const updateUser = (updates) => {
    if (user) {
      setUser({ ...user, ...updates });
      console.log('👤 User updated:', updates);
    }
  };

  /**
   * REFRESH USER DATA
   * 
   * Fetches the latest user data from the server
   */
  const refreshUser = async () => {
    if (!isAuthenticated) {
      console.log('⚠️ Cannot refresh user data - not authenticated');
      return { success: false, error: 'Not authenticated' };
    }

    try {
      console.log('🔄 Refreshing user data...');
      const userData = await authService.getCurrentUser();
      setUser(userData);
      console.log('✅ User data refreshed:', userData.email);
      return { success: true, user: userData };
    } catch (error) {
      console.error('❌ Failed to refresh user data:', error);
      return { success: false, error: error.response?.data?.message || 'Failed to refresh user data' };
    }
  };

  /**
   * CHECK IF USER HAS SPECIFIC ROLE
   * 
   * Helper function to check user permissions
   */
  const hasRole = (role) => {
    return user?.role === role;
  };

  /**
   * CHECK IF USER IS ADMIN
   * 
   * Helper function for admin checks
   */
  const isAdmin = () => {
    return hasRole('admin');
  };

  // The value object contains all the data and functions
  // that child components can access through useAuth()
  const value = {
    // State values
    user,
    isAuthenticated,
    isLoading,
    error,
    isInitialized,
    
    // Functions
    login,
    register,
    logout,
    logoutAll,
    clearError,
    updateUser,
    refreshUser,
    
    // Helper functions
    hasRole,
    isAdmin
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

/**
 * CUSTOM HOOK TO USE AUTH CONTEXT
 * 
 * This hook makes it easy to use authentication in any component.
 * 
 * Example usage:
 * const { user, login, logout, isLoading } = useAuth();
 * 
 * if (isLoading) return <div>Loading...</div>;
 * if (user) return <div>Welcome {user.firstName}!</div>;
 * return <LoginForm onLogin={login} />;
 */
export const useAuth = () => {
  const context = useContext(AuthContext);
  
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider. Make sure to wrap your app with <AuthProvider>');
  }
  
  return context;
}; 