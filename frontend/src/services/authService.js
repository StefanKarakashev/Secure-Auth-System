import axios from 'axios';

/**
 * AUTHENTICATION SERVICE
 * 
 * This service handles all API communication with our backend.
 * It includes:
 * - HTTP requests to auth endpoints
 * - Token management
 * - Request/response interceptors
 * - Error handling
 */

// Base configuration for axios
const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || 'http://192.168.100.3:5000/api/v1';

console.log('🔧 AuthService initialized with API_BASE_URL:', API_BASE_URL);
console.log('🔧 Environment variables:', process.env);

// Create axios instance with base configuration
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: false, // Disabled for mobile compatibility - debug page works without this
});

/**
 * REQUEST INTERCEPTOR
 * 
 * This automatically adds the access token to every request if it exists.
 * It runs before every API call is made.
 */
api.interceptors.request.use(
  (config) => {
    // Get access token from localStorage if it exists
    const accessToken = localStorage.getItem('accessToken');
    
    if (accessToken) {
      config.headers.Authorization = `Bearer ${accessToken}`;
    }
    
    console.log(`🌐 Making ${config.method?.toUpperCase()} request to:`, config.url);
    return config;
  },
  (error) => {
    console.error('❌ Request interceptor error:', error);
    return Promise.reject(error);
  }
);

/**
 * RESPONSE INTERCEPTOR
 * 
 * This handles responses and automatically manages token refresh.
 * It runs after every API response is received.
 */
api.interceptors.response.use(
  (response) => {
    // If response includes new tokens, save them
    if (response.data?.data?.tokens) {
      const { accessToken, refreshToken } = response.data.data.tokens;
      if (accessToken) {
        localStorage.setItem('accessToken', accessToken);
      }
      if (refreshToken) {
        localStorage.setItem('refreshToken', refreshToken);
      }
    }
    
    console.log(`✅ Received response from:`, response.config.url);
    return response;
  },
  async (error) => {
    const originalRequest = error.config;
    
    // Handle rate limiting errors - don't retry
    if (error.response?.status === 429) {
      console.warn('⚠️ Rate limit exceeded. Please wait before making more requests.');
      return Promise.reject(error);
    }
    
    // If we get a 401 (unauthorized) and haven't already tried to refresh
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      
1``      // Don't attempt token refresh on verify-email page or if we don't have refresh token
      const refreshToken = localStorage.getItem('refreshToken');
      if (window.location.pathname === '/verify-email' || !refreshToken) {
        console.log('🚫 Skipping token refresh (no refresh token or on verify-email page)');
        return Promise.reject(error);
      }
      
      try {
        console.log('🔄 Attempting to refresh token...');
        await authService.refreshToken();
        
        // Retry the original request with new token
        const accessToken = localStorage.getItem('accessToken');
        if (accessToken) {
          originalRequest.headers.Authorization = `Bearer ${accessToken}`;
        }
        
        return api(originalRequest);
      } catch (refreshError) {
        console.log('❌ Token refresh failed, logging out...');
        // Refresh failed, user needs to log in again
        authService.clearTokens();
        
        // Only redirect if we're not already on the login page or verify-email page
        if (window.location.pathname !== '/login' && window.location.pathname !== '/verify-email') {
          window.location.href = '/login';
        }
        return Promise.reject(refreshError);
      }
    }
    
    console.error(`❌ API Error:`, error.response?.data || error.message);
    return Promise.reject(error);
  }
);

/**
 * AUTH SERVICE OBJECT
 * 
 * Contains all authentication-related API functions
 */
const authService = {
  
  /**
   * REGISTER NEW USER
   */
  async register(userData) {
    const response = await api.post('/auth/register', {
      email: userData.email,
      password: userData.password,
      firstName: userData.firstName,
      lastName: userData.lastName,
      acceptTerms: userData.acceptTerms
    });
    
    return response.data;
  },

  /**
   * LOGIN USER
   */
  async login(email, password, rememberMe = false) {
    const response = await api.post('/auth/login', {
      email,
      password,
      rememberMe,
      deviceInfo: {
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        language: navigator.language
      }
    });
    
    // Save tokens to localStorage
    if (response.data.data.tokens) {
      const { accessToken, refreshToken } = response.data.data.tokens;
      localStorage.setItem('accessToken', accessToken);
      localStorage.setItem('refreshToken', refreshToken);
    }
    
    return response.data.data;
  },

  /**
   * LOGOUT USER
   */
  async logout() {
    try {
      await api.post('/auth/logout');
    } catch (error) {
      console.error('Logout API error:', error);
    } finally {
      // Always clear tokens, even if API call fails
      this.clearTokens();
    }
  },

  /**
   * LOGOUT FROM ALL DEVICES
   */
  async logoutAll() {
    const response = await api.post('/auth/logout-all');
    this.clearTokens();
    return response.data;
  },

  /**
   * REFRESH ACCESS TOKEN
   */
  async refreshToken() {
    const refreshToken = localStorage.getItem('refreshToken');
    
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }
    
    const response = await api.post('/auth/refresh', {
      refreshToken
    });
    
    // Save new tokens
    if (response.data.data.accessToken) {
      localStorage.setItem('accessToken', response.data.data.accessToken);
    }
    if (response.data.data.refreshToken) {
      localStorage.setItem('refreshToken', response.data.data.refreshToken);
    }
    
    return response.data;
  },

  /**
   * GET CURRENT USER INFO
   */
  async getCurrentUser() {
    const response = await api.get('/auth/me');
    return response.data.data.user;
  },

  /**
   * REQUEST PASSWORD RESET
   */
  async requestPasswordReset(email) {
    const response = await api.post('/auth/forgot-password', { email });
    return response.data;
  },

  /**
   * RESET PASSWORD
   */
  async resetPassword(token, password) {
    const response = await api.post('/auth/reset-password', {
      token,
      password
    });
    return response.data;
  },

  /**
   * VERIFY EMAIL ADDRESS
   */
  async verifyEmail(token) {
    const response = await api.post('/auth/verify-email', { token });
    return response.data;
  },

  /**
   * RESEND VERIFICATION EMAIL
   */
  async resendVerification() {
    const response = await api.post('/auth/resend-verification');
    return response.data;
  },

  /**
   * CHANGE PASSWORD
   */
  async changePassword(currentPassword, newPassword, confirmPassword) {
    const response = await api.post('/auth/change-password', {
      currentPassword,
      newPassword,
      confirmPassword
    });
    return response.data;
  },

  /**
   * GET USER SESSIONS
   */
  async getUserSessions() {
    const response = await api.get('/auth/sessions');
    return response.data;
  },

  /**
   * REVOKE SESSION
   */
  async revokeSession(sessionId) {
    const response = await api.delete(`/auth/sessions/${sessionId}`);
    return response.data;
  },

  /**
   * CHECK AUTHENTICATION STATUS
   */
  async checkAuth() {
    const response = await api.get('/auth/check');
    return response.data.data;
  },

  /**
   * CLEAR TOKENS FROM STORAGE
   */
  clearTokens() {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
  },

  /**
   * CHECK IF USER HAS VALID TOKEN
   */
  hasValidToken() {
    const accessToken = localStorage.getItem('accessToken');
    
    if (!accessToken) {
      return false;
    }
    
    try {
      // Decode JWT token (basic check - don't use this for security!)
      const payload = JSON.parse(atob(accessToken.split('.')[1]));
      const currentTime = Date.now() / 1000;
      
      // Check if token is expired
      return payload.exp > currentTime;
    } catch (error) {
      console.error('Error checking token validity:', error);
      return false;
    }
  },

  /**
   * GET ACCESS TOKEN
   */
  getAccessToken() {
    return localStorage.getItem('accessToken');
  },

  /**
   * GET REFRESH TOKEN
   */
  getRefreshToken() {
    return localStorage.getItem('refreshToken');
  }
};

export default authService; 