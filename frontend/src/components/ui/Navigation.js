import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../../contexts/AuthContext';
import authService from '../../services/authService';

/**
 * NAVIGATION COMPONENT
 * 
 * Production-ready navigation with:
 * - Responsive design
 * - User authentication status
 * - Quick access to all features
 * - Mobile menu support
 * - Security-focused actions
 */

const Navigation = () => {
  const { user, logout, isAuthenticated } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [isUserMenuOpen, setIsUserMenuOpen] = useState(false);

  // Handle logout
  const handleLogout = async () => {
    await logout();
    setIsUserMenuOpen(false);
    setIsMobileMenuOpen(false);
  };

  // Handle logout from all devices
  const handleLogoutAll = async () => {
    if (window.confirm('This will log you out from all devices. Are you sure?')) {
      try {
        await authService.logoutAll();
        await logout();
      } catch (error) {
        console.error('Failed to logout from all devices:', error);
      }
    }
    setIsUserMenuOpen(false);
    setIsMobileMenuOpen(false);
  };

  // Close menus when clicking outside
  React.useEffect(() => {
    const handleClickOutside = () => {
      setIsUserMenuOpen(false);
      setIsMobileMenuOpen(false);
    };

    document.addEventListener('click', handleClickOutside);
    return () => document.removeEventListener('click', handleClickOutside);
  }, []);

  // Navigation items for authenticated users
  const navItems = [
    {
      name: 'Dashboard',
      href: '/dashboard',
      icon: '🏠',
      description: 'Home dashboard'
    },
    {
      name: 'Sessions',
      href: '/sessions',
      icon: '📱',
      description: 'Manage active sessions'
    }
  ];

  // User menu items
  const userMenuItems = [
    {
      name: 'Change Password',
      href: '/change-password',
      icon: '🔑',
      description: 'Update your password',
      requiresEmailVerification: true
    },
    {
      name: 'Sessions',
      href: '/sessions',
      icon: '📱',
      description: 'Manage your sessions'
    }
  ];

  // Check if current route is active
  const isActive = (href) => location.pathname === href;

  if (!isAuthenticated) {
    return null; // Don't show navigation for unauthenticated users
  }

  return (
    <nav className="bg-white shadow-lg sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-16">
          {/* Logo and primary navigation */}
          <div className="flex items-center">
            <Link to="/dashboard" className="flex items-center space-x-2">
              <span className="text-2xl">🔐</span>
              <span className="font-bold text-xl text-gray-900">SecureAuth</span>
            </Link>

            {/* Desktop Navigation */}
            <div className="hidden md:ml-8 md:flex md:space-x-4">
              {navItems.map((item) => (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`px-3 py-2 rounded-md text-sm font-medium transition-colors duration-200 flex items-center space-x-1 ${
                    isActive(item.href)
                      ? 'bg-indigo-100 text-indigo-700'
                      : 'text-gray-700 hover:text-indigo-600 hover:bg-gray-50'
                  }`}
                  title={item.description}
                >
                  <span>{item.icon}</span>
                  <span>{item.name}</span>
                </Link>
              ))}
            </div>
          </div>

          {/* User menu and mobile menu button */}
          <div className="flex items-center space-x-4">
            {/* Email verification status */}
            {!user.isEmailVerified && (
              <div className="hidden sm:flex items-center space-x-2 px-3 py-1 bg-yellow-100 text-yellow-800 rounded-full text-sm">
                <span>⚠️</span>
                <span>Email not verified</span>
              </div>
            )}

            {/* User Menu */}
            <div className="relative">
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  setIsUserMenuOpen(!isUserMenuOpen);
                }}
                className="flex items-center space-x-2 text-gray-700 hover:text-indigo-600 px-3 py-2 rounded-md text-sm font-medium transition-colors duration-200"
              >
                <div className="w-8 h-8 bg-indigo-100 rounded-full flex items-center justify-center">
                  <span className="text-indigo-600 font-semibold">
                    {user.firstName?.[0]?.toUpperCase() || '?'}
                  </span>
                </div>
                <span className="hidden sm:block">{user.firstName}</span>
                <span className={`transform transition-transform duration-200 ${
                  isUserMenuOpen ? 'rotate-180' : ''
                }`}>
                  ⌄
                </span>
              </button>

              {/* User Dropdown Menu */}
              {isUserMenuOpen && (
                <div className="absolute right-0 mt-2 w-72 bg-white rounded-lg shadow-lg border border-gray-200 py-2">
                  {/* User Info */}
                  <div className="px-4 py-3 border-b border-gray-100">
                    <div className="flex items-center space-x-3">
                      <div className="w-10 h-10 bg-indigo-100 rounded-full flex items-center justify-center">
                        <span className="text-indigo-600 font-semibold text-lg">
                          {user.firstName?.[0]?.toUpperCase() || '?'}
                        </span>
                      </div>
                      <div>
                        <p className="font-medium text-gray-900">
                          {user.firstName} {user.lastName}
                        </p>
                        <p className="text-sm text-gray-600">{user.email}</p>
                        <div className="flex items-center space-x-1 mt-1">
                          <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                            user.isEmailVerified 
                              ? 'bg-green-100 text-green-800' 
                              : 'bg-yellow-100 text-yellow-800'
                          }`}>
                            {user.isEmailVerified ? '✓ Verified' : '⚠️ Unverified'}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Menu Items */}
                  <div className="py-1">
                    {userMenuItems.map((item) => {
                      const canAccess = !item.requiresEmailVerification || user.isEmailVerified;
                      
                      return (
                        <Link
                          key={item.name}
                          to={item.href}
                          onClick={() => setIsUserMenuOpen(false)}
                          className={`flex items-center px-4 py-2 text-sm transition-colors duration-200 ${
                            canAccess
                              ? 'text-gray-700 hover:bg-gray-50 hover:text-indigo-600'
                              : 'text-gray-400 cursor-not-allowed'
                          }`}
                          title={canAccess ? item.description : 'Email verification required'}
                        >
                          <span className="mr-3">{item.icon}</span>
                          <div>
                            <div>{item.name}</div>
                            {!canAccess && (
                              <div className="text-xs text-gray-400">
                                Requires email verification
                              </div>
                            )}
                          </div>
                        </Link>
                      );
                    })}
                  </div>

                  {/* Logout Actions */}
                  <div className="border-t border-gray-100 py-1">
                    <button
                      onClick={handleLogout}
                      className="flex items-center w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 hover:text-red-600 transition-colors duration-200"
                    >
                      <span className="mr-3">🚪</span>
                      <span>Logout</span>
                    </button>
                    <button
                      onClick={handleLogoutAll}
                      className="flex items-center w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 hover:text-red-600 transition-colors duration-200"
                    >
                      <span className="mr-3">🔐</span>
                      <span>Logout All Devices</span>
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* Mobile menu button */}
            <button
              onClick={(e) => {
                e.stopPropagation();
                setIsMobileMenuOpen(!isMobileMenuOpen);
              }}
              className="md:hidden inline-flex items-center justify-center p-2 rounded-md text-gray-700 hover:text-indigo-600 hover:bg-gray-50 transition-colors duration-200"
            >
              <span className="sr-only">Open main menu</span>
              <div className={`transform transition-transform duration-200 ${
                isMobileMenuOpen ? 'rotate-90' : ''
              }`}>
                ☰
              </div>
            </button>
          </div>
        </div>

        {/* Mobile Navigation Menu */}
        {isMobileMenuOpen && (
          <div className="md:hidden border-t border-gray-200">
            <div className="px-2 pt-2 pb-3 space-y-1">
              {navItems.map((item) => (
                <Link
                  key={item.name}
                  to={item.href}
                  onClick={() => setIsMobileMenuOpen(false)}
                  className={`block px-3 py-2 rounded-md text-base font-medium transition-colors duration-200 flex items-center space-x-2 ${
                    isActive(item.href)
                      ? 'bg-indigo-100 text-indigo-700'
                      : 'text-gray-700 hover:text-indigo-600 hover:bg-gray-50'
                  }`}
                >
                  <span>{item.icon}</span>
                  <span>{item.name}</span>
                </Link>
              ))}
            </div>
          </div>
        )}
      </div>
    </nav>
  );
};

export default Navigation; 