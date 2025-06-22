import React from 'react';

/**
 * LOADING SPINNER COMPONENT
 * 
 * A reusable loading spinner that can be used throughout the app.
 * It shows when things are loading (like API calls).
 */

const LoadingSpinner = ({ 
  size = 'medium',     // 'small', 'medium', 'large'
  color = 'primary',   // 'primary', 'white', 'gray'
  text = '',           // Optional text to show below spinner
  className = ''       // Additional CSS classes
}) => {
  // Define size classes
  const sizeClasses = {
    small: 'w-4 h-4',
    medium: 'w-8 h-8', 
    large: 'w-12 h-12'
  };

  // Define color classes
  const colorClasses = {
    primary: 'text-primary-600',
    white: 'text-white',
    gray: 'text-gray-600'
  };

  return (
    <div className={`flex flex-col items-center justify-center ${className}`}>
      {/* The spinning circle */}
      <div 
        className={`
          ${sizeClasses[size]} 
          ${colorClasses[color]} 
          animate-spin
        `}
      >
        {/* SVG spinner icon */}
        <svg 
          className="w-full h-full" 
          fill="none" 
          viewBox="0 0 24 24"
        >
          <circle 
            className="opacity-25" 
            cx="12" 
            cy="12" 
            r="10" 
            stroke="currentColor" 
            strokeWidth="4"
          />
          <path 
            className="opacity-75" 
            fill="currentColor" 
            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
          />
        </svg>
      </div>
      
      {/* Optional text below spinner */}
      {text && (
        <p className={`mt-2 text-sm ${colorClasses[color]}`}>
          {text}
        </p>
      )}
    </div>
  );
};

export default LoadingSpinner; 