import React from 'react';

/**
 * ALERT COMPONENT
 * 
 * A reusable alert component for showing different types of messages:
 * - Success messages (green)
 * - Error messages (red)  
 * - Warning messages (yellow)
 * - Info messages (blue)
 */

const Alert = ({ 
  type = 'info',        // 'success', 'error', 'warning', 'info'
  title = '',           // Optional title
  message,              // Main message text
  onClose = null,       // Function to call when X is clicked
  className = ''        // Additional CSS classes
}) => {
  // Define styles for each alert type
  const alertStyles = {
    success: {
      container: 'bg-green-50 border-green-200 text-green-800',
      icon: '✅',
      iconColor: 'text-green-500'
    },
    error: {
      container: 'bg-red-50 border-red-200 text-red-800',
      icon: '❌', 
      iconColor: 'text-red-500'
    },
    warning: {
      container: 'bg-yellow-50 border-yellow-200 text-yellow-800',
      icon: '⚠️',
      iconColor: 'text-yellow-500'
    },
    info: {
      container: 'bg-blue-50 border-blue-200 text-blue-800',
      icon: 'ℹ️',
      iconColor: 'text-blue-500'
    }
  };

  const styles = alertStyles[type];

  return (
    <div className={`
      flex items-start p-4 border rounded-lg
      ${styles.container}
      ${className}
    `}>
      {/* Icon */}
      <div className={`flex-shrink-0 ${styles.iconColor}`}>
        <span className="text-lg">{styles.icon}</span>
      </div>
      
      {/* Content */}
      <div className="ml-3 flex-1">
        {/* Title (optional) */}
        {title && (
          <h3 className="font-medium text-sm mb-1">
            {title}
          </h3>
        )}
        
        {/* Message */}
        <div className="text-sm">
          {message}
        </div>
      </div>
      
      {/* Close button (optional) */}
      {onClose && (
        <button
          onClick={onClose}
          className={`
            flex-shrink-0 ml-3 p-1 rounded-md
            hover:bg-black hover:bg-opacity-10
            focus:outline-none focus:ring-2 focus:ring-offset-2
            ${styles.iconColor}
          `}
        >
          <span className="sr-only">Close</span>
          <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
          </svg>
        </button>
      )}
    </div>
  );
};

export default Alert; 