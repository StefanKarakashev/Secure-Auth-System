import Joi from 'joi';
import validator from 'validator';
import { validatePasswordStrength } from '../utils/security.js';

/**
 * INPUT VALIDATION MIDDLEWARE
 * 
 * This module provides comprehensive input validation for all API endpoints.
 * We use Joi for schema validation because it provides:
 * - Powerful validation rules
 * - Custom validation functions
 * - Clear error messages
 * - Type coercion and sanitization
 * 
 * Security benefits:
 * - Prevents injection attacks
 * - Ensures data integrity
 * - Provides consistent error responses
 * - Sanitizes user input
 */

/**
 * CUSTOM VALIDATION FUNCTIONS
 * 
 * These are reusable validation functions for common patterns.
 */

// Strong password validation
const passwordValidation = (value, helpers) => {
  const validation = validatePasswordStrength(value);
  
  if (!validation.isValid) {
    const messages = [];
    if (validation.feedback.length) messages.push(validation.feedback.length);
    if (validation.feedback.complexity) messages.push(validation.feedback.complexity);
    
    return helpers.error('password.weak', { 
      message: messages.join('. '),
      score: validation.score 
    });
  }
  
  return value;
};

// Email validation with additional checks
const emailValidation = (value, helpers) => {
  // Basic format check
  if (!validator.isEmail(value)) {
    return helpers.error('email.invalid');
  }
  
  // Check for common typos in popular domains
  const commonDomains = {
    'gmai.com': 'gmail.com',
    'gmial.com': 'gmail.com',
    'yahooo.com': 'yahoo.com',
    'hotmial.com': 'hotmail.com'
  };
  
  const domain = value.split('@')[1];
  if (commonDomains[domain]) {
    return helpers.error('email.typo', { 
      suggestion: value.replace(domain, commonDomains[domain]) 
    });
  }
  
  return value.toLowerCase().trim();
};

/**
 * VALIDATION SCHEMAS
 * 
 * Define validation rules for different operations.
 */

export const schemas = {
  // User registration validation
  register: Joi.object({
    email: Joi.string()
      .required()
      .max(320) // RFC 5321 limit
      .custom(emailValidation)
      .messages({
        'email.invalid': 'Please enter a valid email address',
        'email.typo': 'Did you mean {{#suggestion}}?',
        'string.max': 'Email address is too long'
      }),
    
    password: Joi.string()
      .required()
      .min(8)
      .max(128)
      .custom(passwordValidation)
      .messages({
        'password.weak': 'Password is too weak. {{#message}}',
        'string.min': 'Password must be at least 8 characters long',
        'string.max': 'Password cannot exceed 128 characters'
      }),
    
    firstName: Joi.string()
      .required()
      .min(1)
      .max(100)
      .pattern(/^[a-zA-Z\s\-']+$/)
      .trim()
      .messages({
        'string.pattern.base': 'First name can only contain letters, spaces, hyphens, and apostrophes',
        'string.max': 'First name cannot exceed 100 characters'
      }),
    
    lastName: Joi.string()
      .required()
      .min(1)
      .max(100)
      .pattern(/^[a-zA-Z\s\-']+$/)
      .trim()
      .messages({
        'string.pattern.base': 'Last name can only contain letters, spaces, hyphens, and apostrophes',
        'string.max': 'Last name cannot exceed 100 characters'
      }),
    
    // Optional terms acceptance
    acceptTerms: Joi.boolean()
      .truthy()
      .required()
      .messages({
        'any.required': 'You must accept the terms and conditions'
      })
  }),

  // User login validation
  login: Joi.object({
    email: Joi.string()
      .required()
      .email()
      .max(320)
      .messages({
        'string.email': 'Please enter a valid email address'
      }),
    
    password: Joi.string()
      .required()
      .min(1)
      .max(128)
      .messages({
        'string.min': 'Password is required'
      }),
    
    // Optional: remember me flag
    rememberMe: Joi.boolean().default(false),
    
    // Optional: device information for tracking
    deviceInfo: Joi.object({
      deviceName: Joi.string().max(100),
      browserName: Joi.string().max(50),
      osName: Joi.string().max(50)
    }).optional()
  }),

  // Password change validation
  changePassword: Joi.object({
    currentPassword: Joi.string()
      .required()
      .messages({
        'any.required': 'Current password is required'
      }),
    
    newPassword: Joi.string()
      .required()
      .min(8)
      .max(128)
      .custom(passwordValidation)
      .invalid(Joi.ref('currentPassword'))
      .messages({
        'password.weak': 'New password is too weak. {{#message}}',
        'any.invalid': 'New password must be different from current password'
      }),
    
    confirmPassword: Joi.string()
      .required()
      .valid(Joi.ref('newPassword'))
      .messages({
        'any.only': 'Password confirmation does not match'
      })
  }),

  // Password reset request validation
  passwordResetRequest: Joi.object({
    email: Joi.string()
      .required()
      .email()
      .max(320)
      .messages({
        'string.email': 'Please enter a valid email address'
      })
  }),

  // Password reset validation
  passwordReset: Joi.object({
    token: Joi.string()
      .required()
      .messages({
        'any.required': 'Reset token is required'
      }),
    
    password: Joi.string()
      .required()
      .min(8)
      .max(128)
      .custom(passwordValidation)
      .messages({
        'password.weak': 'Password is too weak. {{#message}}'
      }),
    
    confirmPassword: Joi.string()
      .required()
      .valid(Joi.ref('password'))
      .messages({
        'any.only': 'Password confirmation does not match'
      })
  }),

  // Profile update validation
  updateProfile: Joi.object({
    firstName: Joi.string()
      .min(1)
      .max(100)
      .pattern(/^[a-zA-Z\s\-']+$/)
      .trim()
      .messages({
        'string.pattern.base': 'First name can only contain letters, spaces, hyphens, and apostrophes'
      }),
    
    lastName: Joi.string()
      .min(1)
      .max(100)
      .pattern(/^[a-zA-Z\s\-']+$/)
      .trim()
      .messages({
        'string.pattern.base': 'Last name can only contain letters, spaces, hyphens, and apostrophes'
      }),
    
    // Additional profile fields can be added here
    phone: Joi.string()
      .pattern(/^\+?[\d\s\-\(\)]+$/)
      .max(20)
      .optional()
      .messages({
        'string.pattern.base': 'Please enter a valid phone number'
      }),
    
    dateOfBirth: Joi.date()
      .max('now')
      .optional()
      .messages({
        'date.max': 'Date of birth cannot be in the future'
      })
  }),

  // Email verification
  verifyEmail: Joi.object({
    token: Joi.string()
      .required()
      .messages({
        'any.required': 'Verification token is required'
      })
  }),

  // Refresh token validation
  refreshToken: Joi.object({
    refreshToken: Joi.string()
      .required()
      .messages({
        'any.required': 'Refresh token is required'
      })
  }),

  // Admin user creation
  adminCreateUser: Joi.object({
    email: Joi.string()
      .required()
      .custom(emailValidation),
    
    firstName: Joi.string()
      .required()
      .min(1)
      .max(100)
      .pattern(/^[a-zA-Z\s\-']+$/)
      .trim(),
    
    lastName: Joi.string()
      .required()
      .min(1)
      .max(100)
      .pattern(/^[a-zA-Z\s\-']+$/)
      .trim(),
    
    role: Joi.string()
      .valid('user', 'moderator', 'admin')
      .default('user'),
    
    // Admin can create users without passwords (will be set via email)
    sendWelcomeEmail: Joi.boolean().default(true)
  }),

  // Query parameters for user listing
  getUsersList: Joi.object({
    page: Joi.number()
      .integer()
      .min(1)
      .default(1),
    
    limit: Joi.number()
      .integer()
      .min(1)
      .max(100)
      .default(10),
    
    role: Joi.string()
      .valid('user', 'moderator', 'admin')
      .optional(),
    
    active: Joi.boolean().optional(),
    
    search: Joi.string()
      .max(100)
      .optional(),
    
    sortBy: Joi.string()
      .valid('created_at', 'email', 'last_login', 'role')
      .default('created_at'),
    
    sortOrder: Joi.string()
      .valid('asc', 'desc')
      .default('desc')
  }),

  // Contact form validation
  contactForm: Joi.object({
    name: Joi.string()
      .required()
      .min(1)
      .max(100)
      .trim(),
    
    email: Joi.string()
      .required()
      .email()
      .max(320),
    
    subject: Joi.string()
      .required()
      .min(1)
      .max(200)
      .trim(),
    
    message: Joi.string()
      .required()
      .min(10)
      .max(2000)
      .trim(),
    
    // Honeypot field for spam protection
    website: Joi.string()
      .empty('')
      .messages({
        'string.empty': 'Please leave this field empty'
      })
  })
};

/**
 * VALIDATION MIDDLEWARE FACTORY
 * 
 * Creates middleware that validates request body against a schema.
 */
export const validate = (schema, source = 'body') => {
  return (req, res, next) => {
    // Get data from specified source
    let data;
    switch (source) {
      case 'body':
        data = req.body;
        break;
      case 'query':
        data = req.query;
        break;
      case 'params':
        data = req.params;
        break;
      default:
        data = req.body;
    }

    // Validate data against schema
    const { error, value, warning } = schema.validate(data, {
      abortEarly: false, // Return all errors, not just the first
      stripUnknown: true, // Remove unknown properties
      convert: true // Type conversion (e.g., string to number)
    });

    if (error) {
      // Format validation errors
      const errors = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message,
        value: detail.context?.value
      }));

      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        code: 'VALIDATION_ERROR',
        errors
      });
    }

    // Log warnings if any (for debugging)
    if (warning) {
      console.warn('⚠️ Validation warning:', warning.message);
    }

    // Replace request data with validated and sanitized data
    switch (source) {
      case 'body':
        req.body = value;
        break;
      case 'query':
        req.query = value;
        break;
      case 'params':
        req.params = value;
        break;
    }

    next();
  };
};

/**
 * SANITIZATION MIDDLEWARE
 * 
 * Additional sanitization for security (runs after validation).
 */
export const sanitize = (req, res, next) => {
  const sanitizeObject = (obj) => {
    for (const key in obj) {
      if (typeof obj[key] === 'string') {
        // Remove potentially dangerous characters
        obj[key] = obj[key]
          .replace(/[<>]/g, '') // Remove < and > to prevent XSS
          .trim(); // Remove leading/trailing whitespace
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
        sanitizeObject(obj[key]); // Recursively sanitize nested objects
      }
    }
  };

  // Sanitize request body
  if (req.body && typeof req.body === 'object') {
    sanitizeObject(req.body);
  }

  // Sanitize query parameters
  if (req.query && typeof req.query === 'object') {
    sanitizeObject(req.query);
  }

  next();
};

/**
 * FILE UPLOAD VALIDATION
 * 
 * Validates uploaded files for security.
 */
export const validateFileUpload = (options = {}) => {
  const {
    maxSize = 5 * 1024 * 1024, // 5MB default
    allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif'],
    allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif']
  } = options;

  return (req, res, next) => {
    if (!req.file && !req.files) {
      return next(); // No files uploaded
    }

    const files = req.files || [req.file];

    for (const file of files) {
      // Check file size
      if (file.size > maxSize) {
        return res.status(400).json({
          success: false,
          message: `File size exceeds limit of ${maxSize / 1024 / 1024}MB`,
          code: 'FILE_TOO_LARGE'
        });
      }

      // Check MIME type
      if (!allowedMimeTypes.includes(file.mimetype)) {
        return res.status(400).json({
          success: false,
          message: `File type not allowed. Allowed types: ${allowedMimeTypes.join(', ')}`,
          code: 'INVALID_FILE_TYPE'
        });
      }

      // Check file extension
      const ext = path.extname(file.originalname).toLowerCase();
      if (!allowedExtensions.includes(ext)) {
        return res.status(400).json({
          success: false,
          message: `File extension not allowed. Allowed extensions: ${allowedExtensions.join(', ')}`,
          code: 'INVALID_FILE_EXTENSION'
        });
      }
    }

    next();
  };
};

/**
 * HONEYPOT VALIDATION
 * 
 * Checks for honeypot fields to prevent spam bots.
 */
export const checkHoneypot = (honeypotField = 'website') => {
  return (req, res, next) => {
    if (req.body[honeypotField] && req.body[honeypotField].trim() !== '') {
      // Honeypot field was filled, likely a bot
      console.warn('🍯 Honeypot triggered:', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        honeypotValue: req.body[honeypotField]
      });

      // Return success to avoid revealing the honeypot
      return res.status(200).json({
        success: true,
        message: 'Form submitted successfully'
      });
    }

    // Remove honeypot field from request body
    delete req.body[honeypotField];
    next();
  };
};

/**
 * CONDITIONAL VALIDATION
 * 
 * Applies validation only under certain conditions.
 */
export const conditionalValidate = (condition, schema, source = 'body') => {
  return (req, res, next) => {
    // Check if condition is met
    const shouldValidate = typeof condition === 'function' 
      ? condition(req) 
      : condition;

    if (!shouldValidate) {
      return next();
    }

    // Apply validation
    return validate(schema, source)(req, res, next);
  };
};

/**
 * VALIDATION ERROR FORMATTER
 * 
 * Standardizes validation error responses.
 */
export const formatValidationError = (error) => {
  return {
    success: false,
    message: 'Validation failed',
    code: 'VALIDATION_ERROR',
    errors: error.details.map(detail => ({
      field: detail.path.join('.'),
      message: detail.message,
      value: detail.context?.value,
      type: detail.type
    }))
  };
}; 