module.exports = {
  env: {
    node: true,
    es2021: true,
  },
  extends: [
    'eslint:recommended',
  ],
  parserOptions: {
    ecmaVersion: 12,
    sourceType: 'module',
  },
  rules: {
    'no-unused-vars': 'warn',
    'no-console': 'off', // Console is OK in backend
    'prefer-const': 'warn',
    'no-var': 'error',
    'eqeqeq': 'warn',
    'curly': 'warn',
  },
}; 