import baseConfig from '@kitiumai/config/eslint.config.base.js';

export default [
  ...baseConfig,
  {
    rules: {
      // Allow relative imports within the same package for internal organization
      'no-restricted-imports': 'off',
      // Disable explicit any errors for type definitions and adapters
      '@typescript-eslint/no-explicit-any': 'off',
      // Allow missing return types for test files and Express middleware
      '@typescript-eslint/explicit-function-return-type': 'off',
      // Allow flexible naming for HTTP headers and special properties
      '@typescript-eslint/naming-convention': 'off',
    },
  },
];
