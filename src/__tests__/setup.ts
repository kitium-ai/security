/**
 * Vitest setup file
 */
import { initializeLogger } from '@kitiumai/logger';

// Initialize logger for tests
initializeLogger({
  level: 'error',
  enableConsole: false,
  enableFile: false,
  loki: {
    enabled: false,
  },
  sentry: {
    enabled: false,
  },
});
