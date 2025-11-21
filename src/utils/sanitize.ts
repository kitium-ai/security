/**
 * Input Sanitization Utilities
 * Provides utilities for sanitizing user input to prevent XSS, injection attacks, and other security vulnerabilities
 */

import { logger } from './logger';

/**
 * HTML Entity Map for encoding
 */
const HTML_ENTITIES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#x27;',
  '/': '&#x2F;',
};

/**
 * Sanitization Configuration
 */
export interface SanitizeConfig {
  allowedTags?: string[];
  allowedAttributes?: Record<string, string[]>;
  stripScripts?: boolean;
  stripEventHandlers?: boolean;
  maxLength?: number;
}

/**
 * Input Sanitization Service
 */
export class InputSanitizer {
  /**
   * HTML encode a string to prevent XSS
   */
  public static encodeHTML(input: string): string {
    if (typeof input !== 'string') {
      return String(input);
    }

    return input.replace(/[&<>"'/]/g, (char) => HTML_ENTITIES[char] || char);
  }

  /**
   * Decode HTML entities
   */
  public static decodeHTML(input: string): string {
    if (typeof input !== 'string') {
      return String(input);
    }

    const reverseMap: Record<string, string> = {};
    for (const [key, value] of Object.entries(HTML_ENTITIES)) {
      reverseMap[value] = key;
    }

    return input.replace(/&amp;|&lt;|&gt;|&quot;|&#x27;|&#x2F;/g, (entity) => reverseMap[entity] || entity);
  }

  /**
   * Strip all HTML tags from input
   */
  public static stripHTML(input: string): string {
    if (typeof input !== 'string') {
      return String(input);
    }

    return input.replace(/<[^>]*>/g, '');
  }

  /**
   * Remove JavaScript event handlers (onclick, onerror, etc.)
   */
  public static stripEventHandlers(input: string): string {
    if (typeof input !== 'string') {
      return String(input);
    }

    return input.replace(/on\w+\s*=\s*["'][^"']*["']/gi, '');
  }

  /**
   * Remove script tags and their content
   */
  public static stripScripts(input: string): string {
    if (typeof input !== 'string') {
      return String(input);
    }

    return input.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
  }

  /**
   * Sanitize for safe storage in database
   */
  public static sanitizeForDatabase(input: string): string {
    if (typeof input !== 'string') {
      return String(input);
    }

    // Remove null bytes that can cause issues in some databases
    let sanitized = input.replace(/\0/g, '');

    // Normalize unicode characters
    sanitized = sanitized.normalize('NFC');

    return sanitized.trim();
  }

  /**
   * Sanitize email address
   */
  public static sanitizeEmail(email: string): string {
    if (typeof email !== 'string') {
      return '';
    }

    // Basic email format validation and sanitization
    const sanitized = email.toLowerCase().trim();

    // Remove dangerous characters
    return sanitized.replace(/[<>()[\]\\,;:\s@"]/g, (char) => {
      if (char === '@') return '@';
      return '';
    });
  }

  /**
   * Sanitize URL to prevent javascript: and data: protocols
   */
  public static sanitizeURL(url: string): string {
    if (typeof url !== 'string') {
      return '';
    }

    const trimmed = url.trim();

    // Block dangerous protocols
    const dangerousProtocols = [
      'javascript:',
      'data:',
      'vbscript:',
      'file:',
      'about:',
    ];

    const lowerUrl = trimmed.toLowerCase();
    for (const protocol of dangerousProtocols) {
      if (lowerUrl.startsWith(protocol)) {
        logger.warn('Dangerous URL protocol detected', { url: trimmed, protocol });
        return '';
      }
    }

    // Only allow http, https, mailto, tel
    if (trimmed && !trimmed.match(/^(https?|mailto|tel):/i) && !trimmed.startsWith('/') && !trimmed.startsWith('#')) {
      logger.warn('Invalid URL format', { url: trimmed });
      return '';
    }

    return trimmed;
  }

  /**
   * Sanitize filename to prevent path traversal
   */
  public static sanitizeFilename(filename: string): string {
    if (typeof filename !== 'string') {
      return '';
    }

    // Remove path traversal attempts
    let sanitized = filename.replace(/\.\./g, '');

    // Remove directory separators
    sanitized = sanitized.replace(/[\/\\]/g, '');

    // Remove null bytes
    sanitized = sanitized.replace(/\0/g, '');

    // Keep only alphanumeric, dash, underscore, and dot
    sanitized = sanitized.replace(/[^a-zA-Z0-9._-]/g, '_');

    // Prevent hidden files
    if (sanitized.startsWith('.')) {
      sanitized = '_' + sanitized.substring(1);
    }

    return sanitized.trim();
  }

  /**
   * Sanitize SQL identifier (table/column names)
   * Note: Always prefer parameterized queries over this
   */
  public static sanitizeSQLIdentifier(identifier: string): string {
    if (typeof identifier !== 'string') {
      return '';
    }

    // Only allow alphanumeric and underscore
    const sanitized = identifier.replace(/[^a-zA-Z0-9_]/g, '');

    // Prevent starting with a number
    if (/^\d/.test(sanitized)) {
      logger.warn('SQL identifier cannot start with a number', { identifier });
      return '';
    }

    return sanitized;
  }

  /**
   * Sanitize integer input
   */
  public static sanitizeInteger(input: any): number | null {
    const num = parseInt(String(input), 10);
    return isNaN(num) ? null : num;
  }

  /**
   * Sanitize float input
   */
  public static sanitizeFloat(input: any): number | null {
    const num = parseFloat(String(input));
    return isNaN(num) ? null : num;
  }

  /**
   * Sanitize boolean input
   */
  public static sanitizeBoolean(input: any): boolean {
    if (typeof input === 'boolean') {
      return input;
    }

    const str = String(input).toLowerCase();
    return str === 'true' || str === '1' || str === 'yes';
  }

  /**
   * Sanitize phone number
   */
  public static sanitizePhone(phone: string): string {
    if (typeof phone !== 'string') {
      return '';
    }

    // Keep only digits, plus, parentheses, and hyphens
    return phone.replace(/[^\d+()-\s]/g, '').trim();
  }

  /**
   * Truncate string to maximum length
   */
  public static truncate(input: string, maxLength: number): string {
    if (typeof input !== 'string') {
      return '';
    }

    if (input.length <= maxLength) {
      return input;
    }

    return input.substring(0, maxLength);
  }

  /**
   * Comprehensive sanitization with configuration
   */
  public static sanitize(input: string, config: SanitizeConfig = {}): string {
    if (typeof input !== 'string') {
      return String(input);
    }

    let sanitized = input;

    // Apply max length
    if (config.maxLength) {
      sanitized = this.truncate(sanitized, config.maxLength);
    }

    // Strip scripts
    if (config.stripScripts !== false) {
      sanitized = this.stripScripts(sanitized);
    }

    // Strip event handlers
    if (config.stripEventHandlers !== false) {
      sanitized = this.stripEventHandlers(sanitized);
    }

    // If no allowed tags, encode all HTML
    if (!config.allowedTags || config.allowedTags.length === 0) {
      sanitized = this.encodeHTML(sanitized);
    }

    return sanitized;
  }

  /**
   * Sanitize object recursively
   */
  public static sanitizeObject<T extends Record<string, any>>(
    obj: T,
    config: SanitizeConfig = {}
  ): T {
    const sanitized: any = {};

    for (const [key, value] of Object.entries(obj)) {
      if (typeof value === 'string') {
        sanitized[key] = this.sanitize(value, config);
      } else if (Array.isArray(value)) {
        sanitized[key] = value.map((item) =>
          typeof item === 'string'
            ? this.sanitize(item, config)
            : typeof item === 'object' && item !== null
            ? this.sanitizeObject(item, config)
            : item
        );
      } else if (typeof value === 'object' && value !== null) {
        sanitized[key] = this.sanitizeObject(value, config);
      } else {
        sanitized[key] = value;
      }
    }

    return sanitized as T;
  }

  /**
   * Detect potentially malicious patterns
   */
  public static detectMaliciousPatterns(input: string): {
    isSuspicious: boolean;
    patterns: string[];
  } {
    if (typeof input !== 'string') {
      return { isSuspicious: false, patterns: [] };
    }

    const suspiciousPatterns = [
      { pattern: /<script/i, name: 'script tag' },
      { pattern: /javascript:/i, name: 'javascript protocol' },
      { pattern: /on\w+\s*=/i, name: 'event handler' },
      { pattern: /<iframe/i, name: 'iframe tag' },
      { pattern: /eval\(/i, name: 'eval function' },
      { pattern: /expression\(/i, name: 'CSS expression' },
      { pattern: /import\s+/i, name: 'import statement' },
      { pattern: /\.\.\/|\.\.\\/, name: 'path traversal' },
      { pattern: /union\s+select/i, name: 'SQL injection' },
      { pattern: /;\s*drop\s+table/i, name: 'SQL drop' },
      { pattern: /exec\s*\(/i, name: 'exec function' },
    ];

    const detectedPatterns: string[] = [];

    for (const { pattern, name } of suspiciousPatterns) {
      if (pattern.test(input)) {
        detectedPatterns.push(name);
      }
    }

    if (detectedPatterns.length > 0) {
      logger.warn('Malicious patterns detected in input', {
        patterns: detectedPatterns,
        inputLength: input.length,
      });
    }

    return {
      isSuspicious: detectedPatterns.length > 0,
      patterns: detectedPatterns,
    };
  }
}

export const inputSanitizer = InputSanitizer;
