/**
 * Input Validation Utilities
 * Provides secure validation for CLI arguments, file paths, and user inputs
 */

const path = require('path');
const fs = require('fs');
const { ValidationError, SecurityError } = require('./errors');

class Validator {
  /**
   * Validates numeric range
   */
  static validateNumber(value, name, min, max) {
    const num = Number(value);

    if (isNaN(num)) {
      throw new ValidationError(`${name} must be a valid number`, name, value);
    }

    if (min !== undefined && num < min) {
      throw new ValidationError(`${name} must be at least ${min}`, name, value, { min, max });
    }

    if (max !== undefined && num > max) {
      throw new ValidationError(`${name} must be at most ${max}`, name, value, { min, max });
    }

    return num;
  }

  /**
   * Validates integer range
   */
  static validateInteger(value, name, min, max) {
    const num = this.validateNumber(value, name, min, max);

    if (!Number.isInteger(num)) {
      throw new ValidationError(`${name} must be an integer`, name, value);
    }

    return num;
  }

  /**
   * Validates confidence score (0-1)
   */
  static validateConfidence(value, name = 'confidence') {
    return this.validateNumber(value, name, 0, 1);
  }

  /**
   * Validates file path exists and is within project root (prevents path traversal)
   */
  static validatePath(filePath, projectRoot, mustExist = false) {
    if (!filePath || typeof filePath !== 'string') {
      throw new ValidationError('Path must be a non-empty string', 'path', filePath);
    }

    // Resolve to absolute path
    const absolutePath = path.resolve(filePath);
    const absoluteRoot = path.resolve(projectRoot);

    // Check for path traversal - ensure resolved path is within project root
    const relativePath = path.relative(absoluteRoot, absolutePath);
    if (relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
      throw new SecurityError('Path traversal detected - path must be within project root', {
        path: filePath,
        resolved: absolutePath,
        root: absoluteRoot
      });
    }

    // Check existence if required
    if (mustExist && !fs.existsSync(absolutePath)) {
      throw new ValidationError('Path does not exist', 'path', absolutePath);
    }

    return absolutePath;
  }

  /**
   * Validates and sanitizes cache key to prevent directory traversal
   */
  static sanitizeCacheKey(key) {
    if (!key || typeof key !== 'string') {
      throw new ValidationError('Cache key must be a non-empty string', 'cacheKey', key);
    }

    // Remove all special characters except alphanumeric, hyphen, underscore, @
    const sanitized = key.replace(/[^a-zA-Z0-9\-_@.]/g, '_');

    // Ensure no path separators remain
    if (sanitized.includes(path.sep) || sanitized.includes('/') || sanitized.includes('\\')) {
      throw new SecurityError('Cache key contains path separators after sanitization', {
        original: key,
        sanitized
      });
    }

    // Limit length to prevent filesystem issues
    if (sanitized.length > 255) {
      return sanitized.substring(0, 255);
    }

    return sanitized;
  }

  /**
   * Validates output format
   */
  static validateOutputFormat(format) {
    const validFormats = ['table', 'json', 'html', 'sarif', 'markdown'];

    if (!validFormats.includes(format)) {
      throw new ValidationError(
        `Invalid output format. Must be one of: ${validFormats.join(', ')}`,
        'format',
        format,
        { validFormats }
      );
    }

    return format;
  }

  /**
   * Validates severity level
   */
  static validateSeverity(severity) {
    const validSeverities = ['critical', 'high', 'medium', 'low'];
    const lower = severity.toLowerCase();

    if (!validSeverities.includes(lower)) {
      throw new ValidationError(
        `Invalid severity. Must be one of: ${validSeverities.join(', ')}`,
        'severity',
        severity,
        { validSeverities }
      );
    }

    return lower;
  }

  /**
   * Validates file size is within limits
   */
  static validateFileSize(filePath, maxSizeBytes = 100 * 1024 * 1024) { // Default 100MB
    try {
      const stats = fs.statSync(filePath);

      if (stats.size > maxSizeBytes) {
        throw new ValidationError(
          `File size exceeds maximum allowed size of ${maxSizeBytes} bytes`,
          'fileSize',
          stats.size,
          { maxSizeBytes, filePath }
        );
      }

      return stats.size;
    } catch (error) {
      if (error instanceof ValidationError) throw error;
      throw new ValidationError(`Cannot read file size: ${error.message}`, 'fileSize', filePath);
    }
  }

  /**
   * Validates JSON content size before parsing
   */
  static validateJSONSize(content, maxSizeBytes = 10 * 1024 * 1024) { // Default 10MB
    const size = Buffer.byteLength(content, 'utf8');

    if (size > maxSizeBytes) {
      throw new ValidationError(
        `JSON content exceeds maximum allowed size of ${maxSizeBytes} bytes`,
        'jsonSize',
        size,
        { maxSizeBytes }
      );
    }

    return size;
  }

  /**
   * Validates dependency count
   */
  static validateDependencyCount(count, maxCount = 10000) {
    if (count > maxCount) {
      throw new ValidationError(
        `Dependency count exceeds maximum of ${maxCount}`,
        'dependencyCount',
        count,
        { maxCount }
      );
    }

    return count;
  }

  /**
   * Escapes HTML to prevent XSS in reports
   */
  static escapeHtml(text) {
    if (typeof text !== 'string') return text;

    const map = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    };

    return text.replace(/[&<>"']/g, m => map[m]);
  }

  /**
   * Validates URL format
   */
  static validateUrl(url) {
    try {
      const parsed = new URL(url);

      // Only allow https for security
      if (parsed.protocol !== 'https:') {
        throw new SecurityError('Only HTTPS URLs are allowed', { url, protocol: parsed.protocol });
      }

      return url;
    } catch (error) {
      if (error instanceof SecurityError) throw error;
      throw new ValidationError('Invalid URL format', 'url', url);
    }
  }

  /**
   * Validates scanner options object
   * @param {Object} options - Options to validate
   * @param {Object} schema - Validation schema
   */
  static validateOptions(options, schema = {}) {
    const validated = {};

    for (const [key, rules] of Object.entries(schema)) {
      const value = options[key];

      // Skip if undefined and optional
      if (value === undefined && !rules.required) {
        continue;
      }

      // Check required
      if (rules.required && value === undefined) {
        throw new ValidationError(`Option '${key}' is required`, key, value);
      }

      // Type checking
      if (rules.type && value !== undefined) {
        const actualType = typeof value;
        if (actualType !== rules.type) {
          throw new ValidationError(
            `Option '${key}' must be of type ${rules.type}`,
            key,
            value,
            { expectedType: rules.type, actualType }
          );
        }
      }

      // Number validation
      if (rules.type === 'number' && value !== undefined) {
        if (rules.min !== undefined && value < rules.min) {
          throw new ValidationError(
            `Option '${key}' must be at least ${rules.min}`,
            key,
            value,
            { min: rules.min }
          );
        }
        if (rules.max !== undefined && value > rules.max) {
          throw new ValidationError(
            `Option '${key}' must be at most ${rules.max}`,
            key,
            value,
            { max: rules.max }
          );
        }
        if (rules.integer && !Number.isInteger(value)) {
          throw new ValidationError(`Option '${key}' must be an integer`, key, value);
        }
      }

      // String validation
      if (rules.type === 'string' && value !== undefined) {
        if (rules.minLength !== undefined && value.length < rules.minLength) {
          throw new ValidationError(
            `Option '${key}' must be at least ${rules.minLength} characters`,
            key,
            value
          );
        }
        if (rules.enum && !rules.enum.includes(value)) {
          throw new ValidationError(
            `Option '${key}' must be one of: ${rules.enum.join(', ')}`,
            key,
            value,
            { validValues: rules.enum }
          );
        }
      }

      // Path validation
      if (rules.mustExist && value !== undefined) {
        if (!fs.existsSync(value)) {
          throw new ValidationError(`Path '${value}' does not exist`, key, value);
        }
      }

      validated[key] = value;
    }

    return validated;
  }
}

module.exports = Validator;
