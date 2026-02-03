/**
 * Custom Error Classes for DepGuard
 * Provides structured error handling with proper error types
 */

class DepGuardError extends Error {
  constructor(message, code = 'DEPGUARD_ERROR', details = {}) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.details = details;
    Error.captureStackTrace(this, this.constructor);
  }

  toJSON() {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      details: this.details
    };
  }
}

class ManifestParsingError extends DepGuardError {
  constructor(message, manifestPath, details = {}) {
    super(message, 'MANIFEST_PARSING_ERROR', { manifestPath, ...details });
  }
}

class VulnerabilityFetchError extends DepGuardError {
  constructor(message, packageName, details = {}) {
    super(message, 'VULNERABILITY_FETCH_ERROR', { packageName, ...details });
  }
}

class FileSystemError extends DepGuardError {
  constructor(message, filePath, operation, details = {}) {
    super(message, 'FILESYSTEM_ERROR', { filePath, operation, ...details });
  }
}

class ValidationError extends DepGuardError {
  constructor(message, field, value, details = {}) {
    super(message, 'VALIDATION_ERROR', { field, value, ...details });
  }
}

class NetworkError extends DepGuardError {
  constructor(message, url, details = {}) {
    super(message, 'NETWORK_ERROR', { url, ...details });
  }
}

class SecurityError extends DepGuardError {
  constructor(message, details = {}) {
    super(message, 'SECURITY_ERROR', details);
  }
}

class AnalysisError extends DepGuardError {
  constructor(message, details = {}) {
    super(message, 'ANALYSIS_ERROR', details);
  }
}

module.exports = {
  DepGuardError,
  ManifestParsingError,
  VulnerabilityFetchError,
  FileSystemError,
  ValidationError,
  NetworkError,
  SecurityError,
  AnalysisError
};
