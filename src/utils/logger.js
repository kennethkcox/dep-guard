/**
 * Structured Logger for DepGuard
 * Provides production-grade logging with levels, timestamps, and structured output
 */

const fs = require('fs');
const path = require('path');
const chalk = require('chalk');

const LOG_LEVELS = {
  DEBUG: 0,
  INFO: 1,
  WARN: 2,
  ERROR: 3,
  FATAL: 4
};

class Logger {
  constructor(options = {}) {
    this.level = LOG_LEVELS[options.level?.toUpperCase()] ?? LOG_LEVELS.INFO;
    this.outputFile = options.outputFile || null;
    this.format = options.format || 'text'; // 'text' or 'json'
    this.silent = options.silent || false;
    this.colorize = options.colorize !== false;
    this.context = options.context || {};

    // Create log file if specified
    if (this.outputFile) {
      const dir = path.dirname(this.outputFile);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    }
  }

  _log(level, message, meta = {}) {
    const levelNum = LOG_LEVELS[level];
    if (levelNum < this.level || this.silent) return;

    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      level,
      message,
      ...this.context,
      ...meta
    };

    // Format output
    let output;
    if (this.format === 'json') {
      output = JSON.stringify(logEntry);
    } else {
      output = this._formatText(logEntry);
    }

    // Console output
    if (!this.silent) {
      console.log(output);
    }

    // File output
    if (this.outputFile) {
      try {
        fs.appendFileSync(this.outputFile, output + '\n', 'utf8');
      } catch (error) {
        console.error('Failed to write to log file:', error.message);
      }
    }
  }

  _formatText(entry) {
    const { timestamp, level, message, ...meta } = entry;
    const time = timestamp.substring(11, 19); // HH:MM:SS

    let levelStr = level.padEnd(5);
    if (this.colorize) {
      switch (level) {
      case 'DEBUG': levelStr = chalk.gray(levelStr); break;
      case 'INFO':  levelStr = chalk.cyan(levelStr); break;
      case 'WARN':  levelStr = chalk.yellow(levelStr); break;
      case 'ERROR': levelStr = chalk.red(levelStr); break;
      case 'FATAL': levelStr = chalk.red.bold(levelStr); break;
      }
    }

    let output = `[${time}] ${levelStr} ${message}`;

    // Add metadata if present
    const metaKeys = Object.keys(meta).filter(k => !['context', 'component'].includes(k));
    if (metaKeys.length > 0) {
      const metaStr = metaKeys.map(k => `${k}=${JSON.stringify(meta[k])}`).join(' ');
      output += chalk.gray(` {${metaStr}}`);
    }

    return output;
  }

  debug(message, meta = {}) {
    this._log('DEBUG', message, meta);
  }

  info(message, meta = {}) {
    this._log('INFO', message, meta);
  }

  warn(message, meta = {}) {
    this._log('WARN', message, meta);
  }

  error(message, meta = {}) {
    this._log('ERROR', message, meta);
  }

  fatal(message, meta = {}) {
    this._log('FATAL', message, meta);
  }

  // Create child logger with additional context
  child(context = {}) {
    return new Logger({
      level: Object.keys(LOG_LEVELS).find(k => LOG_LEVELS[k] === this.level),
      outputFile: this.outputFile,
      format: this.format,
      silent: this.silent,
      colorize: this.colorize,
      context: { ...this.context, ...context }
    });
  }

  // Metrics tracking
  startTimer(label) {
    return {
      label,
      start: Date.now(),
      end: () => {
        const duration = Date.now() - this.start;
        this.info(`Timer: ${label}`, { duration_ms: duration });
        return duration;
      }
    };
  }
}

// Global logger instance
let globalLogger = new Logger({ level: 'INFO' });

function getLogger() {
  return globalLogger;
}

function setLogger(logger) {
  globalLogger = logger;
}

function configureLogger(options) {
  globalLogger = new Logger(options);
  return globalLogger;
}

module.exports = {
  Logger,
  getLogger,
  setLogger,
  configureLogger,
  LOG_LEVELS
};
