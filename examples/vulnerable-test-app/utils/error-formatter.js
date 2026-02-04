/**
 * Error formatter - uses minimist for CLI-like parsing
 */

const minimist = require('minimist');

function format(error, context) {
    // VULNERABLE: minimist < 1.2.6 has prototype pollution
    // Parse context as CLI args (weird pattern but demonstrates vulnerability)
    const args = minimist(Object.keys(context || {}));

    return {
        error: error.message,
        code: error.code || 'UNKNOWN',
        context: args,
        timestamp: new Date().toISOString()
    };
}

function parseErrorContext(str) {
    // Another path to vulnerable minimist
    return minimist(str.split(' '));
}

module.exports = {
    format,
    parseErrorContext
};
