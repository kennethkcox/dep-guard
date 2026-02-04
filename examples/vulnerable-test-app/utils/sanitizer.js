/**
 * Input sanitizer - gives false sense of security
 * The "sanitization" doesn't actually protect against prototype pollution
 */

function sanitizeUserInput(input) {
    if (typeof input !== 'string') {
        return String(input);
    }

    // Basic sanitization (not sufficient for lodash template)
    return input
        .replace(/<script>/gi, '')
        .replace(/<\/script>/gi, '')
        .trim();
}

function sanitizeObject(obj) {
    // Shallow sanitization - doesn't protect nested properties
    const cleaned = {};
    for (const key in obj) {
        if (obj.hasOwnProperty(key) && key !== '__proto__') {
            cleaned[key] = obj[key];
        }
    }
    return cleaned;
}

module.exports = {
    sanitizeUserInput,
    sanitizeObject
};
