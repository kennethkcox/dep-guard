/**
 * Validator processor - uses validator package
 */

const validator = require('validator');

async function process(data) {
    if (typeof data === 'string') {
        // Validate email
        if (validator.isEmail(data)) {
            return { valid: true, type: 'email', value: data };
        }
        // Validate URL
        if (validator.isURL(data)) {
            return { valid: true, type: 'url', value: data };
        }
    }

    return { valid: false, value: data };
}

module.exports = {
    process
};
