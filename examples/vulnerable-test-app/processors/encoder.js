/**
 * Encoder processor - uses various encoding utilities
 */

const _ = require('lodash');

async function process(data) {
    if (typeof data === 'string') {
        // Encode to base64
        const encoded = Buffer.from(data).toString('base64');
        return {
            encoded,
            original: data
        };
    } else if (typeof data === 'object') {
        // Use lodash to escape HTML entities
        const escaped = _.escape(JSON.stringify(data));
        return {
            escaped,
            original: data
        };
    }

    return data;
}

module.exports = {
    process
};
