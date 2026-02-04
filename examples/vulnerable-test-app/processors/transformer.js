/**
 * Transformer processor - uses lodash operations
 */

const _ = require('lodash');

async function process(data) {
    // Various lodash operations that could be vulnerable
    if (Array.isArray(data)) {
        return _.map(data, item => _.clone(item));
    } else if (typeof data === 'object') {
        // Deep clone with potential vulnerability
        return _.cloneDeep(data);
    } else {
        return data;
    }
}

module.exports = {
    process
};
