/**
 * JSON Handler - uses lodash merge
 */

const _ = require('lodash');

async function process(data) {
    // VULNERABLE: _.merge can cause prototype pollution
    const defaults = {
        type: 'json',
        version: '1.0'
    };

    // Merge user data with defaults
    const merged = _.merge({}, defaults, data);

    return {
        processed: true,
        data: merged
    };
}

function deepMerge(target, source) {
    // Another path to vulnerable merge
    return _.merge(target, source);
}

module.exports = {
    process,
    deepMerge
};
