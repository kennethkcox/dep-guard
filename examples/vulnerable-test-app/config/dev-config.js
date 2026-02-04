/**
 * Development config loader
 */

const _ = require('lodash');

const defaultConfig = {
    env: 'development',
    debug: true,
    logLevel: 'debug'
};

function load(key) {
    if (key) {
        return _.get(defaultConfig, key);
    }
    return _.cloneDeep(defaultConfig);
}

function merge(userConfig) {
    // VULNERABLE: _.merge with user input
    return _.merge({}, defaultConfig, userConfig);
}

module.exports = {
    load,
    merge
};
