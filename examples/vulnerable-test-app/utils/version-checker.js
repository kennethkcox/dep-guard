/**
 * Version checker - uses vulnerable semver
 * Called in promise chain
 */

const semver = require('semver');

async function checkCompatibility(userVersion) {
    // VULNERABLE: semver.satisfies with malicious input causes ReDoS
    // semver < 7.5.2 has ReDoS vulnerability
    const requiredVersion = '>=1.0.0';

    try {
        const isCompatible = semver.satisfies(userVersion, requiredVersion);
        return {
            compatible: isCompatible,
            userVersion,
            requiredVersion
        };
    } catch (error) {
        return {
            compatible: false,
            error: error.message
        };
    }
}

function parseVersion(versionString) {
    // Another path to vulnerable semver
    return semver.parse(versionString);
}

function compareVersions(v1, v2) {
    // Yet another path
    return semver.compare(v1, v2);
}

module.exports = {
    checkCompatibility,
    parseVersion,
    compareVersions
};
