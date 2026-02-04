/**
 * XML Parser - uses vulnerable xml2js
 * Only loaded dynamically when format=xml
 */

const xml2js = require('xml2js');

async function parseXmlData(xmlString) {
    const parser = new xml2js.Parser({
        // VULNERABLE: XXE (XML External Entity) attack possible
        // xml2js < 0.5.0 has XXE vulnerability
        explicitArray: false
    });

    return new Promise((resolve, reject) => {
        parser.parseString(xmlString, (err, result) => {
            if (err) {
                reject(err);
            } else {
                resolve(result);
            }
        });
    });
}

function parseXmlBuffer(buffer) {
    return parseXmlData(buffer.toString('utf8'));
}

module.exports = {
    parseXmlData,
    parseXmlBuffer
};
