/**
 * XML Handler - uses xml parser
 */

const xmlParser = require('../parsers/xml-parser');

async function process(data) {
    if (typeof data === 'string') {
        return xmlParser.parseXmlData(data);
    } else if (Buffer.isBuffer(data)) {
        return xmlParser.parseXmlBuffer(data);
    } else {
        return { error: 'Invalid data type' };
    }
}

module.exports = {
    process
};
