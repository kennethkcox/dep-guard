/**
 * Template processor - uses vulnerable lodash.template
 * Deep in the call chain, making it harder to detect
 */

const _ = require('lodash');

class TemplateProcessor {
    constructor() {
        this.cache = new Map();
    }

    async processTemplate(templateString) {
        // Check cache first
        if (this.cache.has(templateString)) {
            return this.cache.get(templateString);
        }

        // VULNERABLE: lodash.template with user input
        // This is the actual vulnerability but it's nested deep
        const compiled = _.template(templateString);
        const result = compiled({ user: 'guest' });

        this.cache.set(templateString, result);
        return result;
    }

    async processTemplateWithData(templateString, data) {
        // Another path to the vulnerable function
        const compiled = _.template(templateString);
        return compiled(data);
    }

    clearCache() {
        this.cache.clear();
    }
}

module.exports = new TemplateProcessor();
