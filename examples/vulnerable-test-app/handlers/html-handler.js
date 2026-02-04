/**
 * HTML Handler - uses vulnerable handlebars and ejs
 * Accessed via object lookup pattern
 */

const Handlebars = require('handlebars');
const ejs = require('ejs');

async function process(data) {
    const { template, engine, context } = data;

    if (engine === 'handlebars') {
        // VULNERABLE: handlebars < 4.7.8 has prototype pollution
        const compiled = Handlebars.compile(template);
        return compiled(context || {});
    } else if (engine === 'ejs') {
        // VULNERABLE: ejs < 3.1.7 has template injection
        return ejs.render(template, context || {});
    } else {
        return { error: 'Unknown engine' };
    }
}

function processHandlebars(template, data) {
    const compiled = Handlebars.compile(template);
    return compiled(data);
}

module.exports = {
    process,
    processHandlebars
};
