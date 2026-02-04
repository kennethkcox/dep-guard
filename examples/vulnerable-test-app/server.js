/**
 * VULNERABLE TEST APPLICATION
 *
 * This file contains intentionally vulnerable code patterns for testing.
 * These are HARD TO DETECT vulnerabilities that may bypass basic scanners.
 */

const express = require('express');
const axios = require('axios');
const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/**
 * CASE 1: Deep nested call chain to vulnerable function
 * lodash template vulnerability is called through multiple layers
 */
const { processTemplate } = require('./services/template-processor');
const { sanitizeUserInput } = require('./utils/sanitizer');

app.post('/api/render', async (req, res) => {
    try {
        const userInput = req.body.template;
        const sanitized = sanitizeUserInput(userInput);
        const result = await processTemplate(sanitized);
        res.json({ result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * CASE 2: Vulnerability hidden in dynamically imported module
 * The vulnerability is only reachable if certain conditions are met
 */
app.get('/api/parse-xml', async (req, res) => {
    const format = req.query.format || 'json';

    if (format === 'xml') {
        // Dynamic import - harder to trace
        const parser = require('./parsers/xml-parser');
        const result = await parser.parseXmlData(req.query.data);
        res.json(result);
    } else {
        res.json({ data: req.query.data });
    }
});

/**
 * CASE 3: Vulnerability in callback/promise chain
 * Vulnerable code is executed in a callback, making it harder to trace
 */
const { fetchUserData } = require('./services/user-service');

app.get('/api/user/:id', (req, res) => {
    const userId = req.params.id;

    fetchUserData(userId)
        .then(userData => {
            // This calls a function that uses vulnerable semver
            return require('./utils/version-checker').checkCompatibility(userData.version);
        })
        .then(compatible => {
            res.json({ compatible });
        })
        .catch(err => res.status(500).json({ error: err.message }));
});

/**
 * CASE 4: Vulnerability accessed via object property/method lookup
 * Makes static analysis harder
 */
const handlers = {
    json: require('./handlers/json-handler'),
    xml: require('./handlers/xml-handler'),
    html: require('./handlers/html-handler')
};

app.post('/api/process', (req, res) => {
    const type = req.body.type || 'json';
    const handler = handlers[type];

    if (handler) {
        handler.process(req.body.data)
            .then(result => res.json(result))
            .catch(err => res.status(500).json({ error: err.message }));
    } else {
        res.status(400).json({ error: 'Unknown type' });
    }
});

/**
 * CASE 5: Vulnerability in array iteration with dynamic function calls
 */
const processors = [
    require('./processors/validator'),
    require('./processors/transformer'),
    require('./processors/encoder')
];

app.post('/api/pipeline', async (req, res) => {
    let data = req.body.data;

    try {
        // Each processor may use vulnerable packages
        for (const processor of processors) {
            data = await processor.process(data);
        }
        res.json({ result: data });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * CASE 6: Vulnerability triggered only in error handling path
 * Often missed because it's not in the happy path
 */
app.post('/api/validate', async (req, res) => {
    try {
        const data = req.body;

        if (!data.email) {
            throw new Error('Email required');
        }

        res.json({ valid: true });
    } catch (error) {
        // Error handler uses vulnerable package
        const errorFormatter = require('./utils/error-formatter');
        const formatted = errorFormatter.format(error, req.body);
        res.status(400).json(formatted);
    }
});

/**
 * CASE 7: Vulnerability in conditionally loaded module based on environment
 */
const env = process.env.NODE_ENV || 'development';
const configLoader = env === 'production'
    ? require('./config/prod-config')
    : require('./config/dev-config');

app.get('/api/config', (req, res) => {
    // Config loader might use vulnerable packages
    const config = configLoader.load(req.query.key);
    res.json(config);
});

/**
 * CASE 8: Vulnerability in authentication middleware chain
 * Only reachable for authenticated requests
 */
const { authenticateToken } = require('./middleware/auth');
const { logActivity } = require('./services/logger');

app.get('/api/protected', authenticateToken, (req, res) => {
    // Logger uses vulnerable jwt package
    logActivity(req.user, 'accessed_protected_resource');
    res.json({ message: 'Protected data', user: req.user });
});

/**
 * CASE 9: Vulnerability through third-party API integration
 * Vulnerable package used in external service call
 */
app.post('/api/notify', async (req, res) => {
    try {
        const notifier = require('./services/notification-service');
        await notifier.send({
            type: req.body.type,
            message: req.body.message,
            recipients: req.body.recipients
        });
        res.json({ sent: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * CASE 10: Vulnerability in scheduled/background job
 * Not directly triggered by HTTP request
 */
const { scheduleCleanup } = require('./jobs/cleanup-job');

// This runs every hour, using vulnerable packages
scheduleCleanup(() => {
    console.log('Cleanup job executed');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Vulnerable test app listening on port ${PORT}`);
    console.log('WARNING: This app contains intentional vulnerabilities for testing');
});

module.exports = app;
