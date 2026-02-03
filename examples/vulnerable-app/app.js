/**
 * Demo Application with Vulnerable Dependencies
 * This app intentionally uses vulnerable versions to demonstrate DepGuard
 */

const express = require('express');
const _ = require('lodash');
const jwt = require('jsonwebtoken');
const axios = require('axios');

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());

/**
 * VULNERABLE: Uses lodash template which has prototype pollution vulnerability
 * CVE-2021-23337 - This is REACHABLE from the /render endpoint
 */
app.post('/render', (req, res) => {
  const template = req.body.template;

  // This uses vulnerable lodash.template function
  const compiled = _.template(template);
  const result = compiled({ data: req.body.data });

  res.send(result);
});

/**
 * VULNERABLE: Uses axios with potential SSRF
 * CVE-2023-45857 - This is REACHABLE from the /fetch endpoint
 */
app.get('/fetch', async (req, res) => {
  const url = req.query.url;

  try {
    const response = await axios.get(url);
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * VULNERABLE: Uses jsonwebtoken with weak verification
 * CVE-2022-23529 - This is REACHABLE from the /verify endpoint
 */
app.post('/verify', (req, res) => {
  const token = req.body.token;

  try {
    const decoded = jwt.verify(token, 'secret');
    res.json({ valid: true, data: decoded });
  } catch (error) {
    res.json({ valid: false, error: error.message });
  }
});

/**
 * Safe endpoint - no vulnerable code paths
 */
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: Date.now() });
});

/**
 * This function exists but is NEVER called
 * Contains vulnerable code but should be marked as NOT REACHABLE
 */
function unusedVulnerableFunction() {
  const template = _.template('<%= data %>');
  return template({ data: 'test' });
}

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
