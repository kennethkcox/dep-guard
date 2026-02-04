/**
 * Logger service - uses jwt for audit trails
 */

const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const LOG_FILE = path.join(__dirname, '../logs/activity.log');

function logActivity(user, action) {
    const timestamp = new Date().toISOString();

    // Create signed log entry using jwt
    const logEntry = jwt.sign({
        user: user.id || user.username,
        action,
        timestamp
    }, 'log-secret', { algorithm: 'HS256' });

    try {
        fs.appendFileSync(LOG_FILE, logEntry + '\n');
    } catch (error) {
        console.error('Failed to write log:', error.message);
    }
}

function getActivityLogs() {
    try {
        const logs = fs.readFileSync(LOG_FILE, 'utf8');
        return logs.split('\n')
            .filter(line => line.trim())
            .map(line => jwt.decode(line));
    } catch (error) {
        return [];
    }
}

module.exports = {
    logActivity,
    getActivityLogs
};
