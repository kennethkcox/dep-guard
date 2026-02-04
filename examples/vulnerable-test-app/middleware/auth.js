/**
 * Authentication middleware - uses vulnerable jsonwebtoken
 */

const jwt = require('jsonwebtoken');

const SECRET_KEY = 'insecure-secret-key-for-testing';

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        // VULNERABLE: jsonwebtoken < 9.0.0 has multiple vulnerabilities
        // Including algorithm confusion attacks
        const user = jwt.verify(token, SECRET_KEY);
        req.user = user;
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid token' });
    }
}

function generateToken(payload) {
    // VULNERABLE: jwt.sign with weak algorithm
    return jwt.sign(payload, SECRET_KEY, { algorithm: 'HS256' });
}

function decodeToken(token) {
    // VULNERABLE: jwt.decode without verification
    return jwt.decode(token);
}

module.exports = {
    authenticateToken,
    generateToken,
    decodeToken
};
