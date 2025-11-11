// verifyToken.js
require('dotenv').config();
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

module.exports = function verifyToken(req, res, next) {
  // Look for Authorization header
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];
  if (!authHeader) {
    return res.status(401).json({ message: 'Token missing' });
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({ message: 'Invalid authorization format' });
  }

  const token = parts[1];

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      // invalid or expired token => respond 403 to match screenshots/requirements
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    // attach decoded payload (e.g. username, id) to req.user
    req.user = decoded;
    next();
  });
};
