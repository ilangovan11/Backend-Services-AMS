const jwt = require('jsonwebtoken');
const User = require('../models/user.model');
const logger = require('../utils/logger');

const jwtSecret = process.env.JWT_SECRET || 'change-me';

const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ success: false, message: 'Access denied. No token provided.' });
    }

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      return res.status(401).json({ success: false, message: 'Token format is invalid.' });
    }

    const token = parts[1];
    const decoded = jwt.verify(token, jwtSecret);

    let user;
    if (process.env.DB_TYPE === 'mongodb') {
      user = await User.findById(decoded.id).select('-password');
    } else {
      user = await User.findByPk(decoded.id);
    }

    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid token or user not found.' });
    }

    req.user = user;
    next();
  } catch (error) {
    logger.error(`Authentication error: ${error.message}`);

    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ success: false, message: 'Invalid token.' });
    }

    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, message: 'Token expired.' });
    }

    res.status(500).json({ success: false, message: 'Server error during authentication.' });
  }
};

const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ success: false, message: 'Access denied. Insufficient permissions.' });
    }
    next();
  };
};

module.exports = { authenticate, authorize };
