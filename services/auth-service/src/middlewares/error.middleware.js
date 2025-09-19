// src/middlewares/error.middleware.js
const logger = require('../utils/logger');

const errorHandler = (err, req, res, next) => {
  // Log detailed error info
  logger.error(`${err.message} - ${req.method} ${req.originalUrl}`, {
    stack: err.stack
  });

  const status = err.statusCode || err.status || 500;

  const response = {
    success: false,
    message: err.message || 'Internal Server Error'
  };

  if (process.env.NODE_ENV === 'development') {
    response.stack = err.stack;
  }

  res.status(status).json(response);
};

module.exports = errorHandler;