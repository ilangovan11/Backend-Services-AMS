// src/utils/logger.js
const { createLogger, format, transports } = require('winston');
const { combine, timestamp, printf, colorize, json, errors, splat } = format;
const fs = require('fs');
const path = require('path');

const logDir = path.join(__dirname, '../../logs');
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });

const logFormat = printf(({ level, message, timestamp, stack }) => {
  return stack
    ? `${timestamp} [${level}]: ${message} - ${stack}`
    : `${timestamp} [${level}]: ${message}`;
});

const logger = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: combine(
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    errors({ stack: true }),
    splat(),
    process.env.NODE_ENV === 'production'
      ? json()
      : combine(colorize(), logFormat)
  ),
  transports: [
    new transports.Console(),
    new transports.File({
      filename: path.join(logDir, 'error.log'),
      level: 'error'
    }),
    new transports.File({
      filename: path.join(logDir, 'combined.log')
    })
  ],
  exitOnError: false
});

module.exports = logger;