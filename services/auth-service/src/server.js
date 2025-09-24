require('dotenv').config();
const app = require('./app');
const logger = require('./utils/logger');

const PORT = process.env.PORT || 3001;

const server = app.listen(PORT, () => {
  logger.info(`Auth service running in ${process.env.NODE_ENV || 'development'} mode on port ${PORT}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down');
  server.close(() => logger.info('Server closed'));
});

// Optional: handle unhandled promise rejections at server level
process.on('unhandledRejection', (err) => {
  logger.error(`❌ Unhandled Rejection at server: ${err?.message || err}`);
  server.close(() => process.exit(1));
});

module.exports = server;
