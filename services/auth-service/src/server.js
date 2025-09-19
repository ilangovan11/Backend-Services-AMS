const app = require('./app');
const logger = require('./utils/logger');

const PORT = process.env.PORT || 3001;

const server = app.listen(PORT, () => {
  logger.info(`Auth service running in ${process.env.NODE_ENV || 'development'} mode on port ${PORT}`);
});

const DB_HOST = process.env.DB_HOST || 'localhost';

process.on('SIGTERM', () => {
  logger.info('SIGTERM received, shutting down');
  server.close(() => logger.info('Server closed'));
});

module.exports = server;