const sequelize = require('../config/db');
const User = require('../models/user.model');
const logger = require('../utils/logger'); // your combined logger

const run = async () => {
  try {
    logger.info('Authenticating database connection...');
    await sequelize.authenticate();
    logger.info('Database connection established successfully.');

    logger.info('Synchronizing database models...');
    await sequelize.sync({ alter: true });
    logger.info('Database synchronized successfully.');

    process.exit(0);
  } catch (err) {
    logger.error('Database setup failed: %o', err);
    process.exit(1);
  }
};

run();