const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

const { sequelize, connectMongoDB } = require('./config/db'); // <- correct path now
const logger = require('./utils/logger');

(async () => {
  if (process.env.DB_TYPE === 'postgres') {
    try {
      await sequelize.authenticate();
      logger.info('PostgreSQL connection test successful!');
    } catch (err) {
      logger.error('PostgreSQL connection test failed:', err);
    }
  } else {
    await connectMongoDB();
  }
  process.exit(0);
})();
