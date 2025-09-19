require('dotenv').config();
const mongoose = require('mongoose');
const { Sequelize } = require('sequelize');
const logger = require('../utils/logger');

let sequelize = null;

if (process.env.DB_TYPE === 'postgres') {
  const connectionString = `postgres://${process.env.DB_USER}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}:${process.env.DB_PORT}/${process.env.DB_NAME}`;

  sequelize = new Sequelize(connectionString, {
    dialect: 'postgres',
    logging: process.env.NODE_ENV === 'development' ? console.log : false,
    pool: { max: 5, min: 0, acquire: 30000, idle: 10000 }
  });

  (async () => {
    try {
      await sequelize.authenticate();
      logger.info('✅ PostgreSQL connected successfully!');
    } catch (err) {
      logger.error(`❌ PostgreSQL connection error: ${err.message}`);
      process.exit(1);
    }
  })();
}

const connectMongoDB = async () => {
  if (process.env.DB_TYPE !== 'mongodb') return;
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    logger.info(`✅ MongoDB connected: ${conn.connection.host}`);
  } catch (err) {
    logger.error(`❌ MongoDB connection error: ${err.message}`);
    process.exit(1);
  }
};

module.exports = { sequelize, connectMongoDB };