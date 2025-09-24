require('dotenv').config();
require('./config/validateEnv');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const { sequelize, connectMongoDB } = require('./config/db');
const errorHandler = require('./middlewares/error.middleware');
const notFound = require('./middlewares/notFound.middleware');
const logger = require('./utils/logger');

const authRoutes = require('./routes/auth.routes');
const healthRoutes = require('./routes/health.routes');

(async () => {
  try {
    if (process.env.DB_TYPE === 'mongodb') {
      await connectMongoDB();
      logger.info('✅ MongoDB connected');
    } else if (process.env.DB_TYPE === 'postgres' && sequelize) {
      await sequelize.sync({ alter: true });
      logger.info('✅ Sequelize sync completed');
    } else {
      throw new Error('Invalid DB_TYPE or DB connection failed');
    }
  } catch (err) {
    logger.error(`❌ Database initialization failed: ${err.message}`);
    process.exit(1);
  }
})();

const app = express();

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(helmet());
app.use(cors());

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use(limiter);

if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
} else {
  app.use(morgan('combined', { stream: { write: msg => logger.info(msg.trim()) } }));
}

// ROUTES
app.use('/api/auth', authRoutes);
app.use('/api/health', healthRoutes); // ✅ fixed mounting

// 404 & Error Handling
app.use(notFound);
app.use(errorHandler);

process.on('unhandledRejection', err => {
  logger.error(`❌ Unhandled Rejection: ${err && err.message ? err.message : err}`);
  process.exit(1);
});

module.exports = app;