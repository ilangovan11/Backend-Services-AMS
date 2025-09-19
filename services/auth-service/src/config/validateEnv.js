require('dotenv').config();

const required = ['DB_TYPE', 'JWT_SECRET', 'BCRYPT_SALT_ROUNDS'];

required.forEach(key => {
  if (!process.env[key]) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
});

if (process.env.DB_TYPE === 'postgres') {
  ['DB_HOST', 'DB_PORT', 'DB_USER', 'DB_PASSWORD', 'DB_NAME'].forEach(key => {
    if (!process.env[key]) {
      throw new Error(`Missing required environment variable for Postgres: ${key}`);
    }
  });
}

if (process.env.DB_TYPE === 'mongodb') {
  if (!process.env.MONGODB_URI) {
    throw new Error('Missing required environment variable for MongoDB: MONGODB_URI');
  }
}