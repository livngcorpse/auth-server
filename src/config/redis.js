const redis = require('redis');
const logger = require('../utils/logger');

let client;

const createRedisClient = () => {
  return redis.createClient({
    socket: {
      host: process.env.REDIS_HOST,
      port: parseInt(process.env.REDIS_PORT) || 6379
    },
    password: process.env.REDIS_PASSWORD,
    database: parseInt(process.env.REDIS_DB) || 0,
    retry_strategy: (options) => {
      if (options.error && options.error.code === 'ECONNREFUSED') {
        logger.error('Redis connection refused');
        return new Error('Redis connection refused');
      }
      if (options.total_retry_time > 1000 * 60 * 60) {
        return new Error('Redis retry time exhausted');
      }
      if (options.attempt > 10) {
        return undefined;
      }
      return Math.min(options.attempt * 100, 3000);
    }
  });
};

const initializeRedis = async () => {
  try {
    client = createRedisClient();
    
    client.on('error', (err) => {
      logger.error('Redis error:', err);
    });
    
    client.on('connect', () => {
      logger.debug('Redis connecting...');
    });
    
    client.on('ready', () => {
      logger.info('✅ Redis connected successfully');
    });
    
    await client.connect();
  } catch (error) {
    logger.error('❌ Redis connection failed:', error);
    throw error;
  }
};

const getClient = () => {
  if (!client) {
    throw new Error('Redis client not initialized');
  }
  return client;
};

module.exports = {
  initializeRedis,
  getClient
};