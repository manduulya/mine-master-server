// db.js
const knex = require('knex');
const redis = require('redis');

// Knex configuration
const knexConfig = {
    client: 'pg',
    connection: {
        host: process.env.DB_HOST || 'localhost',
        port: process.env.DB_PORT || 5432,
        user: process.env.DB_USER || 'postgres',
        password: process.env.DB_PASSWORD || 'password',
        database: process.env.DB_NAME || 'minemaster',
        // For Docker/production, you can also use a connection string:
        // connectionString: process.env.DATABASE_URL,
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
    },
    pool: {
        min: 2,
        max: 10
    },
    migrations: {
        tableName: 'knex_migrations',
        directory: './migrations'
    }
};

// Initialize Knex
const db = knex(knexConfig);

// Redis configuration
const redisClient = redis.createClient({
    host: process.env.REDIS_HOST || 'localhost',
    port: process.env.REDIS_PORT || 6379,
    password: process.env.REDIS_PASSWORD || undefined,
    // For Docker/production, you can also use a URL:
    // url: process.env.REDIS_URL
});

// Redis connection handling
redisClient.on('error', (err) => {
    console.error('Redis connection error:', err);
});

redisClient.on('connect', () => {
    console.log('Connected to Redis');
});

// Export both connections
module.exports = {
    knex: db,
    redis: redisClient
};