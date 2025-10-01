// db/index.js
const Knex = require('knex');
const config = require('../knexfile').development;
const Redis = require('ioredis');

const knex = Knex(config);
const redis = new Redis(process.env.REDIS_URL || 'redis://redis:6379');

// Optional: simple health check helpers
function verifyDb() {
  return knex.raw('select 1+1 as result');
}

module.exports = {
  knex,
  redis,
  verifyDb
};
