// routes/healthRoutes.js
const express = require('express');
const { knex: db, redis } = require('../db');

const router = express.Router();

/**
 * Lightweight health check (no DB calls)
 * GET /health
 */
router.get('/health', (req, res) => {
    res.json({ status: 'OK', message: 'Mine Master API is running' });
});

/**
 * Deeper readiness check (optional)
 * GET /health/ready
 * - Verifies Postgres and Redis connectivity
 */
router.get('/health/ready', async (req, res) => {
    const checks = {
        postgres: 'unknown',
        redis: 'unknown',
        timestamp: new Date().toISOString(),
    };

    try {
        await db.raw('SELECT 1');
        checks.postgres = 'ok';
    } catch (e) {
        checks.postgres = 'error';
        checks.postgres_error = e?.message || String(e);
    }

    try {
        await redis.ping();
        checks.redis = 'ok';
    } catch (e) {
        checks.redis = 'error';
        checks.redis_error = e?.message || String(e);
    }

    const ok = checks.postgres === 'ok' && checks.redis === 'ok';
    return res.status(ok ? 200 : 503).json({
        status: ok ? 'OK' : 'NOT_READY',
        checks,
    });
});

module.exports = router;