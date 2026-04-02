const express = require('express');
const { knex: db } = require('../db');

const router = express.Router();

router.get('/leaderboard', async (req, res) => {

    try {
        const { level } = req.query; // Changed from level_id to match your schema
        const limit = parseInt(req.query.limit || '50');

        // Build query to aggregate total scores per user
        let query = db('scores as s')
            .join('users as u', 's.user_id', 'u.id')
            .select(
                'u.username',
                'u.country_flag',
                's.level',
                's.score',
            );

        if (level) {
            query = query.where('s.level', level);
        }

        const results = await query
            .orderBy('s.score', 'desc')
            .limit(limit);

        const leaderboard = results.map(row => ({
            username: row.username,
            score: row.score,
            country_flag: row.country_flag || 'international',
            level: row.level,
        }));

        res.json(leaderboard);
    } catch (err) {
        console.error('Leaderboard error:', err);
        res.status(500).json({ error: 'Failed to load leaderboard' });
    }
});

module.exports = router;