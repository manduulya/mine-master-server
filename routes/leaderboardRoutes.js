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
                db.raw('COALESCE(SUM(s.score), 0) as total_score'),
                db.raw('COUNT(s.id) as games_played')
            )
            .groupBy('u.id', 'u.username', 'u.country_flag');

        // Optional: filter by level if provided
        if (level) {
            query = query.where('s.level', level);
        }

        const results = await query
            .orderBy('total_score', 'desc')
            .limit(limit);

        // Return country_flag code directly - Flutter will handle mapping
        const leaderboard = results.map(row => ({
            username: row.username,
            total_score: parseInt(row.total_score) || 0,
            country_flag: row.country_flag || 'international',
            games_played: parseInt(row.games_played) || 0
        }));

        res.json(leaderboard);
    } catch (err) {
        console.error('Leaderboard error:', err);
        res.status(500).json({ error: 'Failed to load leaderboard' });
    }
});

module.exports = router;